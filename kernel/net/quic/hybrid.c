#include <linux/slab.h>
#include <linux/printk.h>
#include "number.h"
#include "socket.h"
#include "frame.h"
#include "intercom.h"
#include "hybrid.h"

#define _HQ_MSG(___sk, ___msg) "[HyQUIC] %s@%s: "___msg"\n",quic_is_serv(___sk)?"server":"client",__func__
#define HQ_MSG(__sk, __msg) _HQ_MSG(__sk, __msg)
#define HQ_PR_ERR(__sk, __msg, ...) printk(KERN_ERR pr_fmt("[HyQUIC] %s@%s: "__msg"\n"), quic_is_serv(__sk)?"server":"client", __func__, ##__VA_ARGS__)
#define HQ_PR_DEBUG(__sk, __msg, ...) pr_debug(_HQ_MSG(__sk, __msg), ##__VA_ARGS__)

#include "hybrid_frame_format_spec.h"

struct hyquic_frame_details_entry {
    struct hlist_node node;
    struct hyquic_frame_details_cont cont;
};

/**
 * Enables hyquic. Is called when user-quic calls a hyquic kernel operation.
*/
inline void hyquic_enable(struct sock *sk)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);

    if (hyquic->enabled)
        return;
    hyquic->enabled = true;
    HQ_PR_DEBUG(sk, "enabled");
}

/**
 * Initializes frame details map.
*/
static int hyquic_frame_details_table_init(struct quic_hash_table *frame_details_table)
{
    struct quic_hash_head *head;
    int i, size = 8;

    head = kmalloc_array(size, sizeof(*head), GFP_KERNEL);
    if (!head)
        return -ENOMEM;
    for (i = 0; i < size; i++) {
		spin_lock_init(&head[i].lock);
		INIT_HLIST_HEAD(&head[i].head);
	}
	frame_details_table->size = size;
	frame_details_table->hash = head;
	return 0;
}

/**
 * Initializes hyquic container.
*/
int hyquic_init(struct hyquic_container *hyquic, struct sock *sk)
{
    hyquic->enabled = false;
    hyquic->sk = sk;
    hyquic->options = (struct hyquic_options) {};

    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);

    hyquic->next_ic_msg_id = 0;
    skb_queue_head_init(&hyquic->usrquic_frames_outqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_fix_inqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_var_deferred);
    if (hyquic_frame_details_table_init(&hyquic->frame_details_table))
        return -ENOMEM;

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Frees frame details map and its content.
*/
static void hyquic_frame_details_table_free(struct quic_hash_table *frame_details_table)
{
    struct quic_hash_head *head;
    struct hyquic_frame_details_entry *entry;
    struct hlist_node *tmp;
    int i;

    for (i = 0; i < frame_details_table->size; i++) {
        head = &frame_details_table->hash[i];
        hlist_for_each_entry_safe(entry, tmp, &head->head, node) {
            hlist_del_init(&entry->node);
            if (entry->cont.format_specification)
                kfree(entry->cont.format_specification);
            kfree(entry);
        }
    }
    kfree(frame_details_table->hash);
}

/**
 * Frees a given transport parameter list and its content.
*/
static void hyquic_transport_params_free(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor, *tmp;

    list_for_each_entry_safe(cursor, tmp, param_list, list) {
        list_del(&cursor->list);
        kfree(cursor->param);
        kfree(cursor);
    }
}

/**
 * Frees hyquic container and its content.
*/
void hyquic_free(struct hyquic_container *hyquic)
{
    hyquic_transport_params_free(&hyquic->transport_params_remote);
    hyquic_transport_params_free(&hyquic->transport_params_local);

    __skb_queue_purge(&hyquic->usrquic_frames_outqueue);
    __skb_queue_purge(&hyquic->unkwn_frames_fix_inqueue);
    __skb_queue_purge(&hyquic->unkwn_frames_var_deferred);
    hyquic_frame_details_table_free(&hyquic->frame_details_table);

    HQ_PR_DEBUG(hyquic->sk, "done");
}

/**
 * Adds a transport parameter list entry to the given transport parameter list.
 * 
 * @param param transport parameter list entry
 * @param param_list transport parameter list
*/
static inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list)
{
    list_add_tail(&param->list, param_list);
}

/**
 * Gets the total length of encoded transport parameters in the given transport parameter list.
 * 
 * @param param_list transport parameter list
 * @return total length in bytes
*/
static inline uint32_t hyquic_transport_params_total_length(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor;
	uint32_t total_length = 0;

	hyquic_transport_param_for_each(cursor, param_list) {
		total_length += cursor->length;
	}
    return total_length;
}

/**
 * Creates and allocates a transport parameter list entry.
 * 
 * @param id transport parameter id
 * @param data encoded transport parameter including id
 * @param length length of encoded transport parameter
 * @return pointer to transport parameter list entry
*/
static inline struct hyquic_transport_param* hyquic_transport_param_create(uint64_t id, void *data, size_t length)
{
    struct hyquic_transport_param *param = (struct hyquic_transport_param*) kmalloc(sizeof(struct hyquic_transport_param), GFP_KERNEL);

    if (!param)
        return NULL;
    param->id = id;
    param->param = data;
    param->length = length;
    return param;
}

/**
 * Creates a frame details list entry and adds it to the frame details map in the given hyquic container.
 * 
 * @param hyquic hyquic container
 * @param frame_details pointer to frame details
 * @param format_specification pointer to frame format specification (may point to NULL)
 * @return negative error code if not successful, otherwise 0
*/
static inline int hyquic_frame_details_create(struct hyquic_container *hyquic, struct hyquic_frame_details *frame_details, uint8_t *format_specification)
{
    struct quic_hash_head *head;
    struct hyquic_frame_details_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;
    
    memcpy(&entry->cont.details, frame_details, sizeof(*frame_details));
    if (format_specification)
        entry->cont.format_specification = kmemdup(format_specification, frame_details->format_specification_avail, GFP_KERNEL);
    else
        entry->cont.format_specification = NULL;

    head = hyquic_raw_frame_type_head(&hyquic->frame_details_table, frame_details->frame_type);
    hlist_add_head(&entry->node, &head->head);

    HQ_PR_DEBUG(hyquic->sk, "done, type=%llu", frame_details->frame_type);
    return 0;
}

/**
 * Gets frame details by frame type.
 * 
 * @param hyquic hyquic container
 * @param frame_type frame type
 * @return pointer to frame details container (may point to NULL if not existent)
*/
struct hyquic_frame_details_cont* hyquic_frame_details_get(struct hyquic_container *hyquic, uint64_t frame_type)
{
    struct quic_hash_head *head = hyquic_raw_frame_type_head(&hyquic->frame_details_table, frame_type);
    struct hyquic_frame_details_entry *cursor;

    hlist_for_each_entry(cursor, &head->head, node) {
        if (cursor->cont.details.frame_type == frame_type)
            return &cursor->cont;
    }

    return NULL;
}

/**
 * Checks if frame type is registered by user-quic and frame details exists.
 * 
 * @param hyquic hyquic container
 * @param frame_type frame type
 * @return true if frame type is registered
*/
inline bool hyquic_is_usrquic_frame(struct hyquic_container *hyquic, uint64_t frame_type)
{
    return hyquic_frame_details_get(hyquic, frame_type);
}

/**
 * Decodes and registers a local transport parameter and associated frame types with frame details communicated by user-quic.
 * 
 * @param hyquic hyquic container
 * @param data encoded data
 * @param length length of encoded data
*/
int hyquic_set_local_transport_parameter(struct hyquic_container *hyquic, void *data, uint32_t length)
{
    struct hyquic_transport_param *entry;
	uint64_t param_id;
	void *param_data;
	uint32_t param_data_length;
	struct hyquic_frame_details *frame_details;
    uint8_t *format_specification;
	size_t num_frame_details;
	void *p = data;
	int i, err;

    num_frame_details = *((size_t*) p);
	p += sizeof(size_t);
	for (i = 0; i < num_frame_details; i++) {
		frame_details = p;
		p += sizeof(struct hyquic_frame_details);

        if (frame_details->format_specification_avail) {
            format_specification = p;
            p += frame_details->format_specification_avail;
        } else {
            format_specification = NULL;
        }

		err = hyquic_frame_details_create(hyquic, frame_details, format_specification);
		if (err)
			return err;
	}

	param_data_length = length - (p - data);
	param_data = kmemdup(p, param_data_length, GFP_KERNEL);
	if (!param_data)
		return -ENOMEM;
	quic_peek_var(param_data, &param_id);
	entry = hyquic_transport_param_create(param_id, param_data, param_data_length);
	if (!entry)
		return -ENOMEM;
	hyquic_transport_params_add(entry, &hyquic->transport_params_local);

    HQ_PR_DEBUG(hyquic->sk, "done, id=%llu, len=%u", param_id, param_data_length);
	return 0;
}

/**
 * Gets and encodes transport parameters from remote peer to be transferred to user-quic via socket options.
 * 
 * @param hyquic hyquic container
 * @param len procided buffer length for option value
 * @param optval pointer to user space option value buffer
 * @param optlen pointer to actual length of option value
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_get_remote_transport_parameters(struct hyquic_container *hyquic, int len, char __user *optval, int __user *optlen)
{
    uint32_t total_params_length = hyquic_transport_params_total_length(&hyquic->transport_params_remote);
	char __user *pos = optval;
	struct hyquic_transport_param *cursor;

	if (len < total_params_length) {
        HQ_PR_ERR(hyquic->sk, "provided buffer too small, %u bytes needed", total_params_length);
		return -EINVAL;
    }

	len = total_params_length;
	if (put_user(len, optlen))
		return -EFAULT;
	
	hyquic_transport_param_for_each(cursor, &hyquic->transport_params_remote) {
		if (copy_to_user(pos, cursor->param, cursor->length))
			return -EINVAL;
		pos += cursor->length;
	}

    HQ_PR_DEBUG(hyquic->sk, "done");
	return 0;
}

/**
 * Gets the total length of transport parameters from remote peer to be transferred to user-quic via socket options.
 * Used to determine the required buffer size for remote transport parameters.
 * 
 * @param hyquic hyquic container
 * @param len procided buffer length for option value
 * @param optval pointer to user space option value buffer
 * @param optlen pointer to actual length of option value
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_get_remote_transport_parameters_length(struct hyquic_container *hyquic, int len, char __user *optval, int __user *optlen)
{
    uint32_t total_params_length;

    if (len < sizeof(total_params_length))
		return -EINVAL;

	len = sizeof(total_params_length);
	total_params_length = hyquic_transport_params_total_length(&hyquic->transport_params_remote);

	if (put_user(len, optlen) || copy_to_user(optval, &total_params_length, len))
		return -EFAULT;
	return 0;
}

/**
 * Decodes and adds one transport parameter from remote peer to the remote transport parameters list.
 * 
 * @param hyquic hyquic container
 * @param id transport parameter id
 * @param pp pointer to buffer position (gets increased by transport parameter)
 * @param plen pointer to remaining length of buffer (gets decreased by transport parameter length)
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_handle_remote_transport_parameter(struct hyquic_container *hyquic, uint64_t id, uint8_t **pp, uint32_t *plen)
{
    uint32_t id_length = quic_var_len(id);
    uint8_t *tp_start = *pp - id_length;
    size_t tp_length;
    uint64_t value_length;
    uint8_t value_length_length;
    void *param;
    struct hyquic_transport_param *entry;

    value_length_length = quic_get_var(pp, plen, &value_length);
    if (!value_length_length) {
        HQ_PR_ERR(hyquic->sk, "invalid value length encoding");
        return -EINVAL;
    }
    tp_length = id_length + value_length_length + value_length;
    param = kmemdup(tp_start, tp_length, GFP_KERNEL);
    if (!param)
        return -ENOMEM;
    entry = hyquic_transport_param_create(id, param, tp_length);
    if (!entry)
        return -ENOMEM;
    hyquic_transport_params_add(entry, &hyquic->transport_params_remote);

    *pp += value_length;
    *plen -= value_length;

    HQ_PR_DEBUG(hyquic->sk, "done, id=%llu, len=%lu", id, tp_length);
    return 0;
}

/**
 * Writes encoded local transport parameters to buffer position.
 * 
 * @param hyquic hyquic container
 * @param pp pointer to buffer position to write to (gets increased by written transport parameter)
 * @param data start of buffer
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_transfer_local_transport_parameters(struct hyquic_container *hyquic, uint8_t **pp, uint8_t *data)
{
    struct hyquic_transport_param *cursor;

    hyquic_transport_param_for_each(cursor, &hyquic->transport_params_local) {
        *pp = quic_put_data(*pp, cursor->param, cursor->length);
        HQ_PR_DEBUG(hyquic->sk, "wrote transport parameter, id=%llu, len=%lu", cursor->id, cursor->length);
    }

    if (*pp - data > 512) {
        HQ_PR_ERR(hyquic->sk, "buffer overflow, %lu bytes needed", (*pp - data));
        return -1;
    }

    return 0;
}

/**
 * Creates and allocates frame socket buffer from user-quic frame data.
 * 
 * @param sk quic socket
 * @param data_ptr pointer to buffer position (gets increased by frame data)
 * @param data_length_ptr remaining buffer length (gets decreased by frame data length)
 * @return pointer to frame socket buffer
*/
static struct sk_buff* hyquic_frame_create_raw(struct sock *sk, uint8_t **data_ptr, uint32_t *data_length_ptr)
{
    uint32_t frame_length;
    uint64_t frame_type;
    struct sk_buff *skb;
    struct hyquic_snd_cb *snd_cb;

    frame_length = hyquic_ic_get_int(data_ptr, 4);
    *data_length_ptr -= 4;
    if (!frame_length || frame_length > *data_length_ptr)
        return NULL;
    quic_peek_var(*data_ptr, &frame_type);

    skb = alloc_skb(frame_length, GFP_ATOMIC);
    if (!skb)
		return NULL;
    skb_put_data(skb, *data_ptr, frame_length);
    *data_ptr += frame_length;
    *data_length_ptr -= frame_length;
    snd_cb = HYQUIC_SND_CB(skb);
    snd_cb->common.frame_type = frame_type;

    HQ_PR_DEBUG(sk, "done, type=%llu, len=%u", frame_type, frame_length);
    return skb;
}

/**
 * Decodes and queues user-quic frames into send buffer.
 * 
 * @param sk quic socket
 * @param data buffer with encoded user-quic frames
 * @param data_length length of buffer
 * @param ctrl_details details of hyquic control data
 * @return negative error code if not successful, otherwise 0
*/
static int hyquic_process_usrquic_frames(struct sock *sk, uint8_t *data, uint32_t data_length, struct hyquic_ctrl_raw_frames *ctrl_details)
{
    struct sk_buff *skb;

    if (!quic_is_established(sk)) {
        HQ_PR_ERR(sk, "cannot send user-quic frames when connection is not established");
        return -EINVAL;
    }

    while (data_length) {
        skb = hyquic_frame_create_raw(sk, &data, &data_length);
        if (!skb) {
            HQ_PR_ERR(sk, "cannot create frame from user-quic data");
            return -EINVAL;
        }

        hyquic_outq_raw_tail(sk, skb, false);
    }

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Continues to parse remaining frames of a deferred packet.
 * This should be called after user-quic responds with the length information of parsed frames unknown to kernel.
 * 
 * @param sk quic socket
 * @param skb socket buffer with remaining packet payload
 * @return negative error code if not successful, otherwise 0
*/
static int hyquic_continue_processing_frames(struct sock *sk, struct sk_buff *skb)
{
    int ret;
    uint32_t len = skb->len, frame_len;
    uint64_t frame_type;
    uint8_t *tmp_data_ptr, frame_type_len;
    struct sk_buff *fskb;
    struct hyquic_frame_details_cont *frame_details_cont;
    struct hyquic_frame_details *frame_details;
    uint32_t parsed_frame_content_length;
    struct hyquic_ctrlrecv_raw_frames_var *ctrl_details = &HYQUIC_RCV_CB(skb)->hyquic_ctrl_details.raw_frames_var;

    while (len > 0)
    {
        tmp_data_ptr = skb->data;
        frame_type_len = quic_get_var(&tmp_data_ptr, &len, &frame_type);

        frame_details_cont = hyquic_frame_details_get(quic_hyquic(sk), frame_type);
        if (frame_details_cont) {
            frame_details = &frame_details_cont->details;
            if (frame_details->format_specification_avail) {
                ret = hyquic_parse_frame_content(sk, tmp_data_ptr, len, frame_details_cont->format_specification, frame_details->format_specification_avail, &parsed_frame_content_length);
                if (ret)
                    return ret;
                frame_len = frame_type_len + parsed_frame_content_length;
                if (frame_len > len) {
                    HQ_PR_ERR(sk, "remaining payload is shorter than advertised frame length, type=%llu", frame_type);
                    return -EINVAL;
                }
                fskb = alloc_skb(frame_len, GFP_ATOMIC);
                if (!fskb)
                    return -ENOMEM;
                quic_put_data(fskb->data, skb->data, frame_len);
                __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_fix_inqueue, fskb);
                skb_pull(skb, frame_len);
                len -= frame_len;
                HQ_PR_DEBUG(sk, "forwarding frame to user-quic, type=%llu", frame_type);
            } else {
                __skb_queue_tail(&sk->sk_receive_queue, fskb);
                sk->sk_data_ready(sk);
                len = 0;
                HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu", frame_type);
            }

            if (frame_details->ack_eliciting) {
                ctrl_details->ack_eliciting = 1;
                if (frame_details->ack_immediate)
                    ctrl_details->ack_immediate = 1;
            }
            if (frame_details->non_probing)
                ctrl_details->non_probing = 1;
        } else {
            if (frame_type > QUIC_FRAME_MAX) {
                pr_err_once("[QUIC] %s unsupported frame %llu\n", __func__, frame_type);
                return -EPROTONOSUPPORT;
            } else if (!frame_type) { /* skip padding */
                skb_pull(skb, len);
                return 0;
            }

            skb_pull(skb, frame_type_len);
		    len -= frame_type_len;

            pr_debug("[QUIC] %s type: %llu level: %d\n", __func__, frame_type, QUIC_RCV_CB(skb)->level);
            ret = __quic_internal_process_frame(sk, skb, frame_type);
            if (ret < 0) {
                pr_warn("[QUIC] %s type: %llu level: %d err: %d\n", __func__, frame_type, QUIC_RCV_CB(skb)->level, ret);
                return ret;
            }

            if (quic_frame_ack_eliciting(frame_type)) {
                ctrl_details->ack_eliciting = 1;
                if (quic_frame_ack_immediate(frame_type))
                    ctrl_details->ack_immediate = 1;
            }
            if (quic_frame_non_probing(frame_type))
                ctrl_details->non_probing = 1;

            skb_pull(skb, ret);
		    len -= ret;
        }
    }

    hyquic_flush_unkwn_frames_inqueue(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Processes the response of user-quic with length information of parsed frames unknown to kernel.
 * First, finds the deferred packet corresponding to the response.
 * Then, continues to parse its remaining frames.
 * 
 * @param sk quic socket
 * @param ctrlsend_details details of hyquic control data sent by user-quic
 * @return negative error code if not successful, otherwise 0
*/
static int hyquic_process_frames_var_reply(struct sock *sk, struct hyquic_ctrlsend_raw_frames_var *ctrlsend_details)
{
    struct sk_buff *cursor, *tmp, *fskb;
    struct sk_buff_head *head;
    struct hyquic_ctrlrecv_raw_frames_var *ctrlrecv_details;
    uint8_t level = 0;
    bool found = false;
    int err;

    if (!ctrlsend_details->processed_length) {
        HQ_PR_ERR(sk, "processed length must not be zero");
        return -EINVAL;
    }

    head = &quic_hyquic(sk)->unkwn_frames_var_deferred;
    skb_queue_walk_safe(head, cursor, tmp) {
        ctrlrecv_details = &HYQUIC_RCV_CB(cursor)->hyquic_ctrl_details.raw_frames_var;
        if (ctrlrecv_details->msg_id == ctrlsend_details->msg_id) {
            found = true;
            __skb_unlink(cursor, head);
            break;
        }
    }
    if (!found) {
        HQ_PR_ERR(sk, "cannot find deferred packet payload, msg_id=%llu", ctrlsend_details->msg_id);
        return -EINVAL;
    }
    
    skb_pull(cursor, ctrlsend_details->processed_length);
    HQ_PR_DEBUG(sk, "skipped %u bytes parsed by user-quic", ctrlsend_details->processed_length);

    if (ctrlsend_details->ack_eliciting) {
        ctrlrecv_details->ack_eliciting = true;
        if (ctrlsend_details->ack_immediate)
            ctrlrecv_details->ack_immediate = true;
    }
    if (ctrlsend_details->non_probing)
        ctrlrecv_details->non_probing = true;

    err = hyquic_continue_processing_frames(sk, cursor);
    if (err)
        return err;

    if (ctrlrecv_details->ack_eliciting && !ctrlrecv_details->ack_sent) {
        if (ctrlrecv_details->ack_immediate) {
            fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
            if (!fskb)
                return -ENOMEM;
            QUIC_SND_CB(fskb)->path_alt = ctrlrecv_details->path_alt;
            quic_outq_ctrl_tail(sk, fskb, true);
            quic_timer_stop(sk, QUIC_TIMER_ACK);
            ctrlrecv_details->ack_sent = true;
        } else if (!ctrlrecv_details->ack_timer_started) {
            quic_timer_start(sk, QUIC_TIMER_ACK);
            ctrlrecv_details->ack_timer_started = true;
        }
    }

    HQ_PR_DEBUG(sk, "done, msg_id=%llu", ctrlsend_details->msg_id);
    return 0;
}

/**
 * Processes any hyquic control data received by user-quic.
 * Currently, these are either frames to send or a response to unknown frame length.
 * 
 * @param sk quic socket
 * @param msg_iter pointer to the message iterator holding hyquic control data payload
 * @param info information to hyquic control data
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_ctrlsend_info *info)
{
    int err = 0;
    uint8_t *data = (uint8_t*) kmalloc_array(info->data_length, sizeof(uint8_t), GFP_KERNEL);

    if (iov_iter_count(msg_iter) < info->data_length) {
        HQ_PR_ERR(sk, "remaining payload is shorter than advertised data length");
        err = -EINVAL;
        goto out;
    }

    if (info->data_length && !copy_from_iter_full(data, info->data_length, msg_iter)) {
        HQ_PR_ERR(sk, "cannot read data from payload");
        err = -EINVAL;
        goto out;
    }

    switch (info->type) {
    case HYQUIC_CTRL_RAW_FRAMES:
        err = hyquic_process_usrquic_frames(sk, data, info->data_length, &info->raw_frames);
        break;
    case HYQUIC_CTRL_RAW_FRAMES_VAR:
        err = hyquic_process_frames_var_reply(sk, &info->raw_frames_var);
        break;
    default:
        HQ_PR_ERR(sk, "unknown user-quic-ctrl type %i", info->type);
        err = -EINVAL;
        break;
    }
    
out:
    kfree(data);
    return err;
}

/**
 * Handles a frame unknown to kernel-quic but registered by user-quic.
 * If user-quic provided a frame format specification, the frame is parsed by kernel-quic and forwarded to user-quic.
 * Otherwise, the remaining packet payload is sent to user-quic, which has to parse the frame and responds to kernel-quic 
 * with the parsed length, so that kernel-quic can continue oarsing the packet payload.
 * 
 * @param sk quic socket
 * @param skb socket buffer with remaining packet payload
 * @param pki quic specific packet information
 * @param remaining_pack_len length of remaining packed payload
 * @param frame_details_cont frame details container of upcoming frame
 * @param var_frame_encountered pointer to flag that gets set if a frame without format specification is encountered
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, uint32_t remaining_pack_len, struct hyquic_frame_details_cont *frame_details_cont, bool *var_frame_encountered)
{
    struct hyquic_frame_details *frame_details = &frame_details_cont->details;
    struct sk_buff *fskb;
    struct hyquic_rcv_cb *rcv_cb;
    struct hyquic_ctrlrecv_raw_frames_var *details;
    uint32_t parsed_frame_content_length;
    uint32_t frame_len;
    uint8_t frame_type_len;
    int ret = 0;

    if (frame_details->format_specification_avail) {
        frame_type_len = quic_var_len(frame_details->frame_type);
        ret = hyquic_parse_frame_content(sk, skb->data + frame_type_len, skb->len - frame_type_len, frame_details_cont->format_specification, frame_details->format_specification_avail, &parsed_frame_content_length);
        if (ret)
            return ret;
        frame_len = frame_type_len + parsed_frame_content_length;
        if (frame_len > remaining_pack_len) {
            HQ_PR_ERR(sk, "remaining payload is shorter than advertised frame length, type=%llu", frame_details->frame_type);
            return -EINVAL;
        }
        fskb = alloc_skb(frame_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        skb_put_data(fskb, skb->data, frame_len);
        __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_fix_inqueue, fskb);
        ret = frame_len;
        HQ_PR_DEBUG(sk, "forwarding frame to user-quic, type=%llu, len=%u", frame_details->frame_type, frame_len);
    } else {
        fskb = alloc_skb(remaining_pack_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        skb_put_data(fskb, skb->data, remaining_pack_len);

        rcv_cb = HYQUIC_RCV_CB(fskb);
        rcv_cb->common.path_alt = QUIC_RCV_CB(skb)->path_alt;
        rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_RAW_FRAMES_VAR;
        details = &rcv_cb->hyquic_ctrl_details.raw_frames_var;
        details->msg_id = quic_hyquic(sk)->next_ic_msg_id++;
        details->ack_eliciting = pki->ack_eliciting;
        details->ack_immediate = pki->ack_immediate;
        details->ack_sent = false;
        details->ack_timer_started = false;
        details->non_probing = pki->non_probing;
        details->path_alt = QUIC_RCV_CB(skb)->path_alt;

        __skb_queue_tail(&sk->sk_receive_queue, fskb);
        sk->sk_data_ready(sk);
        *var_frame_encountered = true;
        HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu, len=%u, msg_id=%llu", frame_details->frame_type, remaining_pack_len, details->msg_id);
    }

    if (frame_details->ack_eliciting) {
        pki->ack_eliciting = 1;
        if (frame_details->ack_immediate)
            pki->ack_immediate = 1;
    }
    if (frame_details->non_probing)
        pki->non_probing = 1;

    return ret;
}

/**
 * Notifies a deferred packet that the ack timer has been started and does not need to be started anymore if parsed frames would require it later on.
 * 
 * @param sk quic socket
*/
inline void hyquic_frame_var_notify_ack_timer_started(struct sock *sk)
{
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    skb_queue_reverse_walk(&sk->sk_receive_queue, skb) {
        rcv_cb = HYQUIC_RCV_CB(skb);
        if (rcv_cb->hyquic_ctrl_type != HYQUIC_CTRL_RAW_FRAMES_VAR)
            continue;

        rcv_cb->hyquic_ctrl_details.raw_frames_var.ack_timer_started = true;
        return;
    }

    HQ_PR_ERR(sk, "no remaining packet in receive queue");
}

/**
 * Notifies a deferred packet that an ack has been sent and does not need to be sent anymore if parsed frames would require it later on.
 * 
 * @param sk quic socket
*/
inline void hyquic_frame_var_notify_ack_sent(struct sock *sk)
{
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    skb_queue_reverse_walk(&sk->sk_receive_queue, skb) {
        rcv_cb = HYQUIC_RCV_CB(skb);
        if (rcv_cb->hyquic_ctrl_type != HYQUIC_CTRL_RAW_FRAMES_VAR)
            continue;

        rcv_cb->hyquic_ctrl_details.raw_frames_var.ack_sent = true;
        return;
    }

    HQ_PR_ERR(sk, "no remaining packet in receive queue");
}

/**
 * Collects all frames waiting to be forwarded to user-quic and sends them to the receive queue.
 * 
 * @param sk quic socket
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_flush_unkwn_frames_inqueue(struct sock *sk)
{
    struct sk_buff_head *head = &quic_hyquic(sk)->unkwn_frames_fix_inqueue;
    struct sk_buff *skb, *fskb;
    struct hyquic_rcv_cb *rcv_cb;
    size_t length = 0;

    if (skb_queue_empty(head))
        return 0;

    skb_queue_walk(head, fskb) {
        length += fskb->len;
    }

    skb = alloc_skb(length, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    fskb = __skb_dequeue(head);
    while (fskb) {
        skb_put_data(skb, fskb->data, fskb->len);
        fskb = __skb_dequeue(head);
    }

    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_RAW_FRAMES_FIX;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Sends a lost frame back to user-quic.
 * 
 * @param sk quic socket
 * @param fskb socket buffer containing lost frame
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb)
{
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    skb = alloc_skb(fskb->len, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    skb_put_data(skb, fskb->data, fskb->len);

    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_LOST_FRAMES;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done, type=%u", QUIC_SND_CB(skb)->frame_type);
    return 0;
}