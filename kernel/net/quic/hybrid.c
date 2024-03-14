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

struct hyquic_frame_details_entry {
    struct hlist_node node;
    struct hyquic_frame_details details;
};

inline void hyquic_enable(struct sock *sk)
{
    struct hyquic_adapter *hyquic = quic_hyquic(sk);

    if (hyquic->enabled)
        return;
    hyquic->enabled = true;
    HQ_PR_DEBUG(sk, "enabled");
}

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

int hyquic_init(struct hyquic_adapter *hyquic, struct sock *sk)
{
    hyquic->enabled = false;
    hyquic->sk = sk;
    hyquic->options = (struct hyquic_options) {};

    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);

    hyquic->next_usrquic_frame_seqnum = 0;
    hyquic->next_ic_msg_id = 0;
    skb_queue_head_init(&hyquic->usrquic_frames_outqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_fix_inqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_var_deferred);
    if (hyquic_frame_details_table_init(&hyquic->frame_details_table))
        return -ENOMEM;

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

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
            kfree(entry);
        }
    }
    kfree(frame_details_table->hash);
}

static void hyquic_transport_params_free(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor, *tmp;

    list_for_each_entry_safe(cursor, tmp, param_list, list) {
        list_del(&cursor->list);
        kfree(cursor->param);
        kfree(cursor);
    }
}

void hyquic_free(struct hyquic_adapter *hyquic)
{
    hyquic_transport_params_free(&hyquic->transport_params_remote);
    hyquic_transport_params_free(&hyquic->transport_params_local);

    __skb_queue_purge(&hyquic->usrquic_frames_outqueue);
    __skb_queue_purge(&hyquic->unkwn_frames_fix_inqueue);
    __skb_queue_purge(&hyquic->unkwn_frames_var_deferred);
    hyquic_frame_details_table_free(&hyquic->frame_details_table);

    HQ_PR_DEBUG(hyquic->sk, "done");
}

static inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list)
{
    list_add_tail(&param->list, param_list);
}

static inline size_t hyquic_transport_params_total_length(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor;
	size_t total_length = 0;

	hyquic_transport_param_for_each(cursor, param_list) {
		total_length += cursor->length;
	}
    return total_length;
}

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

int hyquic_set_local_transport_parameter(struct hyquic_adapter *hyquic, void *data, uint32_t length)
{
    struct hyquic_transport_param *entry;
	uint64_t param_id;
	void *param_data;
	uint32_t param_data_length;
	struct hyquic_frame_details *frame_details;
	size_t num_frame_details;
	void *p = data;
	int i, err;

    num_frame_details = *((size_t*) p);
	p += sizeof(size_t);
	for (i = 0; i < num_frame_details; i++) {
		frame_details = p;
		err = hyquic_frame_details_create(hyquic, frame_details);
		if (err)
			return err;
		p += sizeof(struct hyquic_frame_details);
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

int hyquic_get_remote_transport_parameters(struct hyquic_adapter *hyquic, int len, char __user *optval, int __user *optlen)
{
    size_t total_params_length = hyquic_transport_params_total_length(&hyquic->transport_params_remote);
	char __user *pos = optval;
	struct hyquic_transport_param *cursor;

	if (len < total_params_length) {
        HQ_PR_ERR(hyquic->sk, "provided buffer too small, %lu bytes needed", total_params_length);
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

int hyquic_get_remote_transport_parameters_length(struct hyquic_adapter *hyquic, int len, char __user *optval, int __user *optlen)
{
    size_t total_params_length;

    if (len < sizeof(size_t))
		return -EINVAL;

	len = sizeof(size_t);
	total_params_length = hyquic_transport_params_total_length(&hyquic->transport_params_remote);

	if (put_user(len, optlen) || copy_to_user(optval, &total_params_length, len))
		return -EFAULT;
	return 0;
}

int hyquic_handle_remote_transport_parameter(struct hyquic_adapter *hyquic, uint64_t id, uint8_t **pp, uint32_t *plen)
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

int hyquic_transfer_local_transport_parameters(struct hyquic_adapter *hyquic, uint8_t **pp, uint8_t *data)
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

static struct sk_buff* hyquic_frame_create_raw(struct sock *sk, uint8_t **pdata, uint32_t *pdata_length, uint64_t *pframe_seqnum)
{
    uint32_t frame_length;
    uint64_t frame_type;
    struct sk_buff *skb;
    struct hyquic_snd_cb *snd_cb;

    frame_length = hyquic_ic_get_int(pdata, 4);
    *pdata_length -= 4;
    if (!frame_length || frame_length > *pdata_length)
        return NULL;
    quic_peek_var(*pdata, &frame_type);

    skb = alloc_skb(frame_length, GFP_ATOMIC);
    if (!skb)
		return NULL;
    skb_put_data(skb, *pdata, frame_length);
    *pdata += frame_length;
    *pdata_length -= frame_length;
    snd_cb = HYQUIC_SND_CB(skb);
    snd_cb->common.frame_type = frame_type;
    snd_cb->usrquic_frame_seqnum = *pframe_seqnum;
    *pframe_seqnum += 1;

    HQ_PR_DEBUG(sk, "done, type=%llu", frame_type);
    return skb;
}

static int hyquic_process_usrquic_frames(struct sock *sk, uint8_t *data, uint32_t data_length, struct hyquic_data_raw_frames *info)
{
    struct sk_buff *skb;
    uint64_t frame_seqnum = info->first_frame_seqnum;

    if (!quic_is_established(sk)) {
        HQ_PR_ERR(sk, "cannot send user-quic frames when connection is not established");
        return -EINVAL;
    }

    while (data_length) {
        skb = hyquic_frame_create_raw(sk, &data, &data_length, &frame_seqnum);
        if (!skb) {
            HQ_PR_ERR(sk, "cannot create frame from user-quic data");
            return -EINVAL;
        }

        hyquic_outq_raw_tail(sk, skb, false);
    }

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

static int hyquic_continue_processing_frames(struct sock *sk, struct sk_buff *skb)
{
    int ret;
    uint32_t len = skb->len, frame_len;
    uint64_t frame_type;
    uint8_t *tmp_data_ptr, frame_type_len;
    struct sk_buff *fskb;
    struct hyquic_frame_details *frame_details;
    struct hyquic_data_raw_frames_var_recv *data_details = &HYQUIC_RCV_CB(skb)->hyquic_data_details.raw_frames_var;

    while (len > 0)
    {
        tmp_data_ptr = skb->data;
        frame_type_len = quic_get_var(&tmp_data_ptr, &len, &frame_type);

        frame_details = hyquic_frame_details_get(quic_hyquic(sk), frame_type);
        if (frame_details) {
            if (frame_details->fixed_length < 0) {
                __skb_queue_tail(&sk->sk_receive_queue, fskb);
                sk->sk_data_ready(sk);
                len = 0;
                HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu", frame_type);
            } else {
                frame_len = frame_type_len + frame_details->fixed_length;
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
            }

            if (frame_details->ack_eliciting) {
                data_details->ack_eliciting = 1;
                if (frame_details->ack_immediate)
                    data_details->ack_immediate = 1;
            }
            if (frame_details->non_probing)
                data_details->non_probing = 1;
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
                data_details->ack_eliciting = 1;
                if (quic_frame_ack_immediate(frame_type))
                    data_details->ack_immediate = 1;
            }
            if (quic_frame_non_probing(frame_type))
                data_details->non_probing = 1;

            skb_pull(skb, ret);
		    len -= ret;
        }
    }

    hyquic_flush_unkwn_frames_inqueue(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

static int hyquic_process_frames_var_reply(struct sock *sk, struct hyquic_data_raw_frames_var_send *info)
{
    struct sk_buff *cursor, *tmp, *fskb;
    struct sk_buff_head *head;
    struct hyquic_data_raw_frames_var_recv *details;
    uint8_t level = 0;
    bool found = false;
    int err;

    head = &quic_hyquic(sk)->unkwn_frames_var_deferred;
    skb_queue_walk_safe(head, cursor, tmp) {
        details = &HYQUIC_RCV_CB(cursor)->hyquic_data_details.raw_frames_var;
        if (details->msg_id == info->msg_id) {
            found = true;
            __skb_unlink(cursor, head);
            break;
        }
    }
    if (!found) {
        HQ_PR_ERR(sk, "cannot find deferred packet payload, id=%llu", info->msg_id);
        return -EINVAL;
    }
    
    skb_pull(cursor, info->processed_length);

    if (info->ack_eliciting) {
        details->ack_eliciting = true;
        if (info->ack_immediate)
            details->ack_immediate = true;
    }
    if (info->non_probing)
        details->non_probing = true;

    err = hyquic_continue_processing_frames(sk, cursor);
    if (err)
        return err;

    if (details->ack_eliciting && !details->ack_sent) {
        if (details->ack_immediate) {
            fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
            if (!fskb)
                return -ENOMEM;
            QUIC_SND_CB(fskb)->path_alt = details->path_alt;
            quic_outq_ctrl_tail(sk, fskb, true);
            quic_timer_stop(sk, QUIC_TIMER_ACK);
            details->ack_sent = true;
        } else if (!details->ack_timer_started) {
            quic_timer_start(sk, QUIC_TIMER_ACK);
            details->ack_timer_started = true;
        }
    }

    HQ_PR_DEBUG(sk, "done, id=%llu", info->msg_id);
    return 0;
}

int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_data_sendinfo *info)
{
    int err = 0;
    uint8_t *data = (uint8_t*) kmalloc_array(info->data_length, sizeof(uint8_t), GFP_KERNEL);

    if (iov_iter_count(msg_iter) < info->data_length) {
        HQ_PR_ERR(sk, "remaining payload is shorter than advertised data length");
        err = -EINVAL;
        goto out;
    }

    if (!copy_from_iter_full(data, info->data_length, msg_iter)) {
        HQ_PR_ERR(sk, "cannot read data from payload");
        err = -EINVAL;
        goto out;
    }

    switch (info->type) {
    case HYQUIC_DATA_RAW_FRAMES:
        err = hyquic_process_usrquic_frames(sk, data, info->data_length, &info->raw_frames);
        break;
    case HYQUIC_DATA_RAW_FRAMES_VAR:
        err = hyquic_process_frames_var_reply(sk, &info->raw_frames_var);
        break;
    default:
        HQ_PR_ERR(sk, "unknown user-quic-data type %i", info->type);
        err = -EINVAL;
        break;
    }
    
out:
    kfree(data);
    return err;
}

int hyquic_frame_details_create(struct hyquic_adapter *hyquic, struct hyquic_frame_details *frame_details)
{
    struct quic_hash_head *head;
    struct hyquic_frame_details_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;
    
    memcpy(&entry->details, frame_details, sizeof(struct hyquic_frame_details));

    head = hyquic_raw_frame_type_head(&hyquic->frame_details_table, frame_details->frame_type);
    hlist_add_head(&entry->node, &head->head);

    HQ_PR_DEBUG(hyquic->sk, "done, type=%llu", frame_details->frame_type);
    return 0;
}

struct hyquic_frame_details* hyquic_frame_details_get(struct hyquic_adapter *hyquic, uint64_t frame_type)
{
    struct quic_hash_head *head = hyquic_raw_frame_type_head(&hyquic->frame_details_table, frame_type);
    struct hyquic_frame_details_entry *cursor;

    hlist_for_each_entry(cursor, &head->head, node) {
        if (cursor->details.frame_type == frame_type)
            return &cursor->details;
    }

    return NULL;
}

int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, uint32_t remaining_pack_len, struct hyquic_frame_details *frame_details, bool *var_frame_encountered)
{
    struct sk_buff *fskb;
    struct hyquic_rcv_cb *rcv_cb;
    struct hyquic_data_raw_frames_var_recv *details;
    uint32_t frame_len;
    int ret = 0;

    if (frame_details->fixed_length < 0) {
        fskb = alloc_skb(remaining_pack_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        quic_put_data(fskb->data, skb->data, remaining_pack_len);

        rcv_cb = HYQUIC_RCV_CB(fskb);
        rcv_cb->common.path_alt = QUIC_RCV_CB(skb)->path_alt;
        rcv_cb->hyquic_data_type = HYQUIC_DATA_RAW_FRAMES_VAR;
        details = &rcv_cb->hyquic_data_details.raw_frames_var;
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
        HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu", frame_details->frame_type);
    } else {
        frame_len = quic_var_len(frame_details->frame_type) + frame_details->fixed_length;
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
        HQ_PR_DEBUG(sk, "forwarding frame to user-quic, type=%llu", frame_details->frame_type);
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

inline void hyquic_frame_var_notify_ack_timer_started(struct sock *sk)
{
    struct sk_buff *skb;
    struct hyquic_data_raw_frames_var_recv *details;

    skb = skb_peek_tail(&quic_hyquic(sk)->unkwn_frames_var_deferred);
    details = &HYQUIC_RCV_CB(skb)->hyquic_data_details.raw_frames_var;
    details->ack_timer_started = true;
}

inline void hyquic_frame_var_notify_ack_sent(struct sock *sk)
{
    struct sk_buff *skb;
    struct hyquic_data_raw_frames_var_recv *details;

    skb = skb_peek_tail(&quic_hyquic(sk)->unkwn_frames_var_deferred);
    details = &HYQUIC_RCV_CB(skb)->hyquic_data_details.raw_frames_var;
    details->ack_sent = true;
}

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
    rcv_cb->hyquic_data_type = HYQUIC_DATA_RAW_FRAMES_FIX;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb)
{
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    skb = alloc_skb(fskb->len, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    skb_put_data(skb, fskb->data, fskb->len);

    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_data_type = HYQUIC_DATA_LOST_FRAMES;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done, type=%u", QUIC_SND_CB(skb)->frame_type);
    return 0;
}