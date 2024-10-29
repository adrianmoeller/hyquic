/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#include <linux/slab.h>
#include <linux/printk.h>
#include "number.h"
#include "socket.h"
#include "frame.h"
#include "debug.h"
#include "intercom.h"
#include "hybrid_frame_format_spec.h"
#include "hybrid.h"


struct hyquic_frame_profile_entry {
    struct hlist_node node;
    struct hyquic_frame_profile_cont cont;
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
 * Initializes frame profile map.
*/
static int hyquic_frame_profile_table_init(struct quic_hash_table *frame_profile_table)
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
	frame_profile_table->size = size;
	frame_profile_table->hash = head;
	return 0;
}

/**
 * Initializes hyquic container.
*/
int hyquic_init(struct hyquic_container *hyquic, struct sock *sk)
{
    hyquic->enabled = false;
    hyquic->sk = sk;
    hyquic->options = (struct hyquic_options) {
        .usrquic_retransmit = true
    };

    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);

    hyquic->next_ic_msg_id = 0;
    skb_queue_head_init(&hyquic->usrquic_frames_outqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_fix_inqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_var_deferred);
    skb_queue_head_init(&hyquic->lost_usrquic_frames_inqueue);
    if (hyquic_frame_profile_table_init(&hyquic->frame_profile_table))
        return -ENOMEM;

    hyquic->last_max_payload = 0;
    hyquic->last_max_payload_dgram = 0;

    hyquic->process_frame_copy = false;
    hyquic->packet_payload_deferred = false;

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Frees frame profile map and its content.
*/
static void hyquic_frame_profile_table_free(struct quic_hash_table *frame_profile_table)
{
    struct quic_hash_head *head;
    struct hyquic_frame_profile_entry *entry;
    struct hlist_node *tmp;
    int i;

    for (i = 0; i < frame_profile_table->size; i++) {
        head = &frame_profile_table->hash[i];
        hlist_for_each_entry_safe(entry, tmp, &head->head, node) {
            hlist_del_init(&entry->node);
            if (entry->cont.format_specification)
                kfree(entry->cont.format_specification);
            kfree(entry);
        }
    }
    kfree(frame_profile_table->hash);
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
    __skb_queue_purge(&hyquic->lost_usrquic_frames_inqueue);
    hyquic_frame_profile_table_free(&hyquic->frame_profile_table);

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
 * Creates a frame profile list entry and adds it to the frame profile map in the given hyquic container.
 * 
 * @param hyquic hyquic container
 * @param frame_profile pointer to frame profile
 * @param format_specification pointer to frame format specification (may point to NULL)
 * @return negative error code if not successful, otherwise 0
*/
static inline int hyquic_frame_profile_create(struct hyquic_container *hyquic, struct hyquic_frame_profile *frame_profile, uint8_t *format_specification)
{
    struct quic_hash_head *head;
    struct hyquic_frame_profile_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;
    
    memcpy(&entry->cont.profile, frame_profile, sizeof(*frame_profile));
    if (format_specification)
        entry->cont.format_specification = kmemdup(format_specification, frame_profile->format_specification_avail, GFP_KERNEL);
    else
        entry->cont.format_specification = NULL;

    head = hyquic_raw_frame_type_head(&hyquic->frame_profile_table, frame_profile->frame_type);
    hlist_add_head(&entry->node, &head->head);

    HQ_PR_DEBUG(hyquic->sk, "done, type=%llu", frame_profile->frame_type);
    return 0;
}

/**
 * Gets frame profile by frame type.
 * 
 * @param hyquic hyquic container
 * @param frame_type frame type
 * @return pointer to frame profile container (may point to NULL if not existent)
*/
struct hyquic_frame_profile_cont* hyquic_frame_profile_get(struct hyquic_container *hyquic, uint64_t frame_type)
{
    struct quic_hash_head *head = hyquic_raw_frame_type_head(&hyquic->frame_profile_table, frame_type);
    struct hyquic_frame_profile_entry *cursor;

    hlist_for_each_entry(cursor, &head->head, node) {
        if (cursor->cont.profile.frame_type == frame_type)
            return &cursor->cont;
    }

    return NULL;
}

/**
 * Checks if frame type is registered by user-quic and frame profile exists.
 * 
 * @param hyquic hyquic container
 * @param frame_type frame type
 * @return true if frame type is registered
*/
inline bool hyquic_is_usrquic_frame(struct hyquic_container *hyquic, uint64_t frame_type)
{
    return hyquic_frame_profile_get(hyquic, frame_type);
}

/**
 * Sets hyquic options communicated by user-quic via socket options.
 * 
 * @param sk quic socket
 * @param data hyquic options
 * @param length length of hyquic options
*/
int hyquic_set_options(struct sock *sk, struct hyquic_options *options, uint32_t length)
{
	if (length != sizeof(*options))
		return -EINVAL;
	
	quic_hyquic(sk)->options = *options;
	return 0;
}

/**
 * Decodes and registers a local transport parameter and associated frame types with frame profile communicated by user-quic via socket options.
 * 
 * @param sk quic socket
 * @param data encoded data
 * @param length length of encoded data
*/
int hyquic_set_local_transport_parameter(struct sock *sk, void *data, uint32_t length)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);
    struct hyquic_transport_param *entry;
	uint64_t param_id;
	void *param_data;
	uint32_t param_data_length;
	struct hyquic_frame_profile *frame_profile;
    uint8_t *format_specification;
	size_t num_frame_profiles;
	void *p = data;
	int i, err;

    num_frame_profiles = *((size_t*) p);
	p += sizeof(size_t);
	for (i = 0; i < num_frame_profiles; i++) {
		frame_profile = p;
		p += sizeof(struct hyquic_frame_profile);

        if (frame_profile->format_specification_avail) {
            format_specification = p;
            p += frame_profile->format_specification_avail;
        } else {
            format_specification = NULL;
        }

		err = hyquic_frame_profile_create(hyquic, frame_profile, format_specification);
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

    hyquic_enable(sk);

    HQ_PR_DEBUG(hyquic->sk, "done, id=%llu, len=%u", param_id, param_data_length);
	return 0;
}

/**
 * Gets and encodes transport parameters from remote peer to be transferred to user-quic via socket options.
 * 
 * @param sk quic socket
 * @param len provided buffer length for option value
 * @param optval pointer to user space option value buffer
 * @param optlen pointer to actual length of option value
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_get_remote_transport_parameters(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);
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

    hyquic_enable(sk);

    HQ_PR_DEBUG(hyquic->sk, "done");
	return 0;
}

/**
 * Gets the total length of transport parameters from remote peer to be transferred to user-quic via socket options.
 * Used to determine the required buffer size for remote transport parameters.
 * 
 * @param sk quic socket
 * @param len provided buffer length for option value
 * @param optval pointer to user space option value buffer
 * @param optlen pointer to actual length of option value
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_get_remote_transport_parameters_length(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
    uint32_t total_params_length;

    if (len < sizeof(total_params_length))
		return -EINVAL;

	len = sizeof(total_params_length);
	total_params_length = hyquic_transport_params_total_length(&quic_hyquic(sk)->transport_params_remote);

	if (put_user(len, optlen) || copy_to_user(optval, &total_params_length, len))
		return -EFAULT;

    hyquic_enable(sk);

	return 0;
}

/**
 * Gets the MPS value to be transferred to user-quic via socket options.
 * 
 * @param sk quic socket
 * @param len provided buffer length for option value
 * @param optval pointer to user space option value buffer
 * @param optlen pointer to actual length of option value
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_get_initial_mps(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_packet *packet = quic_packet(sk);
	struct hyquic_ctrlrecv_mps_update initial_mps = {
		.max_payload = quic_packet_max_payload(packet),
		.max_payload_dgram = quic_packet_max_payload_dgram(packet)
	};

	if (len < sizeof(initial_mps)) {
		HQ_PR_ERR(sk, "provided buffer too small, %lu bytes needed", sizeof(initial_mps));
		return -EINVAL;
	}

	len = sizeof(initial_mps);

	if (put_user(len, optlen) || copy_to_user(optval, &initial_mps, len))
		return -EFAULT;

	hyquic_enable(sk);

	HQ_PR_DEBUG(sk, "done, max_payload=%u, max_payload_dgram=%u", initial_mps.max_payload, initial_mps.max_payload_dgram);
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
 * @return pointer to frame socket buffer or error pointer
*/
static struct sk_buff* hyquic_frame_create_raw(struct sock *sk, uint8_t **data_ptr, uint32_t *data_length_ptr)
{
    uint64_t frame_type;
    struct hyquic_frame_to_send_metadata metadata;
    struct sk_buff *skb;
    struct hyquic_snd_cb *snd_cb;
    struct quic_stream *stream;

    hyquic_ic_get_data(data_ptr, (uint8_t*) &metadata, sizeof(struct hyquic_frame_to_send_metadata));
    *data_length_ptr -= sizeof(struct hyquic_frame_to_send_metadata);

    quic_peek_var(*data_ptr, &frame_type);

    skb = alloc_skb(metadata.frame_length, GFP_ATOMIC);
    if (!skb)
		return ERR_PTR(-ENOMEM);
    skb_put_data(skb, *data_ptr, metadata.frame_length);
    *data_ptr += metadata.frame_length;
    *data_length_ptr -= metadata.frame_length;
    snd_cb = HYQUIC_SND_CB(skb);
    snd_cb->common.frame_type = frame_type;
    snd_cb->common.data_bytes = metadata.payload_length;
    snd_cb->common.sent_count = metadata.retransmit_count;
    if (metadata.retransmit_count)
        quic_outq(sk)->rtx_count++;
    if (metadata.has_stream_info) {
        stream = quic_stream_send_get(quic_streams(sk), metadata.stream_info.stream_id, metadata.stream_info.stream_flag, quic_is_serv(sk));
        if (IS_ERR(stream))
            return (void*) stream;
        snd_cb->common.stream = stream;
        stream->send.offset += metadata.payload_length;
    }
    snd_cb->is_user_frame = true;

    HQ_PR_DEBUG(sk, "done, type=%llu, len=%u, rtx=%u", frame_type, metadata.frame_length, metadata.retransmit_count);
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
    struct hyquic_snd_cb *snd_cb;
    long timeo;
    int err;

    if (!quic_is_established(sk)) {
        HQ_PR_ERR(sk, "cannot send user-quic frames when connection is not established");
        return -EINVAL;
    }

    while (data_length) {
        skb = hyquic_frame_create_raw(sk, &data, &data_length);
        if (IS_ERR(skb)) {
            HQ_PR_ERR(sk, "cannot create frame from user-quic data");
            return PTR_ERR(skb);
        }

        snd_cb = HYQUIC_SND_CB(skb);
        if (snd_cb->common.data_bytes) {
            if (sk_stream_wspace(sk) <= 0 || !sk_wmem_schedule(sk, snd_cb->common.data_bytes)) {
                timeo = sock_sndtimeo(sk, ctrl_details->dont_wait);
                err = hyquic_wait_for_send(sk, 0, timeo, snd_cb->common.data_bytes);
                if (err)
                    return err;
            }

            if (snd_cb->common.stream) {
                quic_outq_stream_tail(sk, skb, true);
            } else {
                hyquic_outq_no_stream_data_tail(sk, skb, true);
            }
        } else {
            quic_outq_ctrl_tail(sk, skb, true);
        }
    }
    quic_outq_transmit(sk);

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
    struct hyquic_frame_profile_cont *frame_profile_cont;
    struct hyquic_frame_profile *frame_profile;
    struct hyquic_frame_format_spec_inout ffs_params;
    struct hyquic_ctrlrecv_raw_frames_var *ctrl_details = &HYQUIC_RCV_CB(skb)->hyquic_ctrl_details.raw_frames_var;
    bool deferred_again = false;

    while (len > 0)
    {
        tmp_data_ptr = skb->data;
        frame_type_len = quic_get_var(&tmp_data_ptr, &len, &frame_type);

        frame_profile_cont = hyquic_frame_profile_get(quic_hyquic(sk), frame_type);
        if (frame_profile_cont) {
            frame_profile = &frame_profile_cont->profile;
            if (frame_profile->format_specification_avail) {
                ffs_params = (struct hyquic_frame_format_spec_inout) {.in = {
                    .frame_content = tmp_data_ptr,
                    .remaining_length = len,
                    .format_specification = frame_profile_cont->format_specification,
                    .spec_length = frame_profile->format_specification_avail
                }};
                ret = hyquic_parse_frame_content(sk, &ffs_params);
                if (ret)
                    return ret;

                frame_len = frame_type_len + ffs_params.out.parsed_length;
                if (frame_len > len) {
                    HQ_PR_ERR(sk, "remaining packet payload is shorter than advertised frame length, type=%llu", frame_type);
                    return -EINVAL;
                }
                fskb = alloc_skb(frame_len, GFP_ATOMIC);
                if (!fskb)
                    return -ENOMEM;
                quic_put_data(fskb->data, skb->data, frame_len);
                QUIC_SND_CB(fskb)->data_bytes = ffs_params.out.parsed_payload;
                __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_fix_inqueue, fskb);
                deferred_again = true;

                skb_pull(skb, frame_len);
                len -= frame_len;

                HQ_PR_DEBUG(sk, "forwarding frame to user-quic, type=%llu", frame_type);
            } else {
                __skb_queue_tail(&sk->sk_receive_queue, skb);
                sk->sk_data_ready(sk);
                len = 0;

                HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu", frame_type);
            }

            if (frame_profile->ack_eliciting) {
                ctrl_details->ack_eliciting = 1;
                if (frame_profile->ack_immediate)
                    ctrl_details->ack_immediate = 1;
            }
            if (frame_profile->non_probing)
                ctrl_details->non_probing = 1;
        } else {
            if (frame_type > QUIC_FRAME_MAX) {
                HQ_PR_ERR(sk, "unsupported frame type %llu", frame_type);
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

    if (!deferred_again)
        kfree_skb(skb);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Handles incoming flow control at connection level only.
 * 
 * @param sk quic socket
 * @param freed_bytes amount of freed application data
*/
void hyquic_inq_flow_control(struct sock *sk, uint32_t freed_bytes)
{
    struct quic_inqueue *inq = quic_inq(sk);
    struct sk_buff *nskb = NULL;
    uint32_t window;

    if (!freed_bytes)
		return;

    inq->bytes += freed_bytes;

    if (inq->max_bytes - inq->bytes < inq->window / 2) {
		window = inq->window;
		if (sk_under_memory_pressure(sk))
			window >>= 1;
		inq->max_bytes = inq->bytes + window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

    if (nskb)
		quic_outq_transmit(sk);
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
    struct quic_inqueue *inq = quic_inq(sk);
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
        HQ_PR_ERR(sk, "cannot find deferred packet payload, msg_id=%u", ctrlsend_details->msg_id);
        return -EINVAL;
    }
    
    skb_pull(cursor, ctrlsend_details->processed_length);
    HQ_PR_DEBUG(sk, "skipped %u bytes parsed by user-quic", ctrlsend_details->processed_length);

    hyquic_inq_flow_control(sk, ctrlsend_details->processed_payload);

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
            quic_timer_stop(sk, QUIC_TIMER_SACK);
            ctrlrecv_details->ack_sent = true;
        } else if (!ctrlrecv_details->sack_timer_started) {
            if (!quic_inq_need_sack(inq)) {
                quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
                quic_inq_set_need_sack(inq, 1);
            }
            ctrlrecv_details->sack_timer_started = true;
        }
    }

    HQ_PR_DEBUG(sk, "done, msg_id=%u", ctrlsend_details->msg_id);
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
    case HYQUIC_CTRL_FRAMES:
        err = hyquic_process_usrquic_frames(sk, data, info->data_length, &info->raw_frames);
        break;
    case HYQUIC_CTRL_USER_PARSED_FRAMES:
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
 * Handles a frame received from the peer that is unknown to kernel-quic but registered by user-quic.
 * If user-quic provided a frame format specification, the frame is parsed by kernel-quic and forwarded to user-quic.
 * Otherwise, the remaining packet payload is sent to user-quic, which has to parse the frame and responds to kernel-quic 
 * with the parsed length, so that kernel-quic can continue parsing the packet payload.
 * 
 * @param sk quic socket
 * @param skb socket buffer with remaining packet payload
 * @param remaining_pack_len length of remaining packed payload
 * @param frame_profile_cont frame profile container of upcoming frame
 * @return negative error code if not successful, otherwise length of parsed frame
*/
static int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, uint32_t remaining_pack_len, struct hyquic_frame_profile_cont *frame_profile_cont)
{
	struct quic_packet *packet = quic_packet(sk);
    struct hyquic_frame_profile *frame_profile = &frame_profile_cont->profile;
    struct sk_buff *fskb;
    struct hyquic_rcv_cb *rcv_cb;
    struct hyquic_ctrlrecv_raw_frames_var *details;
    uint32_t frame_len;
    uint8_t frame_type_len;
    struct hyquic_frame_format_spec_inout ffs_params;
    int ret = 0;

    if (frame_profile->format_specification_avail) {
        frame_type_len = quic_var_len(frame_profile->frame_type);
        ffs_params = (struct hyquic_frame_format_spec_inout) {.in = {
            .frame_content = skb->data + frame_type_len,
            .remaining_length = remaining_pack_len - frame_type_len,
            .format_specification = frame_profile_cont->format_specification,
            .spec_length = frame_profile->format_specification_avail
        }};
        ret = hyquic_parse_frame_content(sk, &ffs_params);
        if (ret)
            return ret;

        frame_len = frame_type_len + ffs_params.out.parsed_length;
        if (frame_len > remaining_pack_len) {
            HQ_PR_ERR(sk, "remaining packet payload is shorter than advertised frame length, type=%llu", frame_profile->frame_type);
            return -EINVAL;
        }
        fskb = alloc_skb(frame_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        skb_put_data(fskb, skb->data, frame_len);
        QUIC_SND_CB(fskb)->data_bytes = ffs_params.out.parsed_payload;
        __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_fix_inqueue, fskb);
        ret = frame_len;
        HQ_PR_DEBUG(sk, "forwarding frame to user-quic, type=%llu, len=%u", frame_profile->frame_type, frame_len);
    } else {
        fskb = alloc_skb(remaining_pack_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        skb_put_data(fskb, skb->data, remaining_pack_len);

        rcv_cb = HYQUIC_RCV_CB(fskb);
        rcv_cb->common.path_alt = QUIC_RCV_CB(skb)->path_alt;
        rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_USER_PARSED_FRAMES;
        details = &rcv_cb->hyquic_ctrl_details.raw_frames_var;
        details->msg_id = quic_hyquic(sk)->next_ic_msg_id++;
        details->ack_eliciting = packet->ack_eliciting;
        details->ack_immediate = packet->ack_immediate;
        details->ack_sent = false;
        details->sack_timer_started = false;
        details->non_probing = packet->non_probing;
        details->path_alt = QUIC_RCV_CB(skb)->path_alt;

        __skb_queue_tail(&sk->sk_receive_queue, fskb);
        sk->sk_data_ready(sk);
        quic_hyquic(sk)->packet_payload_deferred = true;
        HQ_PR_DEBUG(sk, "forwarding remaining packet payload to user-quic, type=%llu, len=%u, msg_id=%u", frame_profile->frame_type, remaining_pack_len, details->msg_id);
    }

    if (frame_profile->ack_eliciting) {
        packet->ack_eliciting = 1;
        if (frame_profile->ack_immediate)
            packet->ack_immediate = 1;
    }
    if (frame_profile->non_probing)
        packet->non_probing = 1;

    return ret;
}

/**
 * Handles a frame received from the peer.
 * 
 * @param sk quic socket
 * @param skb socket buffer with remaining packet payload
 * @param remaining_pack_len length of remaining packed payload
 * @param frame_type frame type
 * @param frame_len pointer to which the frame length is set if the frame is parsed by hyquic
 * @return negative error code if not successful, 1 if the frame is parsed by hyquic, otherwise 0
*/
int hyquic_process_received_frame(struct sock *sk, struct sk_buff *skb, uint32_t remaining_pack_len, uint64_t frame_type, int *frame_len)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);
    struct hyquic_frame_profile_cont *frame_profile_cont = hyquic_frame_profile_get(quic_hyquic(sk), frame_type);
    int ret;

    if (frame_profile_cont) {
        switch (frame_profile_cont->profile.recv_mode){
        case HYQUIC_FRAME_RECV_MODE_KERNEL:
            return 0;
        case HYQUIC_FRAME_RECV_MODE_USER:
            ret = hyquic_process_unkwn_frame(sk, skb, remaining_pack_len, frame_profile_cont);
            if (ret < 0) {
                return ret;
            } else {
                *frame_len = ret;
                return 1;
            }
        case HYQUIC_FRAME_RECV_MODE_BOTH:
            hyquic->process_frame_copy = true;
            return 0;
        default:
            return -EINVAL;
        }
    }

    return 0;
}

/**
 * Forwards a copy of a frame to user-quic.
 * This frame was previously parsed and processed by kernel-quic.
 * 
 * @param sk quic socket
 * @param skb socket buffer with remaining packet payload (starting with frame content!)
 * @param frame_content_len length of frame content
 * @param frame_type frame type
 * @param frame_type_len length of frame type
 * @return negative error code if not successful, otherwise length of frame content
*/
int hyquic_process_frame_copy(struct sock *sk, struct sk_buff *skb, uint32_t frame_content_len, uint64_t frame_type, uint8_t frame_type_len)
{
    struct sk_buff *fskb;
    uint8_t *skb_ptr;

    quic_hyquic(sk)->process_frame_copy = false;

    fskb = alloc_skb(frame_type_len + frame_content_len, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;

    skb_ptr = quic_put_var(fskb->data, frame_type);
    skb_put(skb, frame_type_len);
    skb_put_data(fskb, skb->data, frame_content_len);

    __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_fix_inqueue, fskb);

    HQ_PR_DEBUG(sk, "forwarding frame copy to user-quic, type=%llu, len=%u", frame_type, frame_type_len + frame_content_len);
    return frame_content_len;
}

/**
 * Notifies a deferred packet that the ack timer has been started and does not need to be started anymore if parsed frames would require it later on.
 * 
 * @param sk quic socket
*/
inline void hyquic_frame_var_notify_sack_timer_started(struct sock *sk)
{
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    skb_queue_reverse_walk(&sk->sk_receive_queue, skb) {
        rcv_cb = HYQUIC_RCV_CB(skb);
        if (rcv_cb->hyquic_ctrl_type != HYQUIC_CTRL_USER_PARSED_FRAMES)
            continue;

        rcv_cb->hyquic_ctrl_details.raw_frames_var.sack_timer_started = true;
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
        if (rcv_cb->hyquic_ctrl_type != HYQUIC_CTRL_USER_PARSED_FRAMES)
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
    uint32_t payload = 0;

    if (skb_queue_empty(head))
        return 0;

    skb_queue_walk(head, fskb) {
        length += fskb->len;
        payload += QUIC_SND_CB(fskb)->data_bytes;
    }

    skb = alloc_skb(length, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    fskb = __skb_dequeue(head);
    while (fskb) {
        skb_put_data(skb, fskb->data, fskb->len);
        kfree_skb(fskb);
        fskb = __skb_dequeue(head);
    }

    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_FRAMES;
    rcv_cb->hyquic_ctrl_details.raw_frames_fix.payload = payload;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

static int hyquic_process_lost_user_frame(struct sock *sk, struct sk_buff *fskb, bool no_retransmit)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    if (no_retransmit) {
        HQ_PR_DEBUG(sk, "no retransmit, type=%u", QUIC_SND_CB(fskb)->frame_type);
        return 1;
    }

    if (hyquic->options.usrquic_retransmit) {
        skb = alloc_skb(fskb->len, GFP_ATOMIC);
        if (!skb)
            return -ENOMEM;
        skb_put_data(skb, fskb->data, fskb->len);

        rcv_cb = HYQUIC_RCV_CB(skb);
        rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_LOST_FRAMES;
        rcv_cb->hyquic_ctrl_details.lost_frames.payload_length = QUIC_SND_CB(fskb)->data_bytes;
        rcv_cb->hyquic_ctrl_details.lost_frames.retransmit_count = QUIC_SND_CB(fskb)->sent_count;
        __skb_queue_tail(&hyquic->lost_usrquic_frames_inqueue, skb);

        HQ_PR_DEBUG(sk, "forwarded to user-quic, type=%u", QUIC_SND_CB(fskb)->frame_type);
        return 1;
    }
    return 0;
}

/**
 * Processes a lost frame.
 * If frame is a user-frame, sends it back to user-quic or drops it based on specified options.
 * 
 * @param sk quic socket
 * @param fskb socket buffer containing lost frame
 * @return negative error code if not successful, 1 if processed by hyquic, otherwise 0
*/
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb)
{
    struct hyquic_container *hyquic = quic_hyquic(sk);
    struct hyquic_frame_profile_cont *frame_profile_cont = hyquic_frame_profile_get(hyquic, QUIC_SND_CB(fskb)->frame_type);

    if (frame_profile_cont) {
        switch (frame_profile_cont->profile.send_mode) {
        case HYQUIC_FRAME_SEND_MODE_KERNEL:
            return 0;
        case HYQUIC_FRAME_SEND_MODE_USER:
            return hyquic_process_lost_user_frame(sk, fskb, frame_profile_cont->profile.no_retransmit);
        case HYQUIC_FRAME_SEND_MODE_BOTH:
            if (HYQUIC_SND_CB(fskb)->is_user_frame)
                return hyquic_process_lost_user_frame(sk, fskb, frame_profile_cont->profile.no_retransmit);
            return 0;
        default:
            return -EINVAL;
        }
    }

    return 0;
}

/**
 * Collects all lost frames waiting to be send back to user-quic and puts them to the receive queue.
 * 
 * @param sk quic socket
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_flush_lost_frames_inqueue(struct sock *sk)
{
    struct sk_buff_head *head = &quic_hyquic(sk)->lost_usrquic_frames_inqueue;
    struct sk_buff *skb, *fskb;
    struct hyquic_rcv_cb *rcv_cb;
    struct hyquic_lost_frame_metadata metadata;
    size_t length = 0;

    if (skb_queue_empty(head))
        return 0;

    skb_queue_walk(head, fskb) {
        length += fskb->len + sizeof(struct hyquic_lost_frame_metadata);
    }

    skb = alloc_skb(length, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    fskb = __skb_dequeue(head);
    while (fskb) {
        rcv_cb = HYQUIC_RCV_CB(fskb);
        metadata = (struct hyquic_lost_frame_metadata) {
            .frame_length = fskb->len,
            .payload_length = rcv_cb->hyquic_ctrl_details.lost_frames.payload_length,
            .retransmit_count = rcv_cb->hyquic_ctrl_details.lost_frames.retransmit_count
        };
        skb_put_data(skb, &metadata, sizeof(struct hyquic_lost_frame_metadata));
        skb_put_data(skb, fskb->data, fskb->len);
        kfree_skb(fskb);
        fskb = __skb_dequeue(head);
    }

    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_LOST_FRAMES;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done");
    return 0;
}

/**
 * Notifies the user-quic about changed MPS values:
 * - Maximum payload of a packet
 * - Maximum payload of a packet for datagrams
 * 
 * @param sk quic socket
 * @param packet packet information
 * @return negative error code if not successful, otherwise 0
*/
int hyquic_handle_mps_update(struct sock *sk, struct quic_packet *packet)
{
    uint32_t max_payload = quic_packet_max_payload(packet);
    uint32_t max_payload_dgram = quic_packet_max_payload_dgram(packet);
    struct hyquic_container *hyquic = quic_hyquic(sk);
    struct sk_buff *skb;
    struct hyquic_rcv_cb *rcv_cb;

    if (max_payload == hyquic->last_max_payload && max_payload_dgram == hyquic->last_max_payload_dgram) {
        HQ_PR_DEBUG(sk, "no change, max_payload=%u, max_payload_dgram=%u", max_payload, max_payload_dgram);
        return 0;
    }

    hyquic->last_max_payload = max_payload;
    hyquic->last_max_payload_dgram = max_payload_dgram;

    skb = alloc_skb(0, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    
    rcv_cb = HYQUIC_RCV_CB(skb);
    rcv_cb->hyquic_ctrl_type = HYQUIC_CTRL_MPS_UPDATE;
    rcv_cb->hyquic_ctrl_details.mps_update.max_payload = max_payload;
    rcv_cb->hyquic_ctrl_details.mps_update.max_payload_dgram = max_payload_dgram;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);

    HQ_PR_DEBUG(sk, "done, max_payload=%u, max_payload_dgram=%u", max_payload, max_payload_dgram);
    return 0;
}