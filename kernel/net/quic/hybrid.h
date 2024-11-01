/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __QUIC_HYBRID_H__
#define __QUIC_HYBRID_H__

#include <uapi/linux/hyquic.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include "hashtable.h"

/**
 * List entry of a transport parameter.
 * 
 * @list: list entry reference
 * @id: id of transport parameter
 * @param: encoded transport parameter including id
 * @length: length of encoded transport parameter
*/
struct hyquic_transport_param {
    struct list_head list;
    uint64_t id;
    void *param;
    size_t length;
};

/**
 * Holds hyquic specific data. Should be part of the quic socket.
 * 
 * @enabled: tells if hyquic is enabled
 * @sk: back reference to quic socket
 * @options: hyquic options
 * @transport_params_remote: list of additional transport parameters of remote peer
 * @transport_params_local: list of additional transport parameters of host
 * @next_ic_msg_id: next message id used for communication between user- and kernel-quic
 * @usrquic_frames_outqueue: frames from user-quic ready to be sent to peer
 * @unkwn_frames_fix_inqueue: frames of known length from peer ready to be sent to user-quic
 * @unkwn_frames_var_deferred: remaining frames of a packet from peer deferred to be processed because of unknown frame length
 * @lost_usrquic_frames_inqueue: lost user-quic frames ready to be sent back to user-quic
 * @frame_profile_table: mapping of frame type to frame profile
 * @last_max_payload: last value of maximum packet payload length
 * @last_max_payload_dgram: last value of maximum packet payload length for datagrams
 * @process_frame_copy: internal flag that denotes if user-quic should get a copy of the current frame
 * @packet_payload_deferred: internal flag that denotes if the payload processing of the current packet is deferred due to a missing FFS
*/
struct hyquic_container {
    bool enabled;
    struct sock *sk;
    struct hyquic_options options;

    struct list_head transport_params_remote;
    struct list_head transport_params_local;

    uint32_t next_ic_msg_id;
    struct sk_buff_head usrquic_frames_outqueue;
    struct sk_buff_head unkwn_frames_fix_inqueue;
    struct sk_buff_head unkwn_frames_var_deferred;
    struct sk_buff_head lost_usrquic_frames_inqueue;
    struct quic_hash_table frame_profile_table;

    uint32_t last_max_payload;
    uint32_t last_max_payload_dgram;

    uint8_t process_frame_copy:1;
    uint8_t packet_payload_deferred:1;
};

/**
 * Frame profile container.
 * 
 * @profile: frame profile
 * @format_specification: frame format specification (length stored in @profile)
*/
struct hyquic_frame_profile_cont {
    struct hyquic_frame_profile profile;
    uint8_t *format_specification;
};

#define hyquic_transport_param_for_each(pos, head) list_for_each_entry((pos), (head), list)

/**
 * Control buffer content of to be sent frames.
 * 
 * @common: control buffer content of quic
 * @is_user_frame: denotes if frame is sent by user-quic
*/
struct hyquic_snd_cb {
    struct quic_snd_cb common;
    uint8_t is_user_frame:1;
};

#define HYQUIC_SND_CB(__skb) ((struct hyquic_snd_cb *)&((__skb)->cb[0]))

/**
 * Control buffer content of received frames.
 * 
 * @common: control buffer content of quic
 * @hyquic_ctrl_type: type of hyquic control data
 * @hyquic_ctrl_details: details of hyquic control data
*/
struct hyquic_rcv_cb {
    struct quic_rcv_cb common;
	uint8_t hyquic_ctrl_type;
    union hyquic_ctrlrecv_info_details hyquic_ctrl_details;
};

#define HYQUIC_RCV_CB(__skb) ((struct hyquic_rcv_cb *)&((__skb)->cb[0]))

inline void hyquic_enable(struct sock *sk);
int hyquic_init(struct hyquic_container *hyquic, struct sock *sk);
void hyquic_free(struct hyquic_container *hyquic);
struct hyquic_frame_profile_cont* hyquic_frame_profile_get(struct hyquic_container *hyquic, uint64_t frame_type);
inline bool hyquic_is_usrquic_frame(struct hyquic_container *hyquic, uint64_t frame_type);
int hyquic_set_options(struct sock *sk, struct hyquic_options *options, uint32_t length);
int hyquic_set_local_transport_parameter(struct sock *sk, void *data, uint32_t length);
int hyquic_get_remote_transport_parameters(struct sock *sk, int len, char __user *optval, int __user *optlen);
int hyquic_get_remote_transport_parameters_length(struct sock *sk, int len, char __user *optval, int __user *optlen);
int hyquic_get_initial_mps(struct sock *sk, int len, char __user *optval, int __user *optlen);
int hyquic_handle_remote_transport_parameter(struct hyquic_container *hyquic, uint64_t type, uint8_t **pp, uint32_t *plen);
int hyquic_transfer_local_transport_parameters(struct hyquic_container *hyquic, uint8_t **pp, uint8_t *data);
void hyquic_inq_flow_control(struct sock *sk, uint32_t freed_bytes);
int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_ctrlsend_info *info);
int hyquic_process_received_frame(struct sock *sk, struct sk_buff *skb, uint32_t remaining_pack_len, uint64_t frame_type, int *frame_len);
int hyquic_process_frame_copy(struct sock *sk, struct sk_buff *skb, uint32_t frame_content_len, uint64_t frame_type, uint8_t frame_type_len);
inline void hyquic_frame_var_notify_sack_timer_started(struct sock *sk);
inline void hyquic_frame_var_notify_ack_sent(struct sock *sk);
int hyquic_flush_unkwn_frames_inqueue(struct sock *sk);
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb);
int hyquic_flush_lost_frames_inqueue(struct sock *sk);
int hyquic_handle_mps_update(struct sock *sk, struct quic_packet *packet);

#endif /* __QUIC_HYBRID_H__ */