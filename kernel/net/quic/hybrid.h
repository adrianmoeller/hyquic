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
 * @frame_details_table: mapping of frame type to frame details
*/
struct hyquic_container {
    bool enabled;
    struct sock *sk;
    struct hyquic_options options;

    struct list_head transport_params_remote;
    struct list_head transport_params_local;

    uint64_t next_ic_msg_id;
    struct sk_buff_head usrquic_frames_outqueue;
    struct sk_buff_head unkwn_frames_fix_inqueue;
    struct sk_buff_head unkwn_frames_var_deferred;
    struct quic_hash_table frame_details_table;
};

/**
 * Frame details container.
 * 
 * @details: frame details
 * @format_specification: frame format specification (length stored in @details)
*/
struct hyquic_frame_details_cont {
    struct hyquic_frame_details details;
    uint8_t *format_specification;
};

#define hyquic_transport_param_for_each(pos, head) list_for_each_entry((pos), (head), list)

/**
 * Control buffer content of to be sent frames.
 * 
 * @common: control buffer content of quic
*/
struct hyquic_snd_cb {
    struct quic_snd_cb common;
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
struct hyquic_frame_details_cont* hyquic_frame_details_get(struct hyquic_container *hyquic, uint64_t frame_type);
inline bool hyquic_is_usrquic_frame(struct hyquic_container *hyquic, uint64_t frame_type);
int hyquic_set_local_transport_parameter(struct hyquic_container *hyquic, void *data, uint32_t length);
int hyquic_get_remote_transport_parameters(struct hyquic_container *hyquic, int len, char __user *optval, int __user *optlen);
int hyquic_get_remote_transport_parameters_length(struct hyquic_container *hyquic, int len, char __user *optval, int __user *optlen);
int hyquic_handle_remote_transport_parameter(struct hyquic_container *hyquic, uint64_t type, uint8_t **pp, uint32_t *plen);
int hyquic_transfer_local_transport_parameters(struct hyquic_container *hyquic, uint8_t **pp, uint8_t *data);
int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_ctrlsend_info *info);
int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, uint32_t remaining_pack_len, struct hyquic_frame_details_cont *frame_details_cont, bool *var_frame_encountered);
inline void hyquic_frame_var_notify_ack_timer_started(struct sock *sk);
inline void hyquic_frame_var_notify_ack_sent(struct sock *sk);
int hyquic_flush_unkwn_frames_inqueue(struct sock *sk);
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb);

#endif /* __QUIC_HYBRID_H__ */