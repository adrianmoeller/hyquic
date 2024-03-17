#ifndef __QUIC_HYBRID_H__
#define __QUIC_HYBRID_H__

#include <uapi/linux/hyquic.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include "hashtable.h"

struct hyquic_transport_param {
    struct list_head list;
    uint64_t id;
    void *param;
    size_t length;
};

struct hyquic_adapter {
    bool enabled;
    struct sock *sk;
    struct hyquic_options options;

    struct list_head transport_params_remote;
    struct list_head transport_params_local;

    uint64_t next_usrquic_frame_seqnum;
    uint64_t next_ic_msg_id;
    struct sk_buff_head usrquic_frames_outqueue;
    struct sk_buff_head unkwn_frames_fix_inqueue;
    struct sk_buff_head unkwn_frames_var_deferred;
    struct quic_hash_table frame_details_table;
};

#define hyquic_transport_param_for_each(pos, head) list_for_each_entry((pos), (head), list)

struct hyquic_snd_cb {
    struct quic_snd_cb common;
    uint64_t usrquic_frame_seqnum;
};

#define HYQUIC_SND_CB(__skb) ((struct hyquic_snd_cb *)&((__skb)->cb[0]))

struct hyquic_rcv_cb {
    struct quic_rcv_cb common;
	uint8_t hyquic_data_type;
    union hyquic_data_recvinfo_details hyquic_data_details;
};

#define HYQUIC_RCV_CB(__skb) ((struct hyquic_rcv_cb *)&((__skb)->cb[0]))

inline void hyquic_enable(struct sock *sk);
int hyquic_init(struct hyquic_adapter *hyquic, struct sock *sk);
void hyquic_free(struct hyquic_adapter *hyquic);
struct hyquic_frame_details* hyquic_frame_details_get(struct hyquic_adapter *hyquic, uint64_t frame_type);
int hyquic_set_local_transport_parameter(struct hyquic_adapter *hyquic, void *data, uint32_t length);
int hyquic_get_remote_transport_parameters(struct hyquic_adapter *hyquic, int len, char __user *optval, int __user *optlen);
int hyquic_get_remote_transport_parameters_length(struct hyquic_adapter *hyquic, int len, char __user *optval, int __user *optlen);
int hyquic_handle_remote_transport_parameter(struct hyquic_adapter *hyquic, uint64_t type, uint8_t **pp, uint32_t *plen);
int hyquic_transfer_local_transport_parameters(struct hyquic_adapter *hyquic, uint8_t **pp, uint8_t *data);
int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_data_sendinfo *info);
int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, uint32_t remaining_pack_len, struct hyquic_frame_details *frame_details, bool *var_frame_encountered);
inline void hyquic_frame_var_notify_ack_timer_started(struct sock *sk);
inline void hyquic_frame_var_notify_ack_sent(struct sock *sk);
int hyquic_flush_unkwn_frames_inqueue(struct sock *sk);
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb);

static inline bool hyquic_is_usrquic_frame(struct hyquic_adapter *hyquic, uint64_t frame_type)
{
    return hyquic_frame_details_get(hyquic, frame_type);
}

#endif /* __QUIC_HYBRID_H__ */