#ifndef __QUIC_HYBRID_H__
#define __QUIC_HYBRID_H__

#include <uapi/linux/hyquic.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include "hashtable.h"

struct hyquic_transport_param {
    struct list_head list;
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
    struct sk_buff_head usrquic_frames_outqueue;
    struct sk_buff_head unkwn_frames_inqueue;
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
	uint8_t hyquic_data;
};

#define HYQUIC_RCV_CB(__skb) ((struct hyquic_rcv_cb *)&((__skb)->cb[0]))

inline void hyquic_enable(struct sock *sk);
int hyquic_init(struct hyquic_adapter *hyquic, struct sock *sk);
void hyquic_free(struct hyquic_adapter *hyquic);
inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list);
size_t hyquic_transport_params_total_length(struct list_head *param_list);
struct hyquic_transport_param* hyquic_transport_param_create(void *data, size_t length);
int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_data_sendinfo *info);
int hyquic_frame_details_create(struct hyquic_adapter *hyquic, struct hyquic_frame_details *frame_details);
struct hyquic_frame_details* hyquic_frame_details_get(struct hyquic_adapter *hyquic, uint64_t frame_type);
int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, struct hyquic_frame_details *frame_details);
int hyquic_flush_unkwn_frames_inqueue(struct sock *sk);
int hyquic_process_lost_frame(struct sock *sk, struct sk_buff *fskb);

static inline bool hyquic_is_usrquic_frame(struct hyquic_adapter *hyquic, uint64_t frame_type)
{
    return hyquic_frame_details_get(hyquic, frame_type);
}

#endif /* __QUIC_HYBRID_H__ */