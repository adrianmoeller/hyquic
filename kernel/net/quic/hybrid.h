#include <uapi/linux/quic.h>
#include <linux/list.h>
#include <linux/skbuff.h>

struct hyquic_transport_param {
    struct list_head list;
    void *param;
    size_t length;
};

struct hyquic_adapter {
    bool enabled;

    struct list_head transport_params_remote;
    struct list_head transport_params_local;

    uint64_t next_user_frame_seq_no;
    struct sk_buff_head raw_frames_outqueue;
    struct quic_hash_table raw_frame_types;
};

struct hyquic_raw_frame_type {
    struct hlist_node node;
    uint64_t frame_type;
    size_t fixed_length;
};

#define hyquic_transport_param_for_each(pos, head) list_for_each_entry((pos), (head), list)

int hyquic_init(struct hyquic_adapter *hyquic);
void hyquic_free(struct hyquic_adapter *hyquic);
inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list);
size_t hyquic_transport_params_total_length(struct list_head *param_list);
struct hyquic_transport_param* hyquic_transport_param_create(void *data, size_t length);
int hyquic_process_info(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_info *info);
