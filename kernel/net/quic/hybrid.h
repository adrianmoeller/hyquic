#include <linux/list.h>

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
    
};

#define hyquic_transport_param_for_each(pos, head) list_for_each_entry((pos), (head), list)

void hyquic_init(struct hyquic_adapter *hyquic);
void hyquic_free(struct hyquic_adapter *hyquic);
inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list);
size_t hyquic_transport_params_total_length(struct list_head *param_list);
struct hyquic_transport_param* hyquic_transport_param_create(void *data, size_t length);
int hyquic_process_info(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_info *info);
