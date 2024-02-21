#include "hybrid.h"
#include <linux/slab.h>

void hyquic_init(struct hyquic_adapter *hyquic)
{
    hyquic->enabled = false;

    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);

    hyquic->next_user_frame_seq_no = 0;
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
}

inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list)
{
    list_add_tail(&param->list, param_list);
}

size_t hyquic_transport_params_total_length(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor;
	size_t total_length = 0;

	hyquic_transport_param_for_each(cursor, param_list) {
		total_length += cursor->length;
	}
    return total_length;
}

struct hyquic_transport_param* hyquic_transport_param_create(void *data, size_t length)
{
    struct hyquic_transport_param *param = (struct hyquic_transport_param*) kmalloc(sizeof(struct hyquic_transport_param), GFP_KERNEL);
    if (!param)
        return NULL;
    param->param = data;
    param->length = length;
    return param;
}

struct sk_buff* quic_frame_create_raw(struct sock *sk, void **pdata, uint64_t *pdata_length)
{
    uint64_t frame_length;
    struct sk_buff *skb;

    if (!quic_get_var(pdata, pdata_length, &frame_length))
        return NULL;
    if (!frame_length || frame_length > *pdata_length)
        return NULL;

    skb = alloc_skb(frame_length, GFP_ATOMIC);
    if (!skb)
		return NULL;
    skb_put_data(skb, *pdata, frame_length);
    *pdata += frame_length;
    *pdata_length -=frame_length;
    return skb;
}

static int hyquic_process_info_raw_frames(struct sock *sk, void *data, uint64_t data_length, struct hyquic_info_raw_frames *info)
{
    while (data_length)
    {
        // TODO continue
    }
}

int hyquic_process_info(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_info *info)
{
    void data[info->data_length];

    if (iov_iter_count(msg_iter) < info->data_length)
        return -EINVAL;

    if (!copy_from_iter_full(data, info->data_length, msg_iter))
        return 0;

    switch (info->type)
    {
    case HYQUIC_INFO_RAW_FRAMES:
        return hyquic_process_info_raw_frames(sk, data, info->data_length, &info->raw_frames);
    default:
        return -EINVAL;
    }
}