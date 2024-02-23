#include <linux/slab.h>
#include "number.h"
#include "socket.h"
#include "hybrid.h"

static int hyquic_raw_frame_types_init(struct quic_hash_table *raw_frame_types)
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
	raw_frame_types->size = size;
	raw_frame_types->hash = head;
	return 0;
}

int hyquic_init(struct hyquic_adapter *hyquic)
{
    hyquic->enabled = false;

    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);

    hyquic->next_user_frame_seq_no = 0;
    skb_queue_head_init(&hyquic->raw_frames_outqueue);

    if (hyquic_raw_frame_types_init(&hyquic->raw_frame_types))
        return -ENOMEM;

    return 0;
}

static void hyquic_raw_frame_types_free(struct quic_hash_table *raw_frame_types)
{
    // TODO
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

    __skb_queue_purge(&hyquic->raw_frames_outqueue);

    hyquic_raw_frame_types_free(&hyquic->raw_frame_types);
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

struct sk_buff* hyquic_frame_create_raw(uint8_t **pdata, uint32_t *pdata_length)
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

static int hyquic_process_info_raw_frames(struct sock *sk, uint8_t *data, uint32_t data_length, struct hyquic_info_raw_frames *info)
{
    struct sk_buff *skb;

    if (!quic_is_established(sk))
        return -EINVAL;

    while (data_length)
    {
        skb = hyquic_frame_create_raw(&data, &data_length);
        if (!skb)
            return -EINVAL;

        hyquic_outq_raw_tail(sk, skb, false);
    }
    return 0;
}

int hyquic_process_info(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_info *info)
{
    int err = 0;
    uint8_t *data = (uint8_t*) kmalloc_array(info->data_length, sizeof(uint8_t), GFP_KERNEL);

    if (iov_iter_count(msg_iter) < info->data_length)
    {
        err = -EINVAL;
        goto out;
    }

    if (!copy_from_iter_full(data, info->data_length, msg_iter))
        goto out;

    switch (info->type)
    {
    case HYQUIC_INFO_RAW_FRAMES:
        err = hyquic_process_info_raw_frames(sk, data, info->data_length, &info->raw_frames);
        break;
    default:
        err = -EINVAL;
        break;
    }
    
out:
    kfree(data);
    return err;
}

struct hyquic_raw_frame_type* hyquic_raw_frame_type_create(struct hyquic_adapter *hyquic, uint64_t frame_type, size_t fixed_length)
{
    struct quic_hash_head *head;
    struct hyquic_raw_frame_type *raw_frame_type;

    raw_frame_type = kmalloc(sizeof(*raw_frame_type), GFP_ATOMIC);
    if (!raw_frame_type)
        return NULL;
    
    raw_frame_type->frame_type = frame_type;
    raw_frame_type->fixed_length = fixed_length;

    head = hyquic_raw_frame_type_head(&hyquic->raw_frame_types, frame_type);
    hlist_add_head(&raw_frame_type->node, &head->head);
    return raw_frame_type;
}