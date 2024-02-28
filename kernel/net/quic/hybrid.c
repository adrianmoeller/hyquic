#include <linux/slab.h>
#include "number.h"
#include "socket.h"
#include "hybrid.h"

struct hyquic_frame_details_entry {
    struct hlist_node node;
    struct hyquic_frame_details details;
};

struct hyquic_sent_usrquic_frame_entry {
    struct hlist_node node;
    int64_t packet_num;
    uint64_t frame_seqnum;
};

inline void hyquic_enable(struct sock *sk)
{
    struct hyquic_adapter *hyquic = quic_hyquic(sk);

    if (hyquic->enabled)
        return;
    hyquic->enabled = true;
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

static int hyquic_sent_usrquic_frame_table_init(struct quic_hash_table *sent_usrquic_frame_table)
{
    struct quic_hash_head *head;
    int i, size = 32;

    head = kmalloc_array(size, sizeof(*head), GFP_KERNEL);
    if (!head)
        return -ENOMEM;
    for (i = 0; i < size; i++) {
		spin_lock_init(&head[i].lock);
		INIT_HLIST_HEAD(&head[i].head);
	}
    sent_usrquic_frame_table->size = size;
    sent_usrquic_frame_table->hash = head;
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
    skb_queue_head_init(&hyquic->usrquic_frames_outqueue);
    skb_queue_head_init(&hyquic->unkwn_frames_inqueue);
    if (hyquic_frame_details_table_init(&hyquic->frame_details_table))
        return -ENOMEM;
    if (hyquic_sent_usrquic_frame_table_init(&hyquic->sent_usrquic_frame_table))
        return -ENOMEM;

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

static void hyquic_sent_usrquic_frame_table_free(struct quic_hash_table *sent_usrquic_frame_table)
{
    struct quic_hash_head *head;
    struct hyquic_sent_usrquic_frame_entry *entry;
    struct hlist_node *tmp;
    int i;

    for (i = 0; i < sent_usrquic_frame_table->size; i++) {
        head = &sent_usrquic_frame_table->hash[i];
        hlist_for_each_entry_safe(entry, tmp, &head->head, node) {
            hlist_del_init(&entry->node);
            kfree(entry);
        }
    }
    kfree(sent_usrquic_frame_table->hash);
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
    __skb_queue_purge(&hyquic->unkwn_frames_inqueue);
    hyquic_frame_details_table_free(&hyquic->frame_details_table);
    hyquic_sent_usrquic_frame_table_free(&hyquic->sent_usrquic_frame_table);
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

struct sk_buff* hyquic_frame_create_raw(uint8_t **pdata, uint32_t *pdata_length, uint64_t *pframe_seqnum)
{
    uint64_t frame_length, frame_type;
    struct sk_buff *skb;
    struct hyquic_snd_cb *snd_cb;

    if (!quic_get_var(pdata, pdata_length, &frame_length))
        return NULL;
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
    return skb;
}

static int hyquic_process_usrquic_frames(struct sock *sk, uint8_t *data, uint32_t data_length, struct hyquic_data_raw_frames *info)
{
    struct sk_buff *skb;
    uint64_t frame_seqnum = info->first_frame_seqnum;

    if (!quic_is_established(sk))
        return -EINVAL;

    while (data_length) {
        skb = hyquic_frame_create_raw(&data, &data_length, &frame_seqnum);
        if (!skb)
            return -EINVAL;

        hyquic_outq_raw_tail(sk, skb, false);
    }
    return 0;
}

int hyquic_process_usrquic_data(struct sock *sk, struct iov_iter *msg_iter, struct hyquic_data_info *info)
{
    int err = 0;
    uint8_t *data = (uint8_t*) kmalloc_array(info->data_length, sizeof(uint8_t), GFP_KERNEL);

    if (iov_iter_count(msg_iter) < info->data_length) {
        err = -EINVAL;
        goto out;
    }

    if (!copy_from_iter_full(data, info->data_length, msg_iter))
        goto out;

    switch (info->type) {
    case HYQUIC_DATA_RAW_FRAMES:
        err = hyquic_process_usrquic_frames(sk, data, info->data_length, &info->raw_frames);
        break;
    default:
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

int hyquic_process_unkwn_frame(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki, struct hyquic_frame_details *frame_details)
{
    struct sk_buff *fskb;
    uint8_t *p;
    int ret = 0;

    if (frame_details->fixed_length < 0) {
        // TODO handle var length frame
    } else {
        if (frame_details->fixed_length > skb->len)
            return -EINVAL;
        fskb = alloc_skb(quic_var_len(frame_details->frame_type) + frame_details->fixed_length, GFP_ATOMIC);
        if (!fskb)
            return -ENOMEM;
        p = quic_put_var(fskb->data, frame_details->frame_type);
        p = quic_put_data(p, skb->data, frame_details->fixed_length);
        __skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_inqueue, fskb);
        ret = frame_details->fixed_length;
    }

    if (frame_details->ack_eliciting) {
        pki->ack_eliciting = 1;
        if (frame_details->ack_immidiate)
            pki->ack_immediate = 1;
    }
    if (frame_details->non_probing)
        pki->non_probing = 1;

    return ret;
}

int hyquic_flush_unkwn_frames_inqueue(struct sock *sk)
{
    struct sk_buff_head *head = &quic_hyquic(sk)->unkwn_frames_inqueue;
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
    rcv_cb->hyquic_data = HYQUIC_DATA_RAW_FRAMES_FIX;

    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);
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
    rcv_cb->hyquic_data = HYQUIC_DATA_LOST_FRAMES;
    
    __skb_queue_tail(&sk->sk_receive_queue, skb);
    sk->sk_data_ready(sk);
    return 0;
}