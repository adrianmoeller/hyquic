// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "socket.h"
#include "number.h"
#include "frame.h"

/* ACK Frame {
 *  Type (i) = 0x02..0x03,
 *  Largest Acknowledged (i),
 *  ACK Delay (i),
 *  ACK Range Count (i),
 *  First ACK Range (i),
 *  ACK Range (..) ...,
 *  [ECN Counts (..)],
 * }
 */

static struct sk_buff *quic_frame_ack_create(struct sock *sk, void *data, u8 type)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	struct quic_pnmap *map = quic_pnmap(sk);
	u32 largest, smallest, range, pn_ts;
	u32 frame_len, num_gabs;
	struct sk_buff *skb;
	int i;
	u8 *p;

	num_gabs = quic_pnmap_num_gabs(map, gabs);
	frame_len = sizeof(type) + sizeof(u32) * 4;
	frame_len += sizeof(struct quic_gap_ack_block) * num_gabs;

	largest = quic_pnmap_max_pn_seen(map);
	pn_ts = quic_pnmap_max_pn_ts(map);
	smallest = quic_pnmap_min_pn_seen(map);
	if (num_gabs)
		smallest = quic_pnmap_base_pn(map) + gabs[num_gabs - 1].end;
	range = largest - smallest;
	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	pn_ts = jiffies_to_usecs(jiffies) - pn_ts;
	pn_ts = pn_ts / BIT(quic_outq_ack_delay_exponent(quic_outq(sk)));
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged */
	p = quic_put_var(p, pn_ts); /* ACK Delay */
	p = quic_put_var(p, num_gabs); /* ACK Count */
	p = quic_put_var(p, range); /* First ACK Range */

	if (num_gabs) {
		for (i = num_gabs - 1; i > 0; i--) {
			p = quic_put_var(p, gabs[i].end - gabs[i].start); /* Gap */
			p = quic_put_var(p, gabs[i].start - gabs[i - 1].end - 2); /* ACK Range Length */
		}
		p = quic_put_var(p, gabs[0].end - gabs[0].start); /* Gap */
		p = quic_put_var(p, gabs[0].start - 2); /* ACK Range Length */
	}
	frame_len = (u32)(p - skb->data);
	skb_put(skb, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_ping_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_padding_create(struct sock *sk, void *data, u8 type)
{
	u32 *frame_len = data;
	struct sk_buff *skb;

	skb = alloc_skb(*frame_len + 1, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_zero(skb, *frame_len + 1);
	quic_put_var(skb->data, type);

	return skb;
}

static struct sk_buff *quic_frame_new_token_create(struct sock *sk, void *data, u8 type)
{
	struct quic_token *token = data;
	struct sk_buff *skb;
	u8 *p;

	skb = alloc_skb(token->len + 4, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, token->len);
	p = quic_put_data(p, token->data, token->len);
	skb_put(skb, (u32)(p - skb->data));

	return skb;
}

static struct sk_buff *quic_frame_stream_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct quic_msginfo *info = data;
	struct quic_stream *stream;
	struct sk_buff *skb;
	u8 *p;

	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	stream = info->stream;
	hlen += quic_var_len(stream->id);
	if (stream->send.offset) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.offset);
	}

	type |= QUIC_STREAM_BIT_LEN;
	hlen += quic_var_len(max_frame_len);

	msg_len = iov_iter_count(info->msg);
	if (msg_len <= max_frame_len - hlen) {
		if (info->flag & QUIC_STREAM_FLAG_FIN)
			type |= QUIC_STREAM_BIT_FIN;
	} else {
		msg_len = max_frame_len - hlen;
	}

	skb = alloc_skb(msg_len + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, stream->id);
	if (type & QUIC_STREAM_BIT_OFF) {
		p = quic_put_var(p, stream->send.offset);
		QUIC_SND_CB(skb)->stream_offset = stream->send.offset;
	}
	p = quic_put_var(p, msg_len);
	frame_len = (u32)(p - skb->data);

	if (!copy_from_iter_full(p, msg_len, info->msg)) {
		kfree_skb(skb);
		return NULL;
	}
	frame_len += msg_len;
	skb_put(skb, frame_len);
	QUIC_SND_CB(skb)->data_bytes = msg_len;

	stream->send.offset += msg_len;
	quic_stream_send_state_update(stream, type);
	return skb;
}

static struct sk_buff *quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_crypto_create(struct sock *sk, void *data, u8 type)
{
	struct quic_token *ticket = data;
	struct sk_buff *skb;
	u8 *p;

	skb = alloc_skb(ticket->len + 8, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, 0);
	p = quic_put_var(p, ticket->len);
	p = quic_put_data(p, ticket->data, ticket->len);
	skb_put(skb, (u32)(p - skb->data));

	return skb;
}

static struct sk_buff *quic_frame_retire_connection_id_create(struct sock *sk, void *data, u8 type)
{
	u32 *number = data, frame_len;
	struct sk_buff *skb;
	u8 *p, frame[10];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *number);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);
	return skb;
}

static struct sk_buff *quic_frame_new_connection_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_new_connection_id *nums = data;
	u8 *p, frame[100], conn_id[16], token[16];
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, nums->prior);
	p = quic_put_var(p, nums->seqno);
	p = quic_put_var(p, 16);
	get_random_bytes(conn_id, 16);
	quic_put_data(p, conn_id, 16);
	quic_put_data(p, token, 16);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);
	return skb;
}

static struct sk_buff *quic_frame_path_response_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, frame[10], *entropy = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_data(p, entropy, 8);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type)
{
	struct quic_path_addr *path = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	get_random_bytes(path->entropy, sizeof(path->entropy));

	p = quic_put_var(frame, type);
	p = quic_put_data(p, path->entropy, sizeof(path->entropy));
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type)
{
	return 0;
}

static struct sk_buff *quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type)
{
	return 0;
}

static struct sk_buff *quic_frame_max_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_inqueue *inq = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, inq->max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->recv.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type)
{
	u32 *max = data, frame_len;
	struct sk_buff *skb;
	u8 *p, frame[10];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type)
{
	u32 *max = data, frame_len;
	struct sk_buff *skb;
	u8 *p, frame[10];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_connection_close_create(struct sock *sk, void *data, u8 type)
{
	return 0;
}

static struct sk_buff *quic_frame_connection_close_app_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, 0);
	p = quic_put_var(p, 0);

	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, outq->max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_stream_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_streams_blocked_uni_create(struct sock *sk, void *data, u8 type)
{
	return 0;
}

static struct sk_buff *quic_frame_streams_blocked_bidi_create(struct sock *sk, void *data, u8 type)
{
	return 0;
}

static int quic_frame_crypto_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_token *ticket = quic_ticket(sk);
	u32 len, length, offset;
	u8 *p = skb->data;

	offset = quic_get_var(&p, &len);
	if (offset)
		return -EINVAL;
	length = quic_get_var(&p, &len);
	if (*p != 4) /* for TLS NEWSESSION_TICKET message only */
		return -EINVAL;

	ticket->len = length;
	kfree(ticket->data);
	ticket->data = kmemdup(p, ticket->len, GFP_ATOMIC);
	p += length;

	return p - skb->data;
}

static int quic_frame_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 stream_id, payload_len, len, hlen;
	struct sk_buff *nskb;
	u8 *p = skb->data;
	u64 offset = 0;
	int err;

	stream_id = quic_get_var(&p, &len);
	if (type & QUIC_STREAM_BIT_OFF)
		offset = quic_get_var(&p, &len);

	hlen = p - skb->data;
	if (type & QUIC_STREAM_BIT_LEN) {
		payload_len = quic_get_var(&p, &len);
		hlen += len;
	} else {
		payload_len = skb->len - hlen;
	}
	p += payload_len;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;
	skb_pull(nskb, hlen);
	skb_trim(nskb, payload_len);

	QUIC_RCV_CB(nskb)->stream_id = stream_id;
	QUIC_RCV_CB(nskb)->stream_fin = (type & QUIC_STREAM_BIT_FIN);
	QUIC_RCV_CB(nskb)->stream_offset = offset;

	err = quic_inq_reasm_tail(sk, nskb);
	if (err) {
		kfree_skb(nskb);
		return err;
	}

	return p - skb->data;
}

static int quic_frame_ack_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 largest, smallest, range, gap, delay, len, count, i;
	u8 *p = skb->data;

	largest = quic_get_var(&p, &len);
	delay = quic_get_var(&p, &len);
	count = quic_get_var(&p, &len);
	range = quic_get_var(&p, &len);

	smallest = largest - range;
	quic_outq_retransmit_check(sk, largest, smallest, largest, delay);

	for (i = 0; i < count; i++) {
		gap = quic_get_var(&p, &len);
		range = quic_get_var(&p, &len);
		largest = smallest - gap - 2;
		smallest = largest - range;
		quic_outq_retransmit_check(sk, largest, smallest, 0, 0);
	}

	if (type == QUIC_FRAME_ACK_ECN) { /* TODO */
		count = quic_get_var(&p, &len);
		count = quic_get_var(&p, &len);
		count = quic_get_var(&p, &len);
	}

	return p - skb->data;
}

static int quic_frame_new_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_connection_id_set *id_set;
	u8 *p = skb->data, *conn_id, *token;
	struct quic_new_connection_id nums;
	u32 seqno, len, prior;
	int err;

	seqno = quic_get_var(&p, &len);
	prior = quic_get_var(&p, &len);
	len = quic_get_var(&p, &len);
	conn_id = p;
	token = conn_id + len; /* TODO: Stateless Reset */
	p = token + 16;

	id_set = &quic_sk(sk)->dest;
	if (seqno != quic_connection_id_last_number(id_set) + 1 || prior > seqno)
		return -EINVAL;

	nums.prior = prior;
	nums.seqno = seqno;
	err = quic_connection_id_set(id_set, &nums, sk, conn_id, len);
	if (err)
		return err;

	return p - skb->data;
}

int quic_frame_new_connection_id_ack(struct sock *sk, struct sk_buff *skb)
{
	struct quic_connection_id_set *id_set;
	struct quic_new_connection_id nums;
	u8 *p = skb->data, *conn_id;
	u32 len;

	nums.seqno = quic_get_var(&p, &len);
	nums.prior = quic_get_var(&p, &len);
	len = quic_get_var(&p, &len);
	conn_id = p;

	id_set = &quic_sk(sk)->source;
	quic_connection_id_set(id_set, &nums, sk, conn_id, len);
	id_set->pending = 0;
	return 0;

}

static int quic_frame_retire_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_connection_id_set *id_set;
	struct quic_new_connection_id nums;
	struct sk_buff *nskb;
	u8 *p = skb->data;
	u32 seqno, len;

	seqno = quic_get_var(&p, &len);
	nums.prior = seqno;
	id_set = &quic_sk(sk)->source;
	nums.seqno = quic_connection_id_last_number(id_set);
	if (nums.prior > nums.seqno)
		return -EINVAL;

	id_set = &quic_sk(sk)->source;
	if (id_set->pending)
		return -EBUSY;

	nskb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &nums);
	if (!nskb)
		return -ENOMEM;
	quic_outq_data_tail(sk, nskb, true);
	id_set->pending = 1;
	return p - skb->data;
}

static int quic_frame_new_token_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_token *token = quic_token(sk);
	u8 *p = skb->data;
	u32 len;

	token->len = quic_get_var(&p, &len);
	kfree(token->data);
	token->data = kmemdup(p, token->len, GFP_ATOMIC);
	p += len;

	return p - skb->data;
}

static int quic_frame_handshake_done_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return 0; /* no content */
}

static int quic_frame_padding_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return skb->len;
}

static int quic_frame_ping_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return 0; /* no content */
}

static int quic_frame_path_challenge_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *fskb;
	u8 entropy[8], *p;

	memcpy(entropy, skb->data, sizeof(entropy));
	p = skb->data + sizeof(entropy);
	fskb = quic_frame_create(sk, QUIC_FRAME_PATH_RESPONSE, entropy);
	if (!fskb)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, fskb, true);
	return p - skb->data;
}

static int quic_frame_reset_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stop_sending_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p = skb->data;
	u64 max_bytes;
	u32 len;

	max_bytes = quic_get_var(&p, &len);
	if (max_bytes >= outq->max_bytes) {
		outq->max_bytes = max_bytes;
		outq->data_blocked = 0;
	}

	return p - skb->data;
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream *stream;
	u32 stream_id, len;
	u8 *p = skb->data;
	u64 max_bytes;

	stream_id = quic_get_var(&p, &len);
	max_bytes = quic_get_var(&p, &len);

	stream = quic_stream_find(quic_streams(sk), stream_id);
	if (!stream)
		return -EINVAL;
	if (max_bytes >= stream->send.max_bytes) {
		stream->send.max_bytes = max_bytes;
		stream->send.data_blocked = 0;
	}

	return p - skb->data;
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u8 *p = skb->data;
	u32 max, len;

	max = quic_get_var(&p, &len);
	quic_streams(sk)->send.max_streams_uni = max;

	return p - skb->data;
}

static int quic_frame_max_streams_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u8 *p = skb->data;
	u32 max, len;

	max = quic_get_var(&p, &len);
	quic_streams(sk)->send.max_streams_bidi = max;

	return p - skb->data;
}

static int quic_frame_connection_close_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 err_code, len, phrase_len;
	u8 *p = skb->data, ftype;

	err_code = quic_get_var(&p, &len);
	ftype = quic_get_var(&p, &len);
	phrase_len = quic_get_var(&p, &len);
	p += phrase_len;

	sk->sk_err = err_code;
	quic_set_state(sk, QUIC_STATE_USER_CLOSED);

	/*
	 * Now that state is QUIC_STATE_USER_CLOSED, we can wake the waiting
	 * recv thread up.
	 */
	sk->sk_state_change(sk);

	return p - skb->data;
}

static int quic_frame_connection_close_app_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 err_code, len, phrase_len;
	u8 *p = skb->data;

	err_code = quic_get_var(&p, &len);
	phrase_len = quic_get_var(&p, &len);
	p += phrase_len;

	sk->sk_err = err_code;
	quic_set_state(sk, QUIC_STATE_USER_CLOSED);

	/*
	 * Now that state is QUIC_STATE_USER_CLOSED, we can wake the waiting
	 * recv thread up.
	 */
	sk->sk_state_change(sk);

	return p - skb->data;
}

static int quic_frame_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u64 max_bytes, recv_max_bytes;
	struct sk_buff *fskb;
	u8 *p = skb->data;
	u32 len;

	max_bytes = quic_get_var(&p, &len);
	recv_max_bytes = inq->max_bytes;

	inq->max_bytes = inq->bytes + inq->window;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
	if (!fskb) {
		inq->max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, fskb, true);
	return p - skb->data;
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u64 max_bytes, recv_max_bytes;
	struct quic_stream *stream;
	struct sk_buff *fskb;
	u32 stream_id, len;
	u8 *p = skb->data;

	stream_id = quic_get_var(&p, &len);
	max_bytes = quic_get_var(&p, &len);

	stream = quic_stream_find(quic_streams(sk), stream_id);
	if (!stream)
		return -EINVAL;

	recv_max_bytes = stream->recv.max_bytes;
	stream->recv.max_bytes = stream->recv.bytes + stream->recv.window;
	if (recv_max_bytes != stream->recv.max_bytes) {
		fskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
		if (!fskb) {
			stream->recv.max_bytes = recv_max_bytes;
			return -ENOMEM;
		}
		quic_outq_ctrl_tail(sk, fskb, true);
	}
	return p - skb->data;
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_path_response_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_path_addr *path;
	u8 entropy[8], *p;

	memcpy(entropy, skb->data, sizeof(entropy));
	p = skb->data + sizeof(entropy);

	path = &qs->src; /* source address validation */
	if (!memcmp(path->entropy, entropy, sizeof(entropy))) {
		if (path->pending) {
			path->pending = 0;
			quic_udp_sock_put(qs->udp_sk[!path->active]);
			qs->udp_sk[!path->active] = NULL;
			memset(&path->addr[!path->active], 0, quic_addr_len(sk));
		}
	}
	path = &qs->dst; /* dest address validation */
	if (!memcmp(path->entropy, entropy, sizeof(entropy))) {
		if (path->pending) {
			path->pending = 0;
			memset(&path->addr[!path->active], 0, quic_addr_len(sk));
		}
	}
	return p - skb->data;
}

#define quic_frame_create_and_process(type) \
	{quic_frame_##type##_create, quic_frame_##type##_process}

static struct quic_frame_ops quic_frame_ops[QUIC_FRAME_BASE_MAX + 1] = {
	quic_frame_create_and_process(padding), /* 0x00 */
	quic_frame_create_and_process(ping),
	quic_frame_create_and_process(ack),
	quic_frame_create_and_process(ack), /* ack_ecn */
	quic_frame_create_and_process(reset_stream),
	quic_frame_create_and_process(stop_sending),
	quic_frame_create_and_process(crypto),
	quic_frame_create_and_process(new_token),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(max_data), /* 0x10 */
	quic_frame_create_and_process(max_stream_data),
	quic_frame_create_and_process(max_streams_bidi),
	quic_frame_create_and_process(max_streams_uni),
	quic_frame_create_and_process(data_blocked),
	quic_frame_create_and_process(stream_data_blocked),
	quic_frame_create_and_process(streams_blocked_bidi),
	quic_frame_create_and_process(streams_blocked_uni),
	quic_frame_create_and_process(new_connection_id),
	quic_frame_create_and_process(retire_connection_id),
	quic_frame_create_and_process(path_challenge),
	quic_frame_create_and_process(path_response),
	quic_frame_create_and_process(connection_close),
	quic_frame_create_and_process(connection_close_app),
	quic_frame_create_and_process(handshake_done),
};

int quic_frame_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	int err, len;
	u8 type, *p;

	while (1) {
		p = skb->data;
		type = quic_get_var(&p, &len);
		skb_pull(skb, len);

		if (type > QUIC_FRAME_BASE_MAX) {
			pr_err_once("[QUIC] frame err: unsupported frame %x\n", type);
			return -EPROTONOSUPPORT;
		}
		pr_debug("[QUIC] frame process %x %u\n", type, len);
		err = quic_frame_ops[type].frame_process(sk, skb, type);
		if (err < 0) {
			pr_warn("[QUIC] frame err %x %d\n", type, err);
			return err;
		}
		if (quic_frame_ack_eliciting(type)) {
			quic_packet_set_ack_eliciting(packet);
			if (quic_frame_ack_immediate(type))
				quic_packet_set_ack_immediate(packet);
		}
		if (quic_frame_non_probing(type))
			quic_packet_set_non_probing(packet);

		skb_pull(skb, err);
		if (skb->len <= 0)
			break;
	}
	return 0;
}

struct sk_buff *quic_frame_create(struct sock *sk, u8 type, void *data)
{
	struct sk_buff *skb;

	if (type > QUIC_FRAME_BASE_MAX)
		return NULL;
	pr_debug("[QUIC] frame create %u\n", type);
	skb = quic_frame_ops[type].frame_create(sk, data, type);
	if (!skb) {
		pr_err("[QUIC] frame create failed %x\n", type);
		return NULL;
	}
	QUIC_SND_CB(skb)->frame_type = type;
	return skb;
}
