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
 *    Adrian Moeller (modified for HyQUIC)
 */

#include "socket.h"
#include "frame.h"
#include <net/inet_common.h>
#include <net/sock_reuseport.h>
#include <linux/version.h>
#include <net/tls.h>

static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

bool quic_request_sock_exists(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->sa, packet->sa, quic_addr_len(sk)) &&
		    !memcmp(&req->da, packet->da, quic_addr_len(sk)))
			return true;
	}
	return false;
}

int quic_request_sock_enqueue(struct sock *sk, struct quic_connection_id *odcid, u8 retry)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk))
		return -ENOMEM;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->version = packet->version;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->da = packet->daddr;
	req->sa = packet->saddr;
	req->retry = retry;

	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return 0;
}

struct quic_request_sock *quic_request_sock_dequeue(struct sock *sk)
{
	struct quic_request_sock *req;

	req = list_first_entry(quic_reqs(sk), struct quic_request_sock, list);

	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	return req;
}

int quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sock *nsk;
	int ret = 0;

	local_bh_disable();
	nsk = quic_sock_lookup(skb, packet->sa, packet->da);
	if (nsk == sk)
		goto out;
	/* the request sock was just accepted */
	bh_lock_sock(nsk);
	if (sock_owned_by_user(nsk)) {
		if (sk_add_backlog(nsk, skb, READ_ONCE(nsk->sk_rcvbuf)))
			kfree_skb(skb);
	} else {
		sk->sk_backlog_rcv(nsk, skb);
	}
	bh_unlock_sock(nsk);
	ret = 1;
out:
	local_bh_enable();
	return ret;
}

static bool quic_has_bind_any(struct sock *sk)
{
	union quic_addr *sa, a = {};

	sa = quic_path_addr(quic_src(sk), 0);
	a.v4.sin_family = sa->v4.sin_family;
	a.v4.sin_port = sa->v4.sin_port;

	return quic_cmp_sk_addr(sk, sa, &a);
}

struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da)
{
	struct net *net = dev_net(skb->dev);
	struct quic_data alpns = {}, alpn;
	struct sock *sk = NULL, *tmp;
	struct quic_hash_head *head;
	u64 length;
	u32 len;
	u8 *p;

	/* Search for regular socket first */
	head = quic_sock_head(net, sa, da);
	spin_lock(&head->lock);
	sk_for_each(tmp, &head->head) {
		if (net == sock_net(tmp) &&
		    !quic_path_cmp(quic_src(tmp), 0, sa) &&
		    !quic_path_cmp(quic_dst(tmp), 0, da)) {
			sk = tmp;
			break;
		}
	}
	spin_unlock(&head->lock);
	if (sk)
		return sk;

	if (quic_packet_parse_alpn(skb, &alpns) < 0)
		return NULL;

	/* Search for listen socket */
	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock(&head->lock);

	if (!alpns.len) {
		sk_for_each(tmp, &head->head) {
			/* alpns.data != NULL means TLS parse succeed but no ALPN was found,
			 * in such case it only matches the sock with no ALPN set.
			 */
			if (net == sock_net(tmp) && quic_is_listen(tmp) &&
			    quic_cmp_sk_addr(tmp, quic_path_addr(quic_src(tmp), 0), sa) &&
			    (!alpns.data || !quic_alpn(tmp)->len)) {
				sk = tmp;
				if (!quic_has_bind_any(sk))
					break;
			}
		}
		goto unlock;
	}

	for (p = alpns.data, len = alpns.len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_for_each(tmp, &head->head) {
			if (net == sock_net(tmp) && quic_is_listen(tmp) &&
			    quic_cmp_sk_addr(tmp, quic_path_addr(quic_src(tmp), 0), sa) &&
			    quic_data_has(quic_alpn(tmp), &alpn)) {
				sk = tmp;
				if (!quic_has_bind_any(sk))
					break;
			}
		}
		if (sk)
			break;
	}
unlock:
	spin_unlock(&head->lock);

	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_shash(net, da), skb, 1);
	return sk;
}

static void quic_write_space(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND);
	rcu_read_unlock();
}

static void quic_transport_param_init(struct sock *sk)
{
	struct quic_transport_param *param = quic_local(sk);

	param->max_udp_payload_size = QUIC_MAX_UDP_PAYLOAD;
	param->ack_delay_exponent = QUIC_DEF_ACK_DELAY_EXPONENT;
	param->max_ack_delay = QUIC_DEF_ACK_DELAY;
	param->active_connection_id_limit = QUIC_CONNECTION_ID_LIMIT;
	param->max_idle_timeout = QUIC_DEF_IDLE_TIMEOUT;
	param->max_data = QUIC_PATH_MAX_PMTU * 32;
	param->max_stream_data_bidi_local = QUIC_PATH_MAX_PMTU * 4;
	param->max_stream_data_bidi_remote = QUIC_PATH_MAX_PMTU * 4;
	param->max_stream_data_uni = QUIC_PATH_MAX_PMTU * 4;
	param->max_streams_bidi = QUIC_DEF_STREAMS;
	param->max_streams_uni = QUIC_DEF_STREAMS;
	param->initial_smoothed_rtt = QUIC_RTT_INIT;
	param->version = QUIC_VERSION_V1;

	quic_inq_set_param(sk, param);
	quic_cong_set_param(quic_cong(sk), param);
	quic_connection_id_set_param(quic_dest(sk), param);
	quic_stream_set_param(quic_streams(sk), param, NULL);
}

static int quic_init_sock(struct sock *sk)
{
	u8 len, i;

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_set_af_ops(sk, quic_af_ops_get(sk->sk_family));
	quic_connection_id_set_init(quic_source(sk), 1);
	quic_connection_id_set_init(quic_dest(sk), 0);

	len = quic_addr_len(sk);
	quic_path_addr_init(quic_src(sk), len, 1);
	quic_path_addr_init(quic_dst(sk), len, 0);

	quic_transport_param_init(sk);

	quic_outq_init(sk);
	quic_inq_init(sk);
	quic_packet_init(sk);
	quic_timer_init(sk);

	for (i = 0; i < QUIC_PNMAP_MAX; i++) {
		if (quic_pnmap_init(quic_pnmap(sk, i)))
			return -ENOMEM;
	}
	if (quic_stream_init(quic_streams(sk)))
		return -ENOMEM;
	INIT_LIST_HEAD(quic_reqs(sk));

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

	if (hyquic_init(quic_hyquic(sk), sk))
		return -ENOMEM;

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	u8 i;

	for (i = 0; i < QUIC_PNMAP_MAX; i++)
		quic_pnmap_free(quic_pnmap(sk, i));
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_destroy(quic_crypto(sk, i));

	quic_timer_free(sk);
	quic_stream_free(quic_streams(sk));

	kfree(quic_token(sk)->data);
	kfree(quic_ticket(sk)->data);
	kfree(quic_alpn(sk)->data);

	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();

	hyquic_free(quic_hyquic(sk));
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_path_addr *path = quic_src(sk);
	union quic_addr *a;
	int err = 0;

	lock_sock(sk);

	a = quic_path_addr(path, 0);
	if (a->v4.sin_port || addr_len < quic_addr_len(sk) ||
	    addr->sa_family != sk->sk_family || !quic_addr(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}

	quic_path_addr_set(path, quic_addr(addr), 0);
	err = quic_path_set_bind_port(sk, path, 0);
	if (err) {
		quic_path_addr_free(sk, path, 0);
		goto out;
	}
	err = quic_path_set_udp_sock(sk, path, 0);
	if (err) {
		quic_path_addr_free(sk, path, 0);
		goto out;
	}
	quic_set_sk_addr(sk, a, true);

out:
	release_sock(sk);
	return err;
}

static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_connection_id_set *source = quic_source(sk);
	struct quic_connection_id_set *dest = quic_dest(sk);
	struct quic_path_addr *path = quic_src(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_id conn_id, *active;
	struct quic_inqueue *inq = quic_inq(sk);
	union quic_addr *sa;
	int err = -EINVAL;

	lock_sock(sk);
	if (!quic_is_closed(sk) || addr_len < quic_addr_len(sk))
		goto out;

	quic_path_addr_set(quic_dst(sk), quic_addr(addr), 0);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, quic_addr(addr), false);
	sa = quic_path_addr(path, 0);
	if (!sa->v4.sin_port) { /* auto bind */
		err = quic_path_set_bind_port(sk, path, 0);
		if (err) {
			quic_path_addr_free(sk, path, 0);
			goto out;
		}
		err = quic_path_set_udp_sock(sk, path, 0);
		if (err) {
			quic_path_addr_free(sk, path, 0);
			goto out;
		}
		quic_set_sk_addr(sk, sa, true);
	}

	quic_connection_id_generate(&conn_id);
	err = quic_connection_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto out;
	quic_outq_set_orig_dcid(outq, &conn_id);
	quic_connection_id_generate(&conn_id);
	err = quic_connection_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
	active = quic_connection_id_active(dest);
	err = quic_crypto_initial_keys_install(crypto, active, quic_inq_version(inq), 0, 0);
	if (err)
		goto free;

	quic_set_state(sk, QUIC_SS_ESTABLISHING);
out:
	release_sock(sk);
	return err;
free:
	quic_connection_id_set_free(dest);
	quic_connection_id_set_free(source);
	sk->sk_prot->unhash(sk);
	goto out;
}

static int quic_hash(struct sock *sk)
{
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;

	sa = quic_path_addr(quic_src(sk), 0);
	da = quic_path_addr(quic_dst(sk), 0);
	if (!quic_is_listen(sk)) {
		head = quic_sock_head(net, sa, da);
		spin_lock(&head->lock);

		sk_for_each(nsk, &head->head) {
			if (net == sock_net(nsk) &&
			    !quic_path_cmp(quic_src(nsk), 0, sa) &&
			    !quic_path_cmp(quic_dst(nsk), 0, da)) {
				spin_unlock(&head->lock);
				return -EADDRINUSE;
			}
		}
		__sk_add_node(sk, &head->head);

		spin_unlock(&head->lock);
		return 0;
	}

	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock(&head->lock);

	any = quic_has_bind_any(sk);
	sk_for_each(nsk, &head->head) {
		if (net == sock_net(nsk) && quic_is_listen(nsk) &&
		    !quic_path_cmp(quic_src(nsk), 0, sa)) {
			if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				if (sk->sk_reuseport && nsk->sk_reuseport) {
					err = reuseport_add_sock(sk, nsk, any);
					if (!err)
						__sk_add_node(sk, &head->head);
				}
				goto out;
			}
			if (quic_data_match(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				goto out;
			}
		}
	}

	if (sk->sk_reuseport) {
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	__sk_add_node(sk, &head->head);
out:
	spin_unlock(&head->lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_addr(quic_src(sk), 0);
	da = quic_path_addr(quic_dst(sk), 0);
	if (quic_is_listen(sk)) {
		head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
		goto out;
	}
	head = quic_sock_head(net, sa, da);

out:
	spin_lock(&head->lock);
	__sk_del_node_init(sk);
	spin_unlock(&head->lock);
}

static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg, struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo, bool *has_hinfo, bool *has_sinfo)
{
	struct quic_handshake_info *i = NULL;
	struct quic_stream_info *s = NULL;
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;
	u64 active;
	bool has_hyquic_info = false;
	int err;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != IPPROTO_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_HANDSHAKE_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*i)))
				return -EINVAL;
			i = CMSG_DATA(cmsg);
			hinfo->crypto_level = i->crypto_level;
			*has_hinfo = true;
			break;
		case QUIC_STREAM_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*s)))
				return -EINVAL;
			s = CMSG_DATA(cmsg);
			sinfo->stream_id = s->stream_id;
			sinfo->stream_flag = s->stream_flag;
			*has_sinfo = true;
			break;
		case HYQUIC_INFO:
			if (!quic_hyquic(sk)->enabled)
				return -EINVAL;
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct hyquic_ctrlsend_info)))
				return -EINVAL;
			err = hyquic_process_usrquic_data(sk, &msg->msg_iter, CMSG_DATA(cmsg));
			if (err)
				return err;
			has_hyquic_info = true;
			break;
		default:
			return -EINVAL;
		}
	}
	if (i || has_hyquic_info)
		return 0;

	if (!s) { /* stream info is not set, try to use msg_flags*/
		if (msg->msg_flags & MSG_SYN)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_NEW;
		if (msg->msg_flags & MSG_FIN)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_FIN;
		if (msg->msg_flags & MSG_STREAM_UNI)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_UNI;
		if (msg->msg_flags & MSG_DONTWAIT)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_ASYNC;
		if (msg->msg_flags & MSG_DATAGRAM)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_DATAGRAM;
		sinfo->stream_id = -1;
		*has_sinfo = true;
	}

	if (sinfo->stream_id != -1)
		return 0;

	streams = quic_streams(sk);
	active = quic_stream_send_active(streams);
	if (active != -1) {
		sinfo->stream_id = active;
		return 0;
	}
	sinfo->stream_id = (quic_stream_send_bidi(streams) << 2);
	if (sinfo->stream_flag & QUIC_STREAM_FLAG_UNI) {
		sinfo->stream_id = (quic_stream_send_uni(streams) << 2);
		sinfo->stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
	}
	sinfo->stream_id |= quic_is_serv(sk);
	return 0;
}

static int quic_wait_for_send(struct sock *sk, u64 stream_id, long timeo, u32 msg_len)
{
	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			goto out;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			pr_warn("wait sndbuf sk_err %d\n", err);
			goto out;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto out;
		}
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_warn("wait sndbuf closed %d\n", err);
			goto out;
		}

		if (stream_id) {
			if (!quic_stream_id_send_exceeds(quic_streams(sk), stream_id))
				goto out;
		} else {
			if ((int)msg_len <= sk_stream_wspace(sk) &&
			    sk_wmem_schedule(sk, msg_len))
				goto out;
		}

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

int hyquic_wait_for_send(struct sock *sk, u64 stream_id, long timeo, u32 msg_len)
{
	return quic_wait_for_send(sk, stream_id, timeo, msg_len);
}

static struct quic_stream *quic_sock_send_stream(struct sock *sk, struct quic_stream_info *sinfo)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	u8 type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	struct quic_stream *stream;
	struct sk_buff *skb;
	long timeo;
	int err;

	stream = quic_stream_send_get(streams, sinfo->stream_id,
				      sinfo->stream_flag, quic_is_serv(sk));
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL);
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	/* 0rtt data should return err if stream is not found */
	if (!quic_crypto_send_ready(crypto))
		return ERR_PTR(-EINVAL);

	if (sinfo->stream_id & QUIC_STREAM_TYPE_UNI_MASK)
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;

	skb = quic_frame_create(sk, type, &sinfo->stream_id);
	if (!skb)
		return ERR_PTR(-ENOMEM);
	quic_outq_ctrl_tail(sk, skb, false);

	timeo = sock_sndtimeo(sk, sinfo->stream_flag & QUIC_STREAM_FLAG_ASYNC);
	err = quic_wait_for_send(sk, sinfo->stream_id, timeo, 0);
	if (err)
		return ERR_PTR(err);

	return quic_stream_send_get(streams, sinfo->stream_id,
				    sinfo->stream_flag, quic_is_serv(sk));
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_msginfo msginfo;
	struct quic_crypto *crypto;
	struct quic_stream *stream;
	bool has_hinfo = false, has_sinfo = false;
	struct sk_buff *skb;
	int err = 0;
	long timeo;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &hinfo, &sinfo, &has_hinfo, &has_sinfo);
	if (err)
		goto err;

	if (has_hinfo) {
		if (hinfo.crypto_level >= QUIC_CRYPTO_MAX) {
			err = -EINVAL;
			goto err;
		}
		crypto = quic_crypto(sk, hinfo.crypto_level);
		if (!quic_crypto_send_ready(crypto)) {
			err = -EINVAL;
			goto err;
		}
		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		while (iov_iter_count(&msg->msg_iter) > 0) {
			skb = quic_frame_create(sk, QUIC_FRAME_CRYPTO, &msginfo);
			if (!skb)
				goto out;
			quic_outq_ctrl_tail(sk, skb, true);
		}
		goto out;
	}

	if (!has_sinfo)
		goto out;

	if (sinfo.stream_flag & QUIC_STREAM_FLAG_DATAGRAM) {
		if (!quic_outq_max_dgram(quic_outq(sk))) {
			err = -EINVAL;
			goto err;
		}
		if (sk_stream_wspace(sk) <= 0 || !sk_wmem_schedule(sk, msg_len)) {
			timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
			err = quic_wait_for_send(sk, 0, timeo, msg_len);
			if (err)
				goto err;
		}
		while (iov_iter_count(&msg->msg_iter) > 0) {
			skb = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN, &msg->msg_iter);
			if (!skb)
				goto out;
			quic_outq_dgram_tail(sk, skb, true);
		}
		goto out;
	}

	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto err;
	}

	if (sk_stream_wspace(sk) <= 0 || !sk_wmem_schedule(sk, msg_len)) {
		timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
		err = quic_wait_for_send(sk, 0, timeo, msg_len);
		if (err)
			goto err;
	}

	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flag = sinfo.stream_flag;

	while (iov_iter_count(msginfo.msg) > 0) {
		skb = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo);
		if (!skb)
			goto out;
		quic_outq_stream_tail(sk, skb, true);
	}
out:
	err = msg_len - iov_iter_count(&msg->msg_iter);
	if (!(msg->msg_flags & MSG_MORE) && err)
		quic_outq_transmit(sk);
err:
	release_sock(sk);
	return err;
}

static int quic_wait_for_packet(struct sock *sk, long timeo)
{
	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		if (!skb_queue_empty(&sk->sk_receive_queue))
			goto out;

		err = sk->sk_err;
		if (err) {
			pr_warn("wait rcv pkt sk_err %d\n", err);
			goto out;
		}

		err = -ENOTCONN;
		if (quic_is_closed(sk))
			goto out;

		err = -EAGAIN;
		if (!timeo)
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

#if KERNEL_VERSION(5, 18, 0) >= LINUX_VERSION_CODE
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
			int flags, int *addr_len)
{
#else
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
			int *addr_len)
{
	int nonblock = flags & MSG_DONTWAIT;
#endif
	struct quic_handshake_info hinfo = {};
	int err, copy, copied = 0, freed = 0;
	struct quic_stream_info sinfo = {};
	int fin, off, event, dgram, level;
	struct hyquic_ctrlrecv_info hyquic_data_info = {};
	struct hyquic_rcv_cb *hyquic_rcv_cb;
	struct quic_rcv_cb *rcv_cb;
	struct quic_stream *stream;
	struct quic_inqueue *inq;
	struct sk_buff *skb;
	long timeo;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, nonblock);
	err = quic_wait_for_packet(sk, timeo);
	if (err)
		goto out;

	skb = skb_peek(&sk->sk_receive_queue);
	rcv_cb = QUIC_RCV_CB(skb);
	hyquic_rcv_cb = HYQUIC_RCV_CB(skb);
	stream = rcv_cb->stream;
	do {
		off = rcv_cb->read_offset;
		copy = min_t(int, skb->len - off, len - copied);
		err = skb_copy_datagram_msg(skb, off, msg, copy);
		if (err) {
			if (!copied)
				goto out;
			break;
		}
		copied += copy;
		fin = rcv_cb->stream_fin;
		event = rcv_cb->event;
		dgram = rcv_cb->dgram;
		level = rcv_cb->level;
		if (event) {
			msg->msg_flags |= MSG_NOTIFICATION;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_NOTIFICATION;
		} else if (dgram) {
			msg->msg_flags |= MSG_DATAGRAM;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_DATAGRAM;
		} else if (!stream) {
			if (hyquic_rcv_cb->hyquic_ctrl_type) {
				hyquic_data_info.type = hyquic_rcv_cb->hyquic_ctrl_type;
				hyquic_data_info.details = hyquic_rcv_cb->hyquic_ctrl_details;
				hyquic_data_info.data_length = skb->len;
			} else {
				hinfo.crypto_level = level;
				put_cmsg(msg, IPPROTO_QUIC, QUIC_HANDSHAKE_INFO, sizeof(hinfo), &hinfo);
			}
		}
		if (flags & MSG_PEEK)
			break;
		if (copy != skb->len - off) {
			rcv_cb->read_offset += copy;
			if (hyquic_data_info.type)
				hyquic_data_info.incompl = true;
			break;
		}
		if (event) {
			inq = quic_inq(sk);
			if (skb == quic_inq_last_event(inq))
				quic_inq_set_last_event(inq, NULL); /* no more event on list */
			if (event == QUIC_EVENT_STREAM_UPDATE &&
			    stream->recv.state == QUIC_STREAM_RECV_STATE_RESET_RECVD)
				stream->recv.state = QUIC_STREAM_RECV_STATE_RESET_READ;
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		} else if (dgram) {
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		} else if (!stream) {
			skb = __skb_dequeue(&sk->sk_receive_queue);
			if (hyquic_rcv_cb->hyquic_ctrl_type == HYQUIC_CTRL_USER_PARSED_FRAMES) {
				__skb_queue_tail(&quic_hyquic(sk)->unkwn_frames_var_deferred, skb);
				break;
			}
			if (hyquic_rcv_cb->hyquic_ctrl_type == HYQUIC_CTRL_FRAMES)
				freed += hyquic_rcv_cb->hyquic_ctrl_details.raw_frames_fix.payload;

			kfree_skb(skb);
			break;
		}
		freed += skb->len;
		kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
		if (fin) {
			stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			break;
		}

		skb = skb_peek(&sk->sk_receive_queue);
		if (!skb)
			break;
		rcv_cb = QUIC_RCV_CB(skb);
		if (rcv_cb->event || rcv_cb->dgram ||
		    !rcv_cb->stream || rcv_cb->stream->id != stream->id)
			break;
	} while (copied < len);

	if (!event && stream) {
		sinfo.stream_id = stream->id;
		quic_inq_flow_control(sk, stream, freed);
	} else {
		hyquic_inq_flow_control(sk, freed);
	}
	if (event || stream)
		put_cmsg(msg, IPPROTO_QUIC, QUIC_STREAM_INFO, sizeof(sinfo), &sinfo);
	if (hyquic_data_info.type)
		put_cmsg(msg, IPPROTO_QUIC, HYQUIC_INFO, sizeof(hyquic_data_info), &hyquic_data_info);
	err = copied;
out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_accept(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (list_empty(quic_reqs(sk))) {
			release_sock(sk);
			timeo = schedule_timeout(timeo);
			lock_sock(sk);
		}

		if (!quic_is_listen(sk)) {
			err = -EINVAL;
			break;
		}

		if (!list_empty(quic_reqs(sk))) {
			err = 0;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		if (!timeo) {
			err = -EAGAIN;
			break;
		}
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_param_check_and_copy(struct quic_transport_param *p,
				     struct quic_transport_param *param)
{
	if (p->max_udp_payload_size) {
		if (p->max_udp_payload_size < QUIC_MIN_UDP_PAYLOAD ||
		    p->max_udp_payload_size > QUIC_MAX_UDP_PAYLOAD)
			return -EINVAL;
		param->max_udp_payload_size = p->max_udp_payload_size;
	}
	if (p->ack_delay_exponent) {
		if (p->ack_delay_exponent > QUIC_MAX_ACK_DELAY_EXPONENT)
			return -EINVAL;
		param->ack_delay_exponent = p->ack_delay_exponent;
	}
	if (p->max_ack_delay) {
		if (p->max_ack_delay >= QUIC_MAX_ACK_DELAY)
			return -EINVAL;
		param->max_ack_delay = p->max_ack_delay;
	}
	if (p->active_connection_id_limit) {
		if (p->active_connection_id_limit > QUIC_CONNECTION_ID_LIMIT)
			return -EINVAL;
		param->active_connection_id_limit = p->active_connection_id_limit;
	}
	if (p->max_idle_timeout) {
		if (p->max_idle_timeout < QUIC_MIN_IDLE_TIMEOUT)
			return -EINVAL;
		param->max_idle_timeout = p->max_idle_timeout;
	}
	if (p->max_datagram_frame_size) {
		if (p->max_datagram_frame_size < QUIC_MIN_UDP_PAYLOAD ||
		    p->max_datagram_frame_size > QUIC_MAX_UDP_PAYLOAD)
			return -EINVAL;
		param->max_datagram_frame_size = p->max_datagram_frame_size;
	}
	if (p->max_data) {
		if (p->max_data < QUIC_PATH_MAX_PMTU * 2)
			return -EINVAL;
		param->max_data = p->max_data;
	}
	if (p->max_stream_data_bidi_local) {
		if (p->max_stream_data_bidi_local > param->max_data)
			return -EINVAL;
		param->max_stream_data_bidi_local = p->max_stream_data_bidi_local;
	}
	if (p->max_stream_data_bidi_remote) {
		if (p->max_stream_data_bidi_remote > param->max_data)
			return -EINVAL;
		param->max_stream_data_bidi_remote = p->max_stream_data_bidi_remote;
	}
	if (p->max_stream_data_uni) {
		if (p->max_stream_data_uni > param->max_data)
			return -EINVAL;
		param->max_stream_data_uni = p->max_stream_data_uni;
	}
	if (p->max_streams_bidi) {
		if (p->max_streams_bidi > QUIC_MAX_STREAMS)
			return -EINVAL;
		param->max_streams_bidi = p->max_streams_bidi;
	}
	if (p->max_streams_uni) {
		if (p->max_streams_uni > QUIC_MAX_STREAMS)
			return -EINVAL;
		param->max_streams_uni = p->max_streams_uni;
	}
	if (p->initial_smoothed_rtt) {
		if (p->initial_smoothed_rtt < QUIC_RTO_MIN ||
		    p->initial_smoothed_rtt > QUIC_RTO_MAX)
			return -EINVAL;
		param->initial_smoothed_rtt = p->initial_smoothed_rtt;
	}
	if (p->plpmtud_probe_timeout) {
		if (p->plpmtud_probe_timeout < QUIC_MIN_PROBE_TIMEOUT)
			return -EINVAL;
		param->plpmtud_probe_timeout = p->plpmtud_probe_timeout;
	}
	if (p->disable_active_migration)
		param->disable_active_migration = p->disable_active_migration;
	if (p->disable_1rtt_encryption)
		param->disable_1rtt_encryption = p->disable_1rtt_encryption;
	if (p->validate_peer_address)
		param->validate_peer_address = p->validate_peer_address;
	if (p->grease_quic_bit)
		param->grease_quic_bit = p->grease_quic_bit;
	if (p->stateless_reset)
		param->stateless_reset = p->stateless_reset;
	if (p->receive_session_ticket)
		param->receive_session_ticket = p->receive_session_ticket;
	if (p->certificate_request) {
		if (p->certificate_request > 3)
			return -EINVAL;
		param->certificate_request = p->certificate_request;
	}
	if (p->payload_cipher_type) {
		if (p->payload_cipher_type != TLS_CIPHER_AES_GCM_128 &&
		    p->payload_cipher_type != TLS_CIPHER_AES_GCM_256 &&
		    p->payload_cipher_type != TLS_CIPHER_AES_CCM_128 &&
		    p->payload_cipher_type != TLS_CIPHER_CHACHA20_POLY1305)
			return -EINVAL;
		param->payload_cipher_type = p->payload_cipher_type;
	}
	if (p->version)
		param->version = p->version;
	return 0;
}

static int quic_sock_set_transport_param(struct sock *sk, struct quic_transport_param *p, u32 len)
{
	struct quic_transport_param *param = quic_local(sk);

	if (len < sizeof(*param) || quic_is_established(sk))
		return -EINVAL;

	if (p->remote)
		param = quic_remote(sk);

	if (quic_param_check_and_copy(p, param))
		return -EINVAL;

	if (p->remote) {
		param->remote = 1;
		quic_outq_set_param(sk, param);
		quic_connection_id_set_param(quic_source(sk), param);
		quic_stream_set_param(quic_streams(sk), NULL, param);
		return 0;
	}

	quic_inq_set_param(sk, param);
	quic_cong_set_param(quic_cong(sk), param);
	quic_connection_id_set_param(quic_dest(sk), param);
	quic_stream_set_param(quic_streams(sk), param, NULL);
	return 0;
}

static int quic_copy_sock(struct sock *nsk, struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_transport_param *param = quic_local(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff *skb, *tmp;
	union quic_addr sa, da;
	u32 events, type;

	if (quic_data_dup(quic_alpn(nsk), quic_alpn(sk)->data, quic_alpn(sk)->len))
		return -ENOMEM;

	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;

	inet_sk(nsk)->pmtudisc = inet_sk(sk)->pmtudisc;

	skb_queue_walk_safe(quic_inq_backlog_list(inq), skb, tmp) {
		quic_get_msg_addr(nsk, &da, skb, 0);
		quic_get_msg_addr(nsk, &sa, skb, 1);

		if (!memcmp(&req->sa, &da, quic_addr_len(nsk)) &&
		    !memcmp(&req->da, &sa, quic_addr_len(nsk))) {
			__skb_unlink(skb, quic_inq_backlog_list(inq));
			quic_inq_backlog_tail(nsk, skb);
		}
	}

	if (sk->sk_family == AF_INET6) /* nsk uses quicv6 ops in this case */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	quic_sock_set_transport_param(nsk, param, sizeof(*param));
	events = quic_inq_events(inq);
	inq = quic_inq(nsk);
	quic_inq_set_events(inq, events);

	type = quic_crypto_cipher_type(crypto);
	crypto = quic_crypto(nsk, QUIC_CRYPTO_APP);
	quic_crypto_set_cipher_type(crypto, type);

	return 0;
}

static int quic_accept_sock_init(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_connection_id conn_id;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	int err;

	lock_sock(sk);
	quic_path_addr_set(quic_dst(sk), &req->da, 0);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, quic_addr(&req->da.sa), false);

	quic_connection_id_generate(&conn_id);
	err = quic_connection_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	quic_inq_set_version(inq, req->version);
	err = quic_connection_id_add(quic_dest(sk), &req->scid, 0, NULL);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version, 0, 1);
	if (err)
		goto out;

	quic_outq_set_serv(outq);
	quic_outq_set_orig_dcid(outq, &req->orig_dcid);
	if (req->retry) {
		quic_outq_set_retry(outq, 1);
		quic_outq_set_retry_dcid(outq, &req->dcid);
	}
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);

	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(quic_inq_backlog_list(inq), &tmpq);
	skb = __skb_dequeue(&tmpq);
	while (skb) {
		quic_packet_process(sk, skb);
		skb = __skb_dequeue(&tmpq);
	}

out:
	release_sock(sk);
	return err;
}

static struct sock *quic_accept(struct sock *sk, int flags, int *errp, bool kern)
{
	struct quic_request_sock *req = NULL;
	struct sock *nsk = NULL;
	int err = -EINVAL;
	long timeo;

	lock_sock(sk);

	if (!quic_is_listen(sk))
		goto out;

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	err = quic_wait_for_accept(sk, timeo);
	if (err)
		goto out;
	req = quic_request_sock_dequeue(sk);

	nsk = sk_alloc(sock_net(sk), req->sa.v4.sin_family, GFP_KERNEL, sk->sk_prot, kern);
	if (!nsk) {
		err = -ENOMEM;
		goto out;
	}
	sock_init_data(NULL, nsk);
	err = nsk->sk_prot->init(nsk);
	if (err)
		goto free;

	err = quic_copy_sock(nsk, sk, req);
	if (err)
		goto free;
	err = nsk->sk_prot->bind(nsk, &req->sa.sa, quic_addr_len(nsk));
	if (err)
		goto free;

	err = quic_accept_sock_init(nsk, req);
	if (err)
		goto free;
out:
	release_sock(sk);
	*errp = err;
	kfree(req);
	return nsk;
free:
	nsk->sk_prot->close(nsk, 0);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

	quic_outq_transmit_app_close(sk);

	quic_set_state(sk, QUIC_SS_CLOSED);

	quic_outq_free(sk);
	quic_inq_free(sk);

	quic_path_free(sk, quic_src(sk));
	quic_path_free(sk, quic_dst(sk));

	quic_connection_id_set_free(quic_source(sk));
	quic_connection_id_set_free(quic_dest(sk));

	release_sock(sk);
	sk_common_release(sk);
}

int quic_sock_change_daddr(struct sock *sk, union quic_addr *addr, u32 len)
{
	struct quic_path_addr *path = quic_dst(sk);
	u8 cnt = quic_path_sent_cnt(path);
	struct sk_buff *skb;

	if (cnt)
		return -EINVAL;
	quic_path_swap_active(path);

	if (!addr) {
		quic_outq_set_pref_addr(quic_outq(sk), 0);
		goto out;
	}
	quic_path_addr_set(path, addr, 1);

out:
	quic_set_sk_ecn(sk, 0); /* clear ecn during path migration */
	skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
	if (skb)
		quic_outq_ctrl_tail(sk, skb, false);

	quic_path_pl_reset(path);
	quic_path_set_sent_cnt(path, cnt + 1);
	quic_timer_reset(sk, QUIC_TIMER_PATH, quic_cong_rto(quic_cong(sk)) * 3);
	return 0;
}

int quic_sock_change_saddr(struct sock *sk, union quic_addr *addr, u32 len)
{
	struct quic_connection_id_set *id_set = quic_source(sk);
	struct quic_path_addr *path = quic_src(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u8 cnt = quic_path_sent_cnt(path);
	struct sk_buff *skb;
	u64 number;
	int err;

	if (cnt)
		return -EINVAL;

	if (!addr) {
		quic_outq_set_pref_addr(outq, 0);
		goto out;
	}

	if (len != quic_addr_len(sk) ||
	    quic_addr_family(sk) != addr->sa.sa_family)
		return -EINVAL;

	if (!quic_is_established(sk)) { /* set preferred address param */
		if (!quic_is_serv(sk))
			return -EINVAL;
		quic_outq_set_pref_addr(outq, 1);
		quic_path_addr_set(path, addr, 1);
		return 0;
	}

	if (quic_connection_id_disable_active_migration(id_set))
		return -EINVAL;

	quic_path_addr_set(path, addr, 1);
	err = quic_path_set_bind_port(sk, path, 1);
	if (err)
		goto err;
	err = quic_path_set_udp_sock(sk, path, 1);
	if (err)
		goto err;

	number = quic_connection_id_first_number(quic_source(sk)) + 1;
	skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &number);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}
	QUIC_SND_CB(skb)->path_alt = QUIC_PATH_ALT_SRC;
	quic_outq_ctrl_tail(sk, skb, true);

out:
	quic_set_sk_ecn(sk, 0); /* clear ecn during path migration */
	skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
	if (skb) {
		QUIC_SND_CB(skb)->path_alt = QUIC_PATH_ALT_SRC;
		quic_outq_ctrl_tail(sk, skb, false);
	}

	quic_path_pl_reset(quic_dst(sk));
	quic_path_set_sent_cnt(path, cnt + 1);
	quic_timer_reset(sk, QUIC_TIMER_PATH, quic_cong_rto(quic_cong(sk)) * 3);
	return 0;
err:
	quic_path_addr_free(sk, path, 1);
	return err;
}

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	struct sk_buff *skb;

	if (quic_is_serv(sk)) {
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_TOKEN, NULL);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, false);
		return 0;
	}

	if (!len || len > 120)
		return -EINVAL;

	return quic_data_dup(quic_token(sk), data, len);
}

static int quic_sock_set_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	if (!len || len > 4096)
		return -EINVAL;

	return quic_data_dup(quic_ticket(sk), data, len);
}

static int quic_sock_set_transport_params_ext(struct sock *sk, u8 *p, u32 len)
{
	struct quic_transport_param *param = quic_remote(sk);
	u32 errcode;

	if (!quic_is_establishing(sk))
		return -EINVAL;

	if (quic_frame_set_transport_params_ext(sk, param, p, len)) {
		errcode = QUIC_TRANSPORT_ERROR_TRANSPORT_PARAM;
		quic_outq_transmit_close(sk, 0, errcode, QUIC_CRYPTO_INITIAL);
		return -EINVAL;
	}

	param->remote = 1;
	quic_outq_set_param(sk, param);
	quic_connection_id_set_param(quic_source(sk), param);
	quic_stream_set_param(quic_streams(sk), NULL, param);
	return 0;
}

static int quic_sock_set_crypto_secret(struct sock *sk, struct quic_crypto_secret *secret, u32 len)
{
	struct quic_connection_id_set *id_set = quic_source(sk);
	struct quic_path_addr *path = quic_src(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff_head tmpq, list;
	struct sk_buff *skb;
	u32 window, mss;
	int err, seqno;
	u64 prior = 1;

	if (len != sizeof(*secret) || !quic_is_establishing(sk))
		return -EINVAL;

	err = quic_crypto_set_secret(quic_crypto(sk, secret->level), secret,
				     quic_inq_version(inq), 0);
	if (err)
		return err;

	__skb_queue_head_init(&list);
	if (!secret->send) { /* recv key is ready */
		if (!secret->level && quic_is_serv(sk)) {
			if (quic_outq_pref_addr(outq)) {
				err = quic_path_set_bind_port(sk, path, 1);
				if (err)
					return err;
				err = quic_path_set_udp_sock(sk, path, 1);
				if (err)
					return err;
			}
			skb = quic_frame_create(sk, QUIC_FRAME_NEW_TOKEN, NULL);
			if (!skb)
				return -ENOMEM;
			__skb_queue_tail(&list, skb);
			skb = quic_frame_create(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL);
			if (!skb) {
				__skb_queue_purge(&list);
				return -ENOMEM;
			}
			__skb_queue_tail(&list, skb);
		}
		__skb_queue_head_init(&tmpq);
		skb_queue_splice_init(quic_inq_backlog_list(inq), &tmpq);
		skb = __skb_dequeue(&tmpq);
		while (skb) {
			quic_packet_process(sk, skb);
			skb = __skb_dequeue(&tmpq);
		}
		if (secret->level)
			return 0;
		/* app recv key is ready */
		if (quic_is_serv(sk)) {
			/* some implementations don't send ACKs to handshake packets
			 * so ACK them manually.
			 */
			quic_outq_transmitted_sack(sk, QUIC_CRYPTO_INITIAL,
						   QUIC_PN_MAP_MAX_PN, 0, 0, 0);
			quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE,
						   QUIC_PN_MAP_MAX_PN, 0, 0, 0);
			skb = __skb_dequeue(&list);
			while (skb) {
				quic_outq_ctrl_tail(sk, skb, true);
				skb = __skb_dequeue(&list);
			}
			quic_outq_transmit(sk);
		}
		quic_set_state(sk, QUIC_SS_ESTABLISHED);
		/* PATH CHALLENGE timer is reused as PLPMTUD probe timer */
		quic_timer_reset(sk, QUIC_TIMER_PATH, quic_inq_probe_timeout(inq));
		return 0;
	}

	/* send key is ready */
	if (secret->level) {
		/* 0rtt send key is ready */
		if (secret->level == QUIC_CRYPTO_EARLY)
			quic_outq_set_data_level(outq, QUIC_CRYPTO_EARLY);
		return 0;
	}

	/* app send key is ready */
	quic_outq_set_data_level(outq, QUIC_CRYPTO_APP);
	seqno = quic_connection_id_last_number(id_set) + 1;
	for (; seqno <= quic_connection_id_max_count(id_set); seqno++) {
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &prior);
		if (!skb) {
			while (seqno)
				quic_connection_id_remove(quic_source(sk), seqno--);
			__skb_queue_purge(&list);
			return -ENOMEM;
		}
		__skb_queue_tail(&list, skb);
	}
	skb = __skb_dequeue(&list);
	while (skb) {
		quic_outq_ctrl_tail(sk, skb, true);
		skb = __skb_dequeue(&list);
	}
	mss = quic_packet_mss(quic_packet(sk));
	window = max_t(u32, mss * 2, 14720);
	window = min_t(u32, mss * 10, window);
	quic_outq_set_window(quic_outq(sk), window);
	quic_cong_set_window(quic_cong(sk), window);
	return 0;
}

static int quic_sock_retire_connection_id(struct sock *sk, struct quic_connection_id_info *info,
					  u8 len)
{
	struct sk_buff *skb;
	u64 number, first;

	if (len < sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	if (info->source) {
		number = info->source;
		if (number > quic_connection_id_last_number(quic_source(sk)) ||
		    number <= quic_connection_id_first_number(quic_source(sk)))
			return -EINVAL;
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &number);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, false);
		return 0;
	}

	number = info->dest;
	first = quic_connection_id_first_number(quic_dest(sk));
	if (number > quic_connection_id_last_number(quic_dest(sk)) || number <= first)
		return -EINVAL;

	for (; first < number; first++) {
		skb = quic_frame_create(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &first);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, first != number - 1);
	}
	return 0;
}

#define QUIC_ALPN_MAX_LEN	128

static int quic_sock_set_alpn(struct sock *sk, u8 *data, u32 len)
{
	struct quic_data *alpns = quic_alpn(sk);
	u8 *p;

	if (!len || len > QUIC_ALPN_MAX_LEN || quic_is_listen(sk))
		return -EINVAL;

	p = kzalloc(len + 1, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	kfree(alpns->data);
	alpns->data = p;
	alpns->len  = len + 1;

	quic_data_from_string(alpns, data, len);
	return 0;
}

static int quic_sock_stream_reset(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;
	struct sk_buff *skb;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_send_get(streams, info->stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (stream->send.state > QUIC_STREAM_SEND_STATE_SENT)
		return -EINVAL;

	skb = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, info);
	if (!skb)
		return -ENOMEM;

	stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	quic_outq_stream_purge(sk, stream);
	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_stream_stop_sending(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;
	struct sk_buff *skb;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_recv_get(streams, info->stream_id, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	skb = quic_frame_create(sk, QUIC_FRAME_STOP_SENDING, info);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_set_event(struct sock *sk, struct quic_event_option *event, u32 len)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u32 events;

	if (len != sizeof(*event))
		return -EINVAL;
	if (!event->type || event->type > QUIC_EVENT_MAX)
		return -EINVAL;

	events = quic_inq_events(inq);
	if (event->on) {
		quic_inq_set_events(inq, events | (1 << (event->type)));
		return 0;
	}
	quic_inq_set_events(inq, events & ~(1 << event->type));
	return 0;
}

static int quic_sock_set_connection_close(struct sock *sk, struct quic_connection_close *close,
					  u32 len)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *data;

	if (len < sizeof(*close))
		return -EINVAL;

	len -= sizeof(*close);
	if (len > 80 || close->phrase[len - 1])
		return -EINVAL;
	data = kmemdup(close->phrase, len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	quic_outq_set_close_phrase(outq, data);
	quic_outq_set_close_errcode(outq, close->errcode);
	return 0;
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	void *kopt = NULL;
	int retval = 0;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_set_event(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_RESET:
		retval = quic_sock_stream_reset(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_STOP_SENDING:
		retval = quic_sock_stream_stop_sending(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_CLOSE:
		retval = quic_sock_set_connection_close(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_MIGRATION:
		retval = quic_sock_change_saddr(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_KEY_UPDATE:
		retval = quic_crypto_key_update(quic_crypto(sk, QUIC_CRYPTO_APP));
		break;
	case QUIC_SOCKOPT_RETIRE_CONNECTION_ID:
		retval = quic_sock_retire_connection_id(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_ALPN:
		retval = quic_sock_set_alpn(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_TOKEN:
		retval = quic_sock_set_token(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_SESSION_TICKET:
		retval = quic_sock_set_session_ticket(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_set_transport_param(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		retval = quic_sock_set_transport_params_ext(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CRYPTO_SECRET:
		retval = quic_sock_set_crypto_secret(sk, kopt, optlen);
		break;
	case HYQUIC_SOCKOPT_OPTIONS:
		retval = hyquic_set_options(sk, kopt, optlen);
		break;
	case HYQUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = hyquic_set_local_transport_parameter(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_sock_get_token(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_data *token = quic_token(sk);

	if (quic_is_serv(sk) || len < token->len)
		return -EINVAL;
	if (put_user(token->len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, token->data, token->len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_session_ticket(struct sock *sk, int len,
					char __user *optval, int __user *optlen)
{
	struct quic_crypto *crypto;
	u32 ticket_len, addr_len;
	union quic_addr *da;
	u8 *ticket, key[64];

	if (quic_is_serv(sk)) { /* get ticket_key for server */
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		da = quic_path_addr(quic_dst(sk), 0);
		addr_len = quic_addr_len(sk);
		if (quic_crypto_generate_session_ticket_key(crypto, da, addr_len, key, 64))
			return -EINVAL;
		ticket = key;
		ticket_len = 64;
		goto out;
	}

	ticket_len = quic_ticket(sk)->len;
	ticket = quic_ticket(sk)->data;
out:
	if (len < ticket_len)
		return -EINVAL;
	if (put_user(ticket_len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, ticket, ticket_len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_param(struct sock *sk, int len,
					 char __user *optval, int __user *optlen)
{
	struct quic_transport_param param, *p = quic_local(sk);

	if (len < sizeof(param))
		return -EINVAL;

	len = sizeof(param);
	if (copy_from_user(&param, optval, len))
		return -EFAULT;

	if (param.remote)
		p = quic_remote(sk);

	if (len < sizeof(*p))
		return -EINVAL;
	len = sizeof(*p);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, p, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_params_ext(struct sock *sk, int len,
					      char __user *optval, int __user *optlen)
{
	struct quic_transport_param *param = quic_local(sk);
	u8 data[512];
	u32 datalen;

	if (quic_frame_get_transport_params_ext(sk, param, data, &datalen))
		return -EINVAL;
	if (len < datalen)
		return -EINVAL;
	len = datalen;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_crypto_secret(struct sock *sk, int len,
				       char __user *optval, int __user *optlen)
{
	struct quic_crypto_secret secret = {};

	if (len < sizeof(secret))
		return -EINVAL;
	len = sizeof(secret);
	if (copy_from_user(&secret, optval, len))
		return -EFAULT;

	if (quic_crypto_get_secret(quic_crypto(sk, secret.level), &secret))
		return -EINVAL;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &secret, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_active_connection_id(struct sock *sk, int len,
					      char __user *optval, int __user *optlen)
{
	struct quic_connection_id_set *id_set;
	struct quic_connection_id_info info;
	struct quic_connection_id *active;

	if (len < sizeof(info) || !quic_is_established(sk))
		return -EINVAL;

	len = sizeof(info);
	id_set = quic_source(sk);
	active = quic_connection_id_active(id_set);
	info.source = quic_connection_id_number(active);

	id_set = quic_dest(sk);
	active = quic_connection_id_active(id_set);
	info.dest = quic_connection_id_number(active);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &info, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_alpn(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_data *alpns = quic_alpn(sk);
	u8 data[128];

	if (!alpns->len) {
		len = 0;
		goto out;
	}
	if (len < alpns->len)
		return -EINVAL;

	quic_data_to_string(data, &len, alpns);

out:
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_stream_open(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream_info sinfo;
	struct quic_stream *stream;

	if (len < sizeof(sinfo))
		return -EINVAL;

	len = sizeof(sinfo);
	if (copy_from_user(&sinfo, optval, len))
		return -EFAULT;

	if (sinfo.stream_id == -1) {
		sinfo.stream_id = (quic_stream_send_bidi(streams) << 2);
		if (sinfo.stream_flag & QUIC_STREAM_FLAG_UNI) {
			sinfo.stream_id = (quic_stream_send_uni(streams) << 2);
			sinfo.stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
		}
		sinfo.stream_id |= quic_is_serv(sk);
	}

	sinfo.stream_flag |= QUIC_STREAM_FLAG_NEW;
	if (put_user(len, optlen) || copy_to_user(optval, &sinfo, len))
		return -EFAULT;

	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	return 0;
}

static int quic_sock_get_event(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_event_option event;

	if (len < sizeof(event))
		return -EINVAL;

	len = sizeof(event);
	if (copy_from_user(&event, optval, len))
		return -EFAULT;

	if (!event.type || event.type > QUIC_EVENT_MAX)
		return -EINVAL;

	event.on = quic_inq_events(inq) & (1 << event.type);
	if (put_user(len, optlen) || copy_to_user(optval, &event, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_connection_close(struct sock *sk, int len, char __user *optval,
					  int __user *optlen)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close *close;
	u8 phrase_len = 0, frame[100] = {};
	u8 *phrase;

	phrase = quic_outq_close_phrase(outq);
	if (phrase)
		phrase_len = strlen(phrase) + 1;
	if (len < sizeof(close) + phrase_len)
		return -EINVAL;

	len = sizeof(close) + phrase_len;
	close = (void *)frame;
	close->errcode = quic_outq_close_errcode(outq);
	close->frame = quic_outq_close_frame(outq);

	if (phrase_len)
		strscpy(close->phrase, phrase, phrase_len);

	if (put_user(len, optlen) || copy_to_user(optval, close, len))
		return -EFAULT;
	return 0;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	int retval = 0;
	int len;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_get_event(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_OPEN:
		retval = quic_sock_stream_open(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_CLOSE:
		retval = quic_sock_get_connection_close(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_ACTIVE_CONNECTION_ID:
		retval = quic_sock_get_active_connection_id(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_ALPN:
		retval = quic_sock_get_alpn(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TOKEN:
		retval = quic_sock_get_token(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_SESSION_TICKET:
		retval = quic_sock_get_session_ticket(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_get_transport_param(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		retval = quic_sock_get_transport_params_ext(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CRYPTO_SECRET:
		retval = quic_sock_get_crypto_secret(sk, len, optval, optlen);
		break;
	case HYQUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = hyquic_get_remote_transport_parameters(sk, len, optval, optlen);
		break;
	case HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN:
		retval = hyquic_get_remote_transport_parameters_length(sk, len, optval, optlen);
		break;
	case HYQUIC_SOCKOPT_INITIAL_MPS:
		retval = hyquic_get_initial_mps(sk, len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return retval;
}

static void quic_release_cb(struct sock *sk)
{
	if (test_bit(QUIC_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags)) {
		quic_rcv_err_icmp(sk);
		clear_bit(QUIC_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags);
		__sock_put(sk);
	}
}

static int quic_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP;
}

static void quic_shutdown(struct sock *sk, int how)
{
	if (!(how & SEND_SHUTDOWN))
		goto out;

	quic_outq_transmit_app_close(sk);
out:
	quic_set_state(sk, QUIC_SS_CLOSED);
}

struct proto quic_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_packet_process,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_packet_process,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
#if KERNEL_VERSION(6, 5, 0) <= LINUX_VERSION_CODE
	.ipv6_pinfo_offset	= offsetof(struct quic6_sock, inet6),
#endif
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};
