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

#include "uapi/linux/quic.h"
#include <linux/jhash.h>
#include <net/netns/hash.h>
#include <net/sock.h>
#include "hashtable.h"
#include "connection.h"

struct quic_source_connection_id *quic_source_connection_id_lookup(struct net *net, u8 *scid, u32 len)
{
	struct quic_hash_head *head = quic_source_connection_id_head(net, scid);
	struct quic_source_connection_id *tmp, *s_conn_id = NULL;

	spin_lock(&head->lock);
	hlist_for_each_entry(tmp, &head->head, node) {
		if (net == sock_net(tmp->sk) && tmp->common.id.len <= len &&
		    !memcmp(scid, &tmp->common.id.data, tmp->common.id.len)) {
			s_conn_id = tmp;
			break;
		}
	}

	spin_unlock(&head->lock);
	return s_conn_id;
}

static void quic_source_connection_id_free_rcu(struct rcu_head *head)
{
	struct quic_source_connection_id *s_conn_id =
		container_of(head, struct quic_source_connection_id, rcu);

	kfree(s_conn_id);
}

static void quic_source_connection_id_free(struct quic_source_connection_id *s_conn_id)
{
	u8 *data = s_conn_id->common.id.data;
	struct quic_hash_head *head;

	if (!hlist_unhashed(&s_conn_id->node)) {
		head = quic_source_connection_id_head(sock_net(s_conn_id->sk), data);
		spin_lock(&head->lock);
		hlist_del_init(&s_conn_id->node);
		spin_unlock(&head->lock);
	}

	call_rcu(&s_conn_id->rcu, quic_source_connection_id_free_rcu);
}

static void quic_connection_id_del(struct quic_common_connection_id *common)
{
	list_del(&common->list);
	if (!common->hashed) {
		kfree(common);
		return;
	}
	quic_source_connection_id_free((struct quic_source_connection_id *)common);
}

int quic_connection_id_add(struct quic_connection_id_set *id_set,
			   struct quic_connection_id *conn_id, struct sock *sk)
{
	struct quic_common_connection_id *common, *last;
	struct quic_source_connection_id *s_conn_id;
	struct quic_hash_head *head;
	struct list_head *list;

	if (conn_id->len > 20)
		return -EINVAL;
	common = kzalloc(id_set->entry_size, GFP_ATOMIC);
	if (!common)
		return -ENOMEM;
	common->id = *conn_id;

	list = &id_set->head;
	if (!list_empty(list)) {
		last = list_last_entry(list, struct quic_common_connection_id, list);
		if (common->id.number != last->id.number + 1) {
			kfree(common);
			return -EINVAL;
		}
	}
	list_add_tail(&common->list, list);
	if (!id_set->active)
		id_set->active = common;
	id_set->count++;

	if (id_set->entry_size == sizeof(struct quic_dest_connection_id))
		return 0;

	common->hashed = 1;
	s_conn_id = (struct quic_source_connection_id *)common;
	s_conn_id->sk = sk;
	head = quic_source_connection_id_head(sock_net(sk), common->id.data);
	spin_lock(&head->lock);
	hlist_add_head(&s_conn_id->node, &head->head);
	spin_unlock(&head->lock);
	return 0;
}

int quic_connection_id_get(struct quic_connection_id_set *id_set, struct quic_connection_id *conn_id)
{
	struct quic_common_connection_id *common;

	list_for_each_entry(common, &id_set->head, list) {
		if (common->id.number == conn_id->number) {
			*conn_id = common->id;
			return 0;
		}
	}
	return -ENOENT;
}

int quic_connection_id_append(struct quic_connection_id_set *id_set, u32 number, struct sock *sk,
			      u8 *conn_id, u8 len)
{
	struct quic_connection_id conn;

	conn.len = len;
	memcpy(conn.data, conn_id, len);
	conn.number = number;
	return quic_connection_id_add(id_set, &conn, sk);
}

void quic_connection_id_remove(struct quic_connection_id_set *id_set, u32 number)
{
	struct quic_common_connection_id *common, *tmp;
	struct list_head *list;

	list = &id_set->head;
	list_for_each_entry_safe(common, tmp, list, list)
		if (common->id.number <= number)
			quic_connection_id_del(common);

	id_set->active = list_first_entry(list, struct quic_common_connection_id, list);
}

void quic_connection_id_set_init(struct quic_connection_id_set *id_set, bool source)
{
	id_set->entry_size = source ? sizeof(struct quic_source_connection_id)
				    : sizeof(struct quic_dest_connection_id);
	INIT_LIST_HEAD(&id_set->head);
}

void quic_connection_id_set_free(struct quic_connection_id_set *id_set)
{
	struct quic_common_connection_id *common, *tmp;

	list_for_each_entry_safe(common, tmp, &id_set->head, list)
		quic_connection_id_del(common);
	id_set->active = NULL;
}

int quic_connection_id_set_param(struct quic_connection_id_set *id_set, struct quic_transport_param *p)
{
	if (p->active_connection_id_limit < 2)
		return -EINVAL;
	id_set->max_count = p->active_connection_id_limit;
	return 0;
}
