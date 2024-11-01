/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 *    Adrian Moeller (modified for HyQUIC)
 */

#ifndef __QUIC_PNMAP_H__
#define __QUIC_PNMAP_H__

#define QUIC_PN_MAX_GABS	256
#define QUIC_PN_MAP_BASE_PN	0
#define QUIC_PN_MAP_MAX_PN	((1ULL << 62) - 1)

#define QUIC_PN_MAP_INITIAL	BITS_PER_LONG
#define QUIC_PN_MAP_INCREMENT	QUIC_PN_MAP_INITIAL
#define QUIC_PN_MAP_SIZE	4096
#define QUIC_PN_MAP_LIMIT	(QUIC_PN_MAP_SIZE * 3 / 4)

#define QUIC_PNMAP_MAX		(QUIC_CRYPTO_MAX - 1)

struct quic_gap_ack_block {
	u16 start;
	u16 end;
};

/* pn_map:
 * cum_ack_point --v
 * min_pn_seen -->  |----------------------|---------------------|...
 *        base_pn --^   last_max_pn_seen --^       max_pn_seen --^
 *
 * move forward:
 *   min_pn_seen = last_max_pn_seen;
 *   base_pn = first_zero_bit from last_max_pn_seen + 1;
 *   cum_ack_point = base_pn - 1;
 *   last_max_pn_seen = max_pn_seen;
 * when:
 *   'max_pn_ts - last_max_pn_ts >= max_record_ts' or
 *   'max_pn_seen - base_pn > QUIC_PN_MAP_LIMIT'
 *   'max_pn_seen - last_max_pn_seen > QUIC_PN_MAP_LIMIT' or
 * gaps search:
 *    from cum_ack_point/min_pn_seen to max_pn_seen
 */
struct quic_pnmap {
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	unsigned long *pn_map;
	s64 next_number; /* next packet number to send */
	u64 ecn_count[2][3]; /* ECT_1, ECT_0, CE count of local and peer */
	u16 len;

	s64 base_pn;
	s64 min_pn_seen;

	s64 max_pn_seen;
	u32 max_pn_ts;

	u32 max_record_ts;
	s64 cum_ack_point;

	u32 last_max_pn_ts;
	s64 last_max_pn_seen;

	u32 loss_ts;
	u32 inflight;
	u32 last_sent_ts;
	s64 max_pn_acked;
};

static inline struct quic_gap_ack_block *quic_pnmap_gabs(struct quic_pnmap *map)
{
	return map->gabs;
}

static inline void quic_pnmap_set_max_record_ts(struct quic_pnmap *map, u32 max_record_ts)
{
	map->max_record_ts = max_record_ts;
}

static inline s64 quic_pnmap_min_pn_seen(const struct quic_pnmap *map)
{
	return map->min_pn_seen;
}

static inline s64 quic_pnmap_max_pn_seen(const struct quic_pnmap *map)
{
	return map->max_pn_seen;
}

static inline void quic_pnmap_set_max_pn_acked(struct quic_pnmap *map, s64 max_pn_acked)
{
	if (map->max_pn_acked >= max_pn_acked)
		return;
	map->max_pn_acked = max_pn_acked;
}

static inline s64 quic_pnmap_max_pn_acked(const struct quic_pnmap *map)
{
	return map->max_pn_acked;
}

static inline void quic_pnmap_set_loss_ts(struct quic_pnmap *map, u32 loss_ts)
{
	map->loss_ts = loss_ts;
}

static inline u32 quic_pnmap_loss_ts(const struct quic_pnmap *map)
{
	return map->loss_ts;
}

static inline void quic_pnmap_set_last_sent_ts(struct quic_pnmap *map, u32 last_sent_ts)
{
	map->last_sent_ts = last_sent_ts;
}

static inline u32 quic_pnmap_last_sent_ts(const struct quic_pnmap *map)
{
	return map->last_sent_ts;
}

static inline s64 quic_pnmap_next_number(const struct quic_pnmap *map)
{
	return map->next_number;
}

static inline s64 quic_pnmap_inc_next_number(struct quic_pnmap *map)
{
	return map->next_number++;
}

static inline u32 quic_pnmap_inflight(struct quic_pnmap *map)
{
	return map->inflight;
}

static inline void quic_pnmap_inc_inflight(struct quic_pnmap *map, u16 bytes)
{
	map->inflight += bytes;
}

static inline void quic_pnmap_dec_inflight(struct quic_pnmap *map, u16 bytes)
{
	map->inflight -= bytes;
}

static inline s64 quic_pnmap_base_pn(const struct quic_pnmap *map)
{
	return map->base_pn;
}

static inline u32 quic_pnmap_max_pn_ts(const struct quic_pnmap *map)
{
	return map->max_pn_ts;
}

static inline bool quic_pnmap_has_gap(const struct quic_pnmap *map)
{
	return map->cum_ack_point != map->max_pn_seen;
}

static inline void quic_pnmap_inc_ecn_count(struct quic_pnmap *map, u8 ecn)
{
	if (!ecn)
		return;
	map->ecn_count[0][ecn - 1]++;
}

static inline int quic_pnmap_set_ecn_count(struct quic_pnmap *map, u64 *ecn_count)
{
	if (map->ecn_count[1][0] < ecn_count[0])
		map->ecn_count[1][0] = ecn_count[0];
	if (map->ecn_count[1][1] < ecn_count[1])
		map->ecn_count[1][1] = ecn_count[1];
	if (map->ecn_count[1][2] < ecn_count[2]) {
		map->ecn_count[1][2] = ecn_count[2];
		return 1;
	}
	return 0;
}

static inline u64 *quic_pnmap_ecn_count(struct quic_pnmap *map)
{
	return map->ecn_count[0];
}

static inline bool quic_pnmap_has_ecn_count(struct quic_pnmap *map)
{
	return map->ecn_count[0][0] || map->ecn_count[0][1] || map->ecn_count[0][2];
}

int quic_pnmap_init(struct quic_pnmap *map);
int quic_pnmap_check(const struct quic_pnmap *map, s64 pn);
int quic_pnmap_mark(struct quic_pnmap *map, s64 pn);
void quic_pnmap_free(struct quic_pnmap *map);
u16 quic_pnmap_num_gabs(struct quic_pnmap *map);

#endif /* __QUIC_PNMAP_H__ */