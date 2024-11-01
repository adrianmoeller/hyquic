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

#ifndef __QUIC_CONG_H__
#define __QUIC_CONG_H__

#define QUIC_RTT_INIT		333000
#define QUIC_RTO_MIN		100000
#define QUIC_RTO_MAX		6000000

enum quic_cong_state {
	QUIC_CONG_SLOW_START,
	QUIC_CONG_RECOVERY_PERIOD,
	QUIC_CONG_CONGESTION_AVOIDANCE,
};

struct quic_cong {
	u32 rto;
	u32 rttvar;
	u32 min_rtt;
	u32 duration;
	u32 latest_rtt;
	u32 smoothed_rtt;

	s64 last_sent_number;
	s64 max_acked_number;
	u32 max_acked_transmit_ts;
	u32 ack_delay_exponent;
	u32 max_ack_delay;

	u32 mss;
	u32 window;
	u32 max_window;
	u32 prior_window;
	u32 threshold;
	u32 prior_threshold;

	u8 state;
	struct quic_cong_ops *ops;
};

struct quic_cong_ops {
	void (*cwnd_update_after_timeout)(struct quic_cong *cong, s64 number,
					  u32 transmit_ts, s64 last_sent_number);
	void (*cwnd_update_after_sack)(struct quic_cong *cong, s64 acked_number,
				       u32 transmit_ts, u32 acked_bytes, u32 inflight);
	void (*cwnd_update_after_ecn)(struct quic_cong *cong);
};

static inline void quic_cong_set_window(struct quic_cong *cong, u32 window)
{
	cong->window = window;
}

static inline void quic_cong_set_mss(struct quic_cong *cong, u32 mss)
{
	cong->mss = mss;
}

static inline u32 quic_cong_window(struct quic_cong *cong)
{
	return cong->window;
}

static inline u32 quic_cong_rto(struct quic_cong *cong)
{
	return cong->rto;
}

static inline u32 quic_cong_duration(struct quic_cong *cong)
{
	return cong->duration;
}

static inline u32 quic_cong_latest_rtt(struct quic_cong *cong)
{
	return cong->latest_rtt;
}

void quic_cong_set_param(struct quic_cong *cong, struct quic_transport_param *p);
void quic_cong_rtt_update(struct quic_cong *cong, u32 transmit_ts, u32 ack_delay);
void quic_cong_cwnd_update_after_timeout(struct quic_cong *cong, s64 number,
					 u32 transmit_ts, s64 last_sent_number);
void quic_cong_cwnd_update_after_sack(struct quic_cong *cong, s64 acked_number,
				      u32 transmit_ts, u32 acked_bytes, u32 inflight);
void quic_cong_cwnd_update_after_ecn(struct quic_cong *cong);

#endif /* __QUIC_CONG_H__ */