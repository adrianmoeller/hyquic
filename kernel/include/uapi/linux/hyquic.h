#ifndef __uapi_hyquic_h__
#define __uapi_hyquic_h__

#include "quic.h"

/**
 * Hyquic options configurable by user-quic.
 * 
 * @usrquic_retransmit: tells if user-quic frames are retransmitted by user-quic
*/
struct hyquic_options {
	uint8_t usrquic_retransmit:1;
};

/**
 * Type of hyquic control data.
*/
enum hyquic_ctrl_type {
	HYQUIC_CTRL_NONE,
	HYQUIC_CTRL_RAW_FRAMES,
	HYQUIC_CTRL_RAW_FRAMES_FIX,
	HYQUIC_CTRL_RAW_FRAMES_VAR,
	HYQUIC_CTRL_LOST_FRAMES,
	HYQUIC_CTRL_MSS_UPDATE
};

struct hyquic_ctrl_raw_frames {
	uint8_t dont_wait:1;
};

struct hyquic_ctrlsend_raw_frames_var {
	uint32_t msg_id;
	uint32_t processed_length;
	uint32_t processed_payload;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

/**
 * Container holding hyquic control metadata for user- to kernel-quic communication
*/
struct hyquic_ctrlsend_info {
	enum hyquic_ctrl_type type;
	uint32_t data_length;
	union {
		struct hyquic_ctrl_raw_frames raw_frames;
		struct hyquic_ctrlsend_raw_frames_var raw_frames_var;
	};
};

struct hyquic_ctrlrecv_raw_frames_fix {
	uint32_t payload;
};

struct hyquic_ctrlrecv_raw_frames_var {
	uint32_t msg_id;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t ack_sent:1;
	uint8_t sack_timer_started:1;
	uint8_t non_probing:1;
	uint8_t path_alt:1;
};

struct hyquic_ctrlrecv_lost_frames {
	uint32_t payload_length;
	uint8_t retransmit_count;
};

struct hyquic_ctrlrecv_mss_update {
	uint32_t max_payload;
	uint32_t max_payload_dgram;
};

union hyquic_ctrlrecv_info_details {
	struct hyquic_ctrlrecv_raw_frames_fix raw_frames_fix;
	struct hyquic_ctrlrecv_raw_frames_var raw_frames_var;
	struct hyquic_ctrlrecv_lost_frames lost_frames;
	struct hyquic_ctrlrecv_mss_update mss_update;
};

/**
 * Container holding hyquic control metadata for kernel- to user-quic communication
*/
struct hyquic_ctrlrecv_info {
	enum hyquic_ctrl_type type;
	uint32_t data_length;
	uint8_t incompl;
	union hyquic_ctrlrecv_info_details details;
};

/* HyQUIC Socket Options API */
#define HYQUIC_SOCKOPT_OPTIONS					15
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM			16
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN		17
#define HYQUIC_SOCKOPT_INITIAL_MSS				18

/**
 * Specifies if a frame will be sent by the kernel-quic, the user-quic, or both.
*/
enum hyquic_frame_send_mode {
	HYQUIC_FRAME_SEND_MODE_KERNEL,
	HYQUIC_FRAME_SEND_MODE_USER,
	HYQUIC_FRAME_SEND_MODE_BOTH
};

/**
 * Specifies if a frame will be received by the kernel-quic, the user-quic, or both.
*/
enum hyquic_frame_recv_mode {
	HYQUIC_FRAME_RECV_MODE_KERNEL,
	HYQUIC_FRAME_RECV_MODE_USER,
	HYQUIC_FRAME_RECV_MODE_BOTH
};

/**
 * Frame profile communicated by user-quic. Used by kernel-quic to properly handle unknown frames.
 * 
 * @frame_type: frame type
 * @format_specification_avail: if 0, frame format specification is not available, otherwise, holds specification length
 * @send_mode: specifies the send mode
 * @recv_mode: specifies the receive mode
 * @no_retransmit: denotes if frame should never be retransmitted. Note: only applies to frames sent by user-quic
 * @ack_eliciting: denotes if frame is ack-eliciting
 * @ack_immediate: denotes if frame should be acked immediatly
 * @non_probing: denotes if frame is non-probing
*/
struct hyquic_frame_profile {
	uint64_t frame_type;
	uint16_t format_specification_avail;
	enum hyquic_frame_send_mode send_mode;
	enum hyquic_frame_recv_mode recv_mode;
	uint8_t no_retransmit:1;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

/**
 * Metadata attached to every frame sent by user-quic. Used by kernel-QUIC to properly handle user-frames.
 * 
 * @frame_length: length of frame
 * @payload_length: length of payload in bytes contained in a frame. May be 0 if frame is a control frame
 * @retransmit_count: number of times frame has been retransmitted. 0 if frame is new
 * @has_stream_info: true if stream information are available, otherwise false
 * @stream_info: holds optional stream information. May be 0 if frame is not related to a stream (indicated with has_stream_info flag)
*/
struct hyquic_frame_to_send_metadata {
	uint32_t frame_length;
	uint32_t payload_length;
	uint8_t retransmit_count;
	uint8_t has_stream_info;
	struct quic_stream_info stream_info;
};

/**
 * Metadata attached to a lost frame sent back to user-quic.
 * 
 * @frame_length: length of frame
 * @payload_length: length of payload in bytes contained in a frame. May be 0 if frame is a control frame
 * @retransmit_count: number of times frame has been retransmitted. 0 if frame is new
*/
struct hyquic_lost_frame_metadata {
	uint32_t frame_length;
	uint32_t payload_length;
	uint8_t retransmit_count;
};

/**
 * Type of frame format specification component.
*/
enum hyquic_frame_format_spec_component_type {
    HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_CONST_DECL_LEN,
	HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_SCOPE_DECL_LEN,
	HYQUIC_FRAME_FORMAT_SPEC_COMP_BACKFILL
};

#endif /* __uapi_hyquic_h__ */