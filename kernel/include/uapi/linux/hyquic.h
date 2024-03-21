#ifndef __uapi_hyquic_h__
#define __uapi_hyquic_h__

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
};

struct hyquic_ctrl_raw_frames {
	// NO-DATA
};

struct hyquic_ctrlsend_raw_frames_var {
	uint64_t msg_id;
	uint32_t processed_length;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

/**
 * Container holding hyquic control meta data for user- to kernel-quic communication
*/
struct hyquic_ctrlsend_info {
	enum hyquic_ctrl_type type;
	uint32_t data_length;
	union {
		struct hyquic_ctrl_raw_frames raw_frames;
		struct hyquic_ctrlsend_raw_frames_var raw_frames_var;
	};
};

struct hyquic_ctrlrecv_raw_frames_var {
	uint64_t msg_id;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t ack_sent:1;
	uint8_t ack_timer_started:1;
	uint8_t non_probing:1;
	uint8_t path_alt:1;
};

union hyquic_ctrlrecv_info_details {
	struct hyquic_ctrlrecv_raw_frames_var raw_frames_var;
};

/**
 * Container holding hyquic control meta data for kernel- to user-quic communication
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

/**
 * Frame details communicated by user-quic. Used by kernel-quic to properly handle unknown frames.
 * 
 * @frame_type: frame type
 * @format_specification_avail: if 0, frame format specification is not available, otherwise, holds specification length
 * @ack_eliciting: tells if frame is ack-eliciting
 * @ack_immediate: tells if frame should be acked immediatly
 * @non_probing: tells if frame is non-probing
*/
struct hyquic_frame_details {
	uint64_t frame_type;
	uint16_t format_specification_avail;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

/**
 * Type of frame format specification component.
*/
enum hyquic_frame_format_spec_component_type {
    HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_CONST_DECL_LEN,
	HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_SCOPE_DECL_LEN
};

#endif /* __uapi_hyquic_h__ */