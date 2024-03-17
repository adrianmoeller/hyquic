#ifndef __uapi_hyquic_h__
#define __uapi_hyquic_h__

struct hyquic_options {
	uint8_t usrquic_retransmit:1;
};

enum hyquic_data_type {
	HYQUIC_DATA_NONE,
	HYQUIC_DATA_RAW_FRAMES,
	HYQUIC_DATA_RAW_FRAMES_FIX,
	HYQUIC_DATA_RAW_FRAMES_VAR,
	HYQUIC_DATA_LOST_FRAMES,
};

struct hyquic_data_raw_frames {
	uint64_t first_frame_seqnum;
};

struct hyquic_data_raw_frames_var_send {
	uint64_t msg_id;
	uint32_t processed_length;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

struct hyquic_data_sendinfo {
	enum hyquic_data_type type;
	uint32_t data_length;
	union {
		struct hyquic_data_raw_frames raw_frames;
		struct hyquic_data_raw_frames_var_send raw_frames_var;
	};
};

struct hyquic_data_raw_frames_var_recv {
	uint64_t msg_id;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t ack_sent:1;
	uint8_t ack_timer_started:1;
	uint8_t non_probing:1;
	uint8_t path_alt:1;
};

union hyquic_data_recvinfo_details {
	struct hyquic_data_raw_frames_var_recv raw_frames_var;
};

struct hyquic_data_recvinfo {
	enum hyquic_data_type type;
	uint32_t data_length;
	uint8_t incompl;
	union hyquic_data_recvinfo_details details;
};

/* HyQUIC Socket Options API */
#define HYQUIC_SOCKOPT_OPTIONS					15
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM			16
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN		17

struct hyquic_frame_details {
	uint64_t frame_type;
	uint16_t format_specification_avail;
	uint8_t ack_eliciting:1;
	uint8_t ack_immediate:1;
	uint8_t non_probing:1;
};

enum hyquic_frame_format_spec_component_type {
    HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN,
    HYQUIC_FRAME_FORMAT_SPEC_COMP_DECL_LEN
};

#endif /* __uapi_hyquic_h__ */