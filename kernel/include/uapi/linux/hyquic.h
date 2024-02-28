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

struct hyquic_data_info {
	enum hyquic_data_type type;
	uint32_t data_length;
	union {
		struct hyquic_data_raw_frames raw_frames;
		uint8_t incompl;
	};
};

/* HyQUIC Socket Options API */
#define HYQUIC_SOCKOPT_OPTIONS					15
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM			16
#define HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN		17

struct hyquic_frame_details {
	uint64_t frame_type;
	size_t fixed_length;
	uint8_t ack_eliciting:1;
	uint8_t ack_immidiate:1;
	uint8_t non_probing:1;
};

#endif /* __uapi_hyquic_h__ */