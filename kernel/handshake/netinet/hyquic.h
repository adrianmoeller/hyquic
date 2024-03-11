#ifndef __NETINET_HYQUIC_H__
#define __NETINET_HYQUIC_H__

#include <stdint.h>
#include <linux/quic.h>
#include <linux/hyquic.h>

struct hyquic_receive_ops {
    int (*recv_stream_data)(const void *data, const struct quic_stream_info *info);
    int (*recv_hyquic_data)(const void *data, const struct hyquic_data_recvinfo *info);
};

struct hyquic_frame {
    uint32_t length;
    uint8_t *data;
};

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t param_length, const struct hyquic_frame_details *frame_details, size_t num_frame_details);
int hyquic_send_frames(int sockfd, const struct hyquic_frame *frames, size_t num_frames, size_t total_frame_data_length);
int hyquic_receive(int sockfd, const struct hyquic_receive_ops *recv_ops, size_t len);

#endif /* __NETINET_HYQUIC_H__ */