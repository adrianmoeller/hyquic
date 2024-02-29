#include <stdint.h>
#include <sys/socket.h>
#include <linux/hyquic.h>

struct hyquic_frame {
    uint32_t length;
    uint8_t *data;
};

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t param_length, const struct hyquic_frame_details *frame_details, size_t num_frame_details);
int hyquic_send_frames(int sockfd, struct hyquic_frame *frames, size_t num_frames, size_t total_frame_data_length);