#include <stdint.h>
#include <sys/socket.h>
#include <linux/hyquic.h>

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t param_length, struct hyquic_frame_details *frame_details, size_t num_frame_details);