#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netinet/hyquic.h"
#include <linux/quic.h>

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t param_length, struct hyquic_frame_details *frame_details, size_t num_frame_details)
{
    size_t frame_details_length = num_frame_details * sizeof(struct hyquic_frame_details);
    size_t data_length = sizeof(size_t) + frame_details_length + param_length;
    void *data = malloc(data_length);
    uint8_t *p = data;
    int err;

    memcpy(p, &num_frame_details, sizeof(size_t));
    p += sizeof(size_t);
    memcpy(p, frame_details, frame_details_length);
    p += frame_details_length;
    memcpy(p, param, param_length);

    err = setsockopt(sockfd, SOL_QUIC, HYQUIC_SOCKOPT_TRANSPORT_PARAM, data, data_length);

    free(data);
    return err;
}