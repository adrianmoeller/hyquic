#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netinet/hyquic.h"
#include "hyquic_intercom.h"
#include <linux/quic.h>

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t param_length, const struct hyquic_frame_details *frame_details, size_t num_frame_details)
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

static inline void assemble_frame_data(const struct hyquic_frame *frames, size_t num_frames, void *data)
{
    const struct hyquic_frame *frame_cursor = frames;
    uint8_t *data_cursor = data;
    int i;

    for (i = 0; i < num_frames; i++) {
        data_cursor = hyquic_ic_put_int(data_cursor, frame_cursor->length, 4);
        data_cursor = hyquic_ic_put_data(data_cursor, frame_cursor->data, frame_cursor->length);
        frame_cursor += sizeof(*frame_cursor);
    }
}

int hyquic_send_frames(int sockfd, struct hyquic_frame *frames, size_t num_frames, size_t total_frame_data_length)
{
    char outcmsg[CMSG_SPACE(sizeof(struct hyquic_data_info))];
    size_t data_length = sizeof(frames->length) * num_frames + total_frame_data_length;
    void *data = malloc(data_length);
    struct hyquic_data_info *info;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec iov;

    assemble_frame_data(frames, num_frames, data);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    iov.iov_base = data;
    iov.iov_len = data_length;
    msg.msg_iovlen = 1;

    msg.msg_control = outcmsg;
    msg.msg_controllen = sizeof(outcmsg);
    msg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_QUIC;
    cmsg->cmsg_type = HYQUIC_INFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

    msg.msg_controllen = cmsg->cmsg_len;
    info = (struct hyquic_data_info*)CMSG_DATA(cmsg);
    info->type = HYQUIC_DATA_RAW_FRAMES;
    info->data_length = data_length;
    info->raw_frames = (struct hyquic_data_raw_frames) {
        .first_frame_seqnum = 0 // TODO needed?
    };

    return sendmsg(sockfd, &msg, 0);
}