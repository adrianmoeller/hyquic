#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
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

int hyquic_send_frames(int sockfd, const struct hyquic_frame *frames, size_t num_frames, size_t total_frame_data_length)
{
    char outcmsg[CMSG_SPACE(sizeof(struct hyquic_data_sendinfo))];
    size_t data_length = sizeof(frames->length) * num_frames + total_frame_data_length;
    void *data = malloc(data_length);
    struct hyquic_data_sendinfo *info;
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
    info = (struct hyquic_data_sendinfo*)CMSG_DATA(cmsg);
    info->type = HYQUIC_DATA_RAW_FRAMES;
    info->data_length = data_length;
    info->raw_frames = (struct hyquic_data_raw_frames) {
        .first_frame_seqnum = 0 // TODO needed?
    };

    return sendmsg(sockfd, &msg, 0);
}

union hyquic_cmsg_content {
    struct quic_stream_info stream;
    struct hyquic_data_recvinfo hyquic;
};

int hyquic_receive(int sockfd, const struct hyquic_receive_ops *recv_ops, size_t len)
{
    union hyquic_cmsg_content info;
    char cmsg[CMSG_SPACE(sizeof(union hyquic_cmsg_content))];
    struct cmsghdr *cursor;
    struct msghdr msg;
	struct iovec iov;
    void *data = malloc(len);
    int err;

    memset(&msg, 0, sizeof(msg));

	iov.iov_base = data;
	iov.iov_len = len;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
	msg.msg_controllen = sizeof(cmsg);

    err = recvmsg(sockfd, &msg, 0);
    if (err < 0)
		goto out;

    for (cursor = CMSG_FIRSTHDR(&msg); cursor != NULL; cursor = CMSG_NXTHDR(&msg, cursor)) {
        if (cursor->cmsg_level != IPPROTO_QUIC)
            continue;
        if (cursor->cmsg_type == QUIC_STREAM_INFO) {
            memcpy(&info.stream, CMSG_DATA(cursor), sizeof(struct quic_stream_info));
            err = recv_ops->recv_stream_data(data, &info.stream);
            break;
        }
        if (cursor->cmsg_type == HYQUIC_INFO) {
            memcpy(&info.hyquic, CMSG_DATA(cursor), sizeof(struct hyquic_data_recvinfo));
            err = recv_ops->recv_hyquic_data(data, &info.hyquic);
            break;
        }
    }

out:
    free(data);
    return err;
}