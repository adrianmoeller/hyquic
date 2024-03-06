#ifndef __HYQUIC_SOCK_INTERFACE_HPP__
#define __HYQUIC_SOCK_INTERFACE_HPP__

#include <iostream>
#include <cstring>
#include <functional>
#include <linux/quic.h>
#include <linux/hyquic.h>
#include <sys/socket.h>
#include "intercom.hpp"
#include "buffer.hpp"

namespace hyquic
{
    int set_transport_parameter(int sockfd, const buffer &param, const hyquic_frame_details *frame_details, size_t num_frame_details)
    {
        size_t frame_details_length = num_frame_details * sizeof(hyquic_frame_details);
        size_t data_length = sizeof(size_t) + frame_details_length + param.len;
        void *data = malloc(data_length);
        uint8_t *p = (uint8_t*) data;
        int err;

        memcpy(p, &num_frame_details, sizeof(size_t));
        p += sizeof(size_t);
        memcpy(p, frame_details, frame_details_length);
        p += frame_details_length;
        memcpy(p, param.data, param.len);

        err = setsockopt(sockfd, SOL_QUIC, HYQUIC_SOCKOPT_TRANSPORT_PARAM, data, data_length);

        free(data);
        return err;
    }

    static inline void assemble_frame_data(const buffer *frames, size_t num_frames, void *data)
    {
        const buffer *frame_cursor = frames;
        uint8_t *data_cursor = (uint8_t*) data;
        int i;

        for (i = 0; i < num_frames; i++) {
            data_cursor = ic::put_int(data_cursor, frame_cursor->len, 4);
            data_cursor = ic::put_data(data_cursor, frame_cursor->data, frame_cursor->len);
            frame_cursor += sizeof(*frame_cursor);
        }
    }

    int send_frames(int sockfd, const buffer *frames, size_t num_frames, size_t total_frame_data_length)
    {
        char outcmsg[CMSG_SPACE(sizeof(hyquic_data_sendinfo))];
        size_t data_length = sizeof(frames->len) * num_frames + total_frame_data_length;
        void *data = malloc(data_length);
        hyquic_data_sendinfo *info;
        msghdr msg;
        cmsghdr *cmsg;
        iovec iov;

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
        info = (hyquic_data_sendinfo*)CMSG_DATA(cmsg);
        info->type = HYQUIC_DATA_RAW_FRAMES;
        info->data_length = data_length;
        info->raw_frames = (hyquic_data_raw_frames) {
            .first_frame_seqnum = 0 // TODO needed?
        };

        return sendmsg(sockfd, &msg, 0);
    }

    struct receive_ops {
        std::function<int(buffer&&, const quic_stream_info&)> recv_stream_data;
        std::function<int(buffer&&, const hyquic_data_recvinfo&)> recv_hyquic_data;
    };

    union hyquic_cmsg_content {
        quic_stream_info stream;
        hyquic_data_recvinfo hyquic;
    };

    int receive(int sockfd, const receive_ops &recv_ops, size_t len)
    {
        hyquic_cmsg_content info;
        char cmsg[CMSG_SPACE(sizeof(hyquic_cmsg_content))];
        cmsghdr *cursor;
        msghdr msg;
        iovec iov;
        buffer buff((uint8_t*) malloc(len), len);
        int err;

        memset(&msg, 0, sizeof(msg));

        iov.iov_base = buff.data;
        iov.iov_len = len;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg;
        msg.msg_controllen = sizeof(cmsg);

        err = recvmsg(sockfd, &msg, 0);
        if (err < 0)
            return err;

        buff.len = uint32_t(err);

        for (cursor = CMSG_FIRSTHDR(&msg); cursor != NULL; cursor = CMSG_NXTHDR(&msg, cursor)) {
            if (cursor->cmsg_level != IPPROTO_QUIC)
                continue;
            if (cursor->cmsg_type == QUIC_STREAM_INFO) {
                memcpy(&info.stream, CMSG_DATA(cursor), sizeof(quic_stream_info));
                err = recv_ops.recv_stream_data(std::move(buff), info.stream);
                break;
            }
            if (cursor->cmsg_type == HYQUIC_INFO) {
                memcpy(&info.hyquic, CMSG_DATA(cursor), sizeof(hyquic_data_recvinfo));
                err = recv_ops.recv_hyquic_data(std::move(buff), info.hyquic);
                break;
            }
        }
        return err;
    }
} // namespace hyquic



#endif // __HYQUIC_SOCK_INTERFACE_HPP__