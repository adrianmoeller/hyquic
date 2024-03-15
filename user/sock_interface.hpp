#ifndef __HYQUIC_SOCK_INTERFACE_HPP__
#define __HYQUIC_SOCK_INTERFACE_HPP__

#include <iostream>
#include <functional>
#include <vector>
#include <list>
#include <linux/quic.h>
#include <linux/hyquic.h>
#include <sys/socket.h>
#include "buffer.hpp"

namespace hyquic
{
namespace si
{
    inline int socket_socket(int domain, int type)
    {
        return socket(domain, type, IPPROTO_QUIC);
    }

    inline int socket_connect(int sockfd, const sockaddr *addr, socklen_t len)
    {
        return connect(sockfd, addr, len);
    }

    inline int socket_bind(int sockfd, const sockaddr *addr, socklen_t len)
    {
        return bind(sockfd, addr, len);
    }

    inline int socket_listen(int sockfd, int n)
    {
        return listen(sockfd, n);
    }

    inline int socket_accept(int sockfd, sockaddr *addr, socklen_t *len)
    {
        return accept(sockfd, addr, len);
    }

    inline int socket_setsockopt(int sockfd, int optname, const void *optval, socklen_t optlen)
    {
        return setsockopt(sockfd, SOL_QUIC, optname, optval, optlen);
    }

    inline int socket_getsockopt(int sockfd, int optname, void *optval, socklen_t *optlen)
    {
        return getsockopt(sockfd, SOL_QUIC, optname, optval, optlen);
    }

    inline int socket_close(int sockfd)
    {
        return close(sockfd);
    }

    int set_transport_parameter(int sockfd, buffer &&param, const std::vector<hyquic_frame_details> &frame_details_list)
    {
        size_t num_frame_details = frame_details_list.size();
        size_t frame_details_length = num_frame_details * sizeof(hyquic_frame_details);
        buffer buff(sizeof(size_t) + frame_details_length + param.len);
        buffer_view cursor(buff);

        cursor.push(num_frame_details);
        for (const hyquic_frame_details &frame_details : frame_details_list)
            cursor.push(frame_details);
        cursor.push_buff(std::move(param));

        return socket_setsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM, buff.data, buff.len);
    }

    static inline buffer assemble_frame_data(std::list<buffer> &frames)
    {
        size_t total_frame_data_length = 0;
        for (const buffer &frame_buff : frames)
            total_frame_data_length += frame_buff.len;

        buffer buff(4 * frames.size() + total_frame_data_length);
        buffer_view cursor(buff);

        while (!frames.empty()) {
            buffer frame_buff = std::move(frames.front());
            frames.pop_front();
            cursor.push_int<NATIVE>(frame_buff.len, 4);
            cursor.push_buff(std::move(frame_buff));
        }

        return buff;
    }

    int send_frames(int sockfd, std::list<buffer> &frames)
    {
        buffer buff = assemble_frame_data(frames);
        char outcmsg[CMSG_SPACE(sizeof(hyquic_data_sendinfo))];
        hyquic_data_sendinfo *info;
        msghdr msg;
        cmsghdr *cmsg;
        iovec iov;
        int err;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        iov.iov_base = buff.data;
        iov.iov_len = buff.len;
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
        info->data_length = buff.len;
        info->raw_frames = (hyquic_data_raw_frames) {
            .first_frame_seqnum = 0 // TODO needed?
        };

        err = sendmsg(sockfd, &msg, 0);
        if (err < 0)
            return err;
        return err != buff.len;
    }

    int send_notify_bytes_parsed(int sockfd, const hyquic_data_raw_frames_var_send &content)
    {
        char outcmsg[CMSG_SPACE(sizeof(hyquic_data_sendinfo))];
        hyquic_data_sendinfo *info;
        msghdr msg;
        cmsghdr *cmsg;
        iovec iov;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        iov.iov_base = nullptr;
        iov.iov_len = 0;
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
        info->type = HYQUIC_DATA_RAW_FRAMES_VAR;
        info->data_length = 0;
        info->raw_frames_var = content;

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
} // namespace si
} // namespace hyquic

#endif // __HYQUIC_SOCK_INTERFACE_HPP__