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
#include "frame_format_spec.hpp"

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

    struct frame_details_container
    {
        hyquic_frame_details frame_details;
        buffer format_specification;

        frame_details_container(
            uint64_t frame_type,
            bool ack_eliciting,
            bool ack_immediate,
            bool non_probing,
            buffer &&format_specification
        )
            : frame_details{
                .frame_type = frame_type,
                .format_specification_avail = (uint16_t) format_specification.len,
                .ack_eliciting = ack_eliciting,
                .ack_immediate = ack_immediate,
                .non_probing = non_probing
            },
            format_specification(std::move(format_specification))
        {
        }

        frame_details_container(const frame_details_container&) = delete;
        frame_details_container& operator=(frame_details_container&) = delete;

        frame_details_container(frame_details_container &&other)
            : frame_details(other.frame_details), format_specification(std::move(other.format_specification))
        {
            other.frame_details = {0};
        }

        frame_details_container& operator=(frame_details_container &&other)
        {
            std::swap(frame_details, other.frame_details);
            std::swap(format_specification, other.format_specification);
            return *this;
        }
    };

    int set_transport_parameter(int sockfd, buffer &&param, const std::vector<frame_details_container> &frame_details_list)
    {
        size_t num_frame_details = frame_details_list.size();
        size_t format_specifications_length = 0;
        for (const frame_details_container &frame_details_cont : frame_details_list)
            format_specifications_length += frame_details_cont.format_specification.len;
        size_t frame_details_length = num_frame_details * sizeof(hyquic_frame_details) + format_specifications_length;

        buffer buff(sizeof(size_t) + frame_details_length + param.len);
        buffer_view cursor(buff);

        cursor.push(num_frame_details);
        for (const frame_details_container &frame_details_cont : frame_details_list) {
            cursor.push(frame_details_cont.frame_details);
            cursor.push_buff(frame_details_cont.format_specification);
        }
        cursor.push_buff_into(std::move(param));

        return socket_setsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM, buff.data, buff.len);
    }

    struct frame_to_send_container
    {
        buffer frame;
        hyquic_frame_to_send_metadata metadata;

        frame_to_send_container(
            buffer &&frame,
            uint32_t payload_length = 0,
            bool has_stream_info = false,
            quic_stream_info stream_info = {}
        )
            : frame(std::move(frame)),
            metadata{
                .frame_length = this->frame.len,
                .payload_length = payload_length,
                .has_stream_info = has_stream_info,
                .stream_info = stream_info
            }
        {
        }

        frame_to_send_container(const frame_to_send_container&) = delete;
        frame_to_send_container& operator=(frame_to_send_container&) = delete;

        frame_to_send_container(frame_to_send_container &&other)
            : frame(std::move(other.frame)), metadata(other.metadata)
        {
            other.metadata = {0};
        }

        frame_to_send_container& operator=(frame_to_send_container &&other)
        {
            std::swap(frame, other.frame);
            std::swap(metadata, other.metadata);
            return *this;
        }
    };

    static inline buffer assemble_frame_data(std::list<frame_to_send_container> &frames)
    {
        size_t total_frame_data_length = 0;
        for (const frame_to_send_container &frame_cont : frames)
            total_frame_data_length += frame_cont.metadata.frame_length;

        buffer buff(sizeof(hyquic_frame_to_send_metadata) * frames.size() + total_frame_data_length);
        buffer_view cursor(buff);

        while (!frames.empty()) {
            frame_to_send_container frame_cont = std::move(frames.front());
            frames.pop_front();
            cursor.push(frame_cont.metadata);
            cursor.push_buff_into(std::move(frame_cont.frame));
        }

        return buff;
    }

    int send_frames(int sockfd, std::list<frame_to_send_container> &frames)
    {
        buffer buff = assemble_frame_data(frames);
        char outcmsg[CMSG_SPACE(sizeof(hyquic_ctrlsend_info))];
        hyquic_ctrlsend_info *info;
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
        info = (hyquic_ctrlsend_info*) CMSG_DATA(cmsg);
        info->type = HYQUIC_CTRL_RAW_FRAMES;
        info->data_length = buff.len;
        info->raw_frames = (hyquic_ctrl_raw_frames) {};

        err = sendmsg(sockfd, &msg, 0);
        if (err < 0)
            return err;
        return err != buff.len;
    }

    int send_notify_bytes_parsed(int sockfd, const hyquic_ctrlsend_raw_frames_var &content)
    {
        char outcmsg[CMSG_SPACE(sizeof(hyquic_ctrlsend_info))];
        hyquic_ctrlsend_info *info;
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
        info = (hyquic_ctrlsend_info*) CMSG_DATA(cmsg);
        info->type = HYQUIC_CTRL_RAW_FRAMES_VAR;
        info->data_length = 0;
        info->raw_frames_var = content;

        return sendmsg(sockfd, &msg, 0);
    }

    struct receive_ops {
        std::function<int(buffer&&, const quic_stream_info&)> recv_stream_data;
        std::function<int(buffer&&, const hyquic_ctrlrecv_info&)> recv_hyquic_ctrl_data;
    };

    union hyquic_cmsg_content {
        quic_stream_info stream;
        hyquic_ctrlrecv_info hyquic;
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
                memcpy(&info.hyquic, CMSG_DATA(cursor), sizeof(hyquic_ctrlrecv_info));
                err = recv_ops.recv_hyquic_ctrl_data(std::move(buff), info.hyquic);
                break;
            }
        }
        return err;
    }
} // namespace si
} // namespace hyquic

#endif // __HYQUIC_SOCK_INTERFACE_HPP__