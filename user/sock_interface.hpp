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

    struct frame_profile_container
    {
        hyquic_frame_profile frame_profile;
        buffer format_specification;

        frame_profile_container(
            uint64_t frame_type,
            hyquic_frame_send_mode send_mode,
            hyquic_frame_recv_mode recv_mode,
            bool no_retransmit,
            bool ack_eliciting,
            bool ack_immediate,
            bool non_probing,
            buffer &&format_specification
        )
            : frame_profile{
                .frame_type = frame_type,
                .format_specification_avail = (uint16_t) format_specification.len,
                .send_mode = send_mode,
                .recv_mode = recv_mode,
                .no_retransmit = no_retransmit,
                .ack_eliciting = ack_eliciting,
                .ack_immediate = ack_immediate,
                .non_probing = non_probing
            },
            format_specification(std::move(format_specification))
        {
        }

        frame_profile_container(const frame_profile_container&) = delete;
        frame_profile_container& operator=(frame_profile_container&) = delete;

        frame_profile_container(frame_profile_container &&other)
            : frame_profile(other.frame_profile), format_specification(std::move(other.format_specification))
        {
            other.frame_profile = {0};
        }

        frame_profile_container& operator=(frame_profile_container &&other)
        {
            std::swap(frame_profile, other.frame_profile);
            std::swap(format_specification, other.format_specification);
            return *this;
        }
    };
    
    /**
     * Convenience wrapper to communicate an additional transport parameter including frame profiles to the kernel-quic.
     * 
     * @param sockfd socket file descriptor
     * @param param encoded transport parameter
     * @param frame_profiles a list of frame profile containers
     * @return negative error code if not successful, otherwise 0
     */
    int set_transport_parameter(int sockfd, buffer &&param, const std::vector<frame_profile_container> &frame_profiles)
    {
        size_t num_frame_profiles = frame_profiles.size();
        size_t format_specifications_length = 0;
        for (const frame_profile_container &frame_profile_cont : frame_profiles)
            format_specifications_length += frame_profile_cont.format_specification.len;
        size_t frame_profiles_length = num_frame_profiles * sizeof(hyquic_frame_profile) + format_specifications_length;

        buffer buff(sizeof(size_t) + frame_profiles_length + param.len);
        buffer_view cursor(buff);

        cursor.push(num_frame_profiles);
        for (const frame_profile_container &frame_profile_cont : frame_profiles) {
            cursor.push(frame_profile_cont.frame_profile);
            cursor.push_buff(frame_profile_cont.format_specification);
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
            uint8_t retransmit_count = 0,
            bool has_stream_info = false,
            quic_stream_info stream_info = {}
        )
            : frame(std::move(frame)),
            metadata{
                .frame_length = this->frame.len,
                .payload_length = payload_length,
                .retransmit_count = retransmit_count,
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

    /**
     * Abstract class that holds frames to be sent to the kernel-quic.
     * It provides an interface to simplify the encoding process of the message holding all the frames.
     */
    class frames_to_send_provider
    {
    public:
        /**
         * @return the total length of all currently contained frames
         */
        virtual size_t total_frames_data_length() const = 0;
        /**
         * @return the number of contained frames
         */
        virtual size_t size() const = 0;
        /**
         * @return if there are no contained frames
         */
        virtual bool empty() const = 0;
        /**
         * Removes the next frame to be sent and returns it.
         * 
         * @return the next frame to be sent
         */
        virtual frame_to_send_container pop() = 0;
    };

    /**
     * The default provider for frames to be sent maintaining a single FIFO queue of frames.
     */
    class default_frames_to_send_provider : public frames_to_send_provider
    {
    public:
        std::list<frame_to_send_container> frames;

        size_t total_frames_data_length() const
        {
            size_t total_frame_data_length = 0;
            for (const frame_to_send_container &frame_cont : frames)
                total_frame_data_length += frame_cont.metadata.frame_length;
            return total_frame_data_length;
        }

        size_t size() const
        {
            return frames.size();
        }

        bool empty() const
        {
            return frames.empty();
        }

        frame_to_send_container pop()
        {
            frame_to_send_container frame_cont = std::move(frames.front());
            frames.pop_front();
            return frame_cont;
        }

        void push(frame_to_send_container &&frame)
        {
            frames.push_back(std::move(frame));
        }
    };

    static inline buffer assemble_frame_data(frames_to_send_provider &frames)
    {
        size_t total_frame_data_length = frames.total_frames_data_length();

        buffer buff(sizeof(hyquic_frame_to_send_metadata) * frames.size() + total_frame_data_length);
        buffer_view cursor(buff);

        while (!frames.empty()) {
            frame_to_send_container frame_cont = frames.pop();
            cursor.push(frame_cont.metadata);
            cursor.push_buff_into(std::move(frame_cont.frame));
        }

        return buff;
    }

    /**
     * Convenience wrapper for sending encoded frames to the kernel-quic.
     * 
     * @param sockfd socket file descriptor
     * @param frames provider of to be sent frames
     * @param dont_wait does not block until sending is completed
     * @return negative error code if not successful, otherwise the number of bytes sent (of all sent data, not only the frames)
     */
    int send_frames(int sockfd, frames_to_send_provider &frames, bool dont_wait = false)
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
        info->type = HYQUIC_CTRL_FRAMES;
        info->data_length = buff.len;
        info->raw_frames = (hyquic_ctrl_raw_frames) {
            .dont_wait = dont_wait
        };

        return sendmsg(sockfd, &msg, 0);
    }

    /**
     * Convenience wrapper for sending a reply with the parsed bytes of a remaining packet content back to the kernel-quic.
     * 
     * @param sockfd socket file descriptor
     * @param content hyquic control data message
     * @return negative error code if not successful, otherwise the number of bytes sent
     */
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
        info->type = HYQUIC_CTRL_USER_PARSED_FRAMES;
        info->data_length = 0;
        info->raw_frames_var = content;

        return sendmsg(sockfd, &msg, 0);
    }

    /**
     * Both functions should return a negative error code if not successful, otherwise the number of bytes received.
     */
    struct receive_ops {
        std::function<int(buffer&&, const quic_stream_info&)> recv_stream_data;
        std::function<int(buffer&&, const hyquic_ctrlrecv_info&)> recv_hyquic_ctrl_data;
    };

    union hyquic_cmsg_content {
        quic_stream_info stream;
        hyquic_ctrlrecv_info hyquic;
    };

    /**
     * Convenience wrapper for receiving data from the kernel-quic providing demultiplexing of stream data and hyquic control data.
     * 
     * @param sockfd socket file descriptor
     * @param recv_ops handlers for received stream data and hyquic control data
     * @param len length of the socket receive buffer
     * @return negative error code if not successful, otherwise the number of bytes received 
     */
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