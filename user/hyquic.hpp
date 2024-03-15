#ifndef __HYQUIC_HPP__
#define __HYQUIC_HPP__

extern "C" {
#include <netinet/quic.h>
}
#include <iostream>
#include <linux/quic.h>
#include <linux/hyquic.h>
#include <boost/asio.hpp>
#include <memory>
#include <cstdint>
#include <cassert>
#include <cerrno>
#include <vector>
#include <list>
#include <functional>
#include <unordered_map>
#include <atomic>
#include "buffer.hpp"
#include "sock_interface.hpp"
#include "errors.hpp"

namespace hyquic
{
    class extension
    {
    protected:
        buffer remote_param_content;

        virtual inline buffer transport_parameter() = 0;
        virtual const std::vector<hyquic_frame_details>& frame_details_list() = 0;
        virtual uint32_t handle_frame(uint64_t type, buffer_view frame_content) = 0;
        virtual void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame) = 0;
    
    private:
        void set_remote_transport_parameter(buffer &&content)
        {
            remote_param_content = std::move(content);
        }

        friend class hyquic;
    };

#define RECV_STREAM_BUFF_INIT_SIZE  2048
#define RECV_BUFF_INIT_SIZE         65507

    class hyquic
    {
    public:
        hyquic()
            : running(false), closed(false), recv_buff(RECV_STREAM_BUFF_INIT_SIZE), recv_context(1), common_context(1)
        {
        }

        ~hyquic()
        {
            si::socket_close(sockfd);
            closed.store(true);

            recv_context.stop();
            common_context.stop();
            recv_context.join();
            common_context.join();
        }

        hyquic(const hyquic&) = delete;
        hyquic& operator=(hyquic&) = delete;

        void register_extension(extension &ext)
        {
            if (running)
                throw extension_config_error("Extensions must be registered before running HyQUIC.");

            for (auto const &frame_details : ext.frame_details_list()) {
                if (extension_reg.contains(frame_details.frame_type))
                    throw extension_config_error("A frame type can only be managed by one extension at a time.");
                extension_reg.insert({frame_details.frame_type, std::ref(ext)});
                frame_details_reg.insert({frame_details.frame_type, frame_details});
            }

            buffer transport_param = ext.transport_parameter();
            buffer_view transport_param_view(transport_param);
            uint64_t transport_param_id;
            transport_param_view.pull_var(transport_param_id);

            if (tp_id_to_extension.contains(transport_param_id))
                throw extension_config_error("A transport parameter can only be managed by one extension at a time.");
            tp_id_to_extension.insert({transport_param_id, std::ref(ext)});

            int err = si::set_transport_parameter(sockfd, std::move(transport_param), ext.frame_details_list());
            if (err)
                throw network_error("Setting local transport parameter failed.", err);
        }

        inline int set_socket_option(int optname, const void *optval, socklen_t optlen)
        {
            return si::socket_setsockopt(sockfd, optname, optval, optlen);
        }

        inline int get_socket_option(int optname, void *optval, socklen_t *optlen)
        {
            return si::socket_getsockopt(sockfd, optname, optval, optlen);
        }

        inline int send_frames(std::list<buffer> &frames)
        {
            return si::send_frames(sockfd, frames);
        }

        int send_msg()
        {
            // TODO

            return 0;
        }

        int receive_msg()
        {
            // TODO

            return 0;
        }

        inline int close()
        {
            return si::socket_close(sockfd);
        }

    protected:
        bool running;
        std::atomic<bool> closed;
        int sockfd;

        void run()
        {
            running = true;
            boost::asio::post(recv_context, [this]() {
                recv_loop();
            });
        }

        void collect_remote_transport_parameter()
        {
            int err;

            uint32_t total_transport_params_length;
            socklen_t len = sizeof(total_transport_params_length);
            err = si::socket_getsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN, &total_transport_params_length, &len);
            if (err)
                throw network_error("Getting remote transport parameters length failed.", err);

            buffer transport_parameters(total_transport_params_length);
            err = si::socket_getsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM, transport_parameters.data, &total_transport_params_length);
            if (err)
                throw network_error("Getting remote transport parameters failed.", err);
            assert(transport_parameters.len == total_transport_params_length);

            buffer_view cursor(transport_parameters);
            while(!cursor.end()) {
                buffer_view tp_beginning(cursor);
                uint64_t tp_length = 0;
                uint8_t var_length;

                uint64_t tp_id;
                var_length = cursor.pull_var(tp_id);
                assert(!var_length);
                tp_length += var_length;

                if (!tp_id_to_extension.contains(tp_id))
                    continue;

                uint64_t tp_content_length;
                var_length = cursor.pull_var(tp_content_length);
                assert(!var_length);
                tp_length += var_length + tp_content_length;
                cursor.prune(tp_content_length);

                extension &ext = tp_id_to_extension.at(tp_id);
                ext.set_remote_transport_parameter(tp_beginning.copy(tp_length));
            }
        }

    private:
        boost::asio::thread_pool common_context;
        boost::asio::thread_pool recv_context;
        stream_data_buff recv_buff;
        std::unordered_map<uint64_t, std::reference_wrapper<extension>> extension_reg;
        std::unordered_map<uint64_t, std::reference_wrapper<extension>> tp_id_to_extension;
        std::unordered_map<uint64_t, hyquic_frame_details> frame_details_reg;

        struct {
            hyquic_data_type type;
            buffer buff;
            buffer_view buff_view;

            inline void init(hyquic_data_type type, uint32_t len)
            {
                this->type = type;
                this->buff = buffer(len);
                this->buff_view = buffer_view(this->buff);
            }

            inline void clear()
            {
                type = HYQUIC_DATA_NONE;
                buff = buffer();
            }

            inline bool empty()
            {
                return buff.empty();
            }
        } hyquic_data_frag;

        si::receive_ops recv_ops {
            .recv_stream_data = [this](buffer&& data, const quic_stream_info& info) {
                return hyquic::recv_stream_data(std::move(data), info);
            },
            .recv_hyquic_data = [this](buffer&& data, const hyquic_data_recvinfo& info) {
                return hyquic::recv_hyquic_data(std::move(data), info);
            }
        };

        inline int recv_stream_data(buffer&& data, const quic_stream_info& info)
        {
            int ret = data.len;
            auto stream_data_ptr = std::make_shared<stream_data>(info.stream_id, info.stream_flag, std::move(data));
            if(!recv_buff.push(stream_data_ptr))
                ret = -ENOBUFS;
            return ret;
        }

        inline int recv_hyquic_data(buffer&& data, const hyquic_data_recvinfo& info)
        {
            int ret = data.len;
            if (info.incompl) {
                if (hyquic_data_frag.buff.empty()) {
                    hyquic_data_frag.init(info.type, info.data_length);
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                }
                if (!hyquic_data_frag.buff_view.push_buff(std::move(data)))
                    return -EFAULT;
            } else {
                if (hyquic_data_frag.buff.empty()) {
                    boost::asio::post(common_context, [this, mvd_data = std::move(data), type = info.type, details = info.details]() {
                        hyquic::handle_hyquic_data(mvd_data, type, details);
                    });
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.push_buff(std::move(data)))
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.end())
                        return -EFAULT;
                    boost::asio::post(common_context, [this, mvd_data = std::move(hyquic_data_frag.buff), type = info.type, details = info.details]() {
                        hyquic::handle_hyquic_data(mvd_data, type, details);
                    });
                    hyquic_data_frag.clear();
                }
            }
            return ret;
        }

        void recv_loop()
        {
            int err = si::receive(sockfd, recv_ops, RECV_BUFF_INIT_SIZE);
            if (err <= 0)
                return;
            boost::asio::post(recv_context, [this]() {
                recv_loop();
            });
        }

        void handle_hyquic_data(const buffer &buff, hyquic_data_type data_type, const hyquic_data_recvinfo_details &details)
        {
            assert(buff.len);
            switch (data_type)
            {
            case HYQUIC_DATA_RAW_FRAMES_FIX: {
                buffer_view buff_view(buff);
                uint64_t frame_type;

                while(!buff_view.end()) {
                    assert(buff_view.pull_var(frame_type));
                    assert(extension_reg.contains(frame_type));
                    extension &ext = extension_reg.at(frame_type);
                    uint32_t frame_content_len = ext.handle_frame(frame_type, buff_view);
                    buff_view.prune(frame_content_len);
                }
                break;
            }
            case HYQUIC_DATA_RAW_FRAMES_VAR: {
                buffer_view buff_view(buff);
                uint64_t frame_type;
                uint8_t frame_type_len;
                hyquic_data_raw_frames_var_send parsing_results = {
                    .msg_id = details.raw_frames_var.msg_id,
                    .processed_length = 0,
                    .ack_eliciting = details.raw_frames_var.ack_eliciting,
                    .ack_immediate = details.raw_frames_var.ack_immediate,
                    .non_probing = details.raw_frames_var.non_probing
                };

                frame_type_len = buff_view.pull_var(frame_type);
                assert(frame_type_len);
                while (extension_reg.contains(frame_type)) {
                    extension &ext = extension_reg.at(frame_type);
                    const hyquic_frame_details &frame_details = frame_details_reg.at(frame_type);
                    uint32_t frame_content_len = ext.handle_frame(frame_type, buff_view);

                    parsing_results.processed_length += frame_type_len + frame_content_len;
                    if (frame_details.ack_eliciting) {
                        parsing_results.ack_eliciting = true;
                        if (frame_details.ack_immediate)
                            parsing_results.ack_immediate = true;
                    }
                    if (frame_details.non_probing)
                        parsing_results.non_probing = true;

                    buff_view.prune(frame_content_len);
                    if (buff_view.end())
                        break;

                    frame_type_len = buff_view.pull_var(frame_type);
                    assert(frame_type_len);
                }
                int err = si::send_notify_bytes_parsed(sockfd, parsing_results);
                if (err)
                    throw network_error("Sending parsed bytes notification failed.", err);
                break;
            }
            case HYQUIC_DATA_LOST_FRAMES: {
                const buffer_view buff_view(buff);
                buffer_view buff_view_content(buff);
                uint64_t frame_type;

                assert(buff_view_content.pull_var(frame_type));
                assert(extension_reg.contains(frame_type));
                extension &ext = extension_reg.at(frame_type);
                ext.handle_lost_frame(frame_type, buff_view_content, buff_view);
                break;
            }
            default:
                break;
            }
        }
    };
} // namespace hyquic

#endif // __HYQUIC_HPP__