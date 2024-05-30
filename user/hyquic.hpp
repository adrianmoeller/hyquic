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
#include "debug.hpp"

namespace hyquic
{
    struct stream_data
    {
        uint64_t id;
        uint32_t flags;
        buffer buff;

        stream_data(uint64_t id, uint32_t flags, buffer &&buff)
            : id(id), flags(flags), buff(std::move(buff))
        {
        }

        stream_data(const stream_data&) = delete;
        stream_data& operator=(stream_data&) = delete;

        stream_data(stream_data &&other)
            : id(other.id), flags(other.flags), buff(std::move(other.buff))
        {
        }

        stream_data& operator=(stream_data &&other)
        {
            std::swap(id, other.id);
            std::swap(flags, other.flags);
            std::swap(buff, other.buff);
            return *this;
        }
    };

    struct handle_frame_result
    {
        uint32_t content_len;
        uint32_t payload_len = 0;
    };

    struct lost_frame_metadata
    {
        uint32_t payload_length;
        uint8_t retransmit_count;
        bool last_frame;
    };

    class extension
    {
    protected:
        bool remote_transport_param_available = false;
        buffer remote_transport_param_content;

        virtual inline buffer transport_parameter() = 0;
        virtual const std::vector<si::frame_profile_container>& frame_profiles_list() = 0;
        virtual handle_frame_result handle_frame(uint64_t type, buffer_view frame_content) = 0;
        virtual void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame, const lost_frame_metadata &metadata) = 0;
        virtual void before_connection_initiation()
        {
            // NO-OP
        }
        virtual void handshake_done()
        {
            // NO-OP
        }
    
    private:
        void set_remote_transport_parameter(buffer &&content)
        {
            remote_transport_param_available = true;
            remote_transport_param_content = std::move(content);
        }

        friend class hyquic;
    };

#define SOCK_RECV_TIMEOUT 2 // sec
#define SOCK_RECV_BUFF_INIT_SIZE 4096 * 16
#define SOCK_RECV_FAILURE_THRESHOLD 15
#define SOCK_RECV_FAILURE_RECOVERY_TIME 200 // ms

    class hyquic
    {
    public:
        hyquic(
            uint32_t sock_recv_buff_size = SOCK_RECV_BUFF_INIT_SIZE, 
            time_t sock_recv_timeout = SOCK_RECV_TIMEOUT, 
            uint32_t sock_recv_failure_recovery_time = SOCK_RECV_FAILURE_RECOVERY_TIME
        )
            : running(false),
            ready_to_send(false),
            sock_recv_buff_size(sock_recv_buff_size),
            sock_recv_timeout(sock_recv_timeout),
            sock_recv_failure_recovery_time(sock_recv_failure_recovery_time),
            sock_recv_failures_in_row(0),
            recv_context(1), 
            common_context(1),
            recv_timer(recv_context),
            max_payload(0), 
            max_payload_dgram(0)
        {
        }

        ~hyquic()
        {
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

            for (auto const &frame_profile_cont : ext.frame_profiles_list()) {
                if (extension_reg.contains(frame_profile_cont.frame_profile.frame_type))
                    throw extension_config_error("A frame type can only be managed by one extension at a time.");
                extension_reg.insert({frame_profile_cont.frame_profile.frame_type, std::ref(ext)});
                frame_profile_reg.insert({frame_profile_cont.frame_profile.frame_type, frame_profile_cont.frame_profile});
            }

            buffer transport_param = ext.transport_parameter();
            buffer_view transport_param_view(transport_param);
            uint64_t transport_param_id;
            transport_param_view.pull_var(transport_param_id);

            if (tp_id_to_extension.contains(transport_param_id))
                throw extension_config_error("A transport parameter can only be managed by one extension at a time.");
            tp_id_to_extension.insert({transport_param_id, std::ref(ext)});

            int err = si::set_transport_parameter(sockfd, std::move(transport_param), ext.frame_profiles_list());
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

        inline int send_frames(si::frames_to_send_provider &frames, bool dont_wait = false)
        {
            if (!ready_to_send)
                return -EAGAIN;

            return si::send_frames(sockfd, frames, dont_wait);
        }

        inline int send_one_frame(si::frame_to_send_container &&frame_cont, bool dont_wait = false)
        {
            if (!ready_to_send)
                return -EAGAIN;

            si::default_frames_to_send_provider frames_to_send;
            frames_to_send.push(std::move(frame_cont));
            return send_frames(frames_to_send, dont_wait);
        }

        inline int send_msg(const stream_data& msg)
        {
            if (!ready_to_send)
                return -EAGAIN;
                
            return quic_sendmsg(sockfd, msg.buff.data, msg.buff.len, msg.id, msg.flags);
        }

        inline stream_data receive_msg()
        {
            return recv_buff.wait_pop();
        }

        template<class Rep, class Period>
        inline std::optional<stream_data> receive_msg(const std::chrono::duration<Rep, Period> &timeout)
        {
            return recv_buff.wait_pop_for(timeout);
        }

        inline int close()
        {
            running = false;
            return si::socket_close(sockfd);
        }

        inline boost::asio::thread_pool& get_context()
        {
            return common_context;
        }

        const inline uint32_t get_max_payload() const
        {
            return max_payload;
        }

        const inline uint32_t get_max_payload_dgram() const
        {
            return max_payload_dgram;
        }

    protected:
        bool running;
        bool ready_to_send;
        int sockfd;

        void run()
        {
            running = true;
            set_receive_timeout();
            collect_remote_transport_parameter();
            get_inital_mss();
            notify_extensions_handshake_done();
            ready_to_send = true;
            boost::asio::post(recv_context, [this]() {
                recv_loop();
            });
        }

        inline int handshake_client(char *pkey_file, char *cert_file)
        {
            notify_extensions_before_connection_initiation();
            return quic_client_handshake(sockfd, pkey_file, cert_file);
        }

        inline int handshake_server(char *pkey_file, char *cert_file)
        {
            notify_extensions_before_connection_initiation();
            return quic_server_handshake(sockfd, pkey_file, cert_file);
        }

    private:
        boost::asio::thread_pool common_context;
        boost::asio::thread_pool recv_context;
        boost::asio::steady_timer recv_timer;
        wait_queue<stream_data> recv_buff;
        uint32_t sock_recv_buff_size;
        time_t sock_recv_timeout;
        uint32_t sock_recv_failure_recovery_time;
        uint16_t sock_recv_failures_in_row;
        std::unordered_map<uint64_t, std::reference_wrapper<extension>> extension_reg;
        std::unordered_map<uint64_t, std::reference_wrapper<extension>> tp_id_to_extension;
        std::unordered_map<uint64_t, hyquic_frame_profile> frame_profile_reg;

        uint32_t max_payload;
        uint32_t max_payload_dgram;

        void set_receive_timeout()
        {
            timeval tv = {
                .tv_sec = sock_recv_timeout,
                .tv_usec = 0
            };
            int err = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*) &tv, sizeof(tv));
            if (err)
                throw network_error("Socket set receive timeout failed.", err);
        }

        void collect_remote_transport_parameter()
        {
            int err;

            uint32_t total_transport_params_length;
            socklen_t len = sizeof(total_transport_params_length);
            err = si::socket_getsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM_LEN, &total_transport_params_length, &len);
            if (err)
                throw network_error("Getting remote transport parameters length failed.", err);

            if (!total_transport_params_length)
                return;

            buffer transport_parameters(total_transport_params_length);
            err = si::socket_getsockopt(sockfd, HYQUIC_SOCKOPT_TRANSPORT_PARAM, transport_parameters.data, &total_transport_params_length);
            if (err)
                throw network_error("Getting remote transport parameters failed.", err);
            assert(transport_parameters.len == total_transport_params_length);

            buffer_view cursor(transport_parameters);
            while (!cursor.end()) {
                buffer_view tp_beginning(cursor);
                uint64_t tp_length = 0;
                uint8_t var_length;

                uint64_t tp_id;
                var_length = cursor.pull_var(tp_id);
                assert(var_length);
                tp_length += var_length;

                uint64_t tp_content_length;
                var_length = cursor.pull_var(tp_content_length);
                assert(var_length);
                tp_length += var_length + tp_content_length;
                cursor.prune(tp_content_length);

                if (!tp_id_to_extension.contains(tp_id))
                    continue;

                extension &ext = tp_id_to_extension.at(tp_id);
                ext.set_remote_transport_parameter(tp_beginning.copy(tp_length));
            }
        }

        void get_inital_mss()
        {
            hyquic_ctrlrecv_mss_update initial_mss;
            socklen_t len = sizeof(initial_mss);
            int err = si::socket_getsockopt(sockfd, HYQUIC_SOCKOPT_INITIAL_MSS, &initial_mss, &len);
            if (err)
                throw network_error("Getting initial MSS values failed.", err);

            max_payload = initial_mss.max_payload;
            max_payload_dgram = initial_mss.max_payload_dgram;
        }

        void notify_extensions_handshake_done()
        {
            for (const auto &entry : extension_reg)
                entry.second.get().handshake_done();
        }

        void notify_extensions_before_connection_initiation()
        {
            for (const auto &entry : extension_reg)
                entry.second.get().before_connection_initiation();
        }

        struct {
            hyquic_ctrl_type type;
            buffer buff;
            buffer_view buff_view;

            inline void init(hyquic_ctrl_type type, uint32_t len)
            {
                this->type = type;
                this->buff = buffer(len);
                this->buff_view = buffer_view(this->buff);
            }

            inline void clear()
            {
                type = HYQUIC_CTRL_NONE;
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
            .recv_hyquic_ctrl_data = [this](buffer&& data, const hyquic_ctrlrecv_info& info) {
                return hyquic::recv_hyquic_data(std::move(data), info);
            }
        };

        inline int recv_stream_data(buffer&& data, const quic_stream_info& info)
        {
            int ret = data.len;
            recv_buff.push(stream_data(info.stream_id, info.stream_flag, std::move(data)));
            return ret;
        }

        inline int recv_hyquic_data(buffer&& data, const hyquic_ctrlrecv_info& info)
        {
            int ret = data.len;
            if (info.incompl) {
                if (hyquic_data_frag.buff.empty())
                    hyquic_data_frag.init(info.type, info.data_length);
                else
                    assert(hyquic_data_frag.type == info.type);
                hyquic_data_frag.buff_view.push_buff_into(std::move(data));
            } else {
                if (hyquic_data_frag.buff.empty()) {
                    boost::asio::post(common_context, [this, mvd_data = std::move(data), type = info.type, details = info.details]() {
                        hyquic::handle_hyquic_ctrl_data(mvd_data, type, details);
                    });
                } else {
                    assert(hyquic_data_frag.type == info.type);
                    hyquic_data_frag.buff_view.push_buff_into(std::move(data));
                    assert(hyquic_data_frag.buff_view.end());
                    boost::asio::post(common_context, [this, mvd_data = std::move(hyquic_data_frag.buff), type = info.type, details = info.details]() {
                        hyquic::handle_hyquic_ctrl_data(mvd_data, type, details);
                    });
                    hyquic_data_frag.clear();
                }
            }
            return ret;
        }

        void recv_loop()
        {
            int err = si::receive(sockfd, recv_ops, sock_recv_buff_size);
            if (err < 0) {
                if (err == -EAGAIN || err == -EWOULDBLOCK) {
                    recv_timer.expires_from_now(std::chrono::milliseconds(sock_recv_failure_recovery_time));
                    recv_timer.async_wait([this](const auto& e) {
                        recv_loop();
                    });
                } else if (!running) {
                    return;
                } else {
                    sock_recv_failures_in_row++;
                    if (sock_recv_failures_in_row > SOCK_RECV_FAILURE_THRESHOLD) {
                        throw network_error("Socket receive failed " + std::to_string(sock_recv_failures_in_row) + " times in a row.", err);
                    } else {
                        recv_timer.expires_from_now(std::chrono::milliseconds(sock_recv_failure_recovery_time * (long) std::pow(2, sock_recv_failures_in_row)));
                        recv_timer.async_wait([this](const auto& e) {
                            recv_loop();
                        });
                    }
                }
            } else {
                sock_recv_failures_in_row = 0;

                boost::asio::post(recv_context, [this]() {
                    recv_loop();
                });
            }
        }

        void handle_hyquic_ctrl_data(const buffer &buff, hyquic_ctrl_type data_type, const hyquic_ctrlrecv_info_details &details)
        {
            assert(buff.len);
            switch (data_type)
            {
            case HYQUIC_CTRL_FRAMES: {
                buffer_view buff_view(buff);
                uint64_t frame_type;

                while(!buff_view.end()) {
                    assert(buff_view.pull_var(frame_type));
                    assert(extension_reg.contains(frame_type));
                    extension &ext = extension_reg.at(frame_type);
                    handle_frame_result res = ext.handle_frame(frame_type, buff_view);
                    buff_view.prune(res.content_len);
                }
                break;
            }
            case HYQUIC_CTRL_USER_PARSED_FRAMES: {
                buffer_view buff_view(buff);
                uint64_t frame_type;
                uint8_t frame_type_len;
                hyquic_ctrlsend_raw_frames_var parsing_results = {
                    .msg_id = details.raw_frames_var.msg_id,
                    .processed_length = 0,
                    .processed_payload = 0,
                    .ack_eliciting = details.raw_frames_var.ack_eliciting,
                    .ack_immediate = details.raw_frames_var.ack_immediate,
                    .non_probing = details.raw_frames_var.non_probing
                };

                frame_type_len = buff_view.pull_var(frame_type);
                assert(frame_type_len);
                while (extension_reg.contains(frame_type)) {
                    extension &ext = extension_reg.at(frame_type);
                    const hyquic_frame_profile &frame_profile = frame_profile_reg.at(frame_type);
                    handle_frame_result res = ext.handle_frame(frame_type, buff_view);

                    parsing_results.processed_length += frame_type_len + res.content_len;
                    parsing_results.processed_payload += res.payload_len;
                    if (frame_profile.ack_eliciting) {
                        parsing_results.ack_eliciting = true;
                        if (frame_profile.ack_immediate)
                            parsing_results.ack_immediate = true;
                    }
                    if (frame_profile.non_probing)
                        parsing_results.non_probing = true;

                    buff_view.prune(res.content_len);
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
            case HYQUIC_CTRL_LOST_FRAMES: {
                buffer_view cursor(buff);

                while (!cursor.end()) {
                    hyquic_lost_frame_metadata metadata = cursor.pull<hyquic_lost_frame_metadata>();
                    assert(cursor.len >= metadata.frame_length);

                    const buffer_view frame_cursor(cursor.data, metadata.frame_length);
                    buffer_view content_cursor(frame_cursor);

                    cursor.prune(metadata.frame_length);
                    const lost_frame_metadata ext_metadata{
                        .payload_length = metadata.payload_length,
                        .retransmit_count = metadata.retransmit_count,
                        .last_frame = cursor.end()
                    };

                    uint64_t frame_type;
                    assert(content_cursor.pull_var(frame_type));
                    assert(extension_reg.contains(frame_type));
                    extension &ext = extension_reg.at(frame_type);
                    ext.handle_lost_frame(frame_type, content_cursor, frame_cursor, ext_metadata);
                }
                break;
            }
            case HYQUIC_CTRL_MSS_UPDATE: {
                max_payload = details.mss_update.max_payload;
                max_payload_dgram = details.mss_update.max_payload_dgram;
                break;
            }
            default:
                break;
            }
        }
    };
} // namespace hyquic

#endif // __HYQUIC_HPP__