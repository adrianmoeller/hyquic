#ifndef __HYQUIC_HPP__
#define __HYQUIC_HPP__

#include <iostream>
#include <linux/quic.h>
#include <linux/hyquic.h>
#include <boost/asio.hpp>
#include <memory>
#include <cstdint>
#include <vector>
#include <list>
#include <functional>
#include <unordered_map>
#include "buffer.hpp"
#include "sock_interface.hpp"

namespace hyquic
{
    class extension
    {
    public:
        virtual std::vector<uint64_t>& frame_types() = 0;
        virtual uint32_t handle_frame(uint64_t type, buffer_view buff) = 0;
        virtual void handle_lost_frame(uint64_t type, buffer_view buff) = 0;
    };

#define RECV_STREAM_BUFF_INIT_SIZE  2048
#define RECV_BUFF_INIT_SIZE         65507

    class hyquic
    {
    public:
        hyquic(int sockfd)
            : sockfd(sockfd), recv_buff(RECV_STREAM_BUFF_INIT_SIZE), recv_context(1)
        {
            // TODO
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
            for (auto const &frame_type : ext.frame_types()) {
                if (!extension_reg.contains(frame_type))
                    extension_reg[frame_type] = std::vector<std::reference_wrapper<extension>>();
                extension_reg.at(frame_type).push_back(std::ref(ext));
            }
        }

        void run()
        {
            boost::asio::post(recv_context, [this]() {
                recv_loop();
            });
        }

    private:
        const int sockfd;
        boost::asio::thread_pool common_context;
        boost::asio::thread_pool recv_context;
        stream_data_buff recv_buff;
        std::unordered_map<uint64_t, std::vector<std::reference_wrapper<extension>>> extension_reg;

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

        receive_ops recv_ops {
            .recv_stream_data = [this](buffer&& data, const quic_stream_info& info) {
                return hyquic::recv_stream_data(std::move(data), info);
            },
            .recv_hyquic_data = [this](buffer&& data, const hyquic_data_recvinfo& info) {
                return hyquic::recv_hyquic_data(std::move(data), info);
            }
        };

        inline int recv_stream_data(buffer&& data, const quic_stream_info& info)
        {
            int err = data.len;
            auto stream_data_ptr = std::make_shared<stream_data>(info.stream_id, info.stream_flag, std::move(data));
            if(!recv_buff.push(stream_data_ptr))
                err = -ENOBUFS;
            return err;
        }

        inline int recv_hyquic_data(buffer&& data, const hyquic_data_recvinfo& info)
        {
            int err = data.len;
            if (info.incompl) {
                if (hyquic_data_frag.buff.empty()) {
                    hyquic_data_frag.init(info.type, info.data_length);
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                }
                if (!hyquic_data_frag.buff_view.push(std::move(data)))
                    return -EFAULT;
            } else {
                if (hyquic_data_frag.buff.empty()) {
                    boost::asio::post(common_context, [this, mvd_data = std::move(data), type = info.type]() {
                        hyquic::handle_hyquic_data(mvd_data, type);
                    });
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.push(std::move(data)))
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.end())
                        return -EFAULT;
                    boost::asio::post(common_context, [this, mvd_data = std::move(hyquic_data_frag.buff), type = info.type]() {
                        hyquic::handle_hyquic_data(mvd_data, type);
                    });
                    hyquic_data_frag.clear();
                }
            }
            return err;
        }

        void recv_loop()
        {
            int err;
            err = receive(sockfd, recv_ops, RECV_BUFF_INIT_SIZE);
            if (err < 0)
                return;
            boost::asio::post(recv_context, [this]() {
                recv_loop();
            });
        }

        void handle_hyquic_data(const buffer &buff, hyquic_data_type data_type)
        {
            switch (data_type)
            {
            case HYQUIC_DATA_RAW_FRAMES_FIX: {
                buffer_view buff_view(buff);
                while(!buff_view.end()) {
                    auto [frame_type, frame_type_len] = buff_view.pull_var();
                    if (!frame_type_len)
                        return;
                    if (extension_reg.contains(frame_type)) {
                        uint32_t frame_content_len;
                        for (extension &ext : extension_reg.at(frame_type))
                            frame_content_len = ext.handle_frame(frame_type, buff_view);
                        buff_view.prune(frame_content_len);
                    } else {
                        // TODO skip
                    }
                }
            }
                break;
            case HYQUIC_DATA_RAW_FRAMES_VAR:
                // TODO
                break;
            case HYQUIC_DATA_LOST_FRAMES:
                // TODO
                break;
            default:
                break;
            }
        }
    };
} // namespace hyquic

#endif // __HYQUIC_HPP__