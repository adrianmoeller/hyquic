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
    using namespace std;

    class extension
    {
    public:
        virtual vector<uint64_t>& frame_types() = 0;
        virtual void handle_frame(uint64_t type, const buffer_view &buff) = 0;
        virtual uint32_t parse_and_handle_frame(uint64_t type, const buffer_view &buff) = 0;
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
            recv_context.join();
        }

        hyquic(const hyquic&) = delete;
        hyquic& operator=(hyquic&) = delete;

        void register_extension(extension &ext)
        {
            for (auto const &frame_type : ext.frame_types()) {
                if (!extension_reg.contains(frame_type))
                    extension_reg[frame_type] = vector<reference_wrapper<extension>>();
                extension_reg.at(frame_type).push_back(ext);
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
        boost::asio::thread_pool recv_context;
        stream_data_buff recv_buff;
        unordered_map<uint64_t, vector<reference_wrapper<extension>>> extension_reg;

        struct {
            enum hyquic_data_type type;
            buffer buff;
            buffer_view buff_view;
        } hyquic_data_frag;

        receive_ops recv_ops {
            .recv_stream_data = [this](buffer&& data, const quic_stream_info& info) {
                return hyquic::recv_stream_data(move(data), info);
            },
            .recv_hyquic_data = [this](buffer&& data, const hyquic_data_recvinfo& info) {
                return hyquic::recv_hyquic_data(move(data), info);
            }
        };

        inline int recv_stream_data(buffer&& data, const quic_stream_info& info)
        {
            int err = data.len;
            auto stream_data_ptr = make_shared<stream_data>(info.stream_id, info.stream_flag, move(data));
            if(!recv_buff.push(stream_data_ptr))
                err = -ENOBUFS;
            return err;
        }

        inline int recv_hyquic_data(buffer&& data, const hyquic_data_recvinfo& info)
        {
            int err = data.len;
            if (info.incompl) {
                if (hyquic_data_frag.buff.empty()) {
                    hyquic_data_frag.type = info.type;
                    hyquic_data_frag.buff = buffer(info.data_length);
                    hyquic_data_frag.buff_view = buffer_view(hyquic_data_frag.buff);
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                }
                if (!hyquic_data_frag.buff_view.write(move(data)))
                    return -EFAULT;
            } else {
                if (hyquic_data_frag.buff.empty()) {
                    // TODO post directly to hyquic_data_handler
                } else {
                    if (hyquic_data_frag.type != info.type)
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.write(move(data)))
                        return -EFAULT;
                    if (!hyquic_data_frag.buff_view.end())
                        return -EFAULT;
                    // TODO post buff to hyquic_data_handler
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
    };
} // namespace hyquic

#endif // __HYQUIC_HPP__