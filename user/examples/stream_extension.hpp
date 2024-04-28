#ifndef __HYQUIC_STREAM_EXTENSION_HPP__
#define __HYQUIC_STREAM_EXTENSION_HPP__

#include <list>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <cerrno>
#include <variant>
#include <memory>
#include <hyquic.hpp>
#include "stream_frame_utils.hpp"

namespace hyquic
{
    class stream_frame
    {
    private:
        stream &_stream;
    public:
        stream_frame(stream &_stream)
            : _stream(_stream)
        {

        }

        ~stream_frame()
        {

        }
    };


    /**
     * This extension substitutes the transmission of STREAM frames and control frames associated with streams.
     * It also manages stream states and reassembling.
    */
    class stream_extension : public extension
    {
    private:
        hyquic &container;
        bool is_server;
        std::vector<si::frame_details_container> frame_details;
        std::list<si::frame_to_send_container> frames_to_send;

        std::mutex mutex;
        std::condition_variable send_wait_cv;

        std::unordered_map<uint64_t, std::shared_ptr<stream>> streams;
        struct {
            uint64_t max_stream_data_bidi_local;
            uint64_t max_stream_data_bidi_remote;
            uint64_t max_stream_data_uni;
            uint64_t max_streams_bidi;
            uint64_t max_streams_uni;
            uint64_t streams_bidi;
            uint64_t streams_uni;
            uint64_t stream_active;
        } send;
        struct {
            uint64_t max_stream_data_bidi_local;
            uint64_t max_stream_data_bidi_remote;
            uint64_t max_stream_data_uni;
            uint64_t max_streams_bidi;
            uint64_t max_streams_uni;
        } recv;

        std::list<stream_frame> reassemble_list;

        uint64_t max_bytes;
        uint64_t window;
        uint64_t bytes;
        uint64_t highest;

        std::shared_ptr<stream> create_stream(uint64_t id)
        {
            std::shared_ptr<stream> new_stream(new stream{0});

            new_stream->id = id;
            if (id & QUIC_STREAM_TYPE_UNI_MASK) {
                new_stream->send.window = send.max_stream_data_uni;
                new_stream->recv.window = recv.max_stream_data_uni;
                new_stream->send.max_bytes = new_stream->send.window;
                new_stream->recv.max_bytes = new_stream->recv.window;
                if (send.streams_uni <= (id >> 2))
                    send.streams_uni = (id >> 2) + 1;
            } else {
                if (send.streams_bidi <= (id >> 2))
                    send.streams_bidi = (id >> 2) + 1;
                if (is_server ^ !(id & QUIC_STREAM_TYPE_SERVER_MASK)) {
                    new_stream->send.window = send.max_stream_data_bidi_remote;
                    new_stream->recv.window = recv.max_stream_data_bidi_local;
                } else {
                    new_stream->send.window = send.max_stream_data_bidi_local;
                    new_stream->recv.window = recv.max_stream_data_bidi_remote;
                }
                new_stream->send.max_bytes = new_stream->send.window;
                new_stream->recv.max_bytes = new_stream->recv.window;
            }

            streams.insert({id, new_stream});
            return new_stream;
        }

        bool stream_id_exceeds(uint64_t id)
        {
            if (id & QUIC_STREAM_TYPE_UNI_MASK) {
                if ((id >> 2) >= send.max_streams_uni)
                    return true;
            } else {
                if ((id >> 2) >= send.max_streams_bidi)
                    return true;
            }
            return false;
        }

        std::variant<std::shared_ptr<stream>, int> get_stream_send(uint64_t id, uint32_t flags)
        {
            stream_type type = (stream_type) (id & QUIC_STREAM_TYPE_MASK);

            if (is_server) {
                if (type == stream_type::CLIENT_UNI)
                    return -EINVAL;
            } else if (type == stream_type::SERVER_UNI) {
                return -EINVAL;
            }

            if (streams.contains(id)) {
                if (flags & QUIC_STREAM_FLAG_NEW)
                    return -EINVAL;
                return streams.at(id);
            }

            if (!(flags & QUIC_STREAM_FLAG_NEW))
                return -EINVAL;

            if (is_server) {
                if (type == stream_type::CLIENT_BI)
                    return -EINVAL;
            } else {
                if (type == stream_type::SERVER_BI)
                    return -EINVAL;
            }
            if (stream_id_exceeds(id))
                return -EAGAIN;

            send.stream_active = id;
            return create_stream(id);
        }

        std::variant<std::shared_ptr<stream>, int> prepare_send_stream(uint64_t id, uint32_t flags, std::unique_lock<std::mutex> &lock)
        {
            uint64_t type = frame_type::STREAMS_BLOCKED_BIDI;

            auto stream_res = get_stream_send(id, flags);

            if (std::holds_alternative<std::shared_ptr<stream>>(stream_res)) {
                std::shared_ptr<stream> _stream = std::get<std::shared_ptr<stream>>(stream_res);
                if (_stream->send.state >= send_stream_state::SENT)
                    return -EINVAL;
                return _stream;
            } else {
                int err = std::get<int>(stream_res);
                if (err != -EAGAIN)
                    return err;
            }

            // TODO check if crypto is ready to send appl. data

            if (id & QUIC_STREAM_TYPE_UNI_MASK)
		        type = frame_type::STREAMS_BLOCKED_UNI;

            frames_to_send.push_back(create_frame(type, &id));
            container.send_frames(frames_to_send);

            send_wait_cv.wait(lock, [this, &id]() {
                return !stream_id_exceeds(id);
            });

            return get_stream_send(id, flags);
        }

    public:
        stream_extension(hyquic &container, bool is_server)
            : container(container), is_server(is_server)
        {
            // TODO declare frame details
        }

        inline buffer transport_parameter()
        {
            buffer buff(5);
            buffer_view cursor(buff);

            cursor.push_var(0x7934);
            cursor.push_var(0);

            return buff;
        }

        const std::vector<si::frame_details_container>& frame_details_list()
        {
            return frame_details;
        }

        uint32_t handle_frame(uint64_t type, buffer_view frame_content)
        {
            std::lock_guard<std::mutex> lock(mutex);

            // TODO

            // TODO notify max streams value changed

            return 0;
        }

        void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame)
        {
            std::lock_guard<std::mutex> lock(mutex);

            // TODO
        }

        int send_msg(stream_data &msg)
        {
            std::unique_lock<std::mutex> lock(mutex);

            if (msg.id == -1) {
                if (send.stream_active == -1) {
                    msg.id = (send.streams_bidi << 2);
                    if (msg.flags & QUIC_STREAM_FLAG_UNI) {
                        msg.id = send.streams_uni << 2;
                        msg.id |= QUIC_STREAM_TYPE_UNI_MASK;
                    }
                    msg.id |= is_server;
                } else {
                    msg.id = send.stream_active;
                }
            }

            auto stream_res = prepare_send_stream(msg.id, msg.flags, lock);
            if (std::holds_alternative<int>(stream_res))
                return std::get<int>(stream_res);

            std::shared_ptr<stream> _stream = std::get<std::shared_ptr<stream>>(stream_res);

            create_stream_frame_info stream_frame_info{
                .max_frame_len = container.get_max_payload(),
                ._stream = _stream,
                .msg = buffer_view(msg.buff),
                .flags = msg.flags
            };
            while (stream_frame_info.msg.len > 0) {
                frames_to_send.push_back(create_frame(frame_type::STREAM, &stream_frame_info));
            }
            container.send_frames(frames_to_send);

            return 0;
        }
    };
} // namespace hyquic

#endif // __HYQUIC_STREAM_EXTENSION_HPP__