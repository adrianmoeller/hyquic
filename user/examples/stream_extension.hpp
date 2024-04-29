#ifndef __HYQUIC_STREAM_EXTENSION_HPP__
#define __HYQUIC_STREAM_EXTENSION_HPP__

#include <list>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <cerrno>
#include <memory>
#include <hyquic.hpp>
#include "stream_frame_utils.hpp"

namespace hyquic
{
    /**
     * This extension substitutes the transmission of STREAM frames and control frames associated with streams.
     * It also manages stream states and reassembling.
    */
    class stream_extension : public extension
    {
    public:
        stream_extension(hyquic &container, bool is_server)
            : container(container), is_server(is_server)
        {
            stream_mng.is_server = is_server;
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
            if (type & stream_bit::MASK == frame_type::STREAM) {
                return process_stream_frame(type, frame_content);
            } else {
                switch (type)
                {
                case frame_type::RESET_STREAM:
                    return process_reset_stream_frame(type, frame_content);
                case frame_type::STOP_SENDING:
                    return process_stop_sending_frame(type, frame_content);
                case frame_type::MAX_STREAM_DATA:
                    return process_max_stream_data_frame(type, frame_content);
                case frame_type::MAX_STREAMS_UNI:
                    return process_max_streams_uni(type, frame_content);
                case frame_type::MAX_STREAMS_BIDI:
                    return process_max_streams_bidi(type, frame_content);
                case frame_type::STREAM_DATA_BLOCKED:
                    return process_stream_data_blocked(type, frame_content);
                default:
                    break;
                }
            }

            // TODO

            std::lock_guard<std::mutex> lock(mutex);
            // TODO notify max streams value changed

            return 0;
        }

        void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame)
        {
            // TODO
        }

        int send_msg(stream_data &msg)
        {
            auto stream_fut = boost::asio::post(container.get_context(), boost::asio::use_future([this, &msg]() {
                return prepare_send_stream(msg);
            }));

            auto stream_res = stream_fut.get();
            if (is_err(stream_res)) {
                int err = get_err(stream_res);
                if (err != -EAGAIN)
                    return err;

                std::unique_lock<std::mutex> lock(mutex);
                // TODO add timeout
                send_wait_cv.wait(lock, [this, &msg]() {
                    auto fut = boost::asio::post(container.get_context(), boost::asio::use_future([this, &msg]() {
                        return !stream_mng.stream_id_exceeds(msg.id);
                    }));
                    return fut.get();
                });
            }

            auto fut = boost::asio::post(container.get_context(), boost::asio::use_future([this, &msg]() {
                auto stream_res = stream_mng.get_stream_send(msg.id, msg.flags);
                if (is_err(stream_res))
                    return get_err(stream_res);

                std::shared_ptr<stream> _stream = get_val(stream_res);
                buffer_view cursor(msg.buff);

                while (!cursor.end()) {
                    frames_to_send.push(create_stream_frame(container.get_max_payload(), _stream, cursor, msg.flags), msg.id);
                }
                container.send_frames(frames_to_send);

                return 0;
            }));

            return fut.get();
        }

    private:
        hyquic &container;
        bool is_server;
        std::vector<si::frame_details_container> frame_details;
        stream_frames_to_send_provider frames_to_send;

        std::mutex mutex;
        std::condition_variable send_wait_cv;

        stream_manager stream_mng;

        std::list<std::shared_ptr<stream_frame>> reassemble_list;

        uint64_t max_bytes;
        uint64_t window;
        uint64_t bytes;
        uint64_t highest;

        si::frame_to_send_container create_max_streams_frame(uint64_t type, uint64_t max_streams)
        {
            uint8_t tmp[10];
            outsized_buffer_view frame_builder(tmp, 10);

            frame_builder.push_var(type);
            frame_builder.push_var((max_streams >> 2) + 1);

            return si::frame_to_send_container(frame_builder.trim());
        }

        si::frame_to_send_container create_stream_frame(uint32_t max_frame_len,  std::shared_ptr<stream> _stream, buffer_view &msg, uint32_t flags)
        {
            uint64_t type = frame_type::STREAM;
            uint32_t header_len = 1;
            uint32_t msg_len = msg.len;

            header_len += get_var_int_length(_stream->id);
            if (_stream->send.offset) {
                type |= stream_bit::OFF;
                header_len += get_var_int_length(_stream->send.offset);
            }

            type |= stream_bit::LEN;
            header_len += get_var_int_length(max_frame_len);

            if (msg_len <= max_frame_len - header_len) {
                if (flags & QUIC_STREAM_FLAG_FIN)
                    type |= stream_bit::FIN;
            } else {
                msg_len = max_frame_len - header_len;
            }

            buffer frame_buff(header_len + msg_len);
            buffer_view frame_builder(frame_buff);

            frame_builder.push_var(type);
            frame_builder.push_var(_stream->id);
            if (type & stream_bit::OFF)
                frame_builder.push_var(_stream->send.offset);
            frame_builder.push_var(msg_len);
            frame_builder.push_pulled(msg, msg_len);

            return si::frame_to_send_container(std::move(frame_buff), msg_len);
        }

        si::frame_to_send_container create_reset_stream_frame(std::shared_ptr<stream> _stream, uint64_t err_code)
        {
            uint8_t tmp[20];
            outsized_buffer_view frame_builder(tmp, 20);

            frame_builder.push_var(frame_type::RESET_STREAM);
            frame_builder.push_var(_stream->id);
            frame_builder.push_var(err_code);
            frame_builder.push_var(_stream->send.offset);

            _stream->send.errcode = err_code;
            if (stream_mng.send.stream_active == _stream->id)
                stream_mng.send.stream_active = -1;

            return si::frame_to_send_container(frame_builder.trim());
        }

        si::frame_to_send_container create_max_stream_data_frame(std::shared_ptr<stream> _stream)
        {
            uint8_t tmp[10];
            outsized_buffer_view frame_builder(tmp, 10);

            frame_builder.push_var(frame_type::MAX_STREAM_DATA);
            frame_builder.push_var(_stream->id);
            frame_builder.push_var(_stream->recv.max_bytes);

            return si::frame_to_send_container(frame_builder.trim());
        }

        uint32_t process_stream_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t stream_id;
            uint64_t offset = 0;
            uint64_t payload_len;
            
            frame_content.pull_var(stream_id);
            if (type & stream_bit::OFF)
                frame_content.pull_var(offset);

            payload_len = frame_content.len;
            if (type & stream_bit::LEN) {
                frame_content.pull_var(payload_len);
                if (payload_len > frame_content.len)
                    throw network_error("Malformed stream frame.");
            }

            auto stream_res = stream_mng.get_stream_recv(stream_id);
            if (is_err(stream_res))
                throw network_error("Invalid stream id.", get_err(stream_res));

            std::shared_ptr<stream_frame> _stream_frame(new stream_frame{
                ._stream = get_val(stream_res),
                .offset = offset,
                .fin = (bool) (type & stream_bit::FIN),
                .payload = frame_content.pull(payload_len)
            });
            reassemble_list.push_back(_stream_frame);

            return start_len - frame_content.len;
        }

        uint32_t process_reset_stream_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t stream_id;
            uint64_t err_code;
            uint64_t final_size;

            frame_content.pull_var(stream_id);
            frame_content.pull_var(err_code);
            frame_content.pull_var(final_size);

            auto stream_res = stream_mng.get_stream_recv(stream_id);
            if (is_err(stream_res))
                throw network_error("Invalid stream id.", get_err(stream_res));
            
            std::shared_ptr<stream> _stream = get_val(stream_res);
            reassemble_list.remove_if([&_stream](std::shared_ptr<stream_frame> item) {
                return item->_stream->id == _stream->id;
            });

            return start_len - frame_content.len;
        }

        uint32_t process_stop_sending_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t stream_id;
            uint64_t err_code;

            frame_content.pull_var(stream_id);
            frame_content.pull_var(err_code);

            auto stream_res = stream_mng.get_stream_send(stream_id, 0);
            if (is_err(stream_res))
                throw network_error("Invalid stream id.", get_err(stream_res));

            std::shared_ptr<stream> _stream = get_val(stream_res);
            si::frame_to_send_container reset_stream_frame = create_reset_stream_frame(_stream, err_code);

            _stream->send.state = send_stream_state::SENT;

            // TODO remove frames with stream ID from retransmit queue (how?)

            frames_to_send.frames.remove_if([&stream_id](stream_frame_to_send_container &frame_to_send) {
                return frame_to_send.stream_id == stream_id;
            });

            frames_to_send.push(std::move(reset_stream_frame), stream_id);
            return start_len - frame_content.len;
        }

        uint32_t process_max_stream_data_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t stream_id;
            uint64_t max_bytes;

            frame_content.pull_var(stream_id);
            frame_content.pull_var(max_bytes);

            if (!stream_mng.streams.contains(stream_id))
                throw network_error("Invalid stream id.");

            std::shared_ptr<stream> _stream = stream_mng.streams.at(stream_id);

            if (max_bytes >= _stream->send.max_bytes)
                _stream->send.max_bytes = max_bytes;

            return start_len - frame_content.len;
        }

        uint32_t process_max_streams_uni(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.send.max_streams_uni)
                return start_len - frame_content.len;

            stream_mng.send.max_streams_uni = max_streams;
            stream_mng.send.streams_uni = max_streams;

            return start_len - frame_content.len;
        }

        uint32_t process_max_streams_bidi(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.send.max_streams_bidi)
                return start_len - frame_content.len;

            stream_mng.send.max_streams_bidi = max_streams;
            stream_mng.send.streams_bidi = max_streams;

            return start_len - frame_content.len;
        }

        uint32_t process_stream_data_blocked(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t stream_id;
            uint64_t max_bytes;

            frame_content.pull_var(stream_id);
            frame_content.pull_var(max_bytes);

            if (!stream_mng.streams.contains(stream_id))
                throw network_error("Invalid stream id.");

            std::shared_ptr<stream> _stream = stream_mng.streams.at(stream_id);
            uint32_t window = _stream->recv.window;

            if (false /* TODO is under memory pressure */)
                window >>= 1;

            uint64_t recv_max_bytes = _stream->recv.max_bytes;
            _stream->recv.max_bytes = _stream->recv.bytes + window;

            frames_to_send.push(create_max_stream_data_frame(_stream), stream_id);

            return start_len - frame_content.len;
        }

        std::variant<std::shared_ptr<stream>, int> prepare_send_stream(stream_data &msg)
        {
            if (msg.id == -1) {
                if (stream_mng.send.stream_active == -1) {
                    msg.id = (stream_mng.send.streams_bidi << 2);
                    if (msg.flags & QUIC_STREAM_FLAG_UNI) {
                        msg.id = stream_mng.send.streams_uni << 2;
                        msg.id |= QUIC_STREAM_TYPE_UNI_MASK;
                    }
                    msg.id |= is_server;
                } else {
                    msg.id = stream_mng.send.stream_active;
                }
            }

            uint64_t type = frame_type::STREAMS_BLOCKED_BIDI;

            auto stream_res = stream_mng.get_stream_send(msg.id, msg.flags);

            if (is_val(stream_res)) {
                std::shared_ptr<stream> _stream = get_val(stream_res);
                if (_stream->send.state >= send_stream_state::SENT)
                    return -EINVAL;
                return _stream;
            } else {
                int err = get_err(stream_res);
                if (err != -EAGAIN)
                    return err;
            }

            // TODO check if crypto is ready to send appl. data

            if (msg.id & QUIC_STREAM_TYPE_UNI_MASK)
		        type = frame_type::STREAMS_BLOCKED_UNI;

            frames_to_send.push(create_max_streams_frame(type, msg.id), msg.id);
            container.send_frames(frames_to_send);

            return -EAGAIN;
        }
    };
} // namespace hyquic

#endif // __HYQUIC_STREAM_EXTENSION_HPP__