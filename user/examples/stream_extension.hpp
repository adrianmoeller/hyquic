#ifndef __HYQUIC_STREAM_EXTENSION_HPP__
#define __HYQUIC_STREAM_EXTENSION_HPP__

#include <list>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <cerrno>
#include <memory>
#include <algorithm>
#include <hyquic.hpp>
#include "stream_utils.hpp"

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
            stream_mng.send = {};
            stream_mng.recv = {};
            create_stream_frame_details(frame_details);
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

        uint32_t handle_frame(uint64_t type, buffer_view frame_content) override
        {
            if ((type & stream_bit::MASK) == frame_type::STREAM) {
                return process_stream_frame(type, frame_content);
            } else {
                switch (type) {
                case frame_type::RESET_STREAM:
                    return process_reset_stream_frame(type, frame_content);
                case frame_type::STOP_SENDING:
                    return process_stop_sending_frame(type, frame_content);
                case frame_type::MAX_STREAM_DATA:
                    return process_max_stream_data_frame(type, frame_content);
                case frame_type::MAX_STREAMS_UNI:
                    return process_max_streams_uni_frame(type, frame_content);
                case frame_type::MAX_STREAMS_BIDI:
                    return process_max_streams_bidi_frame(type, frame_content);
                case frame_type::STREAM_DATA_BLOCKED:
                    return process_stream_data_blocked_frame(type, frame_content);
                case frame_type::STREAMS_BLOCKED_UNI:
                    return process_streams_blocked_uni_frame(type, frame_content);
                case frame_type::STREAMS_BLOCKED_BIDI:
                    return process_streams_blocked_bidi_frame(type, frame_content);
                default:
                    assert(false);
                    break;
                }
            }
            return 0;
        }

        void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame, const hyquic_ctrlrecv_lost_frames &details) override
        {
            switch (type)
            {
            case frame_type::MAX_STREAMS_UNI:
            case frame_type::MAX_STREAMS_BIDI:
                break;
            default:
                uint64_t stream_id;
                frame_content.pull_var(stream_id);
                auto stream_res = stream_mng.get_stream_send(stream_id, 0);
                if (is_err(stream_res))
                    throw network_error("Invalid stream id.", get_err(stream_res));
                
                std::shared_ptr<stream> _stream = get_val(stream_res);
                if (_stream->send.state >= send_stream_state::RESET_SENT)
                    return;
                break;
            }

            container.send_one_frame(si::frame_to_send_container(frame.copy_all(), details.payload_length, details.retransmit_count + 1));
        }

        void before_connection_initiation() override
        {
            quic_transport_param local_tp = {
                .remote = false,
                .max_data = 0x7FFFFFFFFFFFFFFF // effectively disables connection-based flow control
            };
            socklen_t local_tp_len = sizeof(local_tp);

            int err = container.set_socket_option(QUIC_SOCKOPT_TRANSPORT_PARAM, &local_tp, local_tp_len);
            assert(!err);
        }

        void handshake_done() override
        {
            int err;
            quic_transport_param local_tp = { .remote = false };
            socklen_t local_tp_len = sizeof(local_tp);

            err = container.get_socket_option(QUIC_SOCKOPT_TRANSPORT_PARAM, &local_tp, &local_tp_len);
            assert(!err);

            stream_mng.recv.max_stream_data_bidi_local = local_tp.max_stream_data_bidi_local;
            stream_mng.recv.max_stream_data_bidi_remote = local_tp.max_stream_data_bidi_remote;
            stream_mng.recv.max_stream_data_uni = local_tp.max_stream_data_uni;
            stream_mng.recv.max_streams_bidi = local_tp.max_streams_bidi;
            stream_mng.recv.max_streams_uni = local_tp.max_streams_uni;

            quic_transport_param remote_tp = { .remote = true };
            socklen_t remote_tp_len = sizeof(remote_tp);

            err = container.get_socket_option(QUIC_SOCKOPT_TRANSPORT_PARAM, &remote_tp, &remote_tp_len);
            assert(!err);

            stream_mng.send.max_stream_data_bidi_local = remote_tp.max_stream_data_bidi_local;
            stream_mng.send.max_stream_data_bidi_remote = remote_tp.max_stream_data_bidi_remote;
            stream_mng.send.max_stream_data_uni = remote_tp.max_stream_data_uni;
            stream_mng.send.max_streams_bidi = remote_tp.max_streams_bidi;
            stream_mng.send.max_streams_uni = remote_tp.max_streams_uni;
            stream_mng.send.stream_active = -1;
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

            auto fut = boost::asio::post(container.get_context(), boost::asio::use_future([this, &msg, &stream_res]() {
                if (is_err(stream_res))
                    stream_res = stream_mng.get_stream_send(msg.id, msg.flags);
                if (is_err(stream_res))
                    return get_err(stream_res);

                std::shared_ptr<stream> _stream = get_val(stream_res);
                buffer_view cursor(msg.buff);

                while (!cursor.end()) {
                    data_frames_to_send.push(create_stream_frame(container.get_max_payload(), _stream, cursor, msg.flags), _stream);
                }
                send_frames();

                return (int) msg.buff.len;
            }));

            return fut.get();
        }

        stream_data recv_msg(uint32_t max_length)
        {
            uint8_t tmp[max_length];
            outsized_buffer_view data_builder(tmp, max_length);
            std::shared_ptr<stream> current_stream;
            uint32_t flags = 0;

            if (!started_stream_data.get())
                started_stream_data = recv_buff.wait_pop();

            do {
                buffer_view cursor(started_stream_data->payload);
                current_stream = started_stream_data->_stream;

                uint32_t len_to_copy = std::min(cursor.len, data_builder.len);
                data_builder.push_pulled(cursor, len_to_copy);

                if (!cursor.end()) {
                    started_stream_data_offset = started_stream_data->payload.len - cursor.len;
                    break;
                }

                started_stream_data_offset = 0;

                if (started_stream_data->fin) {
                    boost::asio::post(container.get_context(), [_stream = started_stream_data->_stream]() {
                        _stream->recv.state = recv_stream_state::READ;
                    });
                    started_stream_data = std::shared_ptr<stream_frame>();
                    flags |= QUIC_STREAM_FLAG_FIN;
                    break;
                }

                started_stream_data = recv_buff.wait_pop();
                if (current_stream->id != started_stream_data->_stream->id)
                    break;
            } while (!data_builder.end());

            buffer recv_buff = data_builder.trim();

            boost::asio::post(container.get_context(), [this, current_stream, recv_len = recv_buff.len]() {
                handle_recv_flow_control(current_stream, recv_len);
            });

            return stream_data(current_stream->id, flags, std::move(recv_buff));
        }

        template<class Rep, class Period>
        std::optional<stream_data> recv_msg(uint32_t max_length, const std::chrono::duration<Rep, Period> &timeout)
        {
            std::chrono::time_point abs_timeout = std::chrono::steady_clock::now() + timeout;

            uint8_t tmp[max_length];
            outsized_buffer_view data_builder(tmp, max_length);
            std::shared_ptr<stream> current_stream;
            uint32_t flags = 0;

            if (!started_stream_data.get()) {
                auto opt_stream_data = recv_buff.wait_pop_until(abs_timeout);
                if (opt_stream_data)
                    started_stream_data = opt_stream_data.value();
                else
                    return std::optional<stream_data>();
            }

            do {
                buffer_view cursor(started_stream_data->payload);
                current_stream = started_stream_data->_stream;

                uint32_t len_to_copy = std::min(cursor.len, data_builder.len);
                data_builder.push_pulled(cursor, len_to_copy);

                if (!cursor.end()) {
                    started_stream_data_offset = started_stream_data->payload.len - cursor.len;
                    break;
                }

                started_stream_data_offset = 0;

                if (started_stream_data->fin) {
                    boost::asio::post(container.get_context(), [_stream = started_stream_data->_stream]() {
                        _stream->recv.state = recv_stream_state::READ;
                    });
                    started_stream_data = std::shared_ptr<stream_frame>();
                    flags |= QUIC_STREAM_FLAG_FIN;
                    break;
                }

                auto opt_stream_data = recv_buff.wait_pop_until(abs_timeout);
                if (opt_stream_data)
                    started_stream_data = opt_stream_data.value();
                else if (!started_stream_data.get())
                    return std::optional<stream_data>();
                else
                    break;

                if (current_stream->id != started_stream_data->_stream->id)
                    break;
            } while (!data_builder.end());

            buffer recv_buff = data_builder.trim();

            boost::asio::post(container.get_context(), [this, current_stream, recv_len = recv_buff.len]() {
                handle_recv_flow_control(current_stream, recv_len);
            });

            return stream_data(current_stream->id, flags, std::move(recv_buff));
        }

    private:
        hyquic &container;
        bool is_server;
        std::vector<si::frame_details_container> frame_details;
        stream_frames_to_send_provider ctrl_frames_to_send;
        stream_frames_to_send_provider data_frames_to_send;

        std::mutex mutex;
        std::condition_variable send_wait_cv;

        stream_manager stream_mng;
        std::list<std::shared_ptr<stream_frame>> reassemble_list;
        wait_queue<std::shared_ptr<stream_frame>> recv_buff;

        std::shared_ptr<stream_frame> started_stream_data;
        uint32_t started_stream_data_offset;

        si::frame_to_send_container create_max_streams_frame(uint64_t type, uint64_t max_streams)
        {
            uint8_t tmp[10];
            outsized_buffer_view frame_builder(tmp, 10);

            frame_builder.push_var(type);
            frame_builder.push_var((max_streams >> 2) + 1);

            return si::frame_to_send_container(frame_builder.trim());
        }

        si::frame_to_send_container create_stream_frame(uint32_t max_frame_len, std::shared_ptr<stream> _stream, buffer_view &msg, uint32_t flags)
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

            uint32_t estimated_header_len = header_len + get_var_int_length(max_frame_len);
            assert(max_frame_len >= estimated_header_len);

            if (msg_len <= max_frame_len - estimated_header_len) {
                if (flags & QUIC_STREAM_FLAG_FIN)
                    type |= stream_bit::FIN;
            } else {
                msg_len = max_frame_len - estimated_header_len;
            }
            
            header_len += get_var_int_length(msg_len);

            buffer frame_buff(header_len + msg_len);
            buffer_view frame_builder(frame_buff);

            frame_builder.push_var(type);
            frame_builder.push_var(_stream->id);
            if (type & stream_bit::OFF)
                frame_builder.push_var(_stream->send.offset);
            frame_builder.push_var(msg_len);
            frame_builder.push_pulled(msg, msg_len);

            _stream->send.offset += msg_len;

            if (_stream->send.state == send_stream_state::READY)
                _stream->send.state = send_stream_state::SEND;

            if (type & stream_bit::FIN && _stream->send.state == send_stream_state::SEND) {
                if (stream_mng.send.stream_active == _stream->id)
                    stream_mng.send.stream_active = -1;
                _stream->send.state = send_stream_state::SENT;
            }

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

        si::frame_to_send_container create_stream_data_blocked_frame(std::shared_ptr<stream> _stream)
        {
            uint8_t tmp[10];
            outsized_buffer_view frame_builder(tmp, 10);

            frame_builder.push_var(frame_type::STREAM_DATA_BLOCKED);
            frame_builder.push_var(_stream->id);
            frame_builder.push_var(_stream->send.max_bytes);

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
            do_reassembling(_stream_frame);

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
            _stream->recv.state = recv_stream_state::RESET_RECVD;
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

            _stream->send.state = send_stream_state::RESET_SENT;

            data_frames_to_send.frames.remove_if([&stream_id](stream_frame_to_send_container &frame_to_send) {
                return frame_to_send._stream->id == stream_id;
            });

            ctrl_frames_to_send.push(std::move(reset_stream_frame), _stream);
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

        uint32_t process_max_streams_uni_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.send.max_streams_uni)
                return start_len - frame_content.len;

            stream_mng.send.max_streams_uni = max_streams;
            stream_mng.send.streams_uni = max_streams;
            
            std::lock_guard<std::mutex> lock(mutex);
            send_wait_cv.notify_all();

            return start_len - frame_content.len;
        }

        uint32_t process_max_streams_bidi_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.send.max_streams_bidi)
                return start_len - frame_content.len;

            stream_mng.send.max_streams_bidi = max_streams;
            stream_mng.send.streams_bidi = max_streams;

            std::lock_guard<std::mutex> lock(mutex);
            send_wait_cv.notify_all();

            return start_len - frame_content.len;
        }

        uint32_t process_stream_data_blocked_frame(uint64_t type, buffer_view &frame_content)
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

            ctrl_frames_to_send.push(create_max_stream_data_frame(_stream), _stream);

            return start_len - frame_content.len;
        }

        uint32_t process_streams_blocked_uni_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.recv.max_streams_uni)
                return start_len - frame_content.len;

            ctrl_frames_to_send.push(create_max_streams_frame(frame_type::MAX_STREAMS_UNI, max_streams), 0);
            stream_mng.recv.max_streams_uni = max_streams;

            return start_len - frame_content.len;
        }

        uint32_t process_streams_blocked_bidi_frame(uint64_t type, buffer_view &frame_content)
        {
            uint32_t start_len = frame_content.len;
            uint64_t max_streams;

            frame_content.pull_var(max_streams);

            if (max_streams < stream_mng.recv.max_streams_bidi)
                return start_len - frame_content.len;

            ctrl_frames_to_send.push(create_max_streams_frame(frame_type::MAX_STREAMS_BIDI, max_streams), 0);
            stream_mng.recv.max_streams_bidi = max_streams;

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

            ctrl_frames_to_send.push(create_max_streams_frame(type, msg.id), 0);
            send_frames();

            return -EAGAIN;
        }

        void do_reassembling(std::shared_ptr<stream_frame> frame)
        {
            std::shared_ptr<stream> _stream = frame->_stream;
            uint32_t payload_len = frame->payload.len;
            uint64_t current_highest = 0;
            uint64_t current_offset;

            if (_stream->recv.offset >= frame->offset + payload_len)
                return;

            current_offset = frame->offset + payload_len;
            if (current_offset > _stream->recv.highest) {
                current_highest = current_offset - _stream->recv.highest;
            }

            if (_stream->recv.offset < frame->offset) {
                for (auto &reasm_frame : reassemble_list) {
                    if (reasm_frame->_stream->id < _stream->id)
                        continue;
                    if (reasm_frame->_stream->id > _stream->id)
                        break;
                    if (reasm_frame->offset > frame->offset)
                        break;
                    if (reasm_frame->offset + reasm_frame->payload.len >= frame->offset + payload_len)
                        return;
                }

                if (frame->fin)
                    _stream->recv.state = recv_stream_state::SIZE_KNOWN;

                reassemble_list.push_front(frame);
                _stream->recv.frags++;
                _stream->recv.highest += current_highest;
                return;
            }

            _stream->recv.highest += current_highest;
            append_recv_queue(frame);
            if (!_stream->recv.frags)
                return;

            auto it = reassemble_list.begin();
            while (it != reassemble_list.end()) {
                auto reasm_frame = *it;
                if (reasm_frame->_stream->id < _stream->id)
                    continue;
                if (reasm_frame->_stream->id > _stream->id)
                    break;
                if (reasm_frame->offset > _stream->recv.offset)
                    break;

                it = reassemble_list.erase(it);
                _stream->recv.frags--;
                if (reasm_frame->offset + payload_len <= _stream->recv.offset)
                    continue;
                append_recv_queue(reasm_frame);
            }
        }

        void append_recv_queue(std::shared_ptr<stream_frame> frame)
        {
            uint64_t overlap = frame->_stream->recv.offset - frame->offset;
            if (overlap) {
                buffer_view cursor(frame->payload);
                cursor.prune(overlap);
                frame->payload = cursor.copy_all();
                frame->offset += overlap;
            }

            if (frame->fin)
                frame->_stream->recv.state = recv_stream_state::RECVD;

            frame->_stream->recv.offset += frame->payload.len;
            recv_buff.push(std::move(frame));
        }

        void handle_recv_flow_control(std::shared_ptr<stream> _stream, uint32_t recv_len)
        {
            if (!recv_len)
		        return;

            _stream->recv.bytes += recv_len;

            if (_stream->recv.max_bytes - _stream->recv.bytes < _stream->recv.window / 2) {
                uint32_t window = _stream->recv.window;
                if (false /* TODO is under memory pressure */)
                    window >>= 1;
                _stream->recv.max_bytes = _stream->recv.bytes + window;
                ctrl_frames_to_send.push(create_max_stream_data_frame(_stream), _stream);
            }

            send_frames();
        }

        bool handle_send_flow_control(stream_frame_to_send_container &frame_to_send, stream_frames_to_send_provider &frames_to_send)
        {
            uint32_t payload_len = frame_to_send.frame_to_send.metadata.payload_length;
            std::shared_ptr<stream> _stream = frame_to_send._stream;

            if (_stream->send.bytes + payload_len > _stream->send.max_bytes) {
                if (!_stream->send.data_blocked) {
                    frames_to_send.push(create_stream_data_blocked_frame(_stream), _stream);
                    _stream->send.data_blocked = 1;
                }
                return true;
            }

            _stream->send.frags++;
		    _stream->send.bytes += payload_len;

            return false;
        }

        void send_frames()
        {
            stream_frames_to_send_provider frames_to_send;

            frames_to_send.transfer_all(ctrl_frames_to_send);
            while (!data_frames_to_send.empty()) {
                if (handle_send_flow_control(data_frames_to_send.peek(), frames_to_send))
                    break;

                frames_to_send.transfer_one(data_frames_to_send);
            }

            container.send_frames(frames_to_send);
        }
    };
} // namespace hyquic

#endif // __HYQUIC_STREAM_EXTENSION_HPP__