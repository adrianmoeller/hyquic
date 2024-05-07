#ifndef __HYQUIC_STREAM_UTILS_HPP__
#define __HYQUIC_STREAM_UTILS_HPP__

#include <hyquic.hpp>

namespace hyquic
{
    enum class send_stream_state
    {
        READY,
        SEND,
        SENT,
        RECVD,
        RESET_SENT,
        RESET_RECVD
    };

    enum class recv_stream_state
    {
        RECV,
        SIZE_KNOWN,
        RECVD,
        READ,
        RESET_RECVD,
        RESET_READ
    };

    struct stream
    {
        uint64_t id;

        struct {
            uint64_t max_bytes;
            uint64_t window;
            uint64_t bytes;
            uint64_t offset;

            uint32_t errcode;
            uint32_t frags;
            send_stream_state state;

            uint8_t data_blocked;
        } send;

        struct {
            uint64_t max_bytes;
            uint64_t window;
            uint64_t bytes;
            uint64_t offset;
            uint64_t highest;

            uint32_t frags;
            recv_stream_state state;
        } recv;
    };

    namespace frame_type
    {
        const uint64_t RESET_STREAM = 0x04;
        const uint64_t STOP_SENDING = 0x05;
        const uint64_t STREAM = 0x08;
        const uint64_t MAX_DATA = 0x10;
        const uint64_t MAX_STREAM_DATA = 0x11;
        const uint64_t MAX_STREAMS_BIDI = 0x12;
        const uint64_t MAX_STREAMS_UNI = 0x13;
        const uint64_t DATA_BLOCKED = 0x14;
        const uint64_t STREAM_DATA_BLOCKED = 0x15;
        const uint64_t STREAMS_BLOCKED_BIDI = 0x16;
        const uint64_t STREAMS_BLOCKED_UNI = 0x17;
    };

    enum class stream_type 
    {
        CLIENT_BI = 0x00,
        SERVER_BI = 0x01,
        CLIENT_UNI = 0x02,
        SERVER_UNI = 0x03
    };

    namespace stream_bit
    {
        const uint8_t FIN = 0x01;
        const uint8_t LEN = 0x02;
        const uint8_t OFF = 0x04;
        const uint64_t MASK = ~0x07;
    };

    struct stream_frame
    {
        std::shared_ptr<stream> _stream;
        uint64_t offset;
        bool fin;
        buffer payload;

        stream_frame(std::shared_ptr<stream> _stream, uint64_t offset, bool fin, buffer payload)
            : _stream(_stream), offset(offset), fin(fin), payload(std::move(payload))
        {
        }

        stream_frame(const stream_frame&) = delete;
        stream_frame& operator=(stream_frame&) = delete;

        stream_frame(stream_frame &&other)
            : _stream(other._stream), offset(other.offset), fin(other.fin), payload(std::move(other.payload))
        {
            other._stream = std::shared_ptr<stream>();
            other.offset = 0;
            other.fin = false;
        }

        stream_frame& operator=(stream_frame &&other)
        {
            std::swap(_stream, other._stream);
            std::swap(offset, other.offset);
            std::swap(fin, other.fin);
            std::swap(payload, other.payload);
            return *this;
        }
    };

    struct stream_frame_to_send_container
    {
        si::frame_to_send_container frame_to_send;
        std::shared_ptr<stream> _stream;
    };

    class stream_frames_to_send_provider : public si::frames_to_send_provider
    {
    public:
        std::list<stream_frame_to_send_container> frames;

        size_t total_frames_data_length() const
        {
            size_t total_frame_data_length = 0;
            for (const stream_frame_to_send_container &frame_cont : frames)
                total_frame_data_length += frame_cont.frame_to_send.metadata.frame_length;
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

        si::frame_to_send_container pop()
        {
            si::frame_to_send_container frame_cont = std::move(frames.front().frame_to_send);
            frames.pop_front();
            return frame_cont;
        }

        void push(si::frame_to_send_container &&frame, std::shared_ptr<stream> _stream)
        {
            frames.push_back({
                .frame_to_send = std::move(frame),
                ._stream = _stream
            });
        }

        stream_frame_to_send_container& peek()
        {
            return frames.front();
        }

        void transfer_all(stream_frames_to_send_provider &other)
        {
            frames.splice(frames.end(), other.frames);
        }

        void transfer_one(stream_frames_to_send_provider &other)
        {
            frames.push_back(std::move(other.frames.front()));
            other.frames.pop_front();
        }
    };

    struct stream_manager
    {
        bool is_server;
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

        err_res<std::shared_ptr<stream>> get_stream_send(uint64_t id, uint32_t flags)
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

        err_res<std::shared_ptr<stream>> get_stream_recv(uint64_t id)
        {
            stream_type type = (stream_type) (id & QUIC_STREAM_TYPE_MASK);

            if (is_server) {
                if (type == stream_type::SERVER_UNI)
                    return -EINVAL;
            } else if (type == stream_type::CLIENT_UNI) {
                return -EINVAL;
            }

            if (streams.contains(id))
                return streams.at(id);

            if (id & QUIC_STREAM_TYPE_UNI_MASK) {
                if ((id >> 2) >= recv.max_streams_uni)
                    return -EINVAL;
            } else {
                if ((id >> 2) >= recv.max_streams_bidi)
                    return -EINVAL;
            }

            return create_stream(id);
        }
    };

    si::frame_details_container reset_stream_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x04,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stop_sending_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x05,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_000_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_backfill_component();

        return si::frame_details_container(
            0x08,
            false,
            false,
            true,
            false,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_001_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_backfill_component();

        return si::frame_details_container(
            0x09,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_010_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        uint8_t ref_id = ffs.add_var_int_component(true);
        ffs.add_mult_const_decl_len_component(ref_id, 1);

        return si::frame_details_container(
            0x0a,
            false,
            false,
            true,
            false,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_011_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        uint8_t ref_id = ffs.add_var_int_component(true);
        ffs.add_mult_const_decl_len_component(ref_id, 1);

        return si::frame_details_container(
            0x0b,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_100_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_backfill_component();

        return si::frame_details_container(
            0x0c,
            false,
            false,
            true,
            false,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_101_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_backfill_component();

        return si::frame_details_container(
            0x0d,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_110_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();
        uint8_t ref_id = ffs.add_var_int_component(true);
        ffs.add_mult_const_decl_len_component(ref_id, 1);

        return si::frame_details_container(
            0x0e,
            false,
            false,
            true,
            false,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_111_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();
        uint8_t ref_id = ffs.add_var_int_component(true);
        ffs.add_mult_const_decl_len_component(ref_id, 1);

        return si::frame_details_container(
            0x0f,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container max_stream_data_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x11,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container max_streams_uni_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x12,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container max_streams_bidi_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x13,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container stream_data_blocked_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x15,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container streams_blocked_uni_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x16,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    si::frame_details_container streams_blocked_bidi_frame_details()
    {
        frame_format_specification_builder ffs;
        ffs.add_var_int_component();

        return si::frame_details_container(
            0x17,
            false,
            false,
            true,
            true,
            true,
            ffs.get_specification()
        );
    }

    void create_stream_frame_details(std::vector<si::frame_details_container> &frame_details)
    {
        frame_details.push_back(reset_stream_frame_details());
        frame_details.push_back(stop_sending_frame_details());
        frame_details.push_back(stream_000_frame_details());
        frame_details.push_back(stream_001_frame_details());
        frame_details.push_back(stream_010_frame_details());
        frame_details.push_back(stream_011_frame_details());
        frame_details.push_back(stream_100_frame_details());
        frame_details.push_back(stream_101_frame_details());
        frame_details.push_back(stream_110_frame_details());
        frame_details.push_back(stream_111_frame_details());
        frame_details.push_back(max_stream_data_frame_details());
        frame_details.push_back(max_streams_uni_frame_details());
        frame_details.push_back(max_streams_bidi_frame_details());
        frame_details.push_back(stream_data_blocked_frame_details());
        frame_details.push_back(streams_blocked_uni_frame_details());
        frame_details.push_back(streams_blocked_bidi_frame_details());
    }
} // namespace hyquic

#endif // __HYQUIC_STREAM_UTILS_HPP__