#ifndef __HYQUIC_STREAM_FRAME_UTILS_HPP__
#define __HYQUIC_STREAM_FRAME_UTILS_HPP__

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
        RESET_READ,
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
        const uint8_t MASK = 0x08;
    };

    static si::frame_to_send_container create_frame_max_streams(uint64_t type, uint64_t *max_streams)
    {
        uint8_t tmp[10];
        outsized_buffer_view frame_builder(tmp, 10);

        frame_builder.push_var(type);
        frame_builder.push_var((*max_streams >> 2) + 1);

        return si::frame_to_send_container(frame_builder.trim());
    }

    struct create_stream_frame_info
    {
        const uint32_t max_frame_len;
        const std::shared_ptr<stream> _stream;
        buffer_view msg;
        const uint32_t flags;
    };

    static si::frame_to_send_container create_frame_stream(uint64_t type, create_stream_frame_info *info)
    {
        uint32_t header_len = 1;
        uint32_t msg_len = info->msg.len;
        std::shared_ptr<stream> &_stream = info->_stream;

        header_len += get_var_int_length(_stream->id);
        if (_stream->send.offset) {
            type |= stream_bit::OFF;
            header_len += get_var_int_length(_stream->send.offset);
        }

        type |= stream_bit::LEN;
        header_len += get_var_int_length(info->max_frame_len);

        if (msg_len <= info->max_frame_len - header_len) {
            if (info->flags & QUIC_STREAM_FLAG_FIN)
                type |= stream_bit::FIN;
        } else {
            msg_len = info->max_frame_len - header_len;
        }

        buffer frame_buff(header_len + msg_len);
        buffer_view frame_builder(frame_buff);

        frame_builder.push_var(type);
        frame_builder.push_var(_stream->id);
        if (type & stream_bit::OFF)
            frame_builder.push_var(_stream->send.offset);
        frame_builder.push_var(msg_len);
        frame_builder.push_pulled(info->msg, msg_len);

        return si::frame_to_send_container(std::move(frame_buff), msg_len);
    }

    si::frame_to_send_container create_frame(uint64_t type, void *data)
    {
        switch (type)
        {
        case frame_type::MAX_STREAMS_UNI:
        case frame_type::MAX_STREAMS_BIDI:
            return create_frame_max_streams(type, (uint64_t*) data);
        default:
            throw internal_error("unsupported frame type");
        }
    }
} // namespace hyquic

#endif // __HYQUIC_STREAM_FRAME_UTILS_HPP__