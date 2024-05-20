#include <hyquic.hpp>
#include "stream_utils.hpp"

namespace hyquic
{
    class stream_injector : public extension
    {
    public:
        stream_injector(hyquic &container)
            : container(container)
        {
            create_stream_injector_frame_profiles(frame_profiles);
        }

        inline buffer transport_parameter()
        {
            buffer buff(5);
            buffer_view cursor(buff);

            cursor.push_var(0x7935);
            cursor.push_var(0);

            return buff;
        }

        const std::vector<si::frame_profile_container>& frame_profiles_list() override
        {
            return frame_profiles;
        }

        handle_frame_result handle_frame(uint64_t type, buffer_view frame_content) override
        {
            return {0, 0};
        }

        void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame, const lost_frame_metadata &metadata) override
        {
            // NO-OP
        }

        virtual void before_connection_initiation() override
        {
            hyquic_options options{
                .usrquic_retransmit = false
            };
            container.set_socket_option(HYQUIC_SOCKOPT_OPTIONS, &options, sizeof(options));
        }

        int inject_msg(stream_data &msg, uint64_t offset)
        {
            si::default_frames_to_send_provider frames_to_send;
            buffer_view cursor(msg.buff);

            while (!cursor.end()) {
                frames_to_send.push(create_stream_frame(container.get_max_payload(), cursor, msg.flags, msg.id, offset));
            }

            auto fut = boost::asio::post(container.get_context(), boost::asio::use_future([this, &frames_to_send]() {
                return container.send_frames(frames_to_send);
            }));
            return fut.get();
        }

    private:
        hyquic &container;
        std::vector<si::frame_profile_container> frame_profiles;

        si::frame_to_send_container create_stream_frame(uint32_t max_frame_len, buffer_view &msg, uint32_t flags, uint64_t id, uint64_t offset)
        {
            uint64_t type = frame_type::STREAM;
            uint32_t header_len = 1;
            uint32_t msg_len = msg.len;

            header_len += get_var_int_length(id);

            type |= stream_bit::OFF;
            header_len += get_var_int_length(offset);

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
            frame_builder.push_var(id);
            if (type & stream_bit::OFF)
                frame_builder.push_var(offset);
            frame_builder.push_var(msg_len);
            frame_builder.push_pulled(msg, msg_len);

            quic_stream_info stream_info{
                .stream_id = id,
                .stream_flag = flags
            };
            return si::frame_to_send_container(std::move(frame_buff), msg_len, 0, true, std::move(stream_info));
        }
    };
}