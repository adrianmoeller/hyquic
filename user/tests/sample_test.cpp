#define BOOST_TEST_MODULE sample
#include <boost/test/included/unit_test.hpp>

extern "C" {
#include <linux/tls.h>
}

#include <sys/socket.h>
#include <iostream>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BAZ(expr) BOOST_ASSERT(!(expr))

class simple_extension : public extension
{
public:
    bool first_frame_received = false;

    simple_extension(hyquic::hyquic &container)
        : container(container)
    {
        frame_details.push_back((hyquic_frame_details) {
            .frame_type = 0xb1,
            .fixed_length = 1,
            .ack_eliciting = true,
            .ack_immediate = false,
            .non_probing = true,
        });
        frame_details.push_back((hyquic_frame_details) {
            .frame_type = 0xb2,
            .fixed_length = -1,
            .ack_eliciting = true,
            .ack_immediate = true,
            .non_probing = true,
        });
    }

    inline buffer transport_parameter()
    {
        buffer buff(5);
        buffer_view cursor(buff);

        cursor.push_var(0x7934);
        cursor.push_var(0);

        return buff;
    }

    const std::vector<hyquic_frame_details>& frame_details_list()
    {
        return frame_details;
    }

    uint32_t handle_frame(uint64_t type, buffer_view frame_content)
    {
        uint64_t content;
        switch (type)
        {
        case 0xb1:
            content = frame_content.pull_int<NETWORK>(1);
            BCE(content, 42);
            first_frame_received = true;
            return 1;
        case 0xb2:
            uint8_t content_len = frame_content.pull_var(content);
            BCE(content_len, 4);
            return content_len;
        }
        return 0;
    }

    void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame)
    {
        std::list<buffer> frames_to_resend;
        frames_to_resend.push_back(frame.copy(frame.len));
        BAZ(container.send_frames(frames_to_resend));
    }

private:
    hyquic::hyquic &container;
    std::vector<hyquic_frame_details> frame_details;
};

void test_client(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 3);

    hyquic_client client(argv[2], atoi(argv[3]));

    quic_transport_param transport_param = {};
    transport_param.payload_cipher_type = TLS_CIPHER_AES_GCM_256;
    BAZ(client.set_socket_option(QUIC_SOCKOPT_TRANSPORT_PARAM, &transport_param, sizeof(transport_param)));

    simple_extension ext(client);
    client.register_extension(ext);

    client.connect_to_server();

    client.close();

    sleep(1);

    BOOST_ASSERT(ext.first_frame_received);
}

void test_server(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    quic_transport_param transport_param = {};
    transport_param.payload_cipher_type = TLS_CIPHER_AES_GCM_256;
    BAZ(connection.set_socket_option(QUIC_SOCKOPT_TRANSPORT_PARAM, &transport_param, sizeof(transport_param)));

    simple_extension ext(connection);
    connection.register_extension(ext);

    connection.connect_to_client(argv[4], argv[5]);

    std::list<buffer> frames_to_send;
    buffer frame_buff(3);
    buffer_view cursor(frame_buff);
    cursor.push_var(0xb1);
    cursor.push_int<NETWORK>(42, 1);
    frames_to_send.push_back(std::move(frame_buff));
    BAZ(connection.send_frames(frames_to_send));
}

BOOST_AUTO_TEST_CASE(sample_test)
{
    auto &m_testsuite = boost::unit_test::framework::master_test_suite();

    BOOST_ASSERT(m_testsuite.argc >= 2);
    BOOST_ASSERT(!strcmp(m_testsuite.argv[1], "server") || !strcmp(m_testsuite.argv[1], "client"));

    if (!strcmp(m_testsuite.argv[1], "client"))
		test_client(m_testsuite.argc, m_testsuite.argv);
    else
	    test_server(m_testsuite.argc, m_testsuite.argv);
}