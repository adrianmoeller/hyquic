#define BOOST_TEST_MODULE stream extension
#include <boost/test/included/unit_test.hpp>

#include <iostream>
#include <stream_extension.hpp>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BAZ(expr) BOOST_CHECK_EQUAL(expr,0)

void test_client_stream_ext(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 3);

    hyquic_client client(argv[2], atoi(argv[3]));

    stream_extension ext(client, false);
    client.register_extension(ext);

    client.connect_to_server();

    buffer msg_to_send("Hello, HyQUIC server!");
    uint32_t msg_to_send_len = msg_to_send.len;
    stream_data send_data(0, QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN, std::move(msg_to_send));

    BCE(ext.send_msg(send_data), msg_to_send_len);

    std::optional<stream_data> msg_received = ext.recv_msg(100, std::chrono::seconds(3));
    BOOST_ASSERT(msg_received);
    BCE((char*) msg_received->buff.data, "Hello, HyQUIC client!");

    client.close();
}

void test_client_no_ext(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 3);

    hyquic_client client(argv[2], atoi(argv[3]));
    client.connect_to_server();

    buffer msg_to_send("Hello, HyQUIC server!");
    uint32_t msg_to_send_len = msg_to_send.len;
    BCE(client.send_msg(stream_data(0, QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN, std::move(msg_to_send))), msg_to_send_len);

    std::optional<stream_data> msg_received = client.receive_msg(std::chrono::seconds(3));
    BOOST_ASSERT(msg_received);
    BCE((char*) msg_received->buff.data, "Hello, HyQUIC client!");

    client.close();
}

void test_client(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    if (!strcmp(argv[4], "ext"))
        test_client_stream_ext(argc, argv);
    else
        test_client_no_ext(argc, argv);
}

void test_server_stream_ext(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    stream_extension ext(connection, true);
    connection.register_extension(ext);

    connection.connect_to_client(argv[4], argv[5]);

    std::optional<stream_data> msg_received = ext.recv_msg(100, std::chrono::seconds(3));
    BOOST_ASSERT(msg_received);
    BCE((char*) msg_received->buff.data, "Hello, HyQUIC server!");

    buffer msg_to_send("Hello, HyQUIC client!");
    uint32_t msg_to_send_len = msg_to_send.len;
    stream_data send_data(0, QUIC_STREAM_FLAG_FIN, std::move(msg_to_send));

    BCE(ext.send_msg(send_data), msg_to_send_len);

    connection.close();
}

void test_server_no_ext(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    connection.connect_to_client(argv[4], argv[5]);

    std::optional<stream_data> msg_received = connection.receive_msg(std::chrono::seconds(3));
    BOOST_ASSERT(msg_received);
    BCE((char*) msg_received->buff.data, "Hello, HyQUIC server!");

    buffer msg_to_send("Hello, HyQUIC client!");
    uint32_t msg_to_send_len = msg_to_send.len;
    BCE(connection.send_msg(stream_data(0, QUIC_STREAM_FLAG_FIN, std::move(msg_to_send))), msg_to_send_len);

    connection.close();
}

void test_server(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 7);

    if (!strcmp(argv[7], "ext"))
        test_server_stream_ext(argc, argv);
    else
        test_server_no_ext(argc, argv);
}

BOOST_AUTO_TEST_CASE(sample_test)
{
    auto &m_testsuite = boost::unit_test::framework::master_test_suite();

    BOOST_ASSERT(m_testsuite.argc >= 2);
    BOOST_ASSERT(!strcmp(m_testsuite.argv[1], "server") || !strcmp(m_testsuite.argv[1], "client"));

    if (!strcmp(m_testsuite.argv[1], "client")) {
		test_client(m_testsuite.argc, m_testsuite.argv);
    } else {
	    test_server(m_testsuite.argc, m_testsuite.argv);
    }
}