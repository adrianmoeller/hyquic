#define BOOST_TEST_MODULE frame_format_spec
#include <boost/test/included/unit_test.hpp>

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BAZ(expr) BOOST_CHECK_EQUAL(expr,0)

class ffs_extension : public extension
{
public:
    std::mutex mut;
    std::condition_variable frame_cond;
    bool frame_received;

    ffs_extension(hyquic::hyquic &container)
        : container(container), frame_received(false)
    {
        // TODO
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
        // TODO
        return 0;
    }

    void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame)
    {
    }

    bool is_remote_transport_parameter_available()
    {
        return remote_transport_param_available;
    }

private:
    hyquic::hyquic &container;
    std::vector<si::frame_details_container> frame_details;
};

void client_send_frame(hyquic_client &client, int test_case)
{
    std::list<buffer> frames_to_send;

    switch(test_case) {
    case 1: {
        // TODO
        break;
    }
    }

    BAZ(client.send_frames(frames_to_send));
}

void test_client(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 4);

    hyquic_client client(argv[2], atoi(argv[3]));

    ffs_extension ext(client);
    client.register_extension(ext);
    client.connect_to_server();
    BOOST_ASSERT(ext.is_remote_transport_parameter_available());

    client_send_frame(client, atoi(argv[4]));

    client.close();
}

void test_server(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 6);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    ffs_extension ext(connection);
    connection.register_extension(ext);
    connection.connect_to_client(argv[4], argv[5]);
    BOOST_ASSERT(ext.is_remote_transport_parameter_available());

    std::unique_lock<std::mutex> lk(ext.mut);
    ext.frame_cond.wait_for(lk, std::chrono::seconds(3), [&ext]{return ext.frame_received;});
    BOOST_ASSERT(ext.frame_received);
    lk.unlock();

    connection.close();
}

BOOST_AUTO_TEST_CASE(ffs_test)
{
    auto &m_testsuite = boost::unit_test::framework::master_test_suite();

    BOOST_ASSERT(m_testsuite.argc >= 2);
    BOOST_ASSERT(!strcmp(m_testsuite.argv[1], "server") || !strcmp(m_testsuite.argv[1], "client"));

    if (!strcmp(m_testsuite.argv[1], "client"))
		test_client(m_testsuite.argc, m_testsuite.argv);
    else
	    test_server(m_testsuite.argc, m_testsuite.argv);
}