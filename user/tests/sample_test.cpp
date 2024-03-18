#define BOOST_TEST_MODULE sample
#include <boost/test/included/unit_test.hpp>

extern "C" {
#include <linux/tls.h>
}

#include <sys/socket.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BAZ(expr) BOOST_CHECK_EQUAL(expr,0)

class sample_extension : public extension
{
public:
    std::mutex mut;
    std::condition_variable frame_cond;
    bool first_frame_received;

    sample_extension(hyquic::hyquic &container)
        : container(container), first_frame_received(false)
    {
        frame_details.push_back(si::frame_details_container(
            0xb1,
            true,
            false,
            true,
            fixed_length_frame_format_specification(1)
        ));
        frame_details.push_back(si::frame_details_container(
            0xb2,
            true,
            true,
            true,
            no_frame_format_specification()
        ));
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
        uint64_t content;
        switch (type)
        {
        case 0xb1: {
            content = frame_content.pull_int<NETWORK>(1);
            BCE(content, 42);
            std::lock_guard<std::mutex> lk(mut);
            first_frame_received = true;
            frame_cond.notify_all();
            return 1;
        }
        case 0xb2: {
            uint8_t content_len = frame_content.pull_var(content);
            BCE(content_len, 4);
            std::lock_guard<std::mutex> lk(mut);
            first_frame_received = true;
            frame_cond.notify_all();
            return content_len;
        }
        }
        return 0;
    }

    void handle_lost_frame(uint64_t type, buffer_view frame_content, const buffer_view &frame)
    {
        std::list<buffer> frames_to_resend;
        frames_to_resend.push_back(frame.copy(frame.len));
        BAZ(container.send_frames(frames_to_resend));
    }

    bool is_remote_transport_parameter_available()
    {
        return remote_transport_param_available;
    }

private:
    hyquic::hyquic &container;
    std::vector<si::frame_details_container> frame_details;
};

void test_client(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 3);

    hyquic_client client(argv[2], atoi(argv[3]));

    sample_extension ext(client);
    client.register_extension(ext);

    client.connect_to_server();
    BOOST_ASSERT(ext.is_remote_transport_parameter_available());

    std::list<buffer> frames_to_send;
    buffer frame_buff(2 + 1);
    buffer_view cursor(frame_buff);
    cursor.push_var(0xb1);
    cursor.push_int<NETWORK>(42, 1);
    frames_to_send.push_back(std::move(frame_buff));
    BAZ(client.send_frames(frames_to_send));

    std::unique_lock<std::mutex> lk(ext.mut);
    ext.frame_cond.wait_for(lk, std::chrono::seconds(3), [&ext]{return ext.first_frame_received;});
    BOOST_ASSERT(ext.first_frame_received);
    lk.unlock();

    client.close();
}

void test_server(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    sample_extension ext(connection);
    connection.register_extension(ext);

    connection.connect_to_client(argv[4], argv[5]);
    BOOST_ASSERT(ext.is_remote_transport_parameter_available());

    std::list<buffer> frames_to_send;
    buffer frame_buff(2 + 4);
    buffer_view cursor(frame_buff);
    cursor.push_var(0xb2);
    cursor.push_var(39485);
    frames_to_send.push_back(std::move(frame_buff));
    BAZ(connection.send_frames(frames_to_send));

    std::unique_lock<std::mutex> lk(ext.mut);
    ext.frame_cond.wait_for(lk, std::chrono::seconds(3), [&ext]{return ext.first_frame_received;});
    BOOST_ASSERT(ext.first_frame_received);
    lk.unlock();

    connection.close();
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