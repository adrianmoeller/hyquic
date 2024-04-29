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
        frame_format_specification_builder b0;
        b0.add_var_int_component();

        frame_details.push_back(si::frame_details_container(
            0xb0,
            true,
            false,
            true,
            b0.get_specification()
        ));

        frame_format_specification_builder b1;
        b1.add_fix_len_component(5);

        frame_details.push_back(si::frame_details_container(
            0xb1,
            true,
            false,
            true,
            b1.get_specification()
        ));

        frame_format_specification_builder b2;
        uint8_t ref_id2 = b2.add_var_int_component(true);
        b2.add_mult_const_decl_len_component(ref_id2, 2);

        frame_details.push_back(si::frame_details_container(
            0xb2,
            true,
            false,
            true,
            b2.get_specification()
        ));

        frame_format_specification_builder b3_scope;
        b3_scope.add_var_int_component();

        frame_format_specification_builder b3;
        uint8_t ref_id3 = b3.add_fix_len_component(1, true);
        b3.add_mult_scope_decl_len_component(ref_id3, b3_scope);

        frame_details.push_back(si::frame_details_container(
            0xb3,
            true,
            false,
            true,
            b3.get_specification()
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
        std::lock_guard<std::mutex> lk(mut);
        frame_received = true;
        frame_cond.notify_all();

        switch (type) {
        case 0xb0: {
            uint64_t content;
            uint8_t content_len = frame_content.pull_var(content);
            BCE(content, 42);
            return content_len;
        }
        case 0xb1: {
            uint32_t content0 = frame_content.pull_int<NETWORK>(4);
            BCE(content0, 42);
            uint32_t content1 = frame_content.pull_int<NETWORK>(1);
            BCE(content1, 21);
            return 4 + 1;
        }
        case 0xb2: {
            uint64_t content;
            uint8_t content_len = frame_content.pull_var(content);
            BCE(content, 3);
            uint32_t content0 = frame_content.pull_int<NETWORK>(2);
            BCE(content0, 456);
            uint32_t content1 = frame_content.pull_int<NETWORK>(4);
            BCE(content1, 789);
            return content_len + 3 + 3;
        }
        case 0xb3: {
            uint32_t content0 = frame_content.pull_int<NETWORK>(1);
            BCE(content0, 2);
            uint64_t content1;
            uint8_t content1_len = frame_content.pull_var(content1);
            BCE(content1, 9999);
            uint64_t content2;
            uint8_t content2_len = frame_content.pull_var(content2);
            BCE(content2, 42);
            return 1 + content1_len + content2_len;
        }
        }
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
    si::default_frames_to_send_provider frames_to_send;

    switch(test_case) {
    case 0: {
        buffer frame_buff(2 + 1);
        buffer_view cursor(frame_buff);
        cursor.push_var(0xb0);
        cursor.push_var(42);
        frames_to_send.push(si::frame_to_send_container(std::move(frame_buff)));
        break;
    }
    case 1: {
        buffer frame_buff(2 + 5);
        buffer_view cursor(frame_buff);
        cursor.push_var(0xb1);
        cursor.push_int<NETWORK>(42, 4);
        cursor.push_int<NETWORK>(21, 1);
        frames_to_send.push(si::frame_to_send_container(std::move(frame_buff)));
        break;
    }
    case 2: {
        buffer frame_buff(2 + 1 + 3 + 3);
        buffer_view cursor(frame_buff);
        cursor.push_var(0xb2);
        cursor.push_var(3);
        cursor.push_int<NETWORK>(456, 2);
        cursor.push_int<NETWORK>(789, 4);
        frames_to_send.push(si::frame_to_send_container(std::move(frame_buff)));
        break;
    }
    case 3: {
        buffer frame_buff(2 + 1 + 2 + 1);
        buffer_view cursor(frame_buff);
        cursor.push_var(0xb3);
        cursor.push_int<NETWORK>(2, 1);
        cursor.push_var(9999);
        cursor.push_var(42);
        frames_to_send.push(si::frame_to_send_container(std::move(frame_buff)));
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