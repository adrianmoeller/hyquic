#define BOOST_TEST_MODULE sample
#include <boost/test/included/unit_test.hpp>

#include <sys/socket.h>
#include <iostream>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BAZ(expr) BOOST_ASSERT(!(expr))

void test_client(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 3);

    hyquic_client client(argv[2], atoi(argv[3]));

    // TODO register extension

    client.connect_to_server();

    // TODO
    BAZ(0);
}

void test_server(int argc, char *argv[])
{
    BOOST_ASSERT(argc >= 5);

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    // TODO register extension

    connection.connect_to_client(argv[4], argv[5]);

    // TODO
    BAZ(0);
}

BOOST_AUTO_TEST_CASE(buffer_init)
{
    auto &m_testsuite = boost::unit_test::framework::master_test_suite();

    BOOST_ASSERT(m_testsuite.argc >= 2);
    BOOST_ASSERT(!strcmp(m_testsuite.argv[1], "server") || !strcmp(m_testsuite.argv[1], "client"));

    if (!strcmp(m_testsuite.argv[1], "client"))
		test_client(m_testsuite.argc, m_testsuite.argv);
    else
	    test_server(m_testsuite.argc, m_testsuite.argv);
}