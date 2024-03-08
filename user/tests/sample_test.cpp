#define BOOST_TEST_MODULE sample
#include <boost/test/included/unit_test.hpp>

#include <sys/socket.h>
#include <iostream>
#include <hyquic.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)
#define BA(expr) BOOST_ASSERT(!(expr))

void test_client(int argc, char *argv[])
{
    // TODO
    BA(0);
}

void test_server(int argc, char *argv[])
{
    // TODO
    BA(0);
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