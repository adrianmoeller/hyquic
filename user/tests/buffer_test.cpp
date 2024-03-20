#define BOOST_TEST_MODULE buffer
#include <boost/test/included/unit_test.hpp>

#include <iostream>
#include <buffer.hpp>

using namespace hyquic;

#define BCE(L,R) BOOST_CHECK_EQUAL(L,R)

BOOST_AUTO_TEST_CASE(buffer_init)
{
    buffer b0(20);
    BCE(b0.len, 20);

    buffer b1;
    BCE(b1.len, 0);
    BCE(b1.data, nullptr);
}

BOOST_AUTO_TEST_CASE(buffer_view_prune)
{
    buffer b(20);
    buffer_view bv(b);

    bv.prune(19);
    BCE(bv.end(), false);
    bv.prune(1);
    BCE(bv.end(), true);
    BOOST_CHECK_THROW(bv.prune(1), buffer_error);
}

BOOST_AUTO_TEST_CASE(buffer_view_push_var)
{
    buffer b(15);
    buffer_view bv(b);

    bv.push_var(63);
    bv.push_var(14321);
    bv.push_var(970721120);
    bv.push_var(90217072011235701);

    BCE(b.data[0], 0x3F);
    BCE(b.data[1], 0x77);
    BCE(b.data[2], 0xF1);
    BCE(b.data[3], 0xB9);
    BCE(b.data[4], 0xDC);
    BCE(b.data[5], 0x07);
    BCE(b.data[6], 0x60);
    BCE(b.data[7], 0xC1);
    BCE(b.data[8], 0x40);
    BCE(b.data[9], 0x83);
    BCE(b.data[10], 0xF2);
    BCE(b.data[11], 0xF1);
    BCE(b.data[12], 0xE7);
    BCE(b.data[13], 0xD1);
    BCE(b.data[14], 0x75);
}

BOOST_AUTO_TEST_CASE(buffer_view_pull_var)
{
    buffer b(15);
    buffer_view bv(b);
    uint64_t val;

    b.data[0] = 0x2D;
    b.data[1] = 0x44;
    b.data[2] = 0x01;
    b.data[3] = 0x80;
    b.data[4] = 0xA3;
    b.data[5] = 0xD7;
    b.data[6] = 0x0A;
    b.data[7] = 0xc0;
    b.data[10] = 0x02;
    b.data[11] = 0x80;
    b.data[14] = 0x05;

    BCE(bv.pull_var(val), 1);
    BCE(val, 45);
    BCE(bv.pull_var(val), 2);
    BCE(val, 1025);
    BCE(bv.pull_var(val), 4);
    BCE(val, 10737418);
    BCE(bv.pull_var(val), 8);
    BCE(val, 10737418245);
}

BOOST_AUTO_TEST_CASE(buffer_view_push_int)
{
    buffer b(7);
    buffer_view bv(b);

    bv.push_int<NETWORK>(45, 1);
    bv.push_int<NETWORK>(1284, 2);
    bv.push_int<NETWORK>(412829854, 4);

    BCE(b.data[0], 0x2D);
    BCE(b.data[1], 0x05);
    BCE(b.data[2], 0x04);
    BCE(b.data[3], 0x18);
    BCE(b.data[4], 0x9B);
    BCE(b.data[5], 0x48);
    BCE(b.data[6], 0x9E);
}

BOOST_AUTO_TEST_CASE(buffer_view_pull_int)
{
    buffer b(10);
    buffer_view bv(b);

    b.data[0] = 0x2D;
    b.data[1] = 0x05;
    b.data[2] = 0x04;
    b.data[3] = 0x00;
    b.data[4] = 0x37;
    b.data[5] = 0xCC;
    b.data[6] = 0x18;
    b.data[7] = 0x9B;
    b.data[8] = 0x48;
    b.data[9] = 0x9E;

    BCE(bv.pull_int<NETWORK>(1), 45);
    BCE(bv.pull_int<NETWORK>(2), 1284);
    BCE(bv.pull_int<NETWORK>(3), 14284);
    BCE(bv.pull_int<NETWORK>(4), 412829854);
}