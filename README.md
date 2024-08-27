# HyQUIC

A hybrid user-kernel QUIC implementation.

## Background

The idea of this approach is to utilize the user space such that protocol extensions can be implemented and deployed more easily, while basic protocol features reside in the kernel for an optimized performance behavior.

Aiming to support the implementation of every possible upcoming extension in the user space seems implausible and would eventually result in a user-space-only QUIC implementation and/or an unmanageable state complexity and communication overhead between user and kernel space.
Thus, HyQUIC supports limited user-space extensibility at frame-level to minimize the communication overhead.

The kernel part of this implementation is based on the ["QUIC in Linux Kernel" implementation by Xin Long](https://github.com/lxin/quic).

## Setup

1. Required OS: GNU/Linux
2. Install [Boost C++ libraries](https://www.boost.org/doc/libs/1_86_0/more/getting_started/unix-variants.html) (tested with version 1.84.0)
3. Install the following package dependencies: `make autoconf automake libtool pkg-config gnutls-dev linux-headers-$(uname -r) libkeyutils-dev gcc g++ cmake`
4. Inside the `kernel/` directory, run `sudo ./build.sh -c -t`
5. Inside the `user/` directory, build project via `cmake`
6. Navigate to `user/tests/keys/`, inside this directory, run `sudo ./ca_cert_pkey.sh`
6. Run tests via `ctest` (sudo required)
