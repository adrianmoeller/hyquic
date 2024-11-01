/* SPDX-License-Identifier: GPL-2.0+ */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#include <hyquic.hpp>

namespace hyquic
{
    class hyquic_server_connection : public hyquic 
    {
    public:
        inline void connect_to_client(char *pkey_path, char *cert_path)
        {
            int err = handshake_server(pkey_path, cert_path);
            if (err)
                throw network_error("Handshake failed.", err);

            run();
        }

        inline void connect_to_client(char *psk_path)
        {
            connect_to_client(psk_path, nullptr);
        }

    private:
        sockaddr_in addr;
        socklen_t addr_len;

        hyquic_server_connection(
            int clientfd,
            sockaddr_in addr,
            socklen_t addr_len,
            uint32_t sock_recv_buff_size = SOCK_RECV_BUFF_INIT_SIZE,
            time_t sock_recv_timeout = SOCK_RECV_TIMEOUT, 
            uint32_t sock_recv_failure_recovery_time = SOCK_RECV_FAILURE_RECOVERY_TIME
        )
            : hyquic(sock_recv_buff_size, sock_recv_timeout, sock_recv_failure_recovery_time), addr(addr), addr_len(addr_len)
        {
            sockfd = clientfd;
        }

        friend class hyquic_server;
    };

    class hyquic_server
    {
    public:
        hyquic_server(char *addr, uint16_t port)
        {
            int err;
            listenfd = si::socket_socket(AF_INET, SOCK_DGRAM);
            if (listenfd < 0)
                throw network_error("Socket create failed.", listenfd);
            
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_port = htons(port);
            inet_pton(AF_INET, addr, &sock_addr.sin_addr.s_addr);
            err = si::socket_bind(listenfd, (sockaddr*) &sock_addr, sizeof(sock_addr));
            if (err)
                throw network_error("Socket bind failed.", err);

            err = si::socket_listen(listenfd, 1);
            if (err)
                throw network_error("Socket listen failed.", err);
        }

        ~hyquic_server()
        {
            si::socket_close(listenfd);
        }

        hyquic_server_connection accept_connection(
            uint32_t sock_recv_buff_size = SOCK_RECV_BUFF_INIT_SIZE,
            time_t sock_recv_timeout = SOCK_RECV_TIMEOUT, 
            uint32_t sock_recv_failure_recovery_time = SOCK_RECV_FAILURE_RECOVERY_TIME
        )
        {
            socklen_t addr_len = sizeof(sock_addr);

            int sockfd = si::socket_accept(listenfd, (sockaddr*) &sock_addr, &addr_len);
            if (sockfd < 0)
                throw network_error("Socket accept failed.", sockfd);

            return hyquic_server_connection(sockfd, sock_addr, addr_len, sock_recv_buff_size, sock_recv_timeout, sock_recv_failure_recovery_time);
        }

    private:
        int listenfd;
        sockaddr_in sock_addr = {};
    };
} // namespace hyquic
