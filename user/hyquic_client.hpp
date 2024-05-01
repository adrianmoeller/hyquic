#include <hyquic.hpp>

namespace hyquic
{
    class hyquic_client : public hyquic
    {
    public:
        hyquic_client(char *addr, uint16_t port)
        {
            int err;
            sockfd = si::socket_socket(AF_INET, SOCK_DGRAM);
            if (sockfd < 0)
                throw network_error("Socket create failed.", sockfd);
            
            sockaddr_in sock_addr = {};
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_port = htons(port);
            inet_pton(AF_INET, addr, &sock_addr.sin_addr.s_addr);
            err = si::socket_connect(sockfd, (sockaddr*) &sock_addr, sizeof(sock_addr));
            if (err)
                throw network_error("Socket connect failed.", err);
        }

        inline void connect_to_server(char *psk_path)
        {
            int err = handshake_client(psk_path, nullptr);
            if (err)
                throw network_error("Handshake failed.", err);

            run();
        }

        inline void connect_to_server()
        {
            connect_to_server(nullptr);
        }
    };
} // namespace hyquic
