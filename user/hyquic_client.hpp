#include <hyquic.hpp>

namespace hyquic
{
    class hyquic_client : protected hyquic
    {
    public:
        hyquic_client(char *addr, uint16_t port)
        {
            sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
            if (sockfd < 0)
                throw network_error("Socket create failed.");
            
            sockaddr_in sock_addr = {};
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_port = htons(port);
            inet_pton(AF_INET, addr, &sock_addr.sin_addr.s_addr);
            if (connect(sockfd, (sockaddr*) &sock_addr, sizeof(sock_addr)))
                throw network_error("Socket connect failed.");
        }

        inline void connect_to_server(char *psk_path)
        {
            if (quic_client_handshake(sockfd, psk_path, nullptr))
                throw network_error("Handshake failed.");

            run();
        }

        inline void connect_to_server()
        {
            connect_to_server(nullptr);
        }
    };
} // namespace hyquic
