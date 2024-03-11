#include <hyquic.hpp>

namespace hyquic
{
    class hyquic_server_connection : protected hyquic 
    {
    public:
        inline void connect_to_client(char *pkey_path, char *cert_path)
        {
            if (quic_server_handshake(sockfd, pkey_path, cert_path))
                throw network_error("Handshake failed.");

            run();
        }

        inline void connect_to_client(char *psk_path)
        {
            connect_to_client(psk_path, nullptr);
        }

    private:
        sockaddr addr;
        socklen_t addr_len;

        hyquic_server_connection(int clientfd, sockaddr addr, socklen_t addr_len)
            : addr(addr), addr_len(addr_len)
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
            listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
            if (listenfd < 0)
                throw network_error("Socket create failed.");
            
            sockaddr_in sock_addr = {};
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_port = htons(port);
            inet_pton(AF_INET, addr, &sock_addr.sin_addr.s_addr);
            if (bind(listenfd, (sockaddr*) &sock_addr, sizeof(sock_addr)))
                throw network_error("Socket bind failed.");

            if (listen(listenfd, 1))
                throw network_error("Socket listen failed.");
        }

        hyquic_server_connection accept_connection()
        {
            sockaddr addr;
            socklen_t addr_len = sizeof(addr);

            int sockfd = accept(listenfd, &addr, &addr_len);
            if (sockfd < 0)
                throw network_error("Socket accept failed.");

            return hyquic_server_connection(sockfd, addr, addr_len);
        }

    private:
        int listenfd;
    };
} // namespace hyquic
