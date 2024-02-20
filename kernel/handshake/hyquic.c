#include <sys/socket.h>
#include <stdint.h>
#include "netinet/quic.h"

int hyquic_set_transport_parameter(int sockfd, const void *param, size_t length)
{
    return setsockopt(sockfd, SOL_QUIC, HYQUIC_SOCKOPT_TRANSPORT_PARAM, param, length);
}