/**
 * @file quic_udp.c
 * @brief POSIX UDP socket adapter for QUIC endpoints.
 */

#include "transport/quic/quic_udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static libp2p_quic_err_t quic_udp_errno_to_err(int err)
{
    switch (err)
    {
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    case EMSGSIZE:
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    case ENOMEM:
    case ENOBUFS:
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    case EADDRINUSE:
    case EADDRNOTAVAIL:
    case EAFNOSUPPORT:
        return LIBP2P_QUIC_ERR_ADDR;
    case EBADF:
    case ENOTSOCK:
        return LIBP2P_QUIC_ERR_STATE;
    default:
        return LIBP2P_QUIC_ERR_INTERNAL;
    }
}

static libp2p_quic_err_t quic_udp_addr_to_sockaddr(
    const libp2p_quic_addr_t *addr,
    struct sockaddr_storage *out,
    socklen_t *out_len)
{
    if ((addr == NULL) || (out == NULL) || (out_len == NULL) ||
        (libp2p_quic_addr_validate(addr) != LIBP2P_QUIC_OK))
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }

    (void)memset(out, 0, sizeof(*out));
    if (addr->family == LIBP2P_QUIC_ADDR_IP4)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        (void)memcpy(&sin->sin_addr, addr->ip, 4U);
        *out_len = (socklen_t)sizeof(*sin);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        (void)memcpy(&sin6->sin6_addr, addr->ip, 16U);
        *out_len = (socklen_t)sizeof(*sin6);
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_udp_sockaddr_to_addr(
    const struct sockaddr *addr,
    socklen_t addr_len,
    libp2p_quic_addr_t *out)
{
    if ((addr == NULL) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if ((addr->sa_family == AF_INET) && (addr_len >= (socklen_t)sizeof(struct sockaddr_in)))
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        const uint8_t *ip = (const uint8_t *)&sin->sin_addr;

        return libp2p_quic_addr_from_ip4(ip, ntohs(sin->sin_port), out);
    }
    if ((addr->sa_family == AF_INET6) && (addr_len >= (socklen_t)sizeof(struct sockaddr_in6)))
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        const uint8_t *ip = (const uint8_t *)&sin6->sin6_addr;

        return libp2p_quic_addr_from_ip6(ip, ntohs(sin6->sin6_port), out);
    }

    return LIBP2P_QUIC_ERR_ADDR;
}

static libp2p_quic_err_t quic_udp_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
    {
        return quic_udp_errno_to_err(errno);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return quic_udp_errno_to_err(errno);
    }

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_udp_socket_init(libp2p_quic_udp_socket_t *udp_socket)
{
    if (udp_socket == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(udp_socket, 0, sizeof(*udp_socket));
    udp_socket->fd = LIBP2P_QUIC_UDP_INVALID_FD;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_udp_socket_open(
    libp2p_quic_udp_socket_t *udp_socket,
    const libp2p_quic_addr_t *local_addr,
    int nonblocking)
{
    struct sockaddr_storage storage;
    socklen_t storage_len = 0;
    int fd = LIBP2P_QUIC_UDP_INVALID_FD;
    int one = 1;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (local_addr == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((udp_socket->open != 0U) || (udp_socket->fd != LIBP2P_QUIC_UDP_INVALID_FD))
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    result = quic_udp_addr_to_sockaddr(local_addr, &storage, &storage_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    fd = socket(
        local_addr->family == LIBP2P_QUIC_ADDR_IP4 ? AF_INET : AF_INET6,
        SOCK_DGRAM,
        IPPROTO_UDP);
    if (fd < 0)
    {
        return quic_udp_errno_to_err(errno);
    }

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, (socklen_t)sizeof(one));
#endif

    if (nonblocking != 0)
    {
        result = quic_udp_set_nonblocking(fd);
        if (result != LIBP2P_QUIC_OK)
        {
            goto fail;
        }
    }

    if (bind(fd, (const struct sockaddr *)&storage, storage_len) != 0)
    {
        result = quic_udp_errno_to_err(errno);
        goto fail;
    }

    storage_len = (socklen_t)sizeof(storage);
    if (getsockname(fd, (struct sockaddr *)&storage, &storage_len) != 0)
    {
        result = quic_udp_errno_to_err(errno);
        goto fail;
    }
    result = quic_udp_sockaddr_to_addr(
        (const struct sockaddr *)&storage,
        storage_len,
        &udp_socket->local_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }

    udp_socket->fd = fd;
    udp_socket->open = 1U;
    udp_socket->nonblocking = (uint8_t)(nonblocking != 0);
    return LIBP2P_QUIC_OK;

fail:
    (void)close(fd);
    return result;
}

void libp2p_quic_udp_socket_close(libp2p_quic_udp_socket_t *udp_socket)
{
    if (udp_socket == NULL)
    {
        return;
    }
    if (udp_socket->fd != LIBP2P_QUIC_UDP_INVALID_FD)
    {
        (void)close(udp_socket->fd);
    }
    (void)libp2p_quic_udp_socket_init(udp_socket);
}

libp2p_quic_err_t libp2p_quic_udp_socket_fd(const libp2p_quic_udp_socket_t *udp_socket, int *out_fd)
{
    if ((udp_socket == NULL) || (out_fd == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((udp_socket->open == 0U) || (udp_socket->fd == LIBP2P_QUIC_UDP_INVALID_FD))
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    *out_fd = udp_socket->fd;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_udp_socket_local_addr(
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_addr_t *out_addr)
{
    if ((udp_socket == NULL) || (out_addr == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((udp_socket->open == 0U) || (udp_socket->fd == LIBP2P_QUIC_UDP_INVALID_FD))
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    *out_addr = udp_socket->local_addr;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_udp_socket_recv(
    libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_endpoint_t *endpoint,
    uint8_t *buffer,
    size_t buffer_len,
    libp2p_quic_time_us_t now_us)
{
    struct sockaddr_storage remote_storage;
    socklen_t remote_len = (socklen_t)sizeof(remote_storage);
    ssize_t received = 0;
    libp2p_quic_rx_datagram_t datagram;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (endpoint == NULL) || (buffer == NULL) || (buffer_len == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((udp_socket->open == 0U) || (udp_socket->fd == LIBP2P_QUIC_UDP_INVALID_FD))
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    received = recvfrom(
        udp_socket->fd,
        buffer,
        buffer_len,
        0,
        (struct sockaddr *)&remote_storage,
        &remote_len);
    if (received < 0)
    {
        return quic_udp_errno_to_err(errno);
    }
    if (received == 0)
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    (void)memset(&datagram, 0, sizeof(datagram));
    datagram.local_addr = udp_socket->local_addr;
    result = quic_udp_sockaddr_to_addr(
        (const struct sockaddr *)&remote_storage,
        remote_len,
        &datagram.remote_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    datagram.data = buffer;
    datagram.data_len = (size_t)received;
    datagram.ecn = LIBP2P_QUIC_ECN_NOT_ECT;

    return libp2p_quic_endpoint_recv_datagram(endpoint, &datagram, now_us);
}

libp2p_quic_err_t libp2p_quic_udp_socket_send(
    libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_endpoint_t *endpoint,
    uint8_t *buffer,
    size_t buffer_len,
    libp2p_quic_time_us_t now_us)
{
    struct sockaddr_storage remote_storage;
    socklen_t remote_len = 0;
    ssize_t sent = 0;
    libp2p_quic_tx_datagram_t datagram;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (endpoint == NULL) || (buffer == NULL) || (buffer_len == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((udp_socket->open == 0U) || (udp_socket->fd == LIBP2P_QUIC_UDP_INVALID_FD))
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    (void)memset(&datagram, 0, sizeof(datagram));
    datagram.data = buffer;
    datagram.data_cap = buffer_len;

    result = libp2p_quic_endpoint_next_datagram(endpoint, &datagram, now_us);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (libp2p_quic_addr_equal(&datagram.local_addr, &udp_socket->local_addr, 0) == 0)
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }

    result = quic_udp_addr_to_sockaddr(&datagram.remote_addr, &remote_storage, &remote_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    sent = sendto(
        udp_socket->fd,
        datagram.data,
        datagram.data_len,
        0,
        (const struct sockaddr *)&remote_storage,
        remote_len);
    if (sent < 0)
    {
        return quic_udp_errno_to_err(errno);
    }
    if ((size_t)sent != datagram.data_len)
    {
        return LIBP2P_QUIC_ERR_INTERNAL;
    }

    return LIBP2P_QUIC_OK;
}
