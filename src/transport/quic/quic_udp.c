/**
 * @file quic_udp.c
 * @brief UDP socket adapter for QUIC endpoints.
 */

#include "transport/quic/quic_udp.h"

#include <limits.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

typedef SOCKET quic_udp_native_fd_t;
typedef int quic_udp_socklen_t;
typedef int quic_udp_io_result_t;
typedef int quic_udp_buffer_len_t;

#define QUIC_UDP_NATIVE_INVALID_FD INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef int quic_udp_native_fd_t;
typedef socklen_t quic_udp_socklen_t;
typedef ssize_t quic_udp_io_result_t;
typedef size_t quic_udp_buffer_len_t;

#define QUIC_UDP_NATIVE_INVALID_FD (-1)
#endif

static quic_udp_native_fd_t quic_udp_to_native_fd(libp2p_quic_udp_fd_t fd)
{
#if defined(_WIN32)
    return (quic_udp_native_fd_t)fd;
#else
    return fd > (libp2p_quic_udp_fd_t)INT_MAX ? QUIC_UDP_NATIVE_INVALID_FD : (int)fd;
#endif
}

static libp2p_quic_udp_fd_t quic_udp_from_native_fd(quic_udp_native_fd_t fd)
{
#if defined(_WIN32)
    return (libp2p_quic_udp_fd_t)fd;
#else
    return fd < 0 ? LIBP2P_QUIC_UDP_INVALID_FD : (libp2p_quic_udp_fd_t)fd;
#endif
}

static int quic_udp_last_error(void)
{
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

#if defined(_WIN32)
static libp2p_quic_err_t quic_udp_platform_startup(void)
{
    WSADATA data;
    int rc = WSAStartup(MAKEWORD(2, 2), &data);

    return rc == 0 ? LIBP2P_QUIC_OK : LIBP2P_QUIC_ERR_INTERNAL;
}

static void quic_udp_platform_cleanup(void)
{
    (void)WSACleanup();
}
#endif

static void quic_udp_close_native(quic_udp_native_fd_t fd)
{
#if defined(_WIN32)
    (void)closesocket(fd);
#else
    (void)close(fd);
#endif
}

static int quic_udp_setsockopt_int(
    quic_udp_native_fd_t fd,
    int level,
    int option_name,
    int option_value)
{
#if defined(_WIN32)
    return setsockopt(
        fd,
        level,
        option_name,
        (const char *)&option_value,
        (int)sizeof(option_value));
#else
    return setsockopt(
        fd,
        level,
        option_name,
        &option_value,
        (quic_udp_socklen_t)sizeof(option_value));
#endif
}

static libp2p_quic_err_t quic_udp_errno_to_err(int err)
{
    switch (err)
    {
#if defined(_WIN32)
    case WSAEWOULDBLOCK:
    case WSAEINTR:
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    case WSAEMSGSIZE:
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    case WSAENOBUFS:
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    case WSAEADDRINUSE:
    case WSAEADDRNOTAVAIL:
    case WSAEAFNOSUPPORT:
        return LIBP2P_QUIC_ERR_ADDR;
    case WSAEBADF:
    case WSAENOTSOCK:
        return LIBP2P_QUIC_ERR_STATE;
#else
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
#endif
    default:
        return LIBP2P_QUIC_ERR_INTERNAL;
    }
}

static libp2p_quic_err_t quic_udp_addr_to_sockaddr(
    const libp2p_quic_addr_t *addr,
    struct sockaddr_storage *out,
    quic_udp_socklen_t *out_len)
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
        *out_len = (quic_udp_socklen_t)sizeof(*sin);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        (void)memcpy(&sin6->sin6_addr, addr->ip, 16U);
        *out_len = (quic_udp_socklen_t)sizeof(*sin6);
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_udp_sockaddr_to_addr(
    const struct sockaddr *addr,
    quic_udp_socklen_t addr_len,
    libp2p_quic_addr_t *out)
{
    if ((addr == NULL) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if ((addr->sa_family == AF_INET) &&
        (addr_len >= (quic_udp_socklen_t)sizeof(struct sockaddr_in)))
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        const uint8_t *ip = (const uint8_t *)&sin->sin_addr;

        return libp2p_quic_addr_from_ip4(ip, ntohs(sin->sin_port), out);
    }
    if ((addr->sa_family == AF_INET6) &&
        (addr_len >= (quic_udp_socklen_t)sizeof(struct sockaddr_in6)))
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        const uint8_t *ip = (const uint8_t *)&sin6->sin6_addr;

        return libp2p_quic_addr_from_ip6(ip, ntohs(sin6->sin6_port), out);
    }

    return LIBP2P_QUIC_ERR_ADDR;
}

static libp2p_quic_err_t quic_udp_set_nonblocking(quic_udp_native_fd_t fd)
{
#if defined(_WIN32)
    u_long mode = 1UL;

    if (ioctlsocket(fd, FIONBIO, &mode) != 0)
    {
        return quic_udp_errno_to_err(quic_udp_last_error());
    }
#else
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
    {
        return quic_udp_errno_to_err(quic_udp_last_error());
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return quic_udp_errno_to_err(quic_udp_last_error());
    }
#endif

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
    quic_udp_socklen_t storage_len = 0;
    quic_udp_native_fd_t fd = QUIC_UDP_NATIVE_INVALID_FD;
    int one = 1;
#if defined(_WIN32)
    int platform_started = 0;
#endif
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

#if defined(_WIN32)
    result = quic_udp_platform_startup();
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    platform_started = 1;
#endif

    fd = socket(
        local_addr->family == LIBP2P_QUIC_ADDR_IP4 ? AF_INET : AF_INET6,
        SOCK_DGRAM,
        IPPROTO_UDP);
    if (fd == QUIC_UDP_NATIVE_INVALID_FD)
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
        goto fail;
    }

    (void)quic_udp_setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, one);
#ifdef SO_NOSIGPIPE
    (void)quic_udp_setsockopt_int(fd, SOL_SOCKET, SO_NOSIGPIPE, one);
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
        result = quic_udp_errno_to_err(quic_udp_last_error());
        goto fail;
    }

    storage_len = (quic_udp_socklen_t)sizeof(storage);
    if (getsockname(fd, (struct sockaddr *)&storage, &storage_len) != 0)
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
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

    udp_socket->fd = quic_udp_from_native_fd(fd);
    udp_socket->open = 1U;
    udp_socket->nonblocking = (uint8_t)(nonblocking != 0);
    return LIBP2P_QUIC_OK;

fail:
    if (fd != QUIC_UDP_NATIVE_INVALID_FD)
    {
        quic_udp_close_native(fd);
    }
#if defined(_WIN32)
    if (platform_started != 0)
    {
        quic_udp_platform_cleanup();
    }
#endif
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
        quic_udp_close_native(quic_udp_to_native_fd(udp_socket->fd));
#if defined(_WIN32)
        quic_udp_platform_cleanup();
#endif
    }
    (void)libp2p_quic_udp_socket_init(udp_socket);
}

libp2p_quic_err_t libp2p_quic_udp_socket_fd(
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_udp_fd_t *out_fd)
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
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_endpoint_t *endpoint,
    uint8_t *buffer,
    size_t buffer_len,
    libp2p_quic_time_us_t now_us)
{
    struct sockaddr_storage remote_storage;
    quic_udp_socklen_t remote_len = (quic_udp_socklen_t)sizeof(remote_storage);
    quic_udp_io_result_t received = 0;
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
    if (buffer_len > (size_t)INT_MAX)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    received = recvfrom(
        quic_udp_to_native_fd(udp_socket->fd),
        (char *)buffer,
        (quic_udp_buffer_len_t)buffer_len,
        0,
        (struct sockaddr *)&remote_storage,
        &remote_len);
    if (received < 0)
    {
        return quic_udp_errno_to_err(quic_udp_last_error());
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
    quic_udp_socklen_t remote_len = 0;
    quic_udp_io_result_t sent = 0;
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
    if (buffer_len > (size_t)INT_MAX)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
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
        quic_udp_to_native_fd(udp_socket->fd),
        (const char *)datagram.data,
        (quic_udp_buffer_len_t)datagram.data_len,
        0,
        (const struct sockaddr *)&remote_storage,
        remote_len);
    if (sent < 0)
    {
        return quic_udp_errno_to_err(quic_udp_last_error());
    }
    if ((size_t)sent != datagram.data_len)
    {
        return LIBP2P_QUIC_ERR_INTERNAL;
    }

    return LIBP2P_QUIC_OK;
}
