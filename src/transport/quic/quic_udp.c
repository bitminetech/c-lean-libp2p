/**
 * @file quic_udp.c
 * @brief UDP socket adapter for QUIC endpoints.
 */

#include "transport/quic/quic_udp.h"

#include <limits.h>
#include <string.h>

#if defined(_WIN32)
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

static int quic_udp_fd_is_native_valid(libp2p_quic_udp_fd_t fd)
{
    int result = 1;

#if defined(_WIN32)
    if (fd == LIBP2P_QUIC_UDP_INVALID_FD)
#else
    if ((fd == LIBP2P_QUIC_UDP_INVALID_FD) || (fd > (libp2p_quic_udp_fd_t)INT_MAX))
#endif
    {
        result = 0;
    }

    return result;
}

static libp2p_quic_udp_fd_t quic_udp_from_native_fd(quic_udp_native_fd_t fd)
{
#if defined(_WIN32)
    return (libp2p_quic_udp_fd_t)fd;
#else
    libp2p_quic_udp_fd_t result = LIBP2P_QUIC_UDP_INVALID_FD;

    if (fd >= 0)
    {
        result = (libp2p_quic_udp_fd_t)fd;
    }

    return result;
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
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_INTERNAL;

    switch (err)
    {
#if defined(_WIN32)
    case WSAEWOULDBLOCK:
    case WSAEINTR:
        result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        break;
    case WSAEMSGSIZE:
        result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        break;
    case WSAENOBUFS:
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
        break;
    case WSAEADDRINUSE:
    case WSAEADDRNOTAVAIL:
    case WSAEAFNOSUPPORT:
        result = LIBP2P_QUIC_ERR_ADDR;
        break;
    case WSAEBADF:
    case WSAENOTSOCK:
        result = LIBP2P_QUIC_ERR_STATE;
        break;
#else
    case EAGAIN:
#if defined(EWOULDBLOCK) && defined(EAGAIN) && (EWOULDBLOCK != EAGAIN)
    case EWOULDBLOCK:
#endif
    case EINTR:
        result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        break;
    case EMSGSIZE:
        result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        break;
    case ENOMEM:
    case ENOBUFS:
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
        break;
    case EADDRINUSE:
    case EADDRNOTAVAIL:
    case EAFNOSUPPORT:
        result = LIBP2P_QUIC_ERR_ADDR;
        break;
    case EBADF:
    case ENOTSOCK:
        result = LIBP2P_QUIC_ERR_STATE;
        break;
#endif
    default:
        result = LIBP2P_QUIC_ERR_INTERNAL;
        break;
    }

    return result;
}

static libp2p_quic_err_t quic_udp_addr_to_sockaddr(
    const libp2p_quic_addr_t *addr,
    struct sockaddr_storage *out,
    quic_udp_socklen_t *out_len)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((addr == NULL) || (out == NULL) || (out_len == NULL) ||
        (libp2p_quic_addr_validate(addr) != LIBP2P_QUIC_OK))
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }
    else if (addr->family == LIBP2P_QUIC_ADDR_IP4)
    {
        struct sockaddr_in sin;

        (void)memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(addr->port);
        (void)memcpy(&sin.sin_addr, addr->ip, 4U);
        (void)memset(out, 0, sizeof(*out));
        (void)memcpy(out, &sin, sizeof(sin));
        *out_len = (quic_udp_socklen_t)sizeof(sin);
    }
    else
    {
        struct sockaddr_in6 sin6;

        (void)memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(addr->port);
        (void)memcpy(&sin6.sin6_addr, addr->ip, 16U);
        (void)memset(out, 0, sizeof(*out));
        (void)memcpy(out, &sin6, sizeof(sin6));
        *out_len = (quic_udp_socklen_t)sizeof(sin6);
    }

    return result;
}

static libp2p_quic_err_t quic_udp_sockaddr_to_addr(
    const struct sockaddr *addr,
    quic_udp_socklen_t addr_len,
    libp2p_quic_addr_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_ADDR;

    if ((addr == NULL) || (out == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((addr->sa_family == AF_INET) &&
             (addr_len >= (quic_udp_socklen_t)sizeof(struct sockaddr_in)))
    {
        struct sockaddr_in sin;
        uint8_t ip[4];

        (void)memcpy(&sin, addr, sizeof(sin));
        (void)memcpy(ip, &sin.sin_addr, sizeof(ip));
        result = libp2p_quic_addr_from_ip4(ip, ntohs(sin.sin_port), out);
    }
    else if ((addr->sa_family == AF_INET6) &&
             (addr_len >= (quic_udp_socklen_t)sizeof(struct sockaddr_in6)))
    {
        struct sockaddr_in6 sin6;
        uint8_t ip[16];

        (void)memcpy(&sin6, addr, sizeof(sin6));
        (void)memcpy(ip, &sin6.sin6_addr, sizeof(ip));
        result = libp2p_quic_addr_from_ip6(ip, ntohs(sin6.sin6_port), out);
    }
    else
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }

    return result;
}

static int quic_udp_addr_is_unspecified(const libp2p_quic_addr_t *addr)
{
    int result = 1;

    if (addr == NULL)
    {
        result = 0;
    }
    else
    {
        const size_t limit = (addr->family == LIBP2P_QUIC_ADDR_IP4) ? 4U : 16U;
        size_t index = 0U;

        for (index = 0U; index < limit; index++)
        {
            if (addr->ip[index] != 0U)
            {
                result = 0;
                break;
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_udp_default_route_addr(
    libp2p_quic_addr_family_t family,
    libp2p_quic_addr_t *out)
{
    static const uint8_t probe_ip4[4] = {192U, 0U, 2U, 1U};
    static const uint8_t probe_ip6[16] = {
        0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
        0U,    0U,    0U,    0U,    0U, 0U, 0U, 1U};
    struct sockaddr_storage storage;
    quic_udp_socklen_t storage_len = 0;
    quic_udp_native_fd_t fd = QUIC_UDP_NATIVE_INVALID_FD;
    int socket_family = AF_INET6;
#if defined(_WIN32)
    int platform_started = 0;
#endif
    libp2p_quic_addr_t probe;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (family == LIBP2P_QUIC_ADDR_IP4)
    {
        socket_family = AF_INET;
        result = libp2p_quic_addr_from_ip4(probe_ip4, 9U, &probe);
    }
    else if (family == LIBP2P_QUIC_ADDR_IP6)
    {
        socket_family = AF_INET6;
        result = libp2p_quic_addr_from_ip6(probe_ip6, 9U, &probe);
    }
    else
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_addr_to_sockaddr(&probe, &storage, &storage_len);
    }

#if defined(_WIN32)
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_platform_startup();
        if (result == LIBP2P_QUIC_OK)
        {
            platform_started = 1;
        }
    }
#endif

    if (result == LIBP2P_QUIC_OK)
    {
        fd = socket(socket_family, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == QUIC_UDP_NATIVE_INVALID_FD)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
    }
    /* cppcheck-suppress misra-c2012-17.3 */
    if ((result == LIBP2P_QUIC_OK) &&
        (connect(fd, (const struct sockaddr *)&storage, storage_len) != 0))
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
    }
    if (result == LIBP2P_QUIC_OK)
    {
        storage_len = (quic_udp_socklen_t)sizeof(storage);
        if (getsockname(fd, (struct sockaddr *)&storage, &storage_len) != 0)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_sockaddr_to_addr((const struct sockaddr *)&storage, storage_len, out);
    }
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

static libp2p_quic_err_t quic_udp_set_nonblocking(quic_udp_native_fd_t fd)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

#if defined(_WIN32)
    u_long mode = 1UL;

    if (ioctlsocket(fd, FIONBIO, &mode) != 0)
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
    }
#else
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
    }
    else if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }
#endif

    return result;
}

libp2p_quic_err_t libp2p_quic_udp_socket_init(libp2p_quic_udp_socket_t *udp_socket)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (udp_socket == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(udp_socket, 0, sizeof(*udp_socket));
        udp_socket->fd = LIBP2P_QUIC_UDP_INVALID_FD;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_udp_socket_open(
    libp2p_quic_udp_socket_t *udp_socket,
    const libp2p_quic_addr_t *local_addr,
    int nonblocking)
{
    struct sockaddr_storage storage;
    quic_udp_socklen_t storage_len = 0;
    quic_udp_native_fd_t fd = QUIC_UDP_NATIVE_INVALID_FD;
    int socket_family = AF_INET6;
    int one = 1;
#if defined(_WIN32)
    int platform_started = 0;
#endif
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (local_addr == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((udp_socket->open != 0U) || (udp_socket->fd != LIBP2P_QUIC_UDP_INVALID_FD))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        result = quic_udp_addr_to_sockaddr(local_addr, &storage, &storage_len);
    }

#if defined(_WIN32)
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_platform_startup();
        if (result == LIBP2P_QUIC_OK)
        {
            platform_started = 1;
        }
    }
#endif

    if (result == LIBP2P_QUIC_OK)
    {
        if (local_addr->family == LIBP2P_QUIC_ADDR_IP4)
        {
            socket_family = AF_INET;
        }

        fd = socket(
            socket_family,
            SOCK_DGRAM,
            IPPROTO_UDP);
        if (fd == QUIC_UDP_NATIVE_INVALID_FD)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        (void)quic_udp_setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, one);
#ifdef SO_NOSIGPIPE
        (void)quic_udp_setsockopt_int(fd, SOL_SOCKET, SO_NOSIGPIPE, one);
#endif
    }

    if ((result == LIBP2P_QUIC_OK) && (nonblocking != 0))
    {
        result = quic_udp_set_nonblocking(fd);
    }

    if ((result == LIBP2P_QUIC_OK) && (bind(fd, (const struct sockaddr *)&storage, storage_len) != 0))
    {
        result = quic_udp_errno_to_err(quic_udp_last_error());
    }

    if (result == LIBP2P_QUIC_OK)
    {
        storage_len = (quic_udp_socklen_t)sizeof(storage);
        if (getsockname(fd, (struct sockaddr *)&storage, &storage_len) != 0)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_sockaddr_to_addr(
            (const struct sockaddr *)&storage,
            storage_len,
            &udp_socket->local_addr);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        udp_socket->fd = quic_udp_from_native_fd(fd);
        udp_socket->open = 1U;
        if (nonblocking != 0)
        {
            udp_socket->nonblocking = 1U;
        }
        else
        {
            udp_socket->nonblocking = 0U;
        }
    }
    else
    {
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
    }

    return result;
}

void libp2p_quic_udp_socket_close(libp2p_quic_udp_socket_t *udp_socket)
{
    if (udp_socket != NULL)
    {
        if (quic_udp_fd_is_native_valid(udp_socket->fd) != 0)
        {
            quic_udp_close_native(quic_udp_to_native_fd(udp_socket->fd));
#if defined(_WIN32)
            quic_udp_platform_cleanup();
#endif
        }
        (void)libp2p_quic_udp_socket_init(udp_socket);
    }
}

libp2p_quic_err_t libp2p_quic_udp_socket_fd(
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_udp_fd_t *out_fd)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (out_fd == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((udp_socket->open == 0U) || (quic_udp_fd_is_native_valid(udp_socket->fd) == 0))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        *out_fd = udp_socket->fd;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_udp_socket_local_addr(
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_addr_t *out_addr)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (out_addr == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((udp_socket->open == 0U) || (quic_udp_fd_is_native_valid(udp_socket->fd) == 0))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        *out_addr = udp_socket->local_addr;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_udp_socket_listen_addr(
    const libp2p_quic_udp_socket_t *udp_socket,
    libp2p_quic_addr_t *out_addr)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((udp_socket == NULL) || (out_addr == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (udp_socket->open == 0U)
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        *out_addr = udp_socket->local_addr;
    }
    if ((result == LIBP2P_QUIC_OK) && (quic_udp_addr_is_unspecified(out_addr) != 0))
    {
        libp2p_quic_addr_t route_addr;
        const libp2p_quic_err_t route_result =
            quic_udp_default_route_addr(out_addr->family, &route_addr);

        if ((route_result == LIBP2P_QUIC_OK) &&
            (route_addr.family == out_addr->family) &&
            (quic_udp_addr_is_unspecified(&route_addr) == 0))
        {
            (void)memcpy(out_addr->ip, route_addr.ip, sizeof(out_addr->ip));
        }
    }

    return result;
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
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((udp_socket->open == 0U) || (quic_udp_fd_is_native_valid(udp_socket->fd) == 0))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else if (buffer_len > (size_t)INT_MAX)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
        received = recvfrom(
            quic_udp_to_native_fd(udp_socket->fd),
            (char *)buffer,
            (quic_udp_buffer_len_t)buffer_len,
            0,
            (struct sockaddr *)&remote_storage,
            &remote_len);
        if (received < 0)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
        else if (received == 0)
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            (void)memset(&datagram, 0, sizeof(datagram));
            datagram.local_addr = udp_socket->local_addr;
            result = quic_udp_sockaddr_to_addr(
                (const struct sockaddr *)&remote_storage,
                remote_len,
                &datagram.remote_addr);
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        datagram.data = buffer;
        datagram.data_len = (size_t)received;
        datagram.ecn = LIBP2P_QUIC_ECN_NOT_ECT;
        result = libp2p_quic_endpoint_recv_datagram(endpoint, &datagram, now_us);
    }

    return result;
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
    libp2p_quic_tx_datagram_t datagram;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)memset(&datagram, 0, sizeof(datagram));

    if ((udp_socket == NULL) || (endpoint == NULL) || (buffer == NULL) || (buffer_len == 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((udp_socket->open == 0U) || (quic_udp_fd_is_native_valid(udp_socket->fd) == 0))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else if (buffer_len > (size_t)INT_MAX)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
        datagram.data = buffer;
        datagram.data_cap = buffer_len;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_next_datagram(endpoint, &datagram, now_us);
    }

    if ((result == LIBP2P_QUIC_OK) &&
        (libp2p_quic_addr_equal(&datagram.local_addr, &udp_socket->local_addr, 0) == 0))
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_udp_addr_to_sockaddr(&datagram.remote_addr, &remote_storage, &remote_len);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        quic_udp_io_result_t sent = sendto(
            quic_udp_to_native_fd(udp_socket->fd),
            (const char *)datagram.data,
            (quic_udp_buffer_len_t)datagram.data_len,
            0,
            (const struct sockaddr *)&remote_storage,
            remote_len);
        if (sent < 0)
        {
            result = quic_udp_errno_to_err(quic_udp_last_error());
        }
        else if ((size_t)sent != datagram.data_len)
        {
            result = LIBP2P_QUIC_ERR_INTERNAL;
        }
        else
        {
            result = LIBP2P_QUIC_OK;
        }
    }

    return result;
}
