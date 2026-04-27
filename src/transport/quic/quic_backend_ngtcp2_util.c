/**
 * @file quic_backend_ngtcp2_util.c
 * @brief ngtcp2 + AWS-LC backend for libp2p QUIC v1.
 */

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_validate_endpoint(const libp2p_quic_endpoint_t *endpoint)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((endpoint == NULL) || (endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (endpoint->closed != 0U)
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_validate_conn(const libp2p_quic_conn_t *conn)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (conn->endpoint == NULL) ||
        (conn->endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((conn->state == LIBP2P_QUIC_CONN_CLOSED) ||
             (conn->state == LIBP2P_QUIC_CONN_DRAINED))
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_validate_stream(const libp2p_quic_stream_t *stream)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) ||
        (stream->conn == NULL) || (stream->conn->magic != QUIC_BACKEND_CONN_MAGIC))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((stream->state == LIBP2P_QUIC_STREAM_CLOSED) ||
             (stream->state == LIBP2P_QUIC_STREAM_RESET))
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

QUIC_BACKEND_INTERNAL ngtcp2_tstamp quic_backend_time_to_ngtcp2(libp2p_quic_time_us_t now_us)
{
    ngtcp2_tstamp result = UINT64_MAX;

    if (now_us > (UINT64_MAX / (uint64_t)NGTCP2_MICROSECONDS))
    {
        result = UINT64_MAX;
    }
    else
    {
        result = now_us * (uint64_t)NGTCP2_MICROSECONDS;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_time_us_t quic_backend_time_from_ngtcp2(ngtcp2_tstamp ts)
{
    return (libp2p_quic_time_us_t)(ts / (uint64_t)NGTCP2_MICROSECONDS);
}

QUIC_BACKEND_INTERNAL ngtcp2_duration quic_backend_duration_to_ngtcp2(libp2p_quic_time_us_t duration_us)
{
    return quic_backend_time_to_ngtcp2(duration_us);
}

QUIC_BACKEND_INTERNAL uint8_t quic_backend_ecn_to_ngtcp2(libp2p_quic_ecn_t ecn)
{
    uint8_t result = NGTCP2_ECN_NOT_ECT;

    switch (ecn)
    {
    case LIBP2P_QUIC_ECN_ECT0:
        result = NGTCP2_ECN_ECT_0;
        break;
    case LIBP2P_QUIC_ECN_ECT1:
        result = NGTCP2_ECN_ECT_1;
        break;
    case LIBP2P_QUIC_ECN_CE:
        result = NGTCP2_ECN_CE;
        break;
    case LIBP2P_QUIC_ECN_NOT_ECT:
    default:
        result = NGTCP2_ECN_NOT_ECT;
        break;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_ecn_t quic_backend_ecn_from_ngtcp2(uint8_t ecn)
{
    libp2p_quic_ecn_t result = LIBP2P_QUIC_ECN_NOT_ECT;
    uint8_t masked = ecn & ((uint8_t)NGTCP2_ECN_MASK);

    switch (masked)
    {
    case NGTCP2_ECN_ECT_0:
        result = LIBP2P_QUIC_ECN_ECT0;
        break;
    case NGTCP2_ECN_ECT_1:
        result = LIBP2P_QUIC_ECN_ECT1;
        break;
    case NGTCP2_ECN_CE:
        result = LIBP2P_QUIC_ECN_CE;
        break;
    case NGTCP2_ECN_NOT_ECT:
    default:
        result = LIBP2P_QUIC_ECN_NOT_ECT;
        break;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_event_push(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_type_t type,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code,
    uint64_t transport_error_code)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((endpoint == NULL) || (endpoint->events == NULL) || (endpoint->event_cap == 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (endpoint->event_len == endpoint->event_cap)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
        libp2p_quic_event_t event;

        event.type = type;
        event.conn = conn;
        event.stream = stream;
        event.app_error_code = app_error_code;
        event.transport_error_code = transport_error_code;

        const size_t pos = (endpoint->event_head + endpoint->event_len) % endpoint->event_cap;
        endpoint->events[pos] = event;
        endpoint->event_len++;
    }

    return result;
}

static libp2p_quic_err_t quic_backend_addr_to_sockaddr(
    const libp2p_quic_addr_t *addr,
    struct sockaddr_storage *out,
    ngtcp2_socklen *out_len)
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
        *out_len = (ngtcp2_socklen)sizeof(sin);
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
        *out_len = (ngtcp2_socklen)sizeof(sin6);
    }

    return result;
}

QUIC_BACKEND_INTERNAL void quic_backend_path_from_addrs(
    const libp2p_quic_addr_t *local_addr,
    const libp2p_quic_addr_t *remote_addr,
    ngtcp2_path_storage *path)
{
    struct sockaddr_storage local;
    struct sockaddr_storage remote;
    ngtcp2_socklen local_len = 0;
    ngtcp2_socklen remote_len = 0;

    (void)quic_backend_addr_to_sockaddr(local_addr, &local, &local_len);
    (void)quic_backend_addr_to_sockaddr(remote_addr, &remote, &remote_len);
    ngtcp2_path_storage_init(
        path,
        (const ngtcp2_sockaddr *)&local,
        local_len,
        (const ngtcp2_sockaddr *)&remote,
        remote_len,
        NULL);
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_copy_measure(
    const uint8_t *src,
    size_t src_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (written == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *written = src_len;
        if ((out == NULL) || (out_len < src_len))
        {
            result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        }
        else if (src_len != 0U)
        {
            (void)memcpy(out, src, src_len);
        }
        else
        {
            result = LIBP2P_QUIC_OK;
        }

    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_ngtcp2_err(int rv)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_BACKEND;

    switch (rv)
    {
    case 0:
        result = LIBP2P_QUIC_OK;
        break;
    case NGTCP2_ERR_NOMEM:
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
        break;
    case NGTCP2_ERR_NOBUF:
        result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        break;
    case NGTCP2_ERR_STREAM_ID_BLOCKED:
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        break;
    case NGTCP2_ERR_STREAM_NOT_FOUND:
        result = LIBP2P_QUIC_ERR_NOT_FOUND;
        break;
    case NGTCP2_ERR_STREAM_SHUT_WR:
    case NGTCP2_ERR_CLOSING:
    case NGTCP2_ERR_DRAINING:
    case NGTCP2_ERR_IDLE_CLOSE:
        result = LIBP2P_QUIC_ERR_CLOSED;
        break;
    case NGTCP2_ERR_CRYPTO:
        result = LIBP2P_QUIC_ERR_TLS;
        break;
    case NGTCP2_ERR_VERSION_NEGOTIATION:
    case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
        result = LIBP2P_QUIC_ERR_VERSION;
        break;
    case NGTCP2_ERR_INVALID_ARGUMENT:
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
        break;
    case NGTCP2_ERR_INVALID_STATE:
        result = LIBP2P_QUIC_ERR_STATE;
        break;
    case NGTCP2_ERR_CALLBACK_FAILURE:
        result = LIBP2P_QUIC_ERR_BACKEND;
        break;
    default:
        result = LIBP2P_QUIC_ERR_BACKEND;
        break;
    }

    return result;
}
