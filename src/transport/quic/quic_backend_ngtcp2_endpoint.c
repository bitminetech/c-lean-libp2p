/**
 * @file quic_backend_ngtcp2_endpoint.c
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

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

static libp2p_quic_err_t quic_backend_config_validate(const libp2p_quic_endpoint_config_t *config)
{
    libp2p_quic_allocator_t allocator;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (config == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (
        ((config->role & LIBP2P_QUIC_ROLE_CLIENT_SERVER) == 0U) ||
        ((config->role & ~LIBP2P_QUIC_ROLE_CLIENT_SERVER) != 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (
        (config->random_fn == NULL) || (config->unix_time_fn == NULL) ||
        (config->max_connections == 0U) ||
        (config->max_incoming_connections > config->max_connections) ||
        (config->max_outgoing_connections > config->max_connections) ||
        (config->max_bidi_streams == 0U) ||
        (config->max_datagram_payload_bytes < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES) ||
        (config->max_datagram_payload_bytes > (size_t)NGTCP2_MAX_TX_UDP_PAYLOAD_SIZE) ||
        (config->initial_conn_window_bytes == 0U) || (config->initial_stream_window_bytes == 0U) ||
        (config->idle_timeout_us == 0U) || (config->handshake_timeout_us == 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_quic_local_identity_validate(&config->identity);
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_backend_allocator_normalize(&config->allocator, &allocator);
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_storage_size(
    const libp2p_quic_endpoint_config_t *config,
    size_t *out_len)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((config == NULL) || (out_len == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = sizeof(libp2p_quic_endpoint_t);
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_storage_align(size_t *out_align)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_align == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_align = QUIC_BACKEND_ENDPOINT_STORAGE_ALIGN;
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_endpoint_config_t *config,
    libp2p_quic_endpoint_t **out_endpoint)
{
    libp2p_quic_endpoint_t *endpoint = NULL;
    libp2p_quic_allocator_t allocator;
    size_t events_per_conn = 0U;
    size_t event_cap = 0U;
    size_t pointer_bytes = 0U;
    size_t event_bytes = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)memset(&allocator, 0, sizeof(allocator));

    if (out_endpoint == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_endpoint = NULL;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_backend_config_validate(config);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_backend_allocator_normalize(&config->allocator, &allocator);
    }
    if ((result == LIBP2P_QUIC_OK) &&
        ((storage == NULL) || (storage_len < sizeof(libp2p_quic_endpoint_t))))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        endpoint = quic_backend_endpoint_from_memory(storage);
        (void)memset(endpoint, 0, sizeof(*endpoint));
        endpoint->magic = QUIC_BACKEND_ENDPOINT_MAGIC;
        endpoint->config = *config;
        endpoint->allocator = allocator;
        endpoint->ngtcp2_mem.user_data = endpoint;
        endpoint->ngtcp2_mem.malloc = quic_backend_ngtcp2_malloc;
        endpoint->ngtcp2_mem.free = quic_backend_ngtcp2_free;
        endpoint->ngtcp2_mem.calloc = quic_backend_ngtcp2_calloc;
        endpoint->ngtcp2_mem.realloc = quic_backend_ngtcp2_realloc;

        if (quic_backend_size_mul_overflow(
                config->max_connections,
                // NOLINTNEXTLINE(bugprone-sizeof-expression)
                sizeof(*endpoint->connections),
                &pointer_bytes) != 0)
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
    }

    if ((result == LIBP2P_QUIC_OK) &&
        ((quic_backend_size_mul_overflow(
              config->max_connections,
              QUIC_BACKEND_EVENTS_PER_CONNECTION,
              &events_per_conn) != 0) ||
         (quic_backend_size_add_overflow(events_per_conn, QUIC_BACKEND_EXTRA_EVENTS, &event_cap) !=
          0) ||
         (quic_backend_size_mul_overflow(event_cap, sizeof(*endpoint->events), &event_bytes) != 0)))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        endpoint->connections =
            quic_backend_conn_items_from_memory(quic_backend_calloc(endpoint, 1U, pointer_bytes));
        endpoint->events = quic_backend_events_from_memory(
            quic_backend_calloc(endpoint, event_cap, sizeof(*endpoint->events)));
        endpoint->event_cap = event_cap;
        if ((endpoint->connections == NULL) || (endpoint->events == NULL))
        {
            result = LIBP2P_QUIC_ERR_NO_MEMORY;
        }
        (void)pointer_bytes;
        (void)event_bytes;
    }

    if ((result == LIBP2P_QUIC_OK) && ((config->role & LIBP2P_QUIC_ROLE_CLIENT) != 0U))
    {
        endpoint->client_ctx = quic_backend_ssl_ctx_new(endpoint, LIBP2P_QUIC_ROLE_CLIENT);
        if (endpoint->client_ctx == NULL)
        {
            result = LIBP2P_QUIC_ERR_TLS;
        }
    }

    if ((result == LIBP2P_QUIC_OK) && ((config->role & LIBP2P_QUIC_ROLE_SERVER) != 0U))
    {
        endpoint->server_ctx = quic_backend_ssl_ctx_new(endpoint, LIBP2P_QUIC_ROLE_SERVER);
        if (endpoint->server_ctx == NULL)
        {
            result = LIBP2P_QUIC_ERR_TLS;
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        *out_endpoint = endpoint;
    }
    else
    {
        if (endpoint != NULL)
        {
            SSL_CTX_free(endpoint->client_ctx);
            SSL_CTX_free(endpoint->server_ctx);
            quic_backend_free(endpoint, (void *)endpoint->connections);
            quic_backend_free(endpoint, endpoint->events);
            endpoint->magic = 0U;
        }
    }

    return result;
}

static void quic_backend_endpoint_deinit(libp2p_quic_endpoint_t *endpoint)
{
    if ((endpoint != NULL) && (endpoint->magic == QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        for (size_t index = 0U; index < endpoint->connection_count; index++)
        {
            quic_backend_conn_free(endpoint->connections[index]);
        }
        SSL_CTX_free(endpoint->client_ctx);
        SSL_CTX_free(endpoint->server_ctx);
        quic_backend_free(endpoint, (void *)endpoint->connections);
        quic_backend_free(endpoint, endpoint->events);
        endpoint->magic = 0U;
    }
}

static libp2p_quic_err_t quic_backend_endpoint_bind(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_addr_t *local_addr)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_addr_validate(local_addr);
    }
    if ((result == LIBP2P_QUIC_OK) && (endpoint->connection_count != 0U))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        endpoint->local_addr = *local_addr;
        endpoint->local_addr.has_peer_id = 0U;
        endpoint->local_addr.peer_id_len = 0U;
        endpoint->bound = 1U;
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_dial(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *config,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if ((result == LIBP2P_QUIC_OK) && ((config == NULL) || (out_conn == NULL)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((result == LIBP2P_QUIC_OK) && ((endpoint->config.role & LIBP2P_QUIC_ROLE_CLIENT) == 0U))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    if ((result == LIBP2P_QUIC_OK) && (endpoint->bound == 0U))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_addr_validate(&config->remote_addr);
    }
    if ((result == LIBP2P_QUIC_OK) &&
        ((config->remote_addr.has_peer_id == 0U) || (config->remote_addr.peer_id_len == 0U)))
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_backend_conn_client_new(endpoint, config, out_conn);
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_recv_datagram(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    libp2p_quic_conn_t *conn = NULL;
    ngtcp2_path_storage path;
    ngtcp2_pkt_info pi;
    ngtcp2_pkt_hd hd;
    ngtcp2_tstamp now = 0U;
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if ((result == LIBP2P_QUIC_OK) &&
        ((datagram == NULL) || (datagram->data == NULL) || (datagram->data_len == 0U) ||
         (libp2p_quic_addr_validate(&datagram->local_addr) != LIBP2P_QUIC_OK) ||
         (libp2p_quic_addr_validate(&datagram->remote_addr) != LIBP2P_QUIC_OK)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        now = quic_backend_endpoint_time_to_ngtcp2(endpoint, now_us);
        conn = quic_backend_find_conn_by_packet(endpoint, datagram);
        if (conn == NULL)
        {
            if ((endpoint->config.role & LIBP2P_QUIC_ROLE_SERVER) == 0U)
            {
                result = LIBP2P_QUIC_OK;
            }
            else
            {
                (void)memset(&hd, 0, sizeof(hd));
                const int accept_rv = ngtcp2_accept(&hd, datagram->data, datagram->data_len);
                if ((accept_rv != 0) || (hd.version != LIBP2P_QUIC_VERSION_RFC9000))
                {
                    result = LIBP2P_QUIC_OK;
                }
                else
                {
                    result = quic_backend_conn_server_new(endpoint, datagram, &hd, &conn);
                }
            }
        }
    }

    if ((result == LIBP2P_QUIC_OK) && (conn != NULL))
    {
        quic_backend_path_from_addrs(&datagram->local_addr, &datagram->remote_addr, &path);
        (void)memset(&pi, 0, sizeof(pi));
        pi.ecn = quic_backend_ecn_to_ngtcp2(datagram->ecn);

        const int read_rv = ngtcp2_conn_read_pkt(
            conn->ngconn,
            &path.path,
            &pi,
            datagram->data,
            datagram->data_len,
            now);
        if (read_rv != 0)
        {
            result = quic_backend_handle_conn_error(conn, read_rv);
        }
        else
        {
            (void)quic_backend_event_push(
                endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                conn,
                NULL,
                0U,
                0U);
            if (conn->callback_error != LIBP2P_QUIC_OK)
            {
                result = conn->callback_error;
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_next_datagram(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if ((result == LIBP2P_QUIC_OK) && ((datagram == NULL) || (datagram->data == NULL)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        datagram->data_len = 0U;
        if (datagram->data_cap < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES)
        {
            datagram->data_len = LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES;
            result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        for (size_t index = 0U;
             (index < endpoint->connection_count) && (result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
             index++)
        {
            libp2p_quic_conn_t *conn = endpoint->connections[index];

            if ((conn != NULL) && (conn->state != LIBP2P_QUIC_CONN_CLOSED) &&
                (conn->state != LIBP2P_QUIC_CONN_DRAINED))
            {
                result = quic_backend_write_conn_datagram(conn, datagram, now_us);
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_poll(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t now_us)
{
    ngtcp2_tstamp now = quic_backend_endpoint_time_to_ngtcp2(endpoint, now_us);
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    for (size_t index = 0U; (result == LIBP2P_QUIC_OK) && (index < endpoint->connection_count);
         index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[index];

        if ((conn != NULL) && (conn->state != LIBP2P_QUIC_CONN_CLOSED) &&
            (conn->state != LIBP2P_QUIC_CONN_DRAINED))
        {
            const ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2(conn->ngconn);
            if ((expiry != UINT64_MAX) && (expiry <= now))
            {
                const int rv = ngtcp2_conn_handle_expiry(conn->ngconn, now);
                if (rv != 0)
                {
                    result = quic_backend_handle_conn_error(conn, rv);
                }
                if (result == LIBP2P_QUIC_OK)
                {
                    (void)quic_backend_event_push(
                        endpoint,
                        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                        conn,
                        NULL,
                        0U,
                        0U);
                }
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_next_deadline(
    const libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t *out_deadline_us)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((endpoint == NULL) || (endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC) ||
        (out_deadline_us == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        ngtcp2_tstamp best = UINT64_MAX;

        for (size_t index = 0U; index < endpoint->connection_count; index++)
        {
            const libp2p_quic_conn_t *conn = endpoint->connections[index];

            if ((conn != NULL) && (conn->state != LIBP2P_QUIC_CONN_CLOSED) &&
                (conn->state != LIBP2P_QUIC_CONN_DRAINED))
            {
                const ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2(conn->ngconn);
                if (expiry < best)
                {
                    best = expiry;
                }
            }
        }

        if (best == UINT64_MAX)
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            *out_deadline_us = quic_backend_endpoint_time_from_ngtcp2(endpoint, best);
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_next_event(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_t *out_event)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result == LIBP2P_QUIC_OK)
    {
        if (out_event == NULL)
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else if (endpoint->event_len == 0U)
        {
            (void)memset(out_event, 0, sizeof(*out_event));
            out_event->type = LIBP2P_QUIC_EVENT_NONE;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            *out_event = endpoint->events[endpoint->event_head];
            endpoint->event_head = (endpoint->event_head + 1U) % endpoint->event_cap;
            endpoint->event_len--;
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_endpoint_close(
    libp2p_quic_endpoint_t *endpoint,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result == LIBP2P_QUIC_OK)
    {
        for (size_t index = 0U; index < endpoint->connection_count; index++)
        {
            if (endpoint->connections[index] != NULL)
            {
                ngtcp2_ccerr_set_application_error(
                    &endpoint->connections[index]->close_error,
                    app_error_code,
                    NULL,
                    0U);
                endpoint->connections[index]->close_requested = 1U;
                endpoint->connections[index]->state = LIBP2P_QUIC_CONN_CLOSING;
            }
        }
    }
    return result;
}

const libp2p_quic_backend_vtable_t *libp2p_quic_backend_ngtcp2_awslc(void)
{
    static const libp2p_quic_backend_vtable_t quic_backend_vtable = {
        .abi_version = LIBP2P_QUIC_BACKEND_ABI_VERSION,
        .name = "ngtcp2+aws-lc",
        .endpoint_storage_size = quic_backend_endpoint_storage_size,
        .endpoint_storage_align = quic_backend_endpoint_storage_align,
        .endpoint_init = quic_backend_endpoint_init,
        .endpoint_deinit = quic_backend_endpoint_deinit,
        .endpoint_bind = quic_backend_endpoint_bind,
        .endpoint_dial = quic_backend_endpoint_dial,
        .endpoint_recv_datagram = quic_backend_endpoint_recv_datagram,
        .endpoint_next_datagram = quic_backend_endpoint_next_datagram,
        .endpoint_poll = quic_backend_endpoint_poll,
        .endpoint_next_deadline = quic_backend_endpoint_next_deadline,
        .endpoint_next_event = quic_backend_endpoint_next_event,
        .endpoint_close = quic_backend_endpoint_close,
        .conn_state = quic_backend_conn_state,
        .conn_peer_id = quic_backend_conn_peer_id,
        .conn_peer_identity = quic_backend_conn_peer_identity,
        .conn_local_addr = quic_backend_conn_local_addr,
        .conn_remote_addr = quic_backend_conn_remote_addr,
        .conn_close = quic_backend_conn_close,
        .conn_open_bidi_stream = quic_backend_conn_open_bidi_stream,
        .conn_accept_stream = quic_backend_conn_accept_stream,
        .stream_id = quic_backend_stream_id,
        .stream_state = quic_backend_stream_state,
        .stream_read = quic_backend_stream_read,
        .stream_write = quic_backend_stream_write,
        .stream_finish = quic_backend_stream_finish,
        .stream_reset = quic_backend_stream_reset,
        .stream_stop_sending = quic_backend_stream_stop_sending,
        .stream_conn = quic_backend_stream_conn,
    };

    return &quic_backend_vtable;
}
