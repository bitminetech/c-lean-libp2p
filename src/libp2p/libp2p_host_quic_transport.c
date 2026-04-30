#include <string.h>

#include "libp2p_host_internal.h"

#include "transport/quic/quic.h"
#include "transport/quic/quic_addr.h"
#include "transport/quic/quic_service.h"

static libp2p_host_err_t host_quic_err(libp2p_quic_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    switch (err)
    {
    case LIBP2P_QUIC_OK:
        result = LIBP2P_HOST_OK;
        break;
    case LIBP2P_QUIC_ERR_INVALID_ARG:
        result = LIBP2P_HOST_ERR_INVALID_ARG;
        break;
    case LIBP2P_QUIC_ERR_BUF_TOO_SMALL:
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
        break;
    case LIBP2P_QUIC_ERR_UNSUPPORTED:
        result = LIBP2P_HOST_ERR_UNSUPPORTED;
        break;
    case LIBP2P_QUIC_ERR_STATE:
        result = LIBP2P_HOST_ERR_STATE;
        break;
    case LIBP2P_QUIC_ERR_WOULD_BLOCK:
        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
        break;
    case LIBP2P_QUIC_ERR_LIMIT:
    case LIBP2P_QUIC_ERR_NO_MEMORY:
        result = LIBP2P_HOST_ERR_LIMIT;
        break;
    case LIBP2P_QUIC_ERR_NOT_FOUND:
        result = LIBP2P_HOST_ERR_NOT_FOUND;
        break;
    case LIBP2P_QUIC_ERR_CLOSED:
        result = LIBP2P_HOST_ERR_CLOSED;
        break;
    case LIBP2P_QUIC_ERR_ADDR:
        result = LIBP2P_HOST_ERR_ADDR;
        break;
    case LIBP2P_QUIC_ERR_PEER_ID_MISMATCH:
        result = LIBP2P_HOST_ERR_IDENTITY;
        break;
    default:
        result = LIBP2P_HOST_ERR_TRANSPORT;
        break;
    }

    return result;
}

static const libp2p_quic_service_config_t *host_quic_config_from_const(const void *ptr)
{
    libp2p_quic_service_config_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static libp2p_quic_service_t *host_quic_service_from_void(void *ptr)
{
    libp2p_quic_service_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static const libp2p_quic_service_t *host_quic_service_from_const(const void *ptr)
{
    libp2p_quic_service_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static libp2p_quic_conn_t *host_quic_conn_from_void(void *ptr)
{
    libp2p_quic_conn_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static const libp2p_quic_conn_t *host_quic_conn_from_const(const void *ptr)
{
    libp2p_quic_conn_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static libp2p_quic_stream_t *host_quic_stream_from_void(void *ptr)
{
    libp2p_quic_stream_t *out = NULL;

    (void)memcpy((void *)&out, (const void *)&ptr, sizeof ptr);

    return out;
}

static libp2p_host_err_t host_quic_storage_size(const void *config, size_t *out_len)
{
    const libp2p_quic_service_config_t *quic_config = host_quic_config_from_const(config);

    return host_quic_err(libp2p_quic_service_storage_size(quic_config, out_len));
}

static libp2p_host_err_t host_quic_storage_align(size_t *out_align)
{
    return host_quic_err(libp2p_quic_service_storage_align(out_align));
}

static libp2p_host_err_t host_quic_init(
    void *storage,
    size_t storage_len,
    const void *config,
    const uint8_t *listen_multiaddr,
    size_t listen_multiaddr_len,
    void **out_transport)
{
    const libp2p_quic_service_config_t *quic_config = host_quic_config_from_const(config);
    libp2p_quic_service_config_t local_config;
    libp2p_quic_service_t *service = NULL;
    libp2p_quic_err_t quic_err;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out_transport != NULL)
    {
        *out_transport = NULL;
    }
    if ((quic_config == NULL) || (listen_multiaddr == NULL) || (listen_multiaddr_len == 0U) ||
        (out_transport == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        local_config = *quic_config;
        quic_err = libp2p_quic_addr_from_multiaddr(
            listen_multiaddr,
            listen_multiaddr_len,
            &local_config.local_addr);
        result = host_quic_err(quic_err);
    }
    if (result == LIBP2P_HOST_OK)
    {
        quic_err = libp2p_quic_service_init(storage, storage_len, &local_config, &service);
        result = host_quic_err(quic_err);
    }
    if (result == LIBP2P_HOST_OK)
    {
        *out_transport = service;
    }

    return result;
}

static void host_quic_deinit(void *transport)
{
    libp2p_quic_service_deinit(host_quic_service_from_void(transport));
}

static libp2p_host_err_t host_quic_fd(const void *transport, libp2p_host_fd_t *out_fd)
{
    libp2p_quic_udp_fd_t fd = LIBP2P_QUIC_UDP_INVALID_FD;
    libp2p_host_err_t result =
        host_quic_err(libp2p_quic_service_fd(host_quic_service_from_const(transport), &fd));

    if ((result == LIBP2P_HOST_OK) && (out_fd != NULL))
    {
        *out_fd = (libp2p_host_fd_t)fd;
    }

    return result;
}

static libp2p_host_err_t host_quic_io_interest(
    const void *transport,
    libp2p_host_interest_t *out_interest)
{
    libp2p_quic_service_interest_t quic_interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    libp2p_host_err_t result = host_quic_err(
        libp2p_quic_service_io_interest(host_quic_service_from_const(transport), &quic_interest));

    if ((result == LIBP2P_HOST_OK) && (out_interest != NULL))
    {
        *out_interest = LIBP2P_HOST_INTEREST_NONE;
        if ((quic_interest & LIBP2P_QUIC_SERVICE_INTEREST_READ) != 0U)
        {
            *out_interest |= LIBP2P_HOST_INTEREST_READ;
        }
        if ((quic_interest & LIBP2P_QUIC_SERVICE_INTEREST_WRITE) != 0U)
        {
            *out_interest |= LIBP2P_HOST_INTEREST_WRITE;
        }
    }

    return result;
}

static libp2p_host_err_t host_quic_next_deadline(
    const void *transport,
    libp2p_host_time_us_t *out_deadline_us)
{
    return host_quic_err(libp2p_quic_service_next_deadline(
        host_quic_service_from_const(transport),
        out_deadline_us));
}

static libp2p_host_err_t host_quic_drive(
    void *transport,
    libp2p_host_time_us_t now_us,
    libp2p_host_ready_t ready)
{
    libp2p_quic_service_ready_t quic_ready = 0U;

    if ((ready & LIBP2P_HOST_READY_READ) != 0U)
    {
        quic_ready |= LIBP2P_QUIC_SERVICE_READY_READ;
    }
    if ((ready & LIBP2P_HOST_READY_WRITE) != 0U)
    {
        quic_ready |= LIBP2P_QUIC_SERVICE_READY_WRITE;
    }
    if ((ready & LIBP2P_HOST_READY_TIMER) != 0U)
    {
        quic_ready |= LIBP2P_QUIC_SERVICE_READY_TIMER;
    }
    if ((ready & LIBP2P_HOST_READY_APP) != 0U)
    {
        quic_ready |= LIBP2P_QUIC_SERVICE_READY_APP;
    }

    return host_quic_err(libp2p_quic_service_drive(
        host_quic_service_from_void(transport),
        now_us,
        quic_ready,
        NULL));
}

static libp2p_host_transport_event_type_t host_quic_event_type(
    libp2p_quic_service_event_type_t type)
{
    libp2p_host_transport_event_type_t result = LIBP2P_HOST_TRANSPORT_EVENT_NONE;

    switch (type)
    {
    case LIBP2P_QUIC_SERVICE_EVENT_CONN_ESTABLISHED:
        result = LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_CONN_CLOSED:
        result = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_STREAM_INCOMING:
        result = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_STREAM_READABLE:
        result = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_STREAM_WRITABLE:
        result = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_STREAM_CLOSED:
        result = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_CLOSED;
        break;
    case LIBP2P_QUIC_SERVICE_EVENT_CONN_INCOMING:
    case LIBP2P_QUIC_SERVICE_EVENT_NONE:
    default:
        result = LIBP2P_HOST_TRANSPORT_EVENT_NONE;
        break;
    }

    return result;
}

static libp2p_host_err_t host_quic_next_event(
    void *transport,
    libp2p_host_transport_event_t *out_event)
{
    libp2p_quic_service_t *service = host_quic_service_from_void(transport);
    libp2p_quic_service_event_t quic_event;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out_event == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        uint8_t searching = 1U;

        (void)memset(out_event, 0, sizeof(*out_event));
        while ((result == LIBP2P_HOST_OK) && (searching != 0U))
        {
            (void)memset(&quic_event, 0, sizeof(quic_event));
            result = host_quic_err(libp2p_quic_service_next_event(service, &quic_event));
            if (result == LIBP2P_HOST_OK)
            {
                out_event->type = host_quic_event_type(quic_event.type);
                if (out_event->type == LIBP2P_HOST_TRANSPORT_EVENT_NONE)
                {
                    searching = 1U;
                }
                else
                {
                    searching = 0U;
                    out_event->conn = quic_event.conn;
                    out_event->stream = quic_event.stream;
                    out_event->attempt = quic_event.conn;
                    out_event->app_error_code = quic_event.app_error_code;
                    out_event->transport_error_code = quic_event.transport_error_code;
                }
            }
        }
    }

    return result;
}

static libp2p_host_err_t host_quic_listen_multiaddr(
    const void *transport,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_addr_t addr;
    uint8_t local_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t local_peer_id_len = 0U;
    const libp2p_quic_service_t *service = host_quic_service_from_const(transport);
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    result = host_quic_err(libp2p_quic_service_listen_addr(service, &addr));
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(libp2p_quic_service_local_peer_id(
            service,
            local_peer_id,
            sizeof(local_peer_id),
            &local_peer_id_len));
    }
    if (result == LIBP2P_HOST_OK)
    {
        result =
            host_quic_err(libp2p_quic_addr_set_peer_id(&addr, local_peer_id, local_peer_id_len));
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(libp2p_quic_addr_to_multiaddr(&addr, out, out_len, written));
    }

    return result;
}

static libp2p_host_err_t host_quic_dial(
    void *transport,
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    void *user_data,
    void **out_attempt)
{
    libp2p_quic_addr_t addr;
    libp2p_quic_conn_t *conn = NULL;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out_attempt != NULL)
    {
        *out_attempt = NULL;
    }
    result = host_quic_err(libp2p_quic_addr_from_multiaddr(multiaddr, multiaddr_len, &addr));
    if ((result == LIBP2P_HOST_OK) && (addr.has_peer_id == 0U))
    {
        result = LIBP2P_HOST_ERR_ADDR;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(libp2p_quic_service_dial(
            host_quic_service_from_void(transport),
            &addr,
            user_data,
            &conn));
    }
    if ((result == LIBP2P_HOST_OK) && (out_attempt != NULL))
    {
        *out_attempt = conn;
    }

    return result;
}

static libp2p_host_err_t host_quic_open_stream(void *transport, void *conn, void **out_stream)
{
    libp2p_quic_stream_t *stream = NULL;
    libp2p_host_err_t result = host_quic_err(libp2p_quic_service_open_stream(
        host_quic_service_from_void(transport),
        host_quic_conn_from_void(conn),
        &stream));

    if ((result == LIBP2P_HOST_OK) && (out_stream != NULL))
    {
        *out_stream = stream;
    }

    return result;
}

static libp2p_host_err_t host_quic_conn_peer_id(
    const void *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    return host_quic_err(
        libp2p_quic_service_conn_peer_id(host_quic_conn_from_const(conn), out, out_len, written));
}

static libp2p_host_err_t host_quic_conn_remote_multiaddr(
    const void *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_addr_t addr;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    const libp2p_quic_conn_t *quic_conn = host_quic_conn_from_const(conn);
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    result = host_quic_err(libp2p_quic_conn_remote_addr(quic_conn, &addr));
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(
            libp2p_quic_service_conn_peer_id(quic_conn, peer_id, sizeof(peer_id), &peer_id_len));
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(libp2p_quic_addr_set_peer_id(&addr, peer_id, peer_id_len));
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_quic_err(libp2p_quic_addr_to_multiaddr(&addr, out, out_len, written));
    }

    return result;
}

static libp2p_host_err_t host_quic_conn_peer_identity(
    const void *conn,
    libp2p_host_peer_identity_t *out)
{
    libp2p_quic_peer_identity_t quic_identity = {0};
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        result = host_quic_err(
            libp2p_quic_conn_peer_identity(host_quic_conn_from_const(conn), &quic_identity));
    }
    if (result == LIBP2P_HOST_OK)
    {
        (void)memset(out, 0, sizeof(*out));
        out->key_type = LIBP2P_HOST_KEY_SECP256K1;
        (void)memcpy(out->peer_id, quic_identity.peer_id, quic_identity.peer_id_len);
        out->peer_id_len = quic_identity.peer_id_len;
        (void)memcpy(
            out->public_key_message,
            quic_identity.host_public_key_message,
            quic_identity.host_public_key_message_len);
        out->public_key_message_len = quic_identity.host_public_key_message_len;
    }

    return result;
}

static libp2p_host_err_t host_quic_conn_close(void *transport, void *conn, uint64_t app_error_code)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (conn == NULL)
    {
        result = host_quic_err(
            libp2p_quic_service_close(host_quic_service_from_void(transport), app_error_code));
    }
    else
    {
        result = host_quic_err(libp2p_quic_service_conn_close(
            host_quic_service_from_void(transport),
            host_quic_conn_from_void(conn),
            app_error_code));
    }

    return result;
}

static libp2p_host_err_t host_quic_stream_read(
    void *transport,
    void *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    return host_quic_err(libp2p_quic_service_stream_read(
        host_quic_service_from_void(transport),
        host_quic_stream_from_void(stream),
        out,
        out_len,
        read_len,
        fin));
}

static libp2p_host_err_t host_quic_stream_write(
    void *transport,
    void *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    return host_quic_err(libp2p_quic_service_stream_write(
        host_quic_service_from_void(transport),
        host_quic_stream_from_void(stream),
        data,
        data_len,
        fin,
        accepted));
}

static libp2p_host_err_t host_quic_stream_finish(void *transport, void *stream)
{
    return host_quic_err(libp2p_quic_service_stream_finish(
        host_quic_service_from_void(transport),
        host_quic_stream_from_void(stream)));
}

static libp2p_host_err_t host_quic_stream_reset(
    void *transport,
    void *stream,
    uint64_t app_error_code)
{
    return host_quic_err(libp2p_quic_service_stream_reset(
        host_quic_service_from_void(transport),
        host_quic_stream_from_void(stream),
        app_error_code));
}

static libp2p_host_err_t host_quic_stream_stop_sending(
    void *transport,
    void *stream,
    uint64_t app_error_code)
{
    return host_quic_err(libp2p_quic_service_stream_stop_sending(
        host_quic_service_from_void(transport),
        host_quic_stream_from_void(stream),
        app_error_code));
}

const libp2p_host_transport_vtable_t *libp2p_host_quic_transport(void)
{
    static const libp2p_host_transport_vtable_t transport =
        {2U,
         "quic-v1",
         host_quic_storage_size,
         host_quic_storage_align,
         host_quic_init,
         host_quic_deinit,
         host_quic_fd,
         host_quic_io_interest,
         host_quic_next_deadline,
         host_quic_drive,
         host_quic_next_event,
         host_quic_listen_multiaddr,
         host_quic_dial,
         host_quic_open_stream,
         host_quic_conn_peer_id,
         host_quic_conn_remote_multiaddr,
         host_quic_conn_peer_identity,
         host_quic_conn_close,
         host_quic_stream_read,
         host_quic_stream_write,
         host_quic_stream_finish,
         host_quic_stream_reset,
         host_quic_stream_stop_sending};

    return &transport;
}
