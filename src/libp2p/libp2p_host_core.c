#include <stdint.h>
#include <string.h>

#include "libp2p_host_internal.h"

static int host_size_add_overflow(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a + b;
    }

    return result;
}

static int host_size_mul_overflow(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if ((a != 0U) && (b > (SIZE_MAX / a)))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a * b;
    }

    return result;
}

static libp2p_host_err_t host_align_up_size(size_t value, size_t alignment, size_t *out)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((alignment == 0U) || (out == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        const size_t remainder = value % alignment;

        if (remainder == 0U)
        {
            *out = value;
        }
        else
        {
            const size_t adjustment = alignment - remainder;

            if (adjustment > (SIZE_MAX - value))
            {
                result = LIBP2P_HOST_ERR_LIMIT;
            }
            else
            {
                *out = value + adjustment;
            }
        }
    }

    return result;
}

static uint8_t *host_storage_bytes(void *storage)
{
    uint8_t *bytes = NULL;

    (void)memcpy((void *)&bytes, (const void *)&storage, sizeof storage);

    return bytes;
}

static libp2p_host_t *host_storage_host(void *storage)
{
    libp2p_host_t *host = NULL;

    (void)memcpy((void *)&host, (const void *)&storage, sizeof storage);

    return host;
}

static libp2p_host_protocol_t *host_storage_protocols(void *storage)
{
    libp2p_host_protocol_t *protocols = NULL;

    (void)memcpy((void *)&protocols, (const void *)&storage, sizeof storage);

    return protocols;
}

static libp2p_multistream_select_protocol_t *host_storage_ms_protocols(void *storage)
{
    libp2p_multistream_select_protocol_t *protocols = NULL;

    (void)memcpy((void *)&protocols, (const void *)&storage, sizeof storage);

    return protocols;
}

static libp2p_host_event_t *host_storage_events(void *storage)
{
    libp2p_host_event_t *events = NULL;

    (void)memcpy((void *)&events, (const void *)&storage, sizeof storage);

    return events;
}

static libp2p_host_conn_t *host_storage_conns(void *storage)
{
    libp2p_host_conn_t *conns = NULL;

    (void)memcpy((void *)&conns, (const void *)&storage, sizeof storage);

    return conns;
}

static libp2p_host_stream_t *host_storage_streams(void *storage)
{
    libp2p_host_stream_t *streams = NULL;

    (void)memcpy((void *)&streams, (const void *)&storage, sizeof storage);

    return streams;
}

static libp2p_host_dial_t *host_storage_dials(void *storage)
{
    libp2p_host_dial_t *dials = NULL;

    (void)memcpy((void *)&dials, (const void *)&storage, sizeof storage);

    return dials;
}

static libp2p_host_stream_open_t *host_storage_opens(void *storage)
{
    libp2p_host_stream_open_t *opens = NULL;

    (void)memcpy((void *)&opens, (const void *)&storage, sizeof storage);

    return opens;
}

static libp2p_host_err_t host_reserve(
    size_t *cursor,
    size_t alignment,
    size_t size,
    size_t *out_offset)
{
    size_t aligned = 0U;
    size_t next = 0U;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((cursor == NULL) || (out_offset == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        result = host_align_up_size(*cursor, alignment, &aligned);
        if ((result == LIBP2P_HOST_OK) && (host_size_add_overflow(aligned, size, &next) != 0))
        {
            result = LIBP2P_HOST_ERR_LIMIT;
        }
        if (result == LIBP2P_HOST_OK)
        {
            *out_offset = aligned;
            *cursor = next;
        }
    }

    return result;
}

static libp2p_host_err_t host_vtable_validate(const libp2p_host_transport_vtable_t *transport)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (transport == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (transport->abi_version != HOST_TRANSPORT_ABI_VERSION)
    {
        result = LIBP2P_HOST_ERR_UNSUPPORTED;
    }
    else if (
        (transport->storage_size == NULL) || (transport->storage_align == NULL) ||
        (transport->init == NULL) || (transport->deinit == NULL) || (transport->fd == NULL) ||
        (transport->io_interest == NULL) || (transport->next_deadline == NULL) ||
        (transport->drive == NULL) || (transport->next_event == NULL) ||
        (transport->listen_multiaddr == NULL) || (transport->dial == NULL) ||
        (transport->open_stream == NULL) || (transport->conn_peer_id == NULL) ||
        (transport->conn_remote_multiaddr == NULL) ||
        (transport->conn_peer_identity == NULL) ||
        (transport->conn_close == NULL) || (transport->stream_read == NULL) ||
        (transport->stream_write == NULL) || (transport->stream_finish == NULL) ||
        (transport->stream_reset == NULL) || (transport->stream_stop_sending == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        result = LIBP2P_HOST_OK;
    }

    return result;
}

static libp2p_host_err_t host_config_validate(const libp2p_host_config_t *config)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (config == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (
        (config->identity.peer_id == NULL) || (config->identity.peer_id_len == 0U) ||
        (config->identity.peer_id_len > LIBP2P_PEER_ID_MAX_BYTES) ||
        (config->identity.public_key_message == NULL) ||
        (config->identity.public_key_message_len == 0U) ||
        (config->identity.public_key_message_len >
         LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES) ||
        (config->identity.sign_fn == NULL) || (config->listen_multiaddr == NULL) ||
        (config->listen_multiaddr_len == 0U) || (config->max_protocols == 0U) ||
        (config->max_connections == 0U) || (config->max_streams_per_conn == 0U) ||
        (config->max_pending_dials == 0U) || (config->max_pending_stream_opens == 0U) ||
        (config->event_capacity == 0U) || (config->max_negotiation_steps == 0U))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        result = host_vtable_validate(config->transport);
    }

    return result;
}

static libp2p_host_err_t host_layout_compute(
    const libp2p_host_config_t *config,
    host_layout_t *layout)
{
    size_t cursor = 0U;
    size_t bytes = 0U;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((config == NULL) || (layout == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(layout, 0, sizeof(*layout));
        result = host_config_validate(config);
    }

    if (result == LIBP2P_HOST_OK)
    {
        result = config->transport->storage_size(config->transport_config, &layout->transport_len);
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = config->transport->storage_align(&layout->transport_align);
    }
    if ((result == LIBP2P_HOST_OK) &&
        ((layout->transport_len == 0U) || (layout->transport_align == 0U)))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_HOST_OK)
    {
        layout->protocol_capacity = config->max_protocols;
        layout->conn_capacity = config->max_connections;
        layout->dial_capacity = config->max_pending_dials;
        layout->open_capacity = config->max_pending_stream_opens;
        layout->event_capacity = config->event_capacity;
        layout->max_streams_per_conn = config->max_streams_per_conn;
        layout->max_negotiation_steps = config->max_negotiation_steps;

        if (host_size_mul_overflow(
                config->max_connections,
                config->max_streams_per_conn,
                &layout->stream_capacity) != 0)
        {
            result = LIBP2P_HOST_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        result =
            host_reserve(&cursor, HOST_STORAGE_ALIGN, sizeof(libp2p_host_t), &layout->host_offset);
    }
    if ((result == LIBP2P_HOST_OK) && (host_size_mul_overflow(
                                           layout->protocol_capacity,
                                           sizeof(libp2p_host_protocol_t),
                                           &bytes) != 0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->protocols_offset);
    }
    if ((result == LIBP2P_HOST_OK) && (host_size_mul_overflow(
                                           layout->protocol_capacity,
                                           sizeof(libp2p_multistream_select_protocol_t),
                                           &bytes) != 0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->ms_protocols_offset);
    }
    if ((result == LIBP2P_HOST_OK) &&
        (host_size_mul_overflow(layout->event_capacity, sizeof(libp2p_host_event_t), &bytes) != 0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->events_offset);
    }
    if ((result == LIBP2P_HOST_OK) &&
        (host_size_mul_overflow(layout->conn_capacity, sizeof(libp2p_host_conn_t), &bytes) != 0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->conns_offset);
    }
    if ((result == LIBP2P_HOST_OK) &&
        (host_size_mul_overflow(layout->stream_capacity, sizeof(libp2p_host_stream_t), &bytes) !=
         0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->streams_offset);
    }
    if ((result == LIBP2P_HOST_OK) &&
        (host_size_mul_overflow(layout->dial_capacity, sizeof(libp2p_host_dial_t), &bytes) != 0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->dials_offset);
    }
    if ((result == LIBP2P_HOST_OK) &&
        (host_size_mul_overflow(layout->open_capacity, sizeof(libp2p_host_stream_open_t), &bytes) !=
         0))
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(&cursor, HOST_STORAGE_ALIGN, bytes, &layout->opens_offset);
    }
    if (result == LIBP2P_HOST_OK)
    {
        result = host_reserve(
            &cursor,
            layout->transport_align,
            layout->transport_len,
            &layout->transport_offset);
    }
    if (result == LIBP2P_HOST_OK)
    {
        layout->total_len = cursor;
    }

    return result;
}

libp2p_host_err_t host_validate_any(const libp2p_host_t *host)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((host == NULL) || (host->magic != HOST_MAGIC))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }

    return result;
}

libp2p_host_err_t host_validate_started(const libp2p_host_t *host)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (host->state == HOST_STATE_CLOSED)
        {
            result = LIBP2P_HOST_ERR_CLOSED;
        }
        else if ((host->state != HOST_STATE_STARTED) && (host->state != HOST_STATE_CLOSING))
        {
            result = LIBP2P_HOST_ERR_STATE;
        }
        else
        {
            result = LIBP2P_HOST_OK;
        }
    }

    return result;
}

libp2p_host_err_t host_event_push(
    libp2p_host_t *host,
    const libp2p_host_event_t *event,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t out = LIBP2P_HOST_OK;

    if ((host == NULL) || (event == NULL) || (host->event_capacity == 0U))
    {
        out = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (host->event_len == host->event_capacity)
    {
        out = LIBP2P_HOST_ERR_LIMIT;
    }
    else
    {
        const size_t pos = (host->event_head + host->event_len) % host->event_capacity;

        host->events[pos] = *event;
        host->event_len++;
        if (result != NULL)
        {
            result->host_events++;
            result->made_progress = 1U;
        }
    }

    return out;
}

libp2p_host_err_t host_transport_err(libp2p_host_err_t err)
{
    return err;
}

libp2p_host_err_t libp2p_host_config_default(libp2p_host_config_t *config)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (config == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
        config->max_protocols = LIBP2P_HOST_DEFAULT_MAX_PROTOCOLS;
        config->max_connections = LIBP2P_HOST_DEFAULT_MAX_CONNECTIONS;
        config->max_streams_per_conn = LIBP2P_HOST_DEFAULT_MAX_STREAMS_PER_CONN;
        config->max_pending_dials = LIBP2P_HOST_DEFAULT_MAX_PENDING_DIALS;
        config->max_pending_stream_opens = LIBP2P_HOST_DEFAULT_MAX_PENDING_STREAM_OPENS;
        config->event_capacity = LIBP2P_HOST_DEFAULT_EVENT_CAPACITY;
        config->max_negotiation_steps = LIBP2P_HOST_DEFAULT_MAX_NEGOTIATION_STEPS;
    }

    return result;
}

libp2p_host_err_t libp2p_host_storage_size(const libp2p_host_config_t *config, size_t *out_len)
{
    host_layout_t layout;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out_len == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result = host_layout_compute(config, &layout);
        if (result == LIBP2P_HOST_OK)
        {
            *out_len = layout.total_len;
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_storage_align(size_t *out_align)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out_align == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        *out_align = HOST_STORAGE_ALIGN;
    }

    return result;
}

libp2p_host_err_t libp2p_host_init(
    void *storage,
    size_t storage_len,
    const libp2p_host_config_t *config,
    libp2p_host_t **out_host)
{
    host_layout_t layout;
    libp2p_host_t *host = NULL;
    uint8_t *bytes = host_storage_bytes(storage);
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    (void)memset(&layout, 0, sizeof(layout));
    if (out_host == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        *out_host = NULL;
        result = host_layout_compute(config, &layout);
    }

    if ((result == LIBP2P_HOST_OK) && ((storage == NULL) || (storage_len < layout.total_len)))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_HOST_OK)
    {
        (void)memset(storage, 0, layout.total_len);
        host = host_storage_host(&bytes[layout.host_offset]);
        host->magic = HOST_MAGIC;
        host->state = HOST_STATE_INIT;
        host->config = *config;
        host->transport_storage = &bytes[layout.transport_offset];
        host->transport_storage_len = layout.transport_len;
        host->protocols = host_storage_protocols(&bytes[layout.protocols_offset]);
        host->ms_protocols = host_storage_ms_protocols(&bytes[layout.ms_protocols_offset]);
        host->protocol_capacity = layout.protocol_capacity;
        host->events = host_storage_events(&bytes[layout.events_offset]);
        host->event_capacity = layout.event_capacity;
        host->conns = host_storage_conns(&bytes[layout.conns_offset]);
        host->conn_capacity = layout.conn_capacity;
        host->streams = host_storage_streams(&bytes[layout.streams_offset]);
        host->stream_capacity = layout.stream_capacity;
        host->dials = host_storage_dials(&bytes[layout.dials_offset]);
        host->dial_capacity = layout.dial_capacity;
        host->opens = host_storage_opens(&bytes[layout.opens_offset]);
        host->open_capacity = layout.open_capacity;

        result = config->transport->init(
            host->transport_storage,
            host->transport_storage_len,
            config->transport_config,
            config->listen_multiaddr,
            config->listen_multiaddr_len,
            &host->transport);
    }
    if (result == LIBP2P_HOST_OK)
    {
        *out_host = host;
    }
    else if (host != NULL)
    {
        host->magic = 0U;
    }
    else
    {
        (void)host;
    }

    return result;
}

void libp2p_host_deinit(libp2p_host_t *host)
{
    if ((host != NULL) && (host->magic == HOST_MAGIC))
    {
        host->config.transport->deinit(host->transport);
        host->transport = NULL;
        host->state = HOST_STATE_CLOSED;
        host->magic = 0U;
    }
}

libp2p_host_err_t libp2p_host_handle(libp2p_host_t *host, const libp2p_host_protocol_t *protocol)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (protocol == NULL)
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if (host->state != HOST_STATE_INIT)
        {
            result = LIBP2P_HOST_ERR_STATE;
        }
        else if (
            (protocol->id == NULL) || (protocol->id_len == 0U) ||
            (protocol->id_len > HOST_NEGOTIATION_PAYLOAD_CAP) || (protocol->on_open == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if (host->protocol_count == host->protocol_capacity)
        {
            result = LIBP2P_HOST_ERR_LIMIT;
        }
        else
        {
            host->protocols[host->protocol_count] = *protocol;
            host->protocol_count++;
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_start(libp2p_host_t *host)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (host->state != HOST_STATE_INIT)
        {
            result = LIBP2P_HOST_ERR_STATE;
        }
        else
        {
            size_t index = 0U;

            for (index = 0U; index < host->protocol_count; index++)
            {
                host->ms_protocols[index].id = host->protocols[index].id;
                host->ms_protocols[index].id_len = host->protocols[index].id_len;
            }
            host->state = HOST_STATE_STARTED;
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_close(libp2p_host_t *host, uint64_t app_error_code)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (host->state == HOST_STATE_CLOSING)
        {
            result = LIBP2P_HOST_OK;
        }
        else
        {
            size_t index = 0U;

            host->state = HOST_STATE_CLOSING;
            host->close_app_error_code = app_error_code;
            for (index = 0U; (index < host->conn_capacity) && (result == LIBP2P_HOST_OK); index++)
            {
                if ((host->conns[index].active != 0U) && (host->conns[index].closed == 0U) &&
                    (host->conns[index].transport_conn != NULL))
                {
                    result = host->config.transport->conn_close(
                        host->transport,
                        host->conns[index].transport_conn,
                        app_error_code);
                }
            }
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_fd(const libp2p_host_t *host, libp2p_host_fd_t *out_fd)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        result = host->config.transport->fd(host->transport, out_fd);
    }

    return result;
}

libp2p_host_err_t libp2p_host_io_interest(
    const libp2p_host_t *host,
    libp2p_host_interest_t *out_interest)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        result = host->config.transport->io_interest(host->transport, out_interest);
    }

    return result;
}

libp2p_host_err_t libp2p_host_next_deadline(
    const libp2p_host_t *host,
    libp2p_host_time_us_t *out_deadline_us)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        result = host->config.transport->next_deadline(host->transport, out_deadline_us);
    }

    return result;
}

libp2p_host_err_t libp2p_host_next_event(libp2p_host_t *host, libp2p_host_event_t *out_event)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (out_event == NULL)
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if (host->event_len == 0U)
        {
            (void)memset(out_event, 0, sizeof(*out_event));
            out_event->type = LIBP2P_HOST_EVENT_NONE;
            result = LIBP2P_HOST_ERR_WOULD_BLOCK;
        }
        else
        {
            *out_event = host->events[host->event_head];
            host->event_head = (host->event_head + 1U) % host->event_capacity;
            host->event_len--;
            if (out_event->dial != NULL)
            {
                out_event->dial->state = HOST_DIAL_FREE;
            }
            if (out_event->stream_open != NULL)
            {
                libp2p_host_conn_t *open_conn = out_event->stream_open->conn;

                if (out_event->type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED)
                {
                    host_open_release(out_event->stream_open);
                }
                else if (out_event->type == LIBP2P_HOST_EVENT_STREAM_OPENED)
                {
                    if ((out_event->stream != NULL) &&
                        (out_event->stream->open_attempt == out_event->stream_open))
                    {
                        out_event->stream->open_attempt = NULL;
                    }
                    host_open_release(out_event->stream_open);
                }
                else
                {
                    result = LIBP2P_HOST_OK;
                }
                if (open_conn != NULL)
                {
                    result = host_conn_try_recycle(open_conn);
                }
            }
            if ((result == LIBP2P_HOST_OK) &&
                (out_event->type == LIBP2P_HOST_EVENT_CONN_CLOSED) &&
                (out_event->conn != NULL))
            {
                out_event->conn->close_event_pending = 0U;
                result = host_conn_try_recycle(out_event->conn);
            }
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_listen_multiaddr(
    const libp2p_host_t *host,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        result = host->config.transport->listen_multiaddr(
            host->transport,
            out,
            out_len,
            written);
    }

    return result;
}

libp2p_host_err_t libp2p_host_registered_protocols(
    const libp2p_host_t *host,
    const libp2p_host_protocol_t **out_protocols,
    size_t *out_count)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (out_protocols != NULL)
    {
        *out_protocols = NULL;
    }
    if (out_count != NULL)
    {
        *out_count = 0U;
    }
    if (result == LIBP2P_HOST_OK)
    {
        if ((out_protocols == NULL) || (out_count == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            *out_count = host->protocol_count;
            if (host->protocol_count != 0U)
            {
                *out_protocols = host->protocols;
            }
        }
    }

    return result;
}
