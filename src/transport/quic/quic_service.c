/**
 * @file quic_service.c
 * @brief Lean-facing runtime driver for libp2p QUIC.
 */

#include "transport/quic/quic_service.h"

#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#include "transport/quic/quic_udp.h"

#define QUIC_SERVICE_MAGIC UINT32_C(0x71535631)

#define QUIC_SERVICE_DEFAULT_DATAGRAM_BUDGET 64U
#define QUIC_SERVICE_EVENTS_PER_CONNECTION   8U
#define QUIC_SERVICE_EXTRA_EVENTS            16U

typedef struct
{
    libp2p_quic_conn_t *conn;
    uint8_t incoming;
    uint8_t established;
    uint8_t accepted;
    uint8_t closed;
} quic_service_conn_entry_t;

typedef struct
{
    size_t service_offset;
    size_t endpoint_offset;
    size_t events_offset;
    size_t conns_offset;
    size_t rx_offset;
    size_t tx_offset;
    size_t total_len;
    size_t endpoint_len;
    size_t endpoint_align;
    size_t event_capacity;
    size_t conn_capacity;
    size_t datagram_len;
} quic_service_layout_t;

struct libp2p_quic_service
{
    uint32_t magic;
    libp2p_quic_service_config_t config;
    libp2p_quic_udp_socket_t socket;
    libp2p_quic_endpoint_t *endpoint;
    void *endpoint_storage;
    size_t endpoint_storage_len;
    libp2p_quic_service_event_t *events;
    size_t event_capacity;
    size_t event_head;
    size_t event_len;
    quic_service_conn_entry_t *conns;
    size_t conn_capacity;
    size_t conn_count;
    uint8_t *rx_buffer;
    uint8_t *tx_buffer;
    size_t datagram_buffer_len;
    uint8_t tx_pending;
    uint8_t closed;
};

static int quic_service_size_add_overflow(size_t a, size_t b, size_t *out)
{
    if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a + b;
    return 0;
}

static int quic_service_size_mul_overflow(size_t a, size_t b, size_t *out)
{
    if ((a != 0U) && (b > (SIZE_MAX / a)))
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a * b;
    return 0;
}

static libp2p_quic_err_t quic_service_align_up_size(size_t value, size_t alignment, size_t *out)
{
    size_t remainder = 0U;
    size_t adjustment = 0U;

    if ((alignment == 0U) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    remainder = value % alignment;
    if (remainder == 0U)
    {
        *out = value;
        return LIBP2P_QUIC_OK;
    }

    adjustment = alignment - remainder;
    if (adjustment > (SIZE_MAX - value))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    *out = value + adjustment;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_reserve(
    size_t *cursor,
    size_t alignment,
    size_t size,
    size_t *out_offset)
{
    size_t aligned = 0U;
    size_t next = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((cursor == NULL) || (out_offset == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_service_align_up_size(*cursor, alignment, &aligned);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (quic_service_size_add_overflow(aligned, size, &next) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    *out_offset = aligned;
    *cursor = next;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_derived_event_capacity(
    const libp2p_quic_service_config_t *config,
    size_t *out_capacity)
{
    size_t per_conn = 0U;
    size_t capacity = 0U;

    if ((config == NULL) || (out_capacity == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (config->event_capacity != 0U)
    {
        *out_capacity = config->event_capacity;
        return LIBP2P_QUIC_OK;
    }

    if ((quic_service_size_mul_overflow(
             config->endpoint.max_connections,
             QUIC_SERVICE_EVENTS_PER_CONNECTION,
             &per_conn) != 0) ||
        (quic_service_size_add_overflow(per_conn, QUIC_SERVICE_EXTRA_EVENTS, &capacity) != 0))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    *out_capacity = capacity;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_config_validate(const libp2p_quic_service_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    size_t endpoint_len = 0U;
    size_t event_capacity = 0U;

    if (config == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((config->max_rx_datagrams_per_drive == 0U) || (config->max_tx_datagrams_per_drive == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = libp2p_quic_addr_validate(&config->local_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_endpoint_storage_size(&config->endpoint, &endpoint_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_service_derived_event_capacity(config, &event_capacity);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((endpoint_len == 0U) || (event_capacity == 0U) ||
        (config->endpoint.max_connections == 0U) ||
        (config->endpoint.max_datagram_payload_bytes < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_layout(
    const libp2p_quic_service_config_t *config,
    quic_service_layout_t *layout)
{
    size_t cursor = 0U;
    size_t bytes = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((config == NULL) || (layout == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(layout, 0, sizeof(*layout));
    result = quic_service_config_validate(config);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_endpoint_storage_size(&config->endpoint, &layout->endpoint_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_endpoint_storage_align(&layout->endpoint_align);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_service_derived_event_capacity(config, &layout->event_capacity);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    layout->conn_capacity = config->endpoint.max_connections;
    layout->datagram_len = config->endpoint.max_datagram_payload_bytes;

    result = quic_service_reserve(
        &cursor,
        alignof(libp2p_quic_service_t),
        sizeof(libp2p_quic_service_t),
        &layout->service_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_service_reserve(
        &cursor,
        layout->endpoint_align,
        layout->endpoint_len,
        &layout->endpoint_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (quic_service_size_mul_overflow(
            layout->event_capacity,
            sizeof(libp2p_quic_service_event_t),
            &bytes) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }
    result = quic_service_reserve(
        &cursor,
        alignof(libp2p_quic_service_event_t),
        bytes,
        &layout->events_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (quic_service_size_mul_overflow(
            layout->conn_capacity,
            sizeof(quic_service_conn_entry_t),
            &bytes) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }
    result = quic_service_reserve(
        &cursor,
        alignof(quic_service_conn_entry_t),
        bytes,
        &layout->conns_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result =
        quic_service_reserve(&cursor, alignof(uint8_t), layout->datagram_len, &layout->rx_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result =
        quic_service_reserve(&cursor, alignof(uint8_t), layout->datagram_len, &layout->tx_offset);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    layout->total_len = cursor;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_validate(const libp2p_quic_service_t *service)
{
    if ((service == NULL) || (service->magic != QUIC_SERVICE_MAGIC))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return service->closed != 0U ? LIBP2P_QUIC_ERR_CLOSED : LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_event_push(
    libp2p_quic_service_t *service,
    libp2p_quic_service_event_type_t type,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code,
    uint64_t transport_error_code)
{
    size_t pos = 0U;
    libp2p_quic_service_event_t event;

    if ((service == NULL) || (service->events == NULL) || (service->event_capacity == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (service->event_len == service->event_capacity)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    event.type = type;
    event.conn = conn;
    event.stream = stream;
    event.app_error_code = app_error_code;
    event.transport_error_code = transport_error_code;

    pos = (service->event_head + service->event_len) % service->event_capacity;
    service->events[pos] = event;
    service->event_len++;
    return LIBP2P_QUIC_OK;
}

static quic_service_conn_entry_t *quic_service_find_conn(
    libp2p_quic_service_t *service,
    const libp2p_quic_conn_t *conn)
{
    size_t index = 0U;

    if ((service == NULL) || (conn == NULL))
    {
        return NULL;
    }
    for (index = 0U; index < service->conn_count; index++)
    {
        if (service->conns[index].conn == conn)
        {
            return &service->conns[index];
        }
    }

    return NULL;
}

static libp2p_quic_err_t quic_service_track_conn(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    int incoming)
{
    quic_service_conn_entry_t *entry = NULL;

    if ((service == NULL) || (conn == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    entry = quic_service_find_conn(service, conn);
    if (entry != NULL)
    {
        if (incoming != 0)
        {
            entry->incoming = 1U;
        }
        return LIBP2P_QUIC_OK;
    }
    if (service->conn_count == service->conn_capacity)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    entry = &service->conns[service->conn_count];
    (void)memset(entry, 0, sizeof(*entry));
    entry->conn = conn;
    entry->incoming = (uint8_t)(incoming != 0);
    service->conn_count++;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_mark_conn_established(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn)
{
    quic_service_conn_entry_t *entry = NULL;
    libp2p_quic_err_t result = quic_service_track_conn(service, conn, 0);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    entry = quic_service_find_conn(service, conn);
    if (entry == NULL)
    {
        return LIBP2P_QUIC_ERR_INTERNAL;
    }
    entry->established = 1U;
    return LIBP2P_QUIC_OK;
}

static void quic_service_mark_conn_closed(libp2p_quic_service_t *service, libp2p_quic_conn_t *conn)
{
    quic_service_conn_entry_t *entry = quic_service_find_conn(service, conn);

    if (entry != NULL)
    {
        entry->closed = 1U;
    }
}

static libp2p_quic_err_t quic_service_translate_event(
    libp2p_quic_service_t *service,
    const libp2p_quic_event_t *event)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((service == NULL) || (event == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    switch (event->type)
    {
    case LIBP2P_QUIC_EVENT_CONN_INCOMING:
        result = quic_service_track_conn(service, event->conn, 1);
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_service_event_push(
                service,
                LIBP2P_QUIC_SERVICE_EVENT_CONN_INCOMING,
                event->conn,
                NULL,
                event->app_error_code,
                event->transport_error_code);
        }
        break;

    case LIBP2P_QUIC_EVENT_CONN_ESTABLISHED:
        result = quic_service_mark_conn_established(service, event->conn);
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_service_event_push(
                service,
                LIBP2P_QUIC_SERVICE_EVENT_CONN_ESTABLISHED,
                event->conn,
                NULL,
                event->app_error_code,
                event->transport_error_code);
        }
        break;

    case LIBP2P_QUIC_EVENT_CONN_CLOSED:
        quic_service_mark_conn_closed(service, event->conn);
        result = quic_service_event_push(
            service,
            LIBP2P_QUIC_SERVICE_EVENT_CONN_CLOSED,
            event->conn,
            NULL,
            event->app_error_code,
            event->transport_error_code);
        break;

    case LIBP2P_QUIC_EVENT_STREAM_INCOMING:
        result = quic_service_event_push(
            service,
            LIBP2P_QUIC_SERVICE_EVENT_STREAM_INCOMING,
            event->conn,
            event->stream,
            event->app_error_code,
            event->transport_error_code);
        break;

    case LIBP2P_QUIC_EVENT_STREAM_READABLE:
        result = quic_service_event_push(
            service,
            LIBP2P_QUIC_SERVICE_EVENT_STREAM_READABLE,
            event->conn,
            event->stream,
            event->app_error_code,
            event->transport_error_code);
        break;

    case LIBP2P_QUIC_EVENT_STREAM_WRITABLE:
        result = quic_service_event_push(
            service,
            LIBP2P_QUIC_SERVICE_EVENT_STREAM_WRITABLE,
            event->conn,
            event->stream,
            event->app_error_code,
            event->transport_error_code);
        break;

    case LIBP2P_QUIC_EVENT_STREAM_CLOSED:
        result = quic_service_event_push(
            service,
            LIBP2P_QUIC_SERVICE_EVENT_STREAM_CLOSED,
            event->conn,
            event->stream,
            event->app_error_code,
            event->transport_error_code);
        break;

    case LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY:
        service->tx_pending = 1U;
        break;

    case LIBP2P_QUIC_EVENT_NONE:
    default:
        break;
    }

    return result;
}

static libp2p_quic_err_t quic_service_drain_endpoint_events(
    libp2p_quic_service_t *service,
    libp2p_quic_service_drive_result_t *result)
{
    libp2p_quic_event_t event;
    libp2p_quic_err_t err = LIBP2P_QUIC_OK;

    if (service == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    while ((err = libp2p_quic_endpoint_next_event(service->endpoint, &event)) == LIBP2P_QUIC_OK)
    {
        if (result != NULL)
        {
            result->endpoint_events++;
        }
        err = quic_service_translate_event(service, &event);
        if (err != LIBP2P_QUIC_OK)
        {
            return err;
        }
        if ((result != NULL) && (event.type != LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY))
        {
            result->service_events++;
        }
    }

    return err == LIBP2P_QUIC_ERR_WOULD_BLOCK ? LIBP2P_QUIC_OK : err;
}

static libp2p_quic_err_t quic_service_drive_rx(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_drive_result_t *result)
{
    size_t index = 0U;
    libp2p_quic_err_t err = LIBP2P_QUIC_OK;

    for (index = 0U; index < service->config.max_rx_datagrams_per_drive; index++)
    {
        err = libp2p_quic_udp_socket_recv(
            &service->socket,
            service->endpoint,
            service->rx_buffer,
            service->datagram_buffer_len,
            now_us);
        if (err == LIBP2P_QUIC_OK)
        {
            result->rx_datagrams++;
            result->made_progress = 1U;
            continue;
        }
        if (err == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            result->rx_drained = 1U;
            return LIBP2P_QUIC_OK;
        }
        return err;
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_service_drive_tx(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_drive_result_t *result)
{
    size_t index = 0U;
    libp2p_quic_err_t err = LIBP2P_QUIC_OK;

    for (index = 0U; index < service->config.max_tx_datagrams_per_drive; index++)
    {
        err = libp2p_quic_udp_socket_send(
            &service->socket,
            service->endpoint,
            service->tx_buffer,
            service->datagram_buffer_len,
            now_us);
        if (err == LIBP2P_QUIC_OK)
        {
            result->tx_datagrams++;
            result->made_progress = 1U;
            service->tx_pending = 1U;
            continue;
        }
        if (err == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            service->tx_pending = 0U;
            result->tx_drained = 1U;
            return LIBP2P_QUIC_OK;
        }
        return err;
    }

    service->tx_pending = 1U;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_config_default(libp2p_quic_service_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (config == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(config, 0, sizeof(*config));
    result = libp2p_quic_endpoint_config_default(&config->endpoint);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    config->nonblocking = 1U;
    config->event_capacity = 0U;
    config->max_rx_datagrams_per_drive = QUIC_SERVICE_DEFAULT_DATAGRAM_BUDGET;
    config->max_tx_datagrams_per_drive = QUIC_SERVICE_DEFAULT_DATAGRAM_BUDGET;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_storage_size(
    const libp2p_quic_service_config_t *config,
    size_t *out_len)
{
    quic_service_layout_t layout;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_len == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    *out_len = 0U;

    result = quic_service_layout(config, &layout);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    *out_len = layout.total_len;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_storage_align(size_t *out_align)
{
    size_t endpoint_align = 0U;
    size_t align = alignof(libp2p_quic_service_t);
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_align == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = libp2p_quic_endpoint_storage_align(&endpoint_align);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (endpoint_align > align)
    {
        align = endpoint_align;
    }
    if (alignof(libp2p_quic_service_event_t) > align)
    {
        align = alignof(libp2p_quic_service_event_t);
    }
    if (alignof(quic_service_conn_entry_t) > align)
    {
        align = alignof(quic_service_conn_entry_t);
    }

    *out_align = align;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_service_config_t *config,
    libp2p_quic_service_t **out_service)
{
    quic_service_layout_t layout;
    libp2p_quic_service_t *service = NULL;
    uint8_t *bytes = (uint8_t *)storage;
    libp2p_quic_addr_t bound_addr;
    size_t required_align = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_service == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    *out_service = NULL;

    result = quic_service_layout(config, &layout);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_service_storage_align(&required_align);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((storage == NULL) || (storage_len < layout.total_len) ||
        (((uintptr_t)storage % required_align) != 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(storage, 0, layout.total_len);
    service = (libp2p_quic_service_t *)&bytes[layout.service_offset];
    service->magic = QUIC_SERVICE_MAGIC;
    service->config = *config;
    service->endpoint_storage = &bytes[layout.endpoint_offset];
    service->endpoint_storage_len = layout.endpoint_len;
    service->events = (libp2p_quic_service_event_t *)&bytes[layout.events_offset];
    service->event_capacity = layout.event_capacity;
    service->conns = (quic_service_conn_entry_t *)&bytes[layout.conns_offset];
    service->conn_capacity = layout.conn_capacity;
    service->rx_buffer = &bytes[layout.rx_offset];
    service->tx_buffer = &bytes[layout.tx_offset];
    service->datagram_buffer_len = layout.datagram_len;

    result = libp2p_quic_udp_socket_init(&service->socket);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = libp2p_quic_endpoint_init(
        service->endpoint_storage,
        service->endpoint_storage_len,
        &service->config.endpoint,
        &service->endpoint);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = libp2p_quic_udp_socket_open(
        &service->socket,
        &service->config.local_addr,
        service->config.nonblocking != 0U);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = libp2p_quic_udp_socket_local_addr(&service->socket, &bound_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = libp2p_quic_endpoint_bind(service->endpoint, &bound_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    service->config.local_addr = bound_addr;

    *out_service = service;
    return LIBP2P_QUIC_OK;

fail:
    libp2p_quic_udp_socket_close(&service->socket);
    libp2p_quic_endpoint_deinit(service->endpoint);
    if (service != NULL)
    {
        service->magic = 0U;
    }
    return result;
}

void libp2p_quic_service_deinit(libp2p_quic_service_t *service)
{
    if ((service == NULL) || (service->magic != QUIC_SERVICE_MAGIC))
    {
        return;
    }

    libp2p_quic_udp_socket_close(&service->socket);
    libp2p_quic_endpoint_deinit(service->endpoint);
    service->closed = 1U;
    service->magic = 0U;
}

libp2p_quic_err_t libp2p_quic_service_fd(const libp2p_quic_service_t *service, int *out_fd)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    return libp2p_quic_udp_socket_fd(&service->socket, out_fd);
}

libp2p_quic_err_t libp2p_quic_service_local_addr(
    const libp2p_quic_service_t *service,
    libp2p_quic_addr_t *out_addr)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    return libp2p_quic_udp_socket_local_addr(&service->socket, out_addr);
}

libp2p_quic_err_t libp2p_quic_service_io_interest(
    const libp2p_quic_service_t *service,
    uint32_t *out_interest)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_interest != NULL)
    {
        *out_interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_interest == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_interest = LIBP2P_QUIC_SERVICE_INTEREST_READ;
    if (service->tx_pending != 0U)
    {
        *out_interest |= LIBP2P_QUIC_SERVICE_INTEREST_WRITE;
    }
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_next_deadline(
    const libp2p_quic_service_t *service,
    libp2p_quic_time_us_t *out_deadline_us)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    return libp2p_quic_endpoint_next_deadline(service->endpoint, out_deadline_us);
}

libp2p_quic_err_t libp2p_quic_service_drive(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    uint32_t ready,
    libp2p_quic_service_drive_result_t *out_result)
{
    libp2p_quic_service_drive_result_t local_result;
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_result != NULL)
    {
        (void)memset(out_result, 0, sizeof(*out_result));
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((ready & ~((uint32_t)LIBP2P_QUIC_SERVICE_READY_ALL)) != 0U)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(&local_result, 0, sizeof(local_result));

    result = quic_service_drain_endpoint_events(service, &local_result);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((ready & (uint32_t)LIBP2P_QUIC_SERVICE_READY_READ) != 0U)
    {
        result = quic_service_drive_rx(service, now_us, &local_result);
        if (result != LIBP2P_QUIC_OK)
        {
            return result;
        }
    }
    result = libp2p_quic_endpoint_poll(service->endpoint, now_us);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_service_drain_endpoint_events(service, &local_result);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (((ready &
          ((uint32_t)LIBP2P_QUIC_SERVICE_READY_WRITE | (uint32_t)LIBP2P_QUIC_SERVICE_READY_TIMER |
           (uint32_t)LIBP2P_QUIC_SERVICE_READY_APP)) != 0U) ||
        (service->tx_pending != 0U))
    {
        result = quic_service_drive_tx(service, now_us, &local_result);
        if (result != LIBP2P_QUIC_OK)
        {
            return result;
        }
        result = quic_service_drain_endpoint_events(service, &local_result);
        if (result != LIBP2P_QUIC_OK)
        {
            return result;
        }
    }

    if (out_result != NULL)
    {
        *out_result = local_result;
    }
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_next_event(
    libp2p_quic_service_t *service,
    libp2p_quic_service_event_t *out_event)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_event == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (service->event_len == 0U)
    {
        (void)memset(out_event, 0, sizeof(*out_event));
        out_event->type = LIBP2P_QUIC_SERVICE_EVENT_NONE;
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    *out_event = service->events[service->event_head];
    service->event_head = (service->event_head + 1U) % service->event_capacity;
    service->event_len--;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_dial(
    libp2p_quic_service_t *service,
    const libp2p_quic_addr_t *remote_addr,
    void *user_data,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_dial_config_t dial_config;
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((remote_addr == NULL) || (out_conn == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    dial_config.remote_addr = *remote_addr;
    dial_config.user_data = user_data;
    result = libp2p_quic_endpoint_dial(service->endpoint, &dial_config, out_conn);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_service_track_conn(service, *out_conn, 0);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    service->tx_pending = 1U;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_service_accept_conn(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t **out_conn)
{
    size_t index = 0U;
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_conn == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    for (index = 0U; index < service->conn_count; index++)
    {
        quic_service_conn_entry_t *entry = &service->conns[index];

        if ((entry->conn != NULL) && (entry->incoming != 0U) && (entry->established != 0U) &&
            (entry->accepted == 0U) && (entry->closed == 0U))
        {
            entry->accepted = 1U;
            *out_conn = entry->conn;
            return LIBP2P_QUIC_OK;
        }
    }

    return LIBP2P_QUIC_ERR_WOULD_BLOCK;
}

libp2p_quic_err_t libp2p_quic_service_close(libp2p_quic_service_t *service, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_endpoint_close(service->endpoint, app_error_code);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    return libp2p_quic_conn_peer_id(conn, out, out_len, written);
}

libp2p_quic_err_t libp2p_quic_service_conn_close(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_conn_close(conn, app_error_code);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_open_stream(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    return libp2p_quic_conn_open_bidi_stream(conn, out_stream);
}

libp2p_quic_err_t libp2p_quic_service_accept_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    return libp2p_quic_conn_accept_stream(conn, out_stream);
}

libp2p_quic_err_t libp2p_quic_service_stream_read(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_stream_read(stream, out, out_len, read_len, fin);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_write(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_stream_write(stream, data, data_len, fin, accepted);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_finish(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_stream_finish(stream);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_reset(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_stream_reset(stream, app_error_code);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_stop_sending(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_stream_stop_sending(stream, app_error_code);
    if (result == LIBP2P_QUIC_OK)
    {
        service->tx_pending = 1U;
    }
    return result;
}
