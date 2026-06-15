/**
 * @file quic_service.c
 * @brief Lean-facing runtime driver for libp2p QUIC.
 */

#include "transport/quic/quic_service.h"

#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"
#include "transport/quic/quic_udp.h"

#define QUIC_SERVICE_MAGIC ((uint32_t)0x71535631U)

#define QUIC_SERVICE_EVENTS_PER_CONNECTION 8U
#define QUIC_SERVICE_EXTRA_EVENTS          16U
#define QUIC_SERVICE_STORAGE_ALIGN         8U
#define QUIC_SERVICE_DEBUG_MESSAGE_BYTES   96U

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
    libp2p_quic_tx_datagram_t pending_tx_datagram;
    libp2p_quic_conn_t *pending_tx_conn;
    uint8_t has_pending_tx_datagram;
    uint8_t tx_pending;
    uint8_t closed;
};

static int quic_service_size_add_overflow(size_t a, size_t b, size_t *out)
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

static int quic_service_size_mul_overflow(size_t a, size_t b, size_t *out)
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

static libp2p_quic_err_t quic_service_align_up_size(size_t value, size_t alignment, size_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((alignment == 0U) || (out == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
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
                result = LIBP2P_QUIC_ERR_LIMIT;
            }
            else
            {
                *out = value + adjustment;
            }
        }
    }

    return result;
}

static uint8_t *quic_service_storage_bytes(void *storage)
{
    uint8_t *bytes = NULL;

    (void)memcpy((void *)&bytes, (const void *)&storage, sizeof storage);

    return bytes;
}

static libp2p_quic_service_t *quic_service_storage_service(void *storage)
{
    libp2p_quic_service_t *service = NULL;

    (void)memcpy((void *)&service, (const void *)&storage, sizeof storage);

    return service;
}

static size_t quic_service_debug_append_text(
    char *out,
    size_t out_len,
    size_t pos,
    const char *text)
{
    size_t next = pos;

    if ((out != NULL) && (text != NULL))
    {
        size_t text_index = 0U;

        while ((text[text_index] != '\0') && (next < out_len))
        {
            out[next] = text[text_index];
            next++;
            text_index++;
        }
    }

    return next;
}

static size_t quic_service_debug_append_uint(char *out, size_t out_len, size_t pos, uint32_t value)
{
    char digits[10];
    size_t digit_count = 0U;
    size_t next = pos;
    uint32_t remaining = value;

    do
    {
        digits[digit_count] = (char)('0' + (remaining % 10U));
        digit_count++;
        remaining /= 10U;
    } while ((remaining != 0U) && (digit_count < sizeof(digits)));

    while ((digit_count != 0U) && (next < out_len))
    {
        digit_count--;
        out[next] = digits[digit_count];
        next++;
    }

    return next;
}

static void quic_service_debug_failure(
    const libp2p_quic_service_t *service,
    const char *stage,
    libp2p_quic_err_t err)
{
    if ((service != NULL) && (service->config.endpoint.debug_fn != NULL) && (stage != NULL))
    {
        char message[QUIC_SERVICE_DEBUG_MESSAGE_BYTES];
        size_t pos = 0U;

        pos = quic_service_debug_append_text(message, sizeof(message), pos, "quic service ");
        pos = quic_service_debug_append_text(message, sizeof(message), pos, stage);
        pos = quic_service_debug_append_text(message, sizeof(message), pos, " failed err=");
        pos = quic_service_debug_append_uint(message, sizeof(message), pos, (uint32_t)err);
        service->config.endpoint.debug_fn(
            LIBP2P_QUIC_DEBUG_EVENT_TEXT,
            message,
            pos,
            service->config.endpoint.debug_user_data);
    }
}

static libp2p_quic_service_event_t *quic_service_storage_events(void *storage)
{
    libp2p_quic_service_event_t *events = NULL;

    (void)memcpy((void *)&events, (const void *)&storage, sizeof storage);

    return events;
}

static quic_service_conn_entry_t *quic_service_storage_conns(void *storage)
{
    quic_service_conn_entry_t *conns = NULL;

    (void)memcpy((void *)&conns, (const void *)&storage, sizeof storage);

    return conns;
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
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        result = quic_service_align_up_size(*cursor, alignment, &aligned);
        if ((result == LIBP2P_QUIC_OK) &&
            (quic_service_size_add_overflow(aligned, size, &next) != 0))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        if (result == LIBP2P_QUIC_OK)
        {
            *out_offset = aligned;
            *cursor = next;
        }
    }

    return result;
}

static libp2p_quic_err_t quic_service_derived_event_capacity(
    const libp2p_quic_service_config_t *config,
    size_t *out_capacity)
{
    size_t per_conn = 0U;
    size_t capacity = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((config == NULL) || (out_capacity == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (config->event_capacity != 0U)
    {
        *out_capacity = config->event_capacity;
    }
    else if (
        (quic_service_size_mul_overflow(
             config->endpoint.max_connections,
             QUIC_SERVICE_EVENTS_PER_CONNECTION,
             &per_conn) != 0) ||
        (quic_service_size_add_overflow(per_conn, QUIC_SERVICE_EXTRA_EVENTS, &capacity) != 0))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
        *out_capacity = capacity;
    }

    return result;
}

static libp2p_quic_err_t quic_service_config_validate(const libp2p_quic_service_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    size_t endpoint_len = 0U;
    size_t event_capacity = 0U;

    if (config == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (
        (config->max_rx_datagrams_per_drive == 0U) || (config->max_tx_datagrams_per_drive == 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_quic_addr_validate(&config->local_addr);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_storage_size(&config->endpoint, &endpoint_len);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_derived_event_capacity(config, &event_capacity);
    }
    if ((result == LIBP2P_QUIC_OK) &&
        ((endpoint_len == 0U) || (event_capacity == 0U) ||
         (config->endpoint.max_connections == 0U) ||
         (config->endpoint.max_datagram_payload_bytes < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return result;
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
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(layout, 0, sizeof(*layout));
        result = quic_service_config_validate(config);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_storage_size(&config->endpoint, &layout->endpoint_len);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_storage_align(&layout->endpoint_align);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_derived_event_capacity(config, &layout->event_capacity);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        layout->conn_capacity = config->endpoint.max_connections;
        layout->datagram_len = config->endpoint.max_datagram_payload_bytes;

        result = quic_service_reserve(
            &cursor,
            QUIC_SERVICE_STORAGE_ALIGN,
            sizeof(libp2p_quic_service_t),
            &layout->service_offset);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_reserve(
            &cursor,
            layout->endpoint_align,
            layout->endpoint_len,
            &layout->endpoint_offset);
    }
    if ((result == LIBP2P_QUIC_OK) && (quic_service_size_mul_overflow(
                                           layout->event_capacity,
                                           sizeof(libp2p_quic_service_event_t),
                                           &bytes) != 0))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_reserve(
            &cursor,
            QUIC_SERVICE_STORAGE_ALIGN,
            bytes,
            &layout->events_offset);
    }
    if ((result == LIBP2P_QUIC_OK) && (quic_service_size_mul_overflow(
                                           layout->conn_capacity,
                                           sizeof(quic_service_conn_entry_t),
                                           &bytes) != 0))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result =
            quic_service_reserve(&cursor, QUIC_SERVICE_STORAGE_ALIGN, bytes, &layout->conns_offset);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_reserve(&cursor, 1U, layout->datagram_len, &layout->rx_offset);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_service_reserve(&cursor, 1U, layout->datagram_len, &layout->tx_offset);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        layout->total_len = cursor;
    }

    return result;
}

static libp2p_quic_err_t quic_service_validate(const libp2p_quic_service_t *service)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((service == NULL) || (service->magic != QUIC_SERVICE_MAGIC))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (service->closed != 0U)
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

static libp2p_quic_err_t quic_service_event_push(
    libp2p_quic_service_t *service,
    libp2p_quic_service_event_type_t type,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code,
    uint64_t transport_error_code)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((service == NULL) || (service->events == NULL) || (service->event_capacity == 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (service->event_len == service->event_capacity)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
        libp2p_quic_service_event_t event;

        event.type = type;
        event.conn = conn;
        event.stream = stream;
        event.app_error_code = app_error_code;
        event.transport_error_code = transport_error_code;

        const size_t pos = (service->event_head + service->event_len) % service->event_capacity;
        service->events[pos] = event;
        service->event_len++;
    }

    return result;
}

static quic_service_conn_entry_t *quic_service_find_conn(
    libp2p_quic_service_t *service,
    const libp2p_quic_conn_t *conn)
{
    quic_service_conn_entry_t *result = NULL;

    if ((service != NULL) && (conn != NULL))
    {
        for (size_t index = 0U; index < service->conn_count; index++)
        {
            if (service->conns[index].conn == conn)
            {
                result = &service->conns[index];
                break;
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_service_track_conn(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    int incoming)
{
    quic_service_conn_entry_t *entry = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((service == NULL) || (conn == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        entry = quic_service_find_conn(service, conn);
        if (entry != NULL)
        {
            if (incoming != 0)
            {
                entry->incoming = 1U;
            }
        }
        else if (service->conn_count == service->conn_capacity)
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        else
        {
            entry = &service->conns[service->conn_count];
            (void)memset(entry, 0, sizeof(*entry));
            entry->conn = conn;
            if (incoming != 0)
            {
                entry->incoming = 1U;
            }
            else
            {
                entry->incoming = 0U;
            }
            service->conn_count++;
        }
    }

    return result;
}

static libp2p_quic_err_t quic_service_mark_conn_established(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn)
{
    quic_service_conn_entry_t *entry = NULL;
    libp2p_quic_err_t result = quic_service_track_conn(service, conn, 0);

    if (result == LIBP2P_QUIC_OK)
    {
        entry = quic_service_find_conn(service, conn);
        if (entry == NULL)
        {
            result = LIBP2P_QUIC_ERR_INTERNAL;
        }
        else
        {
            entry->established = 1U;
        }
    }

    return result;
}

static void quic_service_mark_conn_closed(
    libp2p_quic_service_t *service,
    const libp2p_quic_conn_t *conn)
{
    quic_service_conn_entry_t *entry = quic_service_find_conn(service, conn);

    if (entry != NULL)
    {
        entry->closed = 1U;
    }
}

static void quic_service_forget_conn(libp2p_quic_service_t *service, const libp2p_quic_conn_t *conn)
{
    if ((service == NULL) || (conn == NULL))
    {
        return;
    }

    for (size_t index = 0U; index < service->conn_count; index++)
    {
        if (service->conns[index].conn == conn)
        {
            const size_t last_index = service->conn_count - 1U;

            if (index != last_index)
            {
                service->conns[index] = service->conns[last_index];
            }
            (void)memset(&service->conns[last_index], 0, sizeof(service->conns[last_index]));
            service->conn_count--;
            break;
        }
    }
}

static int quic_service_event_references_conn(
    const libp2p_quic_service_event_t *event,
    const libp2p_quic_conn_t *conn)
{
    int result = 0;

    if ((event != NULL) && (conn != NULL))
    {
        if (event->conn == conn)
        {
            result = 1;
        }
        else if ((event->stream != NULL) && (event->stream->conn == conn))
        {
            result = 1;
        }
    }

    return result;
}

static int quic_service_has_event_ref(
    const libp2p_quic_service_t *service,
    const libp2p_quic_conn_t *conn)
{
    int result = 0;

    if ((service != NULL) && (conn != NULL))
    {
        for (size_t index = 0U; index < service->event_len; index++)
        {
            const size_t pos = (service->event_head + index) % service->event_capacity;

            if (quic_service_event_references_conn(&service->events[pos], conn) != 0)
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_service_translate_event(
    libp2p_quic_service_t *service,
    const libp2p_quic_event_t *event)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((service == NULL) || (event == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
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
            quic_service_forget_conn(service, event->conn);
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
        err = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        uint8_t draining = 1U;

        while ((err == LIBP2P_QUIC_OK) && (draining != 0U))
        {
            err = libp2p_quic_endpoint_next_event(service->endpoint, &event);
            if (err == LIBP2P_QUIC_OK)
            {
                if (result != NULL)
                {
                    result->endpoint_events++;
                }
                err = quic_service_translate_event(service, &event);
                if ((err == LIBP2P_QUIC_OK) && (result != NULL) &&
                    (event.type != LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY))
                {
                    result->service_events++;
                }
            }
            else
            {
                draining = 0U;
            }
        }
    }

    if (err == LIBP2P_QUIC_ERR_WOULD_BLOCK)
    {
        err = LIBP2P_QUIC_OK;
    }

    return err;
}

static libp2p_quic_err_t quic_service_drive_rx(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_drive_result_t *result)
{
    size_t index = 0U;
    libp2p_quic_err_t result_code = LIBP2P_QUIC_OK;

    for (index = 0U; (index < service->config.max_rx_datagrams_per_drive) &&
                     (result_code == LIBP2P_QUIC_OK) && (result->rx_drained == 0U);
         index++)
    {
        libp2p_quic_err_t err = libp2p_quic_udp_socket_recv(
            &service->socket,
            service->endpoint,
            service->rx_buffer,
            service->datagram_buffer_len,
            now_us);
        if (err == LIBP2P_QUIC_OK)
        {
            result->rx_datagrams++;
            result->made_progress = 1U;
        }
        else if (err == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            result->rx_drained = 1U;
        }
        else
        {
            result_code = err;
        }
    }

    return result_code;
}

static void quic_service_clear_pending_tx_datagram(libp2p_quic_service_t *service)
{
    if (service != NULL)
    {
        service->has_pending_tx_datagram = 0U;
        service->pending_tx_conn = NULL;
        (void)memset(&service->pending_tx_datagram, 0, sizeof(service->pending_tx_datagram));
    }
}

static libp2p_quic_err_t quic_service_prepare_tx_datagram(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (service == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (service->has_pending_tx_datagram != 0U)
    {
        result = LIBP2P_QUIC_OK;
    }
    else
    {
        (void)memset(&service->pending_tx_datagram, 0, sizeof(service->pending_tx_datagram));
        service->pending_tx_datagram.data = service->tx_buffer;
        service->pending_tx_datagram.data_cap = service->datagram_buffer_len;
        result = libp2p_quic_endpoint_next_datagram(
            service->endpoint,
            &service->pending_tx_datagram,
            now_us);
        if (result == LIBP2P_QUIC_OK)
        {
            service->pending_tx_conn = quic_backend_endpoint_last_tx_conn(service->endpoint);
            service->has_pending_tx_datagram = 1U;
        }
    }

    return result;
}

static libp2p_quic_err_t quic_service_drive_tx(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_drive_result_t *result)
{
    size_t index = 0U;
    libp2p_quic_err_t result_code = LIBP2P_QUIC_OK;

    for (index = 0U; (index < service->config.max_tx_datagrams_per_drive) &&
                     (result_code == LIBP2P_QUIC_OK) && (result->tx_drained == 0U);
         index++)
    {
        uint8_t prepared = 0U;
        libp2p_quic_err_t err = quic_service_prepare_tx_datagram(service, now_us);
        if (err == LIBP2P_QUIC_OK)
        {
            prepared = 1U;
            err = libp2p_quic_udp_socket_send_datagram(
                &service->socket,
                &service->pending_tx_datagram);
        }

        if (err == LIBP2P_QUIC_OK)
        {
            quic_backend_conn_confirm_tx_datagram(service->pending_tx_conn, now_us);
            quic_service_clear_pending_tx_datagram(service);
            result->tx_datagrams++;
            result->made_progress = 1U;
            service->tx_pending = 1U;
        }
        else if (err == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            if (prepared != 0U)
            {
                service->tx_pending = service->has_pending_tx_datagram;
            }
            else
            {
                service->tx_pending = (result->tx_datagrams != 0U) ? 1U : 0U;
            }
            result->tx_drained = 1U;
        }
        else
        {
            quic_backend_conn_discard_tx_datagram(service->pending_tx_conn);
            quic_service_clear_pending_tx_datagram(service);
            result_code = err;
        }
    }

    if ((result_code == LIBP2P_QUIC_OK) && (result->tx_drained == 0U))
    {
        service->tx_pending = 1U;
    }

    if (result_code == LIBP2P_QUIC_OK)
    {
        result_code = quic_backend_endpoint_flush_tx_time_updates(service->endpoint, now_us);
    }

    return result_code;
}

libp2p_quic_err_t libp2p_quic_service_config_default(libp2p_quic_service_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (config == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
        result = libp2p_quic_endpoint_config_default(&config->endpoint);
        if (result == LIBP2P_QUIC_OK)
        {
            config->nonblocking = 1U;
            config->event_capacity = 0U;
            config->max_rx_datagrams_per_drive = LIBP2P_QUIC_SERVICE_DEFAULT_DATAGRAM_BUDGET;
            config->max_tx_datagrams_per_drive = LIBP2P_QUIC_SERVICE_DEFAULT_DATAGRAM_BUDGET;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_storage_size(
    const libp2p_quic_service_config_t *config,
    size_t *out_len)
{
    quic_service_layout_t layout;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_len == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result = quic_service_layout(config, &layout);
        if (result == LIBP2P_QUIC_OK)
        {
            *out_len = layout.total_len;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_storage_align(size_t *out_align)
{
    size_t endpoint_align = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_align == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_quic_endpoint_storage_align(&endpoint_align);
        if (result == LIBP2P_QUIC_OK)
        {
            size_t align = QUIC_SERVICE_STORAGE_ALIGN;

            if (endpoint_align > align)
            {
                align = endpoint_align;
            }
            if (endpoint_align > align)
            {
                align = endpoint_align;
            }

            *out_align = align;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_service_config_t *config,
    libp2p_quic_service_t **out_service)
{
    quic_service_layout_t layout;
    libp2p_quic_service_t *service = NULL;
    uint8_t *bytes = quic_service_storage_bytes(storage);
    libp2p_quic_addr_t bound_addr;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)memset(&layout, 0, sizeof(layout));
    (void)memset(&bound_addr, 0, sizeof(bound_addr));

    if (out_service == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_service = NULL;
        result = quic_service_layout(config, &layout);
    }

    if ((result == LIBP2P_QUIC_OK) && ((storage == NULL) || (storage_len < layout.total_len)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        (void)memset(storage, 0, layout.total_len);
        service = quic_service_storage_service(&bytes[layout.service_offset]);
        service->magic = QUIC_SERVICE_MAGIC;
        service->config = *config;
        service->endpoint_storage = &bytes[layout.endpoint_offset];
        service->endpoint_storage_len = layout.endpoint_len;
        service->events = quic_service_storage_events(&bytes[layout.events_offset]);
        service->event_capacity = layout.event_capacity;
        service->conns = quic_service_storage_conns(&bytes[layout.conns_offset]);
        service->conn_capacity = layout.conn_capacity;
        service->rx_buffer = &bytes[layout.rx_offset];
        service->tx_buffer = &bytes[layout.tx_offset];
        service->datagram_buffer_len = layout.datagram_len;

        result = libp2p_quic_udp_socket_init(&service->socket);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_init(
            service->endpoint_storage,
            service->endpoint_storage_len,
            &service->config.endpoint,
            &service->endpoint);
        if (result == LIBP2P_QUIC_OK)
        {
            quic_backend_endpoint_set_defer_tx_time_updates(service->endpoint, 1U);
        }
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_udp_socket_open(
            &service->socket,
            &service->config.local_addr,
            service->config.nonblocking != 0U);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_udp_socket_local_addr(&service->socket, &bound_addr);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_bind(service->endpoint, &bound_addr);
    }

    if (result == LIBP2P_QUIC_OK)
    {
        service->config.local_addr = bound_addr;
        *out_service = service;
    }
    else
    {
        if (service != NULL)
        {
            libp2p_quic_udp_socket_close(&service->socket);
            libp2p_quic_endpoint_deinit(service->endpoint);
            service->magic = 0U;
        }
    }

    return result;
}

void libp2p_quic_service_deinit(libp2p_quic_service_t *service)
{
    if ((service != NULL) && (service->magic == QUIC_SERVICE_MAGIC))
    {
        libp2p_quic_udp_socket_close(&service->socket);
        libp2p_quic_endpoint_deinit(service->endpoint);
        service->closed = 1U;
        service->magic = 0U;
    }
}

libp2p_quic_err_t libp2p_quic_service_fd(
    const libp2p_quic_service_t *service,
    libp2p_quic_udp_fd_t *out_fd)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_udp_socket_fd(&service->socket, out_fd);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_local_addr(
    const libp2p_quic_service_t *service,
    libp2p_quic_addr_t *out_addr)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_udp_socket_local_addr(&service->socket, out_addr);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_listen_addr(
    const libp2p_quic_service_t *service,
    libp2p_quic_addr_t *out_addr)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_udp_socket_listen_addr(&service->socket, out_addr);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_local_peer_id(
    const libp2p_quic_service_t *service,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_local_identity_peer_id(
            &service->config.endpoint.identity,
            out,
            out_len,
            written);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_io_interest(
    const libp2p_quic_service_t *service,
    libp2p_quic_service_interest_t *out_interest)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_interest != NULL)
    {
        *out_interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        if (out_interest == NULL)
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else
        {
            *out_interest = LIBP2P_QUIC_SERVICE_INTEREST_READ;
            if ((service->tx_pending != 0U) || (service->has_pending_tx_datagram != 0U))
            {
                *out_interest |= LIBP2P_QUIC_SERVICE_INTEREST_WRITE;
            }
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_next_deadline(
    const libp2p_quic_service_t *service,
    libp2p_quic_time_us_t *out_deadline_us)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_next_deadline(service->endpoint, out_deadline_us);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_drive(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_ready_t ready,
    libp2p_quic_service_drive_result_t *out_result)
{
    libp2p_quic_service_drive_result_t local_result;
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_result != NULL)
    {
        (void)memset(out_result, 0, sizeof(*out_result));
    }
    if ((result == LIBP2P_QUIC_OK) && ((ready & ~(LIBP2P_QUIC_SERVICE_READY_ALL)) != 0U))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        uint8_t drive_rx = 0U;

        (void)memset(&local_result, 0, sizeof(local_result));

        result = quic_service_drain_endpoint_events(service, &local_result);
        if (result != LIBP2P_QUIC_OK)
        {
            quic_service_debug_failure(service, "drain-initial", result);
        }
        if ((ready & LIBP2P_QUIC_SERVICE_READY_READ) != 0U)
        {
            drive_rx = 1U;
        }
        else if (
            (service->config.nonblocking != 0U) &&
            ((ready & (LIBP2P_QUIC_SERVICE_READY_WRITE | LIBP2P_QUIC_SERVICE_READY_TIMER |
                       LIBP2P_QUIC_SERVICE_READY_APP)) != 0U))
        {
            drive_rx = 1U;
        }
        else
        {
            drive_rx = 0U;
        }
        if ((result == LIBP2P_QUIC_OK) && (drive_rx != 0U))
        {
            result = quic_service_drive_rx(service, now_us, &local_result);
            if (result != LIBP2P_QUIC_OK)
            {
                quic_service_debug_failure(service, "rx", result);
            }
        }
        if (result == LIBP2P_QUIC_OK)
        {
            result = libp2p_quic_endpoint_poll(service->endpoint, now_us);
            if (result != LIBP2P_QUIC_OK)
            {
                quic_service_debug_failure(service, "endpoint-poll", result);
            }
        }
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_service_drain_endpoint_events(service, &local_result);
            if (result != LIBP2P_QUIC_OK)
            {
                quic_service_debug_failure(service, "drain-after-poll", result);
            }
        }
        if ((result == LIBP2P_QUIC_OK) &&
            ((service->tx_pending != 0U) || (service->has_pending_tx_datagram != 0U)))
        {
            result = quic_service_drive_tx(service, now_us, &local_result);
            if (result != LIBP2P_QUIC_OK)
            {
                quic_service_debug_failure(service, "tx", result);
            }
            if (result == LIBP2P_QUIC_OK)
            {
                result = quic_service_drain_endpoint_events(service, &local_result);
                if (result != LIBP2P_QUIC_OK)
                {
                    quic_service_debug_failure(service, "drain-after-tx", result);
                }
            }
        }

        if ((result == LIBP2P_QUIC_OK) && (out_result != NULL))
        {
            *out_result = local_result;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_next_event(
    libp2p_quic_service_t *service,
    libp2p_quic_service_event_t *out_event)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        if (out_event == NULL)
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else if (service->event_len == 0U)
        {
            (void)memset(out_event, 0, sizeof(*out_event));
            out_event->type = LIBP2P_QUIC_SERVICE_EVENT_NONE;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            *out_event = service->events[service->event_head];
            service->event_head = (service->event_head + 1U) % service->event_capacity;
            service->event_len--;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_autopsy_conn(
    const libp2p_quic_service_t *service,
    size_t conn_index,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_autopsy_conn_t *out_conn)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_conn != NULL)
    {
        (void)memset(out_conn, 0, sizeof(*out_conn));
    }
    if (result == LIBP2P_QUIC_OK)
    {
        if ((out_conn == NULL) || (conn_index >= service->conn_capacity))
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
    }
    if (result == LIBP2P_QUIC_OK)
    {
        const quic_service_conn_entry_t *entry = &service->conns[conn_index];

        if (entry->conn == NULL)
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            const libp2p_quic_conn_t *conn = entry->conn;
            ngtcp2_conn_info info;
            ngtcp2_tstamp expiry = UINT64_MAX;

            (void)memset(&info, 0, sizeof(info));
            out_conn->used = 1U;
            out_conn->closed = entry->closed;
            out_conn->is_server = (conn->role == LIBP2P_QUIC_ROLE_SERVER) ? 1U : 0U;
            out_conn->handshake_confirmed = conn->autopsy_handshake_confirmed;
            out_conn->tx_time_update_unconfirmed = conn->tx_time_update_unconfirmed;
            out_conn->tx_time_update_pending = conn->tx_time_update_pending;
            if (conn->has_peer_identity != 0U)
            {
                out_conn->remote_peer_id_len = conn->peer_identity.peer_id_len;
                (void)memcpy(
                    out_conn->remote_peer_id,
                    conn->peer_identity.peer_id,
                    conn->peer_identity.peer_id_len);
            }
            if (conn->ngconn != NULL)
            {
                ngtcp2_conn_get_conn_info2(conn->ngconn, &info);
                expiry = ngtcp2_conn_get_expiry2(conn->ngconn);
                out_conn->handshake_completed =
                    (ngtcp2_conn_get_handshake_completed2(conn->ngconn) != 0) ? 1U : 0U;
                out_conn->pto_us =
                    quic_backend_time_from_ngtcp2(ngtcp2_conn_get_pto2(conn->ngconn));
                out_conn->path_max_tx_udp_payload_size =
                    ngtcp2_conn_get_path_max_tx_udp_payload_size2(conn->ngconn);
            }
            out_conn->cwnd = info.cwnd;
            out_conn->bytes_in_flight = info.bytes_in_flight;
            out_conn->latest_rtt_us = quic_backend_time_from_ngtcp2(info.latest_rtt);
            out_conn->smoothed_rtt_us = quic_backend_time_from_ngtcp2(info.smoothed_rtt);
            out_conn->pkt_sent = info.pkt_sent;
            out_conn->pkt_recv = info.pkt_recv;
            out_conn->pkt_lost = info.pkt_lost;
            out_conn->pkt_discarded = info.pkt_discarded;
            out_conn->bytes_sent = info.bytes_sent;
            out_conn->bytes_recv = info.bytes_recv;
            out_conn->ping_recv = info.ping_recv;
            out_conn->tx_lost = info.bytes_lost;
            out_conn->tx_sent = conn->autopsy_tx_sent_bytes;
            out_conn->tx_acked = conn->autopsy_tx_acked_bytes;
            out_conn->max_tx_datagram_bytes = conn->autopsy_max_tx_datagram_bytes;
            out_conn->max_tx_stream_data_bytes = conn->autopsy_max_tx_stream_data_bytes;
            out_conn->write_data_packets = conn->autopsy_write_data_packets;
            out_conn->write_control_packets = conn->autopsy_write_control_packets;
            out_conn->write_zero_count = conn->autopsy_write_zero_count;
            out_conn->write_stream_blocked_count = conn->autopsy_write_stream_blocked_count;
            out_conn->write_stream_shut_wr_count = conn->autopsy_write_stream_shut_wr_count;
            out_conn->write_stream_not_found_count = conn->autopsy_write_stream_not_found_count;
            out_conn->write_other_error_count = conn->autopsy_write_other_error_count;
            out_conn->ack_range_count = conn->autopsy_ack_range_count;
            out_conn->ack_reclaim_count = conn->autopsy_ack_reclaim_count;
            out_conn->ack_gap_reclaim_count = conn->autopsy_ack_gap_reclaim_count;
            out_conn->ack_gap_reclaim_bytes = conn->autopsy_ack_gap_reclaim_bytes;
            out_conn->last_ack_gap_stream_id = conn->autopsy_last_ack_gap_stream_id;
            out_conn->last_ack_gap_offset = conn->autopsy_last_ack_gap_offset;
            out_conn->last_ack_gap_len = conn->autopsy_last_ack_gap_len;
            out_conn->last_ack_gap_base = conn->autopsy_last_ack_gap_base;
            out_conn->last_ack_gap_sent_end = conn->autopsy_last_ack_gap_sent_end;
            out_conn->last_rx_us = conn->autopsy_last_rx_us;
            out_conn->last_tx_us = conn->autopsy_last_tx_us;
            if (expiry != UINT64_MAX)
            {
                out_conn->idle_deadline_us =
                    quic_backend_endpoint_time_from_ngtcp2(conn->endpoint, expiry);
            }
            for (size_t stream_index = 0U; stream_index < conn->streams.len; stream_index++)
            {
                const libp2p_quic_stream_t *stream = conn->streams.items[stream_index];

                if (stream != NULL)
                {
                    const uint64_t stream_buffered = (uint64_t)stream->tx_len;
                    const uint64_t sent_pending_ack = (uint64_t)stream->tx_sent_len;

                    out_conn->tx_buffered += stream_buffered;
                    if (out_conn->stream_count < LIBP2P_QUIC_SERVICE_AUTOPSY_MAX_STREAMS)
                    {
                        libp2p_quic_service_autopsy_stream_t *out_stream =
                            &out_conn->streams[out_conn->stream_count];

                        out_stream->used = 1U;
                        out_stream->stream_id = stream->stream_id;
                        out_stream->tx_buffered = stream->tx_len;
                        out_stream->tx_sent_pending_ack = stream->tx_sent_len;
                        out_stream->tx_base_offset = stream->tx_base_offset;
                        if ((conn->ngconn != NULL) && (stream->stream_id >= 0))
                        {
                            out_stream->flow_credit = ngtcp2_conn_get_max_stream_data_left2(
                                conn->ngconn,
                                stream->stream_id);
                            out_stream->loss_count = ngtcp2_conn_get_stream_loss_count2(
                                conn->ngconn,
                                stream->stream_id);
                        }
                    }
                    out_conn->stream_count++;
                    (void)sent_pending_ack;
                }
            }
            (void)now_us;
        }
    }

    return result;
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
    if (result == LIBP2P_QUIC_OK)
    {
        if ((remote_addr == NULL) || (out_conn == NULL))
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else
        {
            dial_config.remote_addr = *remote_addr;
            dial_config.user_data = user_data;
            result = libp2p_quic_endpoint_dial(service->endpoint, &dial_config, out_conn);
            if (result == LIBP2P_QUIC_OK)
            {
                result = quic_service_track_conn(service, *out_conn, 0);
            }
            if (result == LIBP2P_QUIC_OK)
            {
                service->tx_pending = 1U;
            }
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_accept_conn(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        if (out_conn == NULL)
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            for (size_t index = 0U; index < service->conn_count; index++)
            {
                quic_service_conn_entry_t *entry = &service->conns[index];

                if ((entry->conn != NULL) && (entry->incoming != 0U) &&
                    (entry->established != 0U) && (entry->accepted == 0U) && (entry->closed == 0U))
                {
                    entry->accepted = 1U;
                    *out_conn = entry->conn;
                    result = LIBP2P_QUIC_OK;
                    break;
                }
            }
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_close(libp2p_quic_service_t *service, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_endpoint_close(service->endpoint, app_error_code);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
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

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_conn_close(conn, app_error_code);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_conn_release(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        if (conn == NULL)
        {
            result = LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        else if ((service->pending_tx_conn == conn) ||
                 (quic_service_find_conn(service, conn) != NULL) ||
                 (quic_service_has_event_ref(service, conn) != 0))
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            result = quic_backend_endpoint_release_retired_conn(service->endpoint, conn);
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_open_stream(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_conn_open_bidi_stream(conn, out_stream);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
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

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_stream_read(stream, out, out_len, read_len, fin);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
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

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_stream_write(stream, data, data_len, fin, accepted);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_finish(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_stream_finish(stream);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_reset(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_stream_reset(stream, app_error_code);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_service_stream_stop_sending(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_service_validate(service);

    if (result == LIBP2P_QUIC_OK)
    {
        result = libp2p_quic_stream_stop_sending(stream, app_error_code);
        if (result == LIBP2P_QUIC_OK)
        {
            service->tx_pending = 1U;
        }
    }

    return result;
}
