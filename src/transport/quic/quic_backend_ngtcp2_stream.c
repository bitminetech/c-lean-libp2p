/**
 * @file quic_backend_ngtcp2_stream.c
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
#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_conn_find_stream(
    const libp2p_quic_conn_t *conn,
    int64_t stream_id)
{
    libp2p_quic_stream_t *result = NULL;

    if (conn != NULL)
    {
        for (size_t index = 0U; index < conn->streams.len; index++)
        {
            if ((conn->streams.items[index] != NULL) &&
                (conn->streams.items[index]->stream_id == stream_id))
            {
                result = conn->streams.items[index];
                break;
            }
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_stream_vec_push(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (stream == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (conn->streams.len == conn->streams.cap)
    {
        size_t new_cap = 8U;
        size_t new_bytes = 0U;
        libp2p_quic_stream_t **new_items = NULL;

        if (conn->streams.cap != 0U)
        {
            new_cap = conn->streams.cap * 2U;
        }
        if ((new_cap < conn->streams.cap) ||
            // NOLINTNEXTLINE(bugprone-sizeof-expression)
            (quic_backend_size_mul_overflow(new_cap, sizeof(*conn->streams.items), &new_bytes) !=
             0))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        else
        {
            new_items = quic_backend_stream_items_from_memory(
                quic_backend_realloc(conn->endpoint, (void *)conn->streams.items, new_bytes));
            if (new_items == NULL)
            {
                result = LIBP2P_QUIC_ERR_NO_MEMORY;
            }
            else
            {
                conn->streams.items = new_items;
                conn->streams.cap = new_cap;
            }
        }
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        conn->streams.items[conn->streams.len] = stream;
        conn->streams.len++;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_stream_new(
    libp2p_quic_conn_t *conn,
    int64_t stream_id,
    int incoming)
{
    libp2p_quic_stream_t *stream = NULL;

    stream =
        quic_backend_stream_from_memory(quic_backend_calloc(conn->endpoint, 1U, sizeof(*stream)));
    if (stream != NULL)
    {
        stream->magic = QUIC_BACKEND_STREAM_MAGIC;
        stream->conn = conn;
        stream->stream_id = stream_id;
        stream->state = LIBP2P_QUIC_STREAM_OPEN;
        if (incoming != 0)
        {
            stream->incoming = 1U;
        }
        else
        {
            stream->incoming = 0U;
        }

        if (quic_backend_stream_vec_push(conn, stream) != LIBP2P_QUIC_OK)
        {
            quic_backend_free(conn->endpoint, stream);
            stream = NULL;
        }
    }

    return stream;
}

QUIC_BACKEND_INTERNAL void quic_backend_stream_free(libp2p_quic_stream_t *stream)
{
    libp2p_quic_endpoint_t *endpoint = NULL;

    if (stream != NULL)
    {
        if (stream->conn != NULL)
        {
            endpoint = stream->conn->endpoint;
        }
        quic_backend_free(endpoint, stream->rx_data);
        quic_backend_free(endpoint, stream->tx_data);
        stream->magic = 0U;
        quic_backend_free(endpoint, stream);
    }
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_id(const libp2p_quic_stream_t *stream, libp2p_quic_stream_id_t *out_id)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_id == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_id = (libp2p_quic_stream_id_t)stream->stream_id;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_state(const libp2p_quic_stream_t *stream, libp2p_quic_stream_state_t *out_state)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_state == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_state = stream->state;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_read(
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (read_len != NULL)
    {
        *read_len = 0U;
    }
    if (fin != NULL)
    {
        *fin = 0;
    }
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) ||
        (stream->conn == NULL) || (stream->conn->magic != QUIC_BACKEND_CONN_MAGIC))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (stream->state == LIBP2P_QUIC_STREAM_RESET)
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else if (
        (stream->state == LIBP2P_QUIC_STREAM_CLOSED) &&
        (stream->rx_read_offset == stream->rx_len) &&
        ((stream->remote_fin == 0U) || (stream->remote_fin_delivered != 0U)))
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    else
    {
        /* The stream can still be read. */
    }
    if ((result == LIBP2P_QUIC_OK) &&
        ((read_len == NULL) || (fin == NULL) || ((out == NULL) && (out_len != 0U))))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        const size_t available = stream->rx_len - stream->rx_read_offset;
        if (available != 0U)
        {
            size_t copied = out_len;

            if (available < copied)
            {
                copied = available;
            }
            if (copied != 0U)
            {
                (void)memcpy(out, &stream->rx_data[stream->rx_read_offset], copied);
                stream->rx_read_offset += copied;
                *read_len = copied;
                (void)ngtcp2_conn_extend_max_stream_offset(
                    stream->conn->ngconn,
                    stream->stream_id,
                    copied);
                ngtcp2_conn_extend_max_offset(stream->conn->ngconn, copied);
            }
            if (stream->rx_read_offset == stream->rx_len)
            {
                stream->rx_read_offset = 0U;
                stream->rx_len = 0U;
            }
        }

        if ((stream->remote_fin != 0U) && (stream->rx_len == 0U) &&
            (stream->remote_fin_delivered == 0U))
        {
            *fin = 1;
            stream->remote_fin_delivered = 1U;
        }

        if ((*read_len == 0U) && (*fin == 0))
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
    }

    return result;
}

static size_t quic_backend_stream_next_tx_cap(
    size_t current_cap,
    size_t required,
    size_t retained_limit)
{
    size_t result = current_cap;
    size_t min_cap = QUIC_BACKEND_STREAM_SEND_MIN_CAP;

    if (min_cap > retained_limit)
    {
        min_cap = retained_limit;
    }
    if (result < min_cap)
    {
        result = min_cap;
    }
    while ((result < required) && (result < retained_limit))
    {
        if (result > (retained_limit / 2U))
        {
            result = retained_limit;
        }
        else
        {
            result *= 2U;
        }
    }
    if (result < required)
    {
        result = required;
    }
    if (result > retained_limit)
    {
        result = retained_limit;
    }

    return result;
}

static libp2p_quic_err_t quic_backend_stream_reserve_tx(
    libp2p_quic_stream_t *stream,
    size_t required,
    size_t retained_limit)
{
    uint8_t *new_data = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((stream == NULL) || (stream->conn == NULL) || (stream->conn->endpoint == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (required > stream->tx_cap)
    {
        if (stream->tx_sent_len != 0U)
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            const size_t new_cap =
                quic_backend_stream_next_tx_cap(stream->tx_cap, required, retained_limit);

            if (new_cap < required)
            {
                result = LIBP2P_QUIC_ERR_LIMIT;
            }
            else
            {
                new_data = quic_backend_bytes_from_memory(
                    quic_backend_realloc(stream->conn->endpoint, stream->tx_data, new_cap));
                if (new_data == NULL)
                {
                    result = LIBP2P_QUIC_ERR_NO_MEMORY;
                }
                else
                {
                    stream->tx_data = new_data;
                    stream->tx_cap = new_cap;
                }
            }
        }
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

QUIC_BACKEND_INTERNAL void quic_backend_stream_shrink_tx(libp2p_quic_stream_t *stream)
{
    if ((stream != NULL) && (stream->tx_sent_len == 0U))
    {
        if (stream->tx_len == 0U)
        {
            if ((stream->conn != NULL) && (stream->conn->endpoint != NULL))
            {
                quic_backend_free(stream->conn->endpoint, stream->tx_data);
            }
            stream->tx_data = NULL;
            stream->tx_cap = 0U;
        }
        else
        {
            if (stream->tx_len < stream->tx_cap)
            {
                uint8_t *new_data = NULL;
                const size_t new_cap =
                    quic_backend_stream_next_tx_cap(0U, stream->tx_len, stream->tx_cap);

                if ((new_cap < stream->tx_cap) && (stream->conn != NULL) &&
                    (stream->conn->endpoint != NULL))
                {
                    new_data = quic_backend_bytes_from_memory(
                        quic_backend_realloc(stream->conn->endpoint, stream->tx_data, new_cap));
                    if (new_data != NULL)
                    {
                        stream->tx_data = new_data;
                        stream->tx_cap = new_cap;
                    }
                }
            }
        }
    }
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    size_t required = 0U;
    size_t accept_len = data_len;
    uint32_t block_reason = 0U;
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (accepted != NULL)
    {
        *accepted = 0U;
    }
    if ((result == LIBP2P_QUIC_OK) && ((accepted == NULL) || ((data == NULL) && (data_len != 0U))))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((result == LIBP2P_QUIC_OK) && (stream->local_fin_queued != 0U))
    {
        result = LIBP2P_QUIC_ERR_CLOSED;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        size_t retained_limit = 0U;

        if (stream->conn->endpoint->config.initial_stream_window_bytes >
            (SIZE_MAX / QUIC_BACKEND_STREAM_SEND_MULTIPLIER))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        else
        {
            retained_limit = stream->conn->endpoint->config.initial_stream_window_bytes *
                             QUIC_BACKEND_STREAM_SEND_MULTIPLIER;
        }
        if ((result == LIBP2P_QUIC_OK) && (stream->tx_len < stream->tx_sent_len))
        {
            result = LIBP2P_QUIC_ERR_STATE;
        }
        if ((result == LIBP2P_QUIC_OK) && (stream->tx_len >= retained_limit) && (accept_len != 0U))
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            block_reason = 2U;
        }
        if (result == LIBP2P_QUIC_OK)
        {
            const size_t available = retained_limit - stream->tx_len;

            if (accept_len > available)
            {
                accept_len = available;
            }
        }
        if ((result == LIBP2P_QUIC_OK) &&
            ((quic_backend_size_add_overflow(stream->tx_len, accept_len, &required) != 0) ||
             (required > retained_limit)))
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            block_reason = 2U;
        }

        if ((result == LIBP2P_QUIC_OK) && (required > stream->tx_cap))
        {
            result = quic_backend_stream_reserve_tx(stream, required, retained_limit);
            if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
            {
                block_reason = 3U;
            }
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        if (accept_len != 0U)
        {
            (void)memcpy(&stream->tx_data[stream->tx_len], data, accept_len);
            stream->tx_len += accept_len;
            *accepted = accept_len;
        }
        if ((fin != 0) && (accept_len == data_len))
        {
            stream->local_fin_queued = 1U;
        }

        result = quic_backend_event_push(
            stream->conn->endpoint,
            LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
            stream->conn,
            stream,
            0U,
            0U);
    }
    if ((stream != NULL) && (stream->magic == QUIC_BACKEND_STREAM_MAGIC))
    {
        if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            stream->write_blocked = 1U;
            quic_backend_debug_stream_state(
                stream,
                "stream_write_blocked",
                (uint64_t)data_len,
                (uint64_t)accept_len,
                block_reason);
        }
        else if (result == LIBP2P_QUIC_OK)
        {
            stream->write_blocked = 0U;
        }
        else
        {
            /* Other write errors leave the blocked marker unchanged. */
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_finish(libp2p_quic_stream_t *stream)
{
    size_t accepted = 0U;
    libp2p_quic_err_t result = quic_backend_stream_write(stream, NULL, 0U, 1, &accepted);

    return result;
}

QUIC_BACKEND_INTERNAL void quic_backend_stream_clear_ack_ranges(libp2p_quic_stream_t *stream)
{
    if (stream != NULL)
    {
        (void)memset(stream->tx_ack_ranges, 0, sizeof(stream->tx_ack_ranges));
        stream->tx_ack_range_count = 0U;
    }
}

static void quic_backend_stream_remove_ack_range(libp2p_quic_stream_t *stream, size_t index)
{
    size_t shift = index;

    while ((shift + 1U) < stream->tx_ack_range_count)
    {
        stream->tx_ack_ranges[shift] = stream->tx_ack_ranges[shift + 1U];
        shift++;
    }
    if (stream->tx_ack_range_count != 0U)
    {
        stream->tx_ack_range_count--;
        stream->tx_ack_ranges[stream->tx_ack_range_count].start = 0U;
        stream->tx_ack_ranges[stream->tx_ack_range_count].end = 0U;
    }
}

static void quic_backend_stream_insert_ack_range(
    libp2p_quic_stream_t *stream,
    uint64_t start,
    uint64_t end)
{
    size_t index = 0U;
    uint64_t merged_start = start;
    uint64_t merged_end = end;

    while (index < stream->tx_ack_range_count)
    {
        const quic_backend_ack_range_t *const range = &stream->tx_ack_ranges[index];

        if (range->end < merged_start)
        {
            index++;
        }
        else if (range->start > merged_end)
        {
            break;
        }
        else
        {
            if (range->start < merged_start)
            {
                merged_start = range->start;
            }
            if (range->end > merged_end)
            {
                merged_end = range->end;
            }
            quic_backend_stream_remove_ack_range(stream, index);
        }
    }

    if (stream->tx_ack_range_count < QUIC_BACKEND_STREAM_ACK_RANGE_CAP)
    {
        size_t shift = stream->tx_ack_range_count;

        while (shift > index)
        {
            stream->tx_ack_ranges[shift] = stream->tx_ack_ranges[shift - 1U];
            shift--;
        }
        stream->tx_ack_ranges[index].start = merged_start;
        stream->tx_ack_ranges[index].end = merged_end;
        stream->tx_ack_range_count++;
    }
}

QUIC_BACKEND_INTERNAL int quic_backend_stream_record_acked_range(
    libp2p_quic_stream_t *stream,
    uint64_t offset,
    uint64_t datalen,
    uint8_t *out_sent_window_acked)
{
    int result = 0;

    if (out_sent_window_acked != NULL)
    {
        *out_sent_window_acked = 0U;
    }

    if ((stream == NULL) || (out_sent_window_acked == NULL))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else if (
        (datalen > (UINT64_MAX - offset)) || (stream->tx_len < stream->tx_sent_len) ||
        ((uint64_t)stream->tx_sent_len > (UINT64_MAX - stream->tx_base_offset)))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else if ((datalen == 0U) || (stream->tx_sent_len == 0U))
    {
        result = 0;
    }
    else
    {
        const uint64_t ack_end = offset + datalen;
        const uint64_t sent_end = stream->tx_base_offset + (uint64_t)stream->tx_sent_len;
        uint64_t start = offset;
        uint64_t end = ack_end;

        if (start < stream->tx_base_offset)
        {
            start = stream->tx_base_offset;
        }
        if (end > sent_end)
        {
            end = sent_end;
        }

        if (start < end)
        {
            if ((stream->conn != NULL) && (start > stream->tx_base_offset))
            {
                const uint64_t gap_bytes = start - stream->tx_base_offset;

                stream->conn->autopsy_ack_gap_reclaim_count++;
                stream->conn->autopsy_ack_gap_reclaim_bytes += gap_bytes;
                stream->conn->autopsy_last_ack_gap_stream_id = stream->stream_id;
                stream->conn->autopsy_last_ack_gap_offset = offset;
                stream->conn->autopsy_last_ack_gap_len = datalen;
                stream->conn->autopsy_last_ack_gap_base = stream->tx_base_offset;
                stream->conn->autopsy_last_ack_gap_sent_end = sent_end;
            }
            quic_backend_stream_insert_ack_range(stream, start, end);
            if ((stream->tx_ack_range_count != 0U) &&
                (stream->tx_ack_ranges[0].start <= stream->tx_base_offset) &&
                (stream->tx_ack_ranges[0].end >= sent_end))
            {
                *out_sent_window_acked = 1U;
            }
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL void quic_backend_stream_discard_tx(libp2p_quic_stream_t *stream)
{
    if (stream != NULL)
    {
        const size_t sent_len = stream->tx_sent_len;

        if (sent_len != 0U)
        {
            const uint64_t sent_offset = (uint64_t)sent_len;

            if (sent_offset <= (UINT64_MAX - stream->tx_base_offset))
            {
                stream->tx_base_offset += sent_offset;
            }
            else
            {
                stream->tx_base_offset = UINT64_MAX;
            }
        }

        quic_backend_debug_stream_state(
            stream,
            "stream_tx_discard",
            (uint64_t)stream->tx_len,
            (uint64_t)stream->tx_sent_len,
            0U);
        stream->tx_len = 0U;
        stream->tx_sent_len = 0U;
        quic_backend_stream_shrink_tx(stream);
        quic_backend_stream_clear_ack_ranges(stream);
        stream->local_fin_queued = 0U;
        stream->local_fin_sent = 0U;
        stream->write_blocked = 0U;
    }
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_reset(libp2p_quic_stream_t *stream, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (result == LIBP2P_QUIC_OK)
    {
        const int rv = ngtcp2_conn_shutdown_stream_write(
            stream->conn->ngconn,
            0U,
            stream->stream_id,
            app_error_code);
        if (rv != 0)
        {
            result = quic_backend_ngtcp2_err(rv);
        }
        else
        {
            quic_backend_stream_discard_tx(stream);
            stream->state = LIBP2P_QUIC_STREAM_RESET;
            stream->reset = 1U;
            result = quic_backend_event_push(
                stream->conn->endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                stream->conn,
                stream,
                app_error_code,
                0U);
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_stop_sending(libp2p_quic_stream_t *stream, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (result == LIBP2P_QUIC_OK)
    {
        const int rv = ngtcp2_conn_shutdown_stream_read(
            stream->conn->ngconn,
            0U,
            stream->stream_id,
            app_error_code);
        if (rv != 0)
        {
            result = quic_backend_ngtcp2_err(rv);
        }
        else
        {
            result = quic_backend_event_push(
                stream->conn->endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                stream->conn,
                stream,
                app_error_code,
                0U);
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_conn(libp2p_quic_stream_t *stream, libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_conn == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_conn = stream->conn;
    }

    return result;
}
