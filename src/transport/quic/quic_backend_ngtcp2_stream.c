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

    stream = quic_backend_stream_from_memory(quic_backend_calloc(conn->endpoint, 1U, sizeof(*stream)));
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_id(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_id_t *out_id)
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_state(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_state_t *out_state)
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
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (read_len != NULL)
    {
        *read_len = 0U;
    }
    if (fin != NULL)
    {
        *fin = 0;
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    size_t required = 0U;
    uint8_t *new_data = NULL;
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
        size_t limit = 0U;

        if (stream->conn->endpoint->config.initial_stream_window_bytes >
            (SIZE_MAX / QUIC_BACKEND_STREAM_SEND_MULTIPLIER))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        else
        {
            limit = stream->conn->endpoint->config.initial_stream_window_bytes *
                    QUIC_BACKEND_STREAM_SEND_MULTIPLIER;
        }
        if ((result == LIBP2P_QUIC_OK) &&
            ((quic_backend_size_add_overflow(stream->tx_len, data_len, &required) != 0) ||
             (required > limit)))
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }

        if ((result == LIBP2P_QUIC_OK) && (required > stream->tx_cap))
        {
            if (stream->tx_cap != 0U)
            {
                result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            }
            else
            {
                /*
                 * ngtcp2 retains pointers to submitted stream bytes until ACK
                 * or stream close. Allocate the per-stream send window once so
                 * later writes cannot move data still eligible for retransmit.
                 */
                new_data = quic_backend_bytes_from_memory(
                    quic_backend_realloc(stream->conn->endpoint, stream->tx_data, limit));
                if (new_data == NULL)
                {
                    result = LIBP2P_QUIC_ERR_NO_MEMORY;
                }
                else
                {
                    stream->tx_data = new_data;
                    stream->tx_cap = limit;
                }
            }
        }
    }

    if (result == LIBP2P_QUIC_OK)
    {
        if (data_len != 0U)
        {
            (void)memcpy(&stream->tx_data[stream->tx_len], data, data_len);
            stream->tx_len += data_len;
            *accepted = data_len;
        }
        if (fin != 0)
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

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_finish(libp2p_quic_stream_t *stream)
{
    size_t accepted = 0U;
    libp2p_quic_err_t result = quic_backend_stream_write(stream, NULL, 0U, 1, &accepted);

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_reset(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_stop_sending(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_conn(
    libp2p_quic_stream_t *stream,
    libp2p_quic_conn_t **out_conn)
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
