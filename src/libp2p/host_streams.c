#include <string.h>

#include "host_internal.h"

static int host_bytes_equal(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    int result = 0;

    if ((a_len == b_len) && (a != NULL) && (b != NULL) && (memcmp(a, b, a_len) == 0))
    {
        result = 1;
    }

    return result;
}

static libp2p_host_err_t host_ms_err(libp2p_multistream_select_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (err == LIBP2P_MULTISTREAM_SELECT_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (err == LIBP2P_MULTISTREAM_SELECT_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_MULTISTREAM_SELECT_ERR_NOT_AVAILABLE)
    {
        result = LIBP2P_HOST_ERR_NOT_FOUND;
    }
    else if (err == LIBP2P_MULTISTREAM_SELECT_ERR_WOULD_BLOCK)
    {
        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    else
    {
        result = LIBP2P_HOST_ERR_NEGOTIATION;
    }

    return result;
}

libp2p_host_conn_t *host_conn_find(libp2p_host_t *host, const void *transport_conn)
{
    libp2p_host_conn_t *result = NULL;

    if ((host != NULL) && (transport_conn != NULL))
    {
        size_t index = 0U;

        for (index = 0U; index < host->conn_capacity; index++)
        {
            if ((host->conns[index].active != 0U) &&
                (host->conns[index].transport_conn == transport_conn))
            {
                result = &host->conns[index];
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t host_conn_alloc(
    libp2p_host_t *host,
    void *transport_conn,
    libp2p_host_conn_t **out)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out != NULL)
    {
        *out = NULL;
    }
    if ((host == NULL) || (transport_conn == NULL) || (out == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        libp2p_host_conn_t *existing = host_conn_find(host, transport_conn);

        if (existing != NULL)
        {
            *out = existing;
        }
        else
        {
            size_t index = 0U;

            result = LIBP2P_HOST_ERR_LIMIT;
            for (index = 0U; index < host->conn_capacity; index++)
            {
                if (host->conns[index].active == 0U)
                {
                    (void)memset(&host->conns[index], 0, sizeof(host->conns[index]));
                    host->conns[index].host = host;
                    host->conns[index].transport_conn = transport_conn;
                    host->conns[index].active = 1U;
                    *out = &host->conns[index];
                    result = LIBP2P_HOST_OK;
                    break;
                }
            }
        }
    }

    return result;
}

libp2p_host_stream_t *host_stream_find(libp2p_host_t *host, const void *transport_stream)
{
    libp2p_host_stream_t *result = NULL;

    if ((host != NULL) && (transport_stream != NULL))
    {
        size_t index = 0U;

        for (index = 0U; index < host->stream_capacity; index++)
        {
            if ((host->streams[index].state != HOST_STREAM_FREE) &&
                (host->streams[index].transport_stream == transport_stream))
            {
                result = &host->streams[index];
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t host_stream_alloc(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *transport_stream,
    libp2p_host_stream_direction_t direction,
    const libp2p_host_protocol_t *protocol,
    libp2p_host_stream_open_t *open_attempt,
    libp2p_host_stream_t **out)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out != NULL)
    {
        *out = NULL;
    }
    if ((host == NULL) || (conn == NULL) || (transport_stream == NULL) || (out == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (conn->stream_count >= host->config.max_streams_per_conn)
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    else
    {
        size_t index = 0U;

        result = LIBP2P_HOST_ERR_LIMIT;
        for (index = 0U; index < host->stream_capacity; index++)
        {
            if (host->streams[index].state == HOST_STREAM_FREE)
            {
                libp2p_host_stream_t *stream = &host->streams[index];

                (void)memset(stream, 0, sizeof(*stream));
                stream->host = host;
                stream->conn = conn;
                stream->transport_stream = transport_stream;
                stream->protocol = protocol;
                stream->open_attempt = open_attempt;
                stream->direction = direction;
                stream->state = HOST_STREAM_NEGOTIATING;
                stream->neg_state = (direction == LIBP2P_HOST_STREAM_OUTBOUND)
                                        ? HOST_NEG_OUT_SEND_MS
                                        : HOST_NEG_IN_READ_MS;
                conn->stream_count++;
                *out = stream;
                result = LIBP2P_HOST_OK;
                break;
            }
        }
    }

    return result;
}

static libp2p_host_stream_open_t *host_open_alloc(libp2p_host_t *host)
{
    libp2p_host_stream_open_t *result = NULL;
    size_t index;

    if (host != NULL)
    {
        for (index = 0U; index < host->open_capacity; index++)
        {
            if (host->opens[index].state == HOST_OPEN_FREE)
            {
                result = &host->opens[index];
                (void)memset(result, 0, sizeof(*result));
                result->host = host;
                break;
            }
        }
    }

    return result;
}

static libp2p_host_err_t host_stream_prepare_message(
    libp2p_host_stream_t *stream,
    const uint8_t *payload,
    size_t payload_len)
{
    libp2p_multistream_select_err_t err;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((stream == NULL) || ((payload == NULL) && (payload_len != 0U)))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        err = libp2p_multistream_select_message_encode(
            payload,
            payload_len,
            stream->out_frame,
            sizeof(stream->out_frame),
            &stream->out_len);
        stream->out_pos = 0U;
        result = host_ms_err(err);
    }

    return result;
}

static libp2p_host_err_t host_stream_prepare_ls(
    const libp2p_host_t *host,
    libp2p_host_stream_t *stream)
{
    libp2p_multistream_select_err_t err;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    err = libp2p_multistream_select_ls_response_payload_encode(
        host->ms_protocols,
        host->protocol_count,
        stream->payload,
        sizeof(stream->payload),
        &stream->payload_len);
    if (err == LIBP2P_MULTISTREAM_SELECT_OK)
    {
        result = host_stream_prepare_message(stream, stream->payload, stream->payload_len);
    }
    else
    {
        result = host_ms_err(err);
    }

    return result;
}

static libp2p_host_err_t host_stream_send_prepared(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *made_progress)
{
    size_t accepted = 0U;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (stream->out_pos >= stream->out_len)
    {
        result = LIBP2P_HOST_OK;
    }
    else
    {
        result = host->config.transport->stream_write(
            host->transport,
            stream->transport_stream,
            &stream->out_frame[stream->out_pos],
            stream->out_len - stream->out_pos,
            0,
            &accepted);
        if (result == LIBP2P_HOST_OK)
        {
            stream->out_pos += accepted;
            if (accepted != 0U)
            {
                *made_progress = 1U;
            }
            if (stream->out_pos == stream->out_len)
            {
                stream->out_len = 0U;
                stream->out_pos = 0U;
            }
            else if (accepted == 0U)
            {
                result = LIBP2P_HOST_ERR_WOULD_BLOCK;
            }
            else
            {
                result = LIBP2P_HOST_OK;
            }
        }
    }

    return result;
}

static libp2p_host_err_t host_stream_read_message(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *made_progress,
    uint8_t *out_message_ready)
{
    size_t written = 0U;
    size_t consumed = 0U;
    libp2p_multistream_select_err_t decode_err = LIBP2P_MULTISTREAM_SELECT_ERR_TRUNCATED;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    *out_message_ready = 0U;
    if (stream->in_len != 0U)
    {
        decode_err = libp2p_multistream_select_message_decode(
            stream->in_frame,
            stream->in_len,
            stream->payload,
            sizeof(stream->payload),
            &written,
            &consumed);
    }
    if (decode_err == LIBP2P_MULTISTREAM_SELECT_OK)
    {
        stream->payload_len = written;
        if (consumed < stream->in_len)
        {
            (void)memmove(stream->in_frame, &stream->in_frame[consumed], stream->in_len - consumed);
        }
        stream->in_len -= consumed;
        *out_message_ready = 1U;
        *made_progress = 1U;
    }
    else if (decode_err == LIBP2P_MULTISTREAM_SELECT_ERR_TRUNCATED)
    {
        size_t read_len = 0U;
        int fin = 0;

        if (stream->in_len == sizeof(stream->in_frame))
        {
            result = LIBP2P_HOST_ERR_NEGOTIATION;
        }
        else
        {
            result = host->config.transport->stream_read(
                host->transport,
                stream->transport_stream,
                &stream->in_frame[stream->in_len],
                sizeof(stream->in_frame) - stream->in_len,
                &read_len,
                &fin);
            if (result == LIBP2P_HOST_OK)
            {
                stream->in_len += read_len;
                if (read_len != 0U)
                {
                    *made_progress = 1U;
                }
                if ((read_len == 0U) && (fin != 0))
                {
                    result = LIBP2P_HOST_ERR_NEGOTIATION;
                }
                else
                {
                    decode_err = libp2p_multistream_select_message_decode(
                        stream->in_frame,
                        stream->in_len,
                        stream->payload,
                        sizeof(stream->payload),
                        &written,
                        &consumed);
                    if (decode_err == LIBP2P_MULTISTREAM_SELECT_OK)
                    {
                        stream->payload_len = written;
                        if (consumed < stream->in_len)
                        {
                            (void)memmove(
                                stream->in_frame,
                                &stream->in_frame[consumed],
                                stream->in_len - consumed);
                        }
                        stream->in_len -= consumed;
                        *out_message_ready = 1U;
                        *made_progress = 1U;
                    }
                    else if (decode_err == LIBP2P_MULTISTREAM_SELECT_ERR_TRUNCATED)
                    {
                        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
                    }
                    else
                    {
                        result = host_ms_err(decode_err);
                    }
                }
            }
        }
    }
    else
    {
        result = host_ms_err(decode_err);
    }

    return result;
}

static libp2p_host_err_t host_stream_complete_negotiation(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    stream->neg_state = HOST_NEG_DONE;
    stream->state = HOST_STREAM_OPEN;
    err = host_protocol_open(host, stream, result);
    if (err != LIBP2P_HOST_OK)
    {
        err = host_stream_fail_negotiation(host, stream, LIBP2P_HOST_ERR_PROTOCOL, result);
    }
    else if (
        (stream->direction == LIBP2P_HOST_STREAM_OUTBOUND) &&
        (stream->outbound_open_event_queued == 0U))
    {
        libp2p_host_event_t event;

        (void)memset(&event, 0, sizeof(event));
        event.type = LIBP2P_HOST_EVENT_STREAM_OPENED;
        event.conn = stream->conn;
        event.stream = stream;
        event.stream_open = stream->open_attempt;
        if (stream->open_attempt != NULL)
        {
            event.user_data = stream->open_attempt->user_data;
            stream->open_attempt->state = HOST_OPEN_EVENTED;
        }
        stream->outbound_open_event_queued = 1U;
        err = host_event_push(host, &event, result);
    }
    else
    {
        err = LIBP2P_HOST_OK;
    }

    return err;
}

libp2p_host_err_t host_stream_fail_negotiation(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_err_t reason,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if ((host == NULL) || (stream == NULL))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        stream->neg_state = HOST_NEG_FAILED;
        stream->state = HOST_STREAM_CLOSED;
        (void)host->config.transport->stream_reset(host->transport, stream->transport_stream, 0U);
        if ((stream->direction == LIBP2P_HOST_STREAM_OUTBOUND) &&
            (stream->outbound_fail_event_queued == 0U))
        {
            libp2p_host_event_t event;

            (void)memset(&event, 0, sizeof(event));
            event.type = LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED;
            event.conn = stream->conn;
            event.stream_open = stream->open_attempt;
            event.reason = reason;
            if (stream->open_attempt != NULL)
            {
                event.user_data = stream->open_attempt->user_data;
                stream->open_attempt->state = HOST_OPEN_EVENTED;
            }
            stream->outbound_fail_event_queued = 1U;
            err = host_event_push(host, &event, result);
        }
    }

    return err;
}

static libp2p_host_err_t host_stream_outbound_step(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *made_progress,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if (stream->neg_state == HOST_NEG_OUT_SEND_MS)
    {
        if (stream->out_len == 0U)
        {
            err = host_stream_prepare_message(
                stream,
                (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
                LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
        }
        if (err == LIBP2P_HOST_OK)
        {
            err = host_stream_send_prepared(host, stream, made_progress);
            if ((err == LIBP2P_HOST_OK) && (stream->out_len == 0U))
            {
                stream->neg_state = HOST_NEG_OUT_SEND_PROTOCOL;
                *made_progress = 1U;
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_OUT_SEND_PROTOCOL)
    {
        if ((stream->protocol == NULL) || (stream->protocol->id == NULL))
        {
            err = LIBP2P_HOST_ERR_NEGOTIATION;
        }
        else
        {
            if (stream->out_len == 0U)
            {
                err = host_stream_prepare_message(
                    stream,
                    stream->protocol->id,
                    stream->protocol->id_len);
            }
            if (err == LIBP2P_HOST_OK)
            {
                err = host_stream_send_prepared(host, stream, made_progress);
                if ((err == LIBP2P_HOST_OK) && (stream->out_len == 0U))
                {
                    stream->neg_state = HOST_NEG_OUT_READ_MS;
                    *made_progress = 1U;
                }
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_OUT_READ_MS)
    {
        uint8_t ready = 0U;

        err = host_stream_read_message(host, stream, made_progress, &ready);
        if ((err == LIBP2P_HOST_OK) && (ready != 0U))
        {
            if (host_bytes_equal(
                    stream->payload,
                    stream->payload_len,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
                    LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) != 0)
            {
                stream->neg_state = HOST_NEG_OUT_READ_PROTOCOL;
            }
            else
            {
                err = LIBP2P_HOST_ERR_NEGOTIATION;
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_OUT_READ_PROTOCOL)
    {
        uint8_t ready = 0U;

        err = host_stream_read_message(host, stream, made_progress, &ready);
        if ((err == LIBP2P_HOST_OK) && (ready != 0U))
        {
            if ((stream->protocol != NULL) && (host_bytes_equal(
                                                   stream->payload,
                                                   stream->payload_len,
                                                   stream->protocol->id,
                                                   stream->protocol->id_len) != 0))
            {
                err = host_stream_complete_negotiation(host, stream, result);
            }
            else if (
                host_bytes_equal(
                    stream->payload,
                    stream->payload_len,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_NA,
                    LIBP2P_MULTISTREAM_SELECT_NA_LEN) != 0)
            {
                err =
                    host_stream_fail_negotiation(host, stream, LIBP2P_HOST_ERR_UNSUPPORTED, result);
            }
            else
            {
                err = LIBP2P_HOST_ERR_NEGOTIATION;
            }
        }
    }
    else
    {
        err = LIBP2P_HOST_ERR_STATE;
    }

    return err;
}

static libp2p_host_err_t host_stream_inbound_step(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *made_progress,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if (stream->neg_state == HOST_NEG_IN_READ_MS)
    {
        uint8_t ready = 0U;

        err = host_stream_read_message(host, stream, made_progress, &ready);
        if ((err == LIBP2P_HOST_OK) && (ready != 0U))
        {
            if (host_bytes_equal(
                    stream->payload,
                    stream->payload_len,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
                    LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) != 0)
            {
                err = host_stream_prepare_message(
                    stream,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
                    LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
                if (err == LIBP2P_HOST_OK)
                {
                    stream->neg_state = HOST_NEG_IN_SEND_PROTOCOL;
                }
            }
            else
            {
                err = LIBP2P_HOST_ERR_NEGOTIATION;
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_IN_SEND_PROTOCOL)
    {
        err = host_stream_send_prepared(host, stream, made_progress);
        if ((err == LIBP2P_HOST_OK) && (stream->out_len == 0U))
        {
            if (stream->protocol != NULL)
            {
                err = host_stream_complete_negotiation(host, stream, result);
            }
            else
            {
                stream->neg_state = HOST_NEG_IN_READ_PROTOCOL;
                *made_progress = 1U;
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_IN_READ_PROTOCOL)
    {
        const libp2p_host_protocol_t *protocol = NULL;
        uint8_t ready = 0U;

        err = host_stream_read_message(host, stream, made_progress, &ready);
        if ((err == LIBP2P_HOST_OK) && (ready != 0U))
        {
            if (host_bytes_equal(
                    stream->payload,
                    stream->payload_len,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_LS,
                    LIBP2P_MULTISTREAM_SELECT_LS_LEN) != 0)
            {
                err = host_stream_prepare_ls(host, stream);
                if (err == LIBP2P_HOST_OK)
                {
                    stream->neg_state = HOST_NEG_IN_SEND_LS;
                }
            }
            else if (
                host_protocol_find(host, stream->payload, stream->payload_len, &protocol) ==
                LIBP2P_HOST_OK)
            {
                stream->protocol = protocol;
                err = host_stream_prepare_message(stream, protocol->id, protocol->id_len);
                if (err == LIBP2P_HOST_OK)
                {
                    stream->neg_state = HOST_NEG_IN_SEND_PROTOCOL;
                }
            }
            else
            {
                err = host_stream_prepare_message(
                    stream,
                    (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_NA,
                    LIBP2P_MULTISTREAM_SELECT_NA_LEN);
                if (err == LIBP2P_HOST_OK)
                {
                    stream->neg_state = HOST_NEG_IN_SEND_NA;
                }
            }
        }
    }
    else if (stream->neg_state == HOST_NEG_IN_SEND_NA)
    {
        err = host_stream_send_prepared(host, stream, made_progress);
        if ((err == LIBP2P_HOST_OK) && (stream->out_len == 0U))
        {
            stream->neg_state = HOST_NEG_IN_READ_PROTOCOL;
            *made_progress = 1U;
        }
    }
    else if (stream->neg_state == HOST_NEG_IN_SEND_LS)
    {
        err = host_stream_send_prepared(host, stream, made_progress);
        if ((err == LIBP2P_HOST_OK) && (stream->out_len == 0U))
        {
            stream->neg_state = HOST_NEG_IN_READ_PROTOCOL;
            *made_progress = 1U;
        }
    }
    else
    {
        err = LIBP2P_HOST_ERR_STATE;
    }

    return err;
}

static libp2p_host_err_t host_stream_negotiation_step(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_drive_result_t *result)
{
    uint8_t made_progress = 0U;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if (result != NULL)
    {
        result->negotiation_steps++;
    }
    if (stream->direction == LIBP2P_HOST_STREAM_OUTBOUND)
    {
        err = host_stream_outbound_step(host, stream, &made_progress, result);
    }
    else
    {
        err = host_stream_inbound_step(host, stream, &made_progress, result);
    }

    if (err == LIBP2P_HOST_ERR_WOULD_BLOCK)
    {
        err = LIBP2P_HOST_OK;
    }
    else if (err != LIBP2P_HOST_OK)
    {
        err = host_stream_fail_negotiation(host, stream, err, result);
    }
    else
    {
        err = LIBP2P_HOST_OK;
    }
    if ((made_progress != 0U) && (result != NULL))
    {
        result->made_progress = 1U;
    }

    return err;
}

libp2p_host_err_t host_stream_negotiation_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;
    size_t checked;

    if (out_progress != NULL)
    {
        *out_progress = 0U;
    }
    if ((host == NULL) || (out_progress == NULL))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if ((result != NULL) && (result->negotiation_steps >= host->config.max_negotiation_steps))
    {
        err = LIBP2P_HOST_OK;
    }
    else
    {
        checked = 0U;
        while ((checked < host->stream_capacity) && (*out_progress == 0U) &&
               (err == LIBP2P_HOST_OK))
        {
            const size_t index = host->negotiation_cursor % host->stream_capacity;
            libp2p_host_stream_t *stream = &host->streams[index];

            host->negotiation_cursor = (host->negotiation_cursor + 1U) % host->stream_capacity;
            checked++;
            if (stream->state == HOST_STREAM_NEGOTIATING)
            {
                *out_progress = 1U;
                err = host_stream_negotiation_step(host, stream, result);
            }
        }
    }

    return err;
}

libp2p_host_err_t host_stream_open_retry_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;
    size_t index;

    if (out_progress != NULL)
    {
        *out_progress = 0U;
    }
    if ((host == NULL) || (out_progress == NULL))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        for (index = 0U; index < host->open_capacity; index++)
        {
            libp2p_host_stream_open_t *open = &host->opens[index];

            if (open->state == HOST_OPEN_WAIT_TRANSPORT)
            {
                void *transport_stream = NULL;

                err = host->config.transport
                          ->open_stream(host->transport, open->transport_conn, &transport_stream);
                if (err == LIBP2P_HOST_OK)
                {
                    libp2p_host_stream_t *stream = NULL;

                    open->transport_stream = transport_stream;
                    open->state = HOST_OPEN_NEGOTIATING;
                    err = host_stream_alloc(
                        host,
                        open->conn,
                        transport_stream,
                        LIBP2P_HOST_STREAM_OUTBOUND,
                        open->protocol,
                        open,
                        &stream);
                    if (result != NULL)
                    {
                        result->made_progress = 1U;
                    }
                    *out_progress = 1U;
                }
                else if (err == LIBP2P_HOST_ERR_WOULD_BLOCK)
                {
                    err = LIBP2P_HOST_OK;
                }
                else
                {
                    libp2p_host_event_t event;

                    (void)memset(&event, 0, sizeof(event));
                    event.type = LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED;
                    event.conn = open->conn;
                    event.stream_open = open;
                    event.user_data = open->user_data;
                    event.reason = err;
                    open->state = HOST_OPEN_EVENTED;
                    err = host_event_push(host, &event, result);
                    if (err == LIBP2P_HOST_OK)
                    {
                        *out_progress = 1U;
                    }
                }
                break;
            }
        }
    }

    return err;
}

libp2p_host_err_t libp2p_host_open_stream(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    const libp2p_host_protocol_t *protocol = NULL;
    libp2p_host_stream_open_t *open = NULL;
    void *transport_stream = NULL;
    libp2p_host_err_t result = host_validate_started(host);

    if (out_open != NULL)
    {
        *out_open = NULL;
    }
    if (result == LIBP2P_HOST_OK)
    {
        if ((conn == NULL) || (conn->host != host) || (protocol_id == NULL) ||
            (protocol_id_len == 0U) || (out_open == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if (host->state == HOST_STATE_CLOSING)
        {
            result = LIBP2P_HOST_ERR_CLOSED;
        }
        else
        {
            result = host_protocol_find(host, protocol_id, protocol_id_len, &protocol);
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        open = host_open_alloc(host);
        if (open == NULL)
        {
            result = LIBP2P_HOST_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        open->conn = conn;
        open->transport_conn = conn->transport_conn;
        open->protocol = protocol;
        open->user_data = user_data;
        result = host->config.transport
                     ->open_stream(host->transport, conn->transport_conn, &transport_stream);
        if (result == LIBP2P_HOST_OK)
        {
            libp2p_host_stream_t *stream = NULL;

            open->transport_stream = transport_stream;
            open->state = HOST_OPEN_NEGOTIATING;
            result = host_stream_alloc(
                host,
                conn,
                transport_stream,
                LIBP2P_HOST_STREAM_OUTBOUND,
                protocol,
                open,
                &stream);
        }
        else if (result == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            open->state = HOST_OPEN_WAIT_TRANSPORT;
            result = LIBP2P_HOST_OK;
        }
        else
        {
            open->state = HOST_OPEN_FREE;
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        *out_open = open;
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_set_user_data(libp2p_host_stream_t *stream, void *user_data)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (stream == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        stream->user_data = user_data;
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_direction(
    const libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t *out_direction)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((stream == NULL) || (out_direction == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        *out_direction = stream->direction;
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_user_data(
    const libp2p_host_stream_t *stream,
    void **out_user_data)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((stream == NULL) || (out_user_data == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        *out_user_data = stream->user_data;
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_read(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if ((stream == NULL) || (stream->host != host) || (stream->state != HOST_STREAM_OPEN))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result = host->config.transport->stream_read(
                host->transport,
                stream->transport_stream,
                out,
                out_len,
                read_len,
                fin);
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_write(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if ((stream == NULL) || (stream->host != host) || (stream->state != HOST_STREAM_OPEN))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result = host->config.transport->stream_write(
                host->transport,
                stream->transport_stream,
                data,
                data_len,
                fin,
                accepted);
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_finish(libp2p_host_t *host, libp2p_host_stream_t *stream)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if ((stream == NULL) || (stream->host != host))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result =
                host->config.transport->stream_finish(host->transport, stream->transport_stream);
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_reset(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if ((stream == NULL) || (stream->host != host))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result = host->config.transport
                         ->stream_reset(host->transport, stream->transport_stream, app_error_code);
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_stream_stop_sending(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint64_t app_error_code)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        if ((stream == NULL) || (stream->host != host))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result = host->config.transport->stream_stop_sending(
                host->transport,
                stream->transport_stream,
                app_error_code);
        }
    }

    return result;
}
