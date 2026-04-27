#include <string.h>

#include "libp2p_host_internal.h"

libp2p_host_err_t host_protocol_find(
    const libp2p_host_t *host,
    const uint8_t *id,
    size_t id_len,
    const libp2p_host_protocol_t **out)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out != NULL)
    {
        *out = NULL;
    }
    if ((host == NULL) || (id == NULL) || (id_len == 0U) || (out == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        size_t index = 0U;

        result = LIBP2P_HOST_ERR_NOT_FOUND;
        for (index = 0U; index < host->protocol_count; index++)
        {
            const libp2p_host_protocol_t *protocol = &host->protocols[index];

            if ((protocol->id_len == id_len) && (memcmp(protocol->id, id, id_len) == 0))
            {
                *out = protocol;
                result = LIBP2P_HOST_OK;
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t host_protocol_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t out = LIBP2P_HOST_OK;

    if ((host == NULL) || (stream == NULL) || (stream->protocol == NULL) ||
        (stream->protocol->on_open == NULL))
    {
        out = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        out =
            stream->protocol->on_open(host, stream, stream->direction, stream->protocol->user_data);
        if (result != NULL)
        {
            result->protocol_events++;
            result->made_progress = 1U;
        }
    }

    return out;
}

static libp2p_host_err_t host_protocol_call_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t out = LIBP2P_HOST_OK;

    if ((stream->protocol != NULL) && (stream->protocol->on_event != NULL))
    {
        out = stream->protocol->on_event(host, stream, kind, stream->protocol->user_data);
        if (result != NULL)
        {
            result->protocol_events++;
            result->made_progress = 1U;
        }
    }

    if (out != LIBP2P_HOST_OK)
    {
        (void)host->config.transport->stream_reset(host->transport, stream->transport_stream, 0U);
        stream->state = HOST_STREAM_CLOSED;
    }

    return out;
}

libp2p_host_err_t host_protocol_event_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

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
        size_t checked = 0U;

        while ((checked < host->stream_capacity) && (err == LIBP2P_HOST_OK) &&
               (*out_progress == 0U))
        {
            const size_t index = host->protocol_cursor % host->stream_capacity;
            libp2p_host_stream_t *stream = &host->streams[index];

            host->protocol_cursor = (host->protocol_cursor + 1U) % host->stream_capacity;
            checked++;
            if (stream->state == HOST_STREAM_OPEN)
            {
                if (stream->pending_reset != 0U)
                {
                    stream->pending_reset = 0U;
                    *out_progress = 1U;
                    err = host_protocol_call_event(
                        host,
                        stream,
                        LIBP2P_HOST_PROTOCOL_EVENT_RESET,
                        result);
                    stream->state = HOST_STREAM_CLOSED;
                }
                else if (stream->pending_closed != 0U)
                {
                    stream->pending_closed = 0U;
                    *out_progress = 1U;
                    err = host_protocol_call_event(
                        host,
                        stream,
                        LIBP2P_HOST_PROTOCOL_EVENT_CLOSED,
                        result);
                    stream->state = HOST_STREAM_CLOSED;
                }
                else if (stream->pending_readable != 0U)
                {
                    stream->pending_readable = 0U;
                    *out_progress = 1U;
                    err = host_protocol_call_event(
                        host,
                        stream,
                        LIBP2P_HOST_PROTOCOL_EVENT_READABLE,
                        result);
                }
                else if (stream->pending_writable != 0U)
                {
                    stream->pending_writable = 0U;
                    *out_progress = 1U;
                    err = host_protocol_call_event(
                        host,
                        stream,
                        LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE,
                        result);
                }
                else
                {
                    err = LIBP2P_HOST_OK;
                }
            }
        }
    }

    return err;
}
