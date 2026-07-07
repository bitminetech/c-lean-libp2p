#include <string.h>

#include "libp2p_host_internal.h"

static libp2p_host_err_t host_transport_event_conn_established(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_conn_t *conn = NULL;
    libp2p_host_dial_t *dial = NULL;
    libp2p_host_event_t event;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    err = host_conn_alloc(host, transport_event->conn, &conn);
    if (err == LIBP2P_HOST_OK)
    {
        dial = host_dial_find(
            host,
            (transport_event->attempt != NULL) ? transport_event->attempt : transport_event->conn);

        (void)memset(&event, 0, sizeof(event));
        event.type = LIBP2P_HOST_EVENT_CONN_ESTABLISHED;
        event.conn = conn;
        event.dial = dial;
        event.user_data = (dial != NULL) ? dial->user_data : transport_event->user_data;
        if (dial != NULL)
        {
            (void)host_dial_mark_evented(dial);
        }
        err = host_event_push(host, &event, result);
    }

    return err;
}

static libp2p_host_err_t host_conn_fail_waiting_opens(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if ((host == NULL) || (conn == NULL))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U; (index < host->open_capacity) && (err == LIBP2P_HOST_OK);
             index++)
        {
            libp2p_host_stream_open_t *open = &host->opens[index];

            if ((open->state == HOST_OPEN_WAIT_TRANSPORT) && (open->conn == conn))
            {
                libp2p_host_event_t event;

                (void)memset(&event, 0, sizeof(event));
                event.type = LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED;
                event.conn = conn;
                event.stream_open = open;
                event.user_data = open->user_data;
                event.reason = LIBP2P_HOST_ERR_CLOSED;
                open->state = HOST_OPEN_EVENTED;
                err = host_event_push(host, &event, result);
                if (err != LIBP2P_HOST_OK)
                {
                    host_open_release(open);
                }
            }
        }
    }

    return err;
}

static libp2p_host_err_t host_conn_close_streams(
    libp2p_host_t *host,
    const libp2p_host_conn_t *conn,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if ((host == NULL) || (conn == NULL))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U; (index < host->stream_capacity) && (err == LIBP2P_HOST_OK);
             index++)
        {
            libp2p_host_stream_t *stream = &host->streams[index];

            if ((stream->state != HOST_STREAM_FREE) && (stream->conn == conn))
            {
                if (stream->state == HOST_STREAM_NEGOTIATING)
                {
                    err = host_stream_fail_negotiation(
                        host,
                        stream,
                        LIBP2P_HOST_ERR_CLOSED,
                        result);
                }
                else if (stream->state == HOST_STREAM_OPEN)
                {
                    stream->pending_closed = 1U;
                }
                else
                {
                    host_stream_release(stream);
                }
            }
        }
    }

    return err;
}

static libp2p_host_err_t host_transport_event_conn_closed(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_conn_t *conn = host_conn_find(host, transport_event->conn);
    libp2p_host_dial_t *dial = host_dial_find(
        host,
        (transport_event->attempt != NULL) ? transport_event->attempt : transport_event->conn);
    libp2p_host_event_t event;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    (void)memset(&event, 0, sizeof(event));
    if (conn != NULL)
    {
        if (conn->closed == 0U)
        {
            err = host_conn_fail_waiting_opens(host, conn, result);
            if (err == LIBP2P_HOST_OK)
            {
                err = host_conn_close_streams(host, conn, result);
            }
            if (err == LIBP2P_HOST_OK)
            {
                event.type = LIBP2P_HOST_EVENT_CONN_CLOSED;
                event.conn = conn;
                event.reason = transport_event->reason;
                event.app_error_code = transport_event->app_error_code;
                event.transport_error_code = transport_event->transport_error_code;
                conn->closed = 1U;
                conn->close_event_pending = 1U;
                err = host_event_push(host, &event, result);
            }
        }
    }
    else if (dial != NULL)
    {
        event.type = LIBP2P_HOST_EVENT_DIAL_FAILED;
        event.dial = dial;
        event.user_data = dial->user_data;
        event.reason = (transport_event->reason == LIBP2P_HOST_OK) ? LIBP2P_HOST_ERR_TRANSPORT
                                                                   : transport_event->reason;
        event.app_error_code = transport_event->app_error_code;
        event.transport_error_code = transport_event->transport_error_code;
        (void)host_dial_mark_evented(dial);
        err = host_event_push(host, &event, result);
    }
    else
    {
        err = LIBP2P_HOST_OK;
    }

    return err;
}

static libp2p_host_err_t host_transport_event_dial_failed(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_dial_t *dial = host_dial_find(host, transport_event->attempt);
    libp2p_host_event_t event;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if (dial != NULL)
    {
        (void)memset(&event, 0, sizeof(event));
        event.type = LIBP2P_HOST_EVENT_DIAL_FAILED;
        event.dial = dial;
        event.user_data = dial->user_data;
        event.reason = (transport_event->reason == LIBP2P_HOST_OK) ? LIBP2P_HOST_ERR_TRANSPORT
                                                                   : transport_event->reason;
        event.app_error_code = transport_event->app_error_code;
        event.transport_error_code = transport_event->transport_error_code;
        (void)host_dial_mark_evented(dial);
        err = host_event_push(host, &event, result);
    }

    return err;
}

static libp2p_host_err_t host_transport_event_stream_incoming(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event)
{
    libp2p_host_conn_t *conn = host_conn_find(host, transport_event->conn);
    libp2p_host_stream_t *stream = NULL;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if (conn == NULL)
    {
        err = LIBP2P_HOST_ERR_STATE;
    }
    else if (host_conn_validate_usable(conn, host) != LIBP2P_HOST_OK)
    {
        (void)host->config.transport->stream_reset(host->transport, transport_event->stream, 0U);
        err = LIBP2P_HOST_OK;
    }
    else
    {
        err = host_stream_alloc(
            host,
            conn,
            transport_event->stream,
            LIBP2P_HOST_STREAM_INBOUND,
            NULL,
            NULL,
            &stream);
        if (err != LIBP2P_HOST_OK)
        {
            (void)
                host->config.transport->stream_reset(host->transport, transport_event->stream, 0U);
            err = LIBP2P_HOST_OK;
        }
    }

    return err;
}

static void host_transport_event_stream_mark(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event)
{
    libp2p_host_stream_t *stream = host_stream_find(host, transport_event->stream);

    if (stream != NULL)
    {
        if (transport_event->type == LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE)
        {
            stream->pending_readable = 1U;
        }
        else if (transport_event->type == LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE)
        {
            stream->pending_writable = 1U;
        }
        else if (transport_event->type == LIBP2P_HOST_TRANSPORT_EVENT_STREAM_RESET)
        {
            if (stream->state == HOST_STREAM_NEGOTIATING)
            {
                host_stream_release(stream);
            }
            else
            {
                stream->pending_reset = 1U;
            }
        }
        else if (transport_event->type == LIBP2P_HOST_TRANSPORT_EVENT_STREAM_CLOSED)
        {
            if (stream->state == HOST_STREAM_NEGOTIATING)
            {
                host_stream_release(stream);
            }
            else
            {
                stream->pending_closed = 1U;
            }
        }
        else
        {
            (void)stream;
        }
    }
}

static libp2p_host_err_t host_transport_event_process(
    libp2p_host_t *host,
    const libp2p_host_transport_event_t *transport_event,
    libp2p_host_drive_result_t *result)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    switch (transport_event->type)
    {
    case LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED:
        err = host_transport_event_conn_established(host, transport_event, result);
        break;
    case LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED:
        err = host_transport_event_conn_closed(host, transport_event, result);
        break;
    case LIBP2P_HOST_TRANSPORT_EVENT_DIAL_FAILED:
        err = host_transport_event_dial_failed(host, transport_event, result);
        break;
    case LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING:
        err = host_transport_event_stream_incoming(host, transport_event);
        break;
    case LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE:
    case LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE:
    case LIBP2P_HOST_TRANSPORT_EVENT_STREAM_RESET:
    case LIBP2P_HOST_TRANSPORT_EVENT_STREAM_CLOSED:
        host_transport_event_stream_mark(host, transport_event);
        break;
    case LIBP2P_HOST_TRANSPORT_EVENT_NONE:
    default:
        break;
    }

    return err;
}

static libp2p_host_err_t host_transport_event_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    *out_progress = 0U;
    err = host->config.transport->next_event(host->transport, &transport_event);
    if (err == LIBP2P_HOST_OK)
    {
        *out_progress = 1U;
        if (result != NULL)
        {
            result->transport_events++;
            result->made_progress = 1U;
        }
        err = host_transport_event_process(host, &transport_event, result);
    }
    else if (err == LIBP2P_HOST_ERR_WOULD_BLOCK)
    {
        err = LIBP2P_HOST_OK;
    }
    else
    {
        err = LIBP2P_HOST_ERR_TRANSPORT;
    }

    return err;
}

static int host_has_active_work(const libp2p_host_t *host)
{
    int active = 0;
    size_t index = 0U;

    for (index = 0U; index < host->conn_capacity; index++)
    {
        if ((host->conns[index].active != 0U) && (host->conns[index].closed == 0U))
        {
            active = 1;
            break;
        }
    }
    for (index = 0U; (active == 0) && (index < host->stream_capacity); index++)
    {
        if ((host->streams[index].state != HOST_STREAM_FREE) &&
            (host->streams[index].state != HOST_STREAM_CLOSED))
        {
            active = 1;
        }
    }
    for (index = 0U; (active == 0) && (index < host->dial_capacity); index++)
    {
        if (host->dials[index].state == HOST_DIAL_PENDING)
        {
            active = 1;
        }
    }
    for (index = 0U; (active == 0) && (index < host->open_capacity); index++)
    {
        if ((host->opens[index].state == HOST_OPEN_WAIT_TRANSPORT) ||
            (host->opens[index].state == HOST_OPEN_NEGOTIATING))
        {
            active = 1;
        }
    }

    return active;
}

static libp2p_host_err_t host_close_maybe_complete(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress)
{
    libp2p_host_err_t err = LIBP2P_HOST_OK;

    if ((host->state == HOST_STATE_CLOSING) && (host->host_closed_event_queued == 0U) &&
        (host_has_active_work(host) == 0))
    {
        libp2p_host_event_t event;

        (void)memset(&event, 0, sizeof(event));
        event.type = LIBP2P_HOST_EVENT_HOST_CLOSED;
        event.reason = LIBP2P_HOST_OK;
        err = host_event_push(host, &event, result);
        if (err == LIBP2P_HOST_OK)
        {
            host->host_closed_event_queued = 1U;
            host->state = HOST_STATE_CLOSED;
            *out_progress = 1U;
        }
    }

    return err;
}

libp2p_host_err_t libp2p_host_drive(
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us,
    libp2p_host_ready_t ready,
    libp2p_host_drive_result_t *out_result)
{
    libp2p_host_drive_result_t local_result;
    libp2p_host_err_t err = host_validate_started(host);

    if (out_result != NULL)
    {
        (void)memset(out_result, 0, sizeof(*out_result));
    }
    (void)memset(&local_result, 0, sizeof(local_result));

    if ((err == LIBP2P_HOST_OK) && ((ready & ~(LIBP2P_HOST_READY_ALL)) != 0U))
    {
        err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (err == LIBP2P_HOST_OK)
    {
        err = host->config.transport->drive(host->transport, now_us, ready);
    }
    if (err == LIBP2P_HOST_OK)
    {
        uint8_t loop_progress = 1U;
        size_t guard = 0U;
        const size_t guard_limit = host->event_capacity + host->stream_capacity +
                                   host->open_capacity + host->config.max_negotiation_steps + 8U;

        while ((loop_progress != 0U) && (err == LIBP2P_HOST_OK) && (guard < guard_limit))
        {
            uint8_t transport_progress = 0U;
            uint8_t open_progress = 0U;
            uint8_t negotiation_progress = 0U;
            uint8_t protocol_progress = 0U;
            uint8_t close_progress = 0U;

            loop_progress = 0U;
            guard++;

            err = host_transport_event_one(host, &local_result, &transport_progress);
            if (err == LIBP2P_HOST_OK)
            {
                err = host_stream_open_retry_one(host, &local_result, &open_progress);
            }
            if ((err == LIBP2P_HOST_OK) &&
                (local_result.negotiation_steps < host->config.max_negotiation_steps))
            {
                err = host_stream_negotiation_one(host, &local_result, &negotiation_progress);
            }
            if (err == LIBP2P_HOST_OK)
            {
                err = host_protocol_event_one(host, &local_result, &protocol_progress);
            }
            if (err == LIBP2P_HOST_OK)
            {
                err = host_conn_recycle_quiet(host);
            }
            if (err == LIBP2P_HOST_OK)
            {
                err = host_close_maybe_complete(host, &local_result, &close_progress);
            }
            if ((transport_progress != 0U) || (open_progress != 0U) ||
                (negotiation_progress != 0U) || (protocol_progress != 0U) || (close_progress != 0U))
            {
                loop_progress = 1U;
            }
        }
    }

    if (out_result != NULL)
    {
        *out_result = local_result;
    }

    return err;
}

libp2p_host_err_t libp2p_host_conn_peer_id(
    const libp2p_host_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    result = host_conn_validate_usable(conn, NULL);
    if (result == LIBP2P_HOST_OK)
    {
        result =
            conn->host->config.transport->conn_peer_id(conn->transport_conn, out, out_len, written);
    }

    return result;
}

libp2p_host_err_t libp2p_host_conn_for_peer_id(
    libp2p_host_t *host,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_host_conn_t **out_conn)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if (result == LIBP2P_HOST_OK)
    {
        if ((peer_id == NULL) || (peer_id_len == 0U) ||
            (peer_id_len > LIBP2P_PEER_ID_MAX_BYTES) || (out_conn == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        uint8_t candidate[LIBP2P_PEER_ID_MAX_BYTES];
        size_t written = 0U;

        result = LIBP2P_HOST_ERR_NOT_FOUND;
        for (size_t index = 0U; index < host->conn_capacity; index++)
        {
            libp2p_host_conn_t *conn = &host->conns[index];

            if (host_conn_validate_usable(conn, host) != LIBP2P_HOST_OK)
            {
                continue;
            }
            written = 0U;
            if (host->config.transport->conn_peer_id(
                    conn->transport_conn,
                    candidate,
                    sizeof(candidate),
                    &written) != LIBP2P_HOST_OK)
            {
                continue;
            }
            if ((written == peer_id_len) && (memcmp(candidate, peer_id, peer_id_len) == 0))
            {
                *out_conn = conn;
                result = LIBP2P_HOST_OK;
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_conn_remote_multiaddr(
    const libp2p_host_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    result = host_conn_validate_usable(conn, NULL);
    if (result == LIBP2P_HOST_OK)
    {
        result = conn->host->config.transport
                     ->conn_remote_multiaddr(conn->transport_conn, out, out_len, written);
    }

    return result;
}

libp2p_host_err_t libp2p_host_conn_peer_identity(
    const libp2p_host_conn_t *conn,
    libp2p_host_peer_identity_t *out)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    result = host_conn_validate_usable(conn, NULL);
    if (result == LIBP2P_HOST_OK)
    {
        result = conn->host->config.transport->conn_peer_identity(conn->transport_conn, out);
    }

    return result;
}

libp2p_host_err_t libp2p_host_conn_close(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    uint64_t app_error_code)
{
    libp2p_host_err_t result = host_validate_started(host);

    if (result == LIBP2P_HOST_OK)
    {
        result = host_conn_validate_usable(conn, host);
        if (result == LIBP2P_HOST_OK)
        {
            result = host->config.transport
                         ->conn_close(host->transport, conn->transport_conn, app_error_code);
        }
    }

    return result;
}
