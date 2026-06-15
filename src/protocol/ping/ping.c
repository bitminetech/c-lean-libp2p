#include "protocol/ping/ping.h"

#include <string.h>

static libp2p_host_err_t ping_host_err(libp2p_ping_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_ERR_PROTOCOL;

    if (err == LIBP2P_PING_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (err == LIBP2P_PING_ERR_INVALID_ARG)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_PING_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_PING_ERR_LIMIT)
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    else if (err == LIBP2P_PING_ERR_STATE)
    {
        result = LIBP2P_HOST_ERR_STATE;
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

static libp2p_ping_err_t ping_host_to_err(libp2p_host_err_t err)
{
    libp2p_ping_err_t result = LIBP2P_PING_ERR_HOST;

    if (err == LIBP2P_HOST_OK)
    {
        result = LIBP2P_PING_OK;
    }
    else if (err == LIBP2P_HOST_ERR_INVALID_ARG)
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_HOST_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_PING_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_HOST_ERR_LIMIT)
    {
        result = LIBP2P_PING_ERR_LIMIT;
    }
    else if (err == LIBP2P_HOST_ERR_STATE)
    {
        result = LIBP2P_PING_ERR_STATE;
    }
    else
    {
        result = LIBP2P_PING_ERR_HOST;
    }

    return result;
}

static libp2p_ping_t *ping_from_user_data(void *user_data)
{
    libp2p_ping_t *ping = NULL;

    (void)memcpy((void *)&ping, (const void *)&user_data, sizeof user_data);

    return ping;
}

static libp2p_ping_err_t ping_now(const libp2p_ping_t *ping, libp2p_host_time_us_t *out_now)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (out_now == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (ping->config.time_fn == NULL)
    {
        *out_now = 0U;
    }
    else
    {
        result = ping->config.time_fn(out_now, ping->config.time_user_data);
    }

    return result;
}

static libp2p_ping_err_t ping_event_push(
    libp2p_ping_t *ping,
    size_t slot_index,
    const libp2p_ping_event_t *event)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (event == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (ping->event_len == LIBP2P_PING_EVENT_CAPACITY)
    {
        result = LIBP2P_PING_ERR_LIMIT;
    }
    else
    {
        const size_t pos = (ping->event_head + ping->event_len) % LIBP2P_PING_EVENT_CAPACITY;

        ping->events[pos].event = *event;
        ping->events[pos].slot_index = slot_index;
        ping->event_len++;
    }

    return result;
}

static libp2p_ping_stream_state_t *ping_slot_at(libp2p_ping_t *ping, size_t slot_index)
{
    libp2p_ping_stream_state_t *slot = NULL;

    if ((ping != NULL) && (slot_index < LIBP2P_PING_MAX_STREAMS))
    {
        slot = &ping->streams[slot_index];
    }

    return slot;
}

static libp2p_ping_stream_state_t *ping_alloc_slot(libp2p_ping_t *ping, size_t *out_index)
{
    libp2p_ping_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_PING_MAX_STREAMS;
    }
    if ((ping != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_PING_MAX_STREAMS; index++)
        {
            if (ping->streams[index].state == LIBP2P_PING_SLOT_FREE)
            {
                slot = &ping->streams[index];
                (void)memset(slot, 0, sizeof(*slot));
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static libp2p_ping_stream_state_t *ping_find_stream(
    libp2p_ping_t *ping,
    const libp2p_host_stream_t *stream,
    size_t *out_index)
{
    libp2p_ping_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_PING_MAX_STREAMS;
    }
    if ((ping != NULL) && (stream != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_PING_MAX_STREAMS; index++)
        {
            if ((ping->streams[index].state != LIBP2P_PING_SLOT_FREE) &&
                (ping->streams[index].stream == stream))
            {
                slot = &ping->streams[index];
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static libp2p_ping_stream_state_t *ping_find_opening(libp2p_ping_t *ping, size_t *out_index)
{
    libp2p_ping_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_PING_MAX_STREAMS;
    }
    if ((ping != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_PING_MAX_STREAMS; index++)
        {
            if (ping->streams[index].state == LIBP2P_PING_SLOT_OPENING)
            {
                slot = &ping->streams[index];
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static int ping_conn_has_outbound(const libp2p_ping_t *ping, const libp2p_host_conn_t *conn)
{
    int found = 0;

    if ((ping != NULL) && (conn != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_PING_MAX_STREAMS; index++)
        {
            const libp2p_ping_stream_state_t *slot = &ping->streams[index];

            if ((slot->state != LIBP2P_PING_SLOT_FREE) &&
                (slot->state != LIBP2P_PING_SLOT_EVENTED) &&
                (slot->direction == LIBP2P_HOST_STREAM_OUTBOUND) && (slot->conn == conn))
            {
                found = 1;
                break;
            }
        }
    }

    return found;
}

static libp2p_ping_err_t ping_prepare_payload(libp2p_ping_t *ping, libp2p_ping_stream_state_t *slot)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (slot == NULL) || (ping->config.random_fn == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        result = ping->config
                     .random_fn(slot->tx, LIBP2P_PING_PAYLOAD_BYTES, ping->config.random_user_data);
        if (result == LIBP2P_PING_OK)
        {
            slot->tx_pos = 0U;
            slot->rx_len = 0U;
            slot->timer_started = 0U;
        }
        else
        {
            result = LIBP2P_PING_ERR_RANDOM;
        }
    }

    return result;
}

static libp2p_host_err_t ping_fail_stream(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    size_t slot_index,
    libp2p_ping_err_t reason)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    libp2p_ping_event_t event;
    libp2p_ping_err_t err;

    (void)memset(&event, 0, sizeof(event));
    if (slot == NULL)
    {
        err = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        event.type = LIBP2P_PING_EVENT_ERROR;
        event.stream = slot->stream;
        event.direction = slot->direction;
        event.reason = reason;
        event.user_data = slot->user_data;
        err = ping_event_push(ping, slot_index, &event);
        slot->conn = NULL;
        slot->state = LIBP2P_PING_SLOT_EVENTED;
        if ((host != NULL) && (slot->stream != NULL))
        {
            (void)libp2p_host_stream_reset(host, slot->stream, 0U);
        }
    }

    return ping_host_err(err);
}

static libp2p_host_err_t ping_emit_closed(libp2p_ping_t *ping, size_t slot_index)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    libp2p_ping_event_t event;
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    (void)memset(&event, 0, sizeof(event));
    if (slot == NULL)
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        event.type = LIBP2P_PING_EVENT_CLOSED;
        event.stream = slot->stream;
        event.direction = slot->direction;
        event.user_data = slot->user_data;
        result = ping_event_push(ping, slot_index, &event);
        slot->conn = NULL;
        slot->state = LIBP2P_PING_SLOT_EVENTED;
    }

    return ping_host_err(result);
}

static libp2p_host_err_t ping_emit_pong(
    libp2p_ping_t *ping,
    size_t slot_index,
    libp2p_host_time_us_t now_us)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    libp2p_ping_event_t event;
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    (void)memset(&event, 0, sizeof(event));
    if (slot == NULL)
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        event.type = LIBP2P_PING_EVENT_PONG;
        event.stream = slot->stream;
        event.direction = slot->direction;
        (void)memcpy(event.payload, slot->rx, sizeof(event.payload));
        event.rtt_us = (now_us >= slot->started_us) ? (now_us - slot->started_us) : 0U;
        event.reason = LIBP2P_PING_OK;
        event.user_data = slot->user_data;
        result = ping_event_push(ping, slot_index, &event);
        if (result == LIBP2P_PING_OK)
        {
            slot->state = LIBP2P_PING_SLOT_INITIATOR_IDLE;
            slot->rx_len = 0U;
            slot->tx_pos = 0U;
            slot->timer_started = 0U;
        }
    }

    return ping_host_err(result);
}

static libp2p_host_err_t ping_write_stream(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    size_t slot_index)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    size_t accepted = 0U;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;
    libp2p_ping_err_t err = LIBP2P_PING_OK;

    if ((ping == NULL) || (host == NULL) || (slot == NULL))
    {
        host_err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (slot->tx_pos >= LIBP2P_PING_PAYLOAD_BYTES)
    {
        host_err = LIBP2P_HOST_OK;
    }
    else
    {
        host_err = libp2p_host_stream_write(
            host,
            slot->stream,
            &slot->tx[slot->tx_pos],
            LIBP2P_PING_PAYLOAD_BYTES - slot->tx_pos,
            0,
            &accepted);
        if (host_err == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            host_err = LIBP2P_HOST_OK;
        }
        else if (host_err == LIBP2P_HOST_OK)
        {
            if ((accepted != 0U) && (slot->timer_started == 0U) &&
                (slot->direction == LIBP2P_HOST_STREAM_OUTBOUND))
            {
                err = ping_now(ping, &slot->started_us);
                if (err == LIBP2P_PING_OK)
                {
                    slot->timer_started = 1U;
                }
            }
            if (err == LIBP2P_PING_OK)
            {
                slot->tx_pos += accepted;
                if (slot->tx_pos == LIBP2P_PING_PAYLOAD_BYTES)
                {
                    if (slot->direction == LIBP2P_HOST_STREAM_OUTBOUND)
                    {
                        slot->state = LIBP2P_PING_SLOT_INITIATOR_READING;
                        slot->rx_len = 0U;
                    }
                    else
                    {
                        slot->state = LIBP2P_PING_SLOT_RESPONDER_READING;
                        slot->tx_pos = 0U;
                        slot->rx_len = 0U;
                    }
                }
            }
            host_err = ping_host_err(err);
        }
        else
        {
            host_err = ping_fail_stream(ping, host, slot_index, ping_host_to_err(host_err));
        }
    }

    return host_err;
}

static libp2p_host_err_t ping_read_responder(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    size_t slot_index)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    size_t read_len = 0U;
    int fin = 0;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;

    if ((ping == NULL) || (host == NULL) || (slot == NULL))
    {
        host_err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        host_err = libp2p_host_stream_read(
            host,
            slot->stream,
            &slot->rx[slot->rx_len],
            LIBP2P_PING_PAYLOAD_BYTES - slot->rx_len,
            &read_len,
            &fin);
        if (host_err == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            host_err = LIBP2P_HOST_OK;
        }
        else if (host_err == LIBP2P_HOST_OK)
        {
            slot->rx_len += read_len;
            if (slot->rx_len == LIBP2P_PING_PAYLOAD_BYTES)
            {
                (void)memcpy(slot->tx, slot->rx, sizeof(slot->tx));
                slot->tx_pos = 0U;
                slot->state = LIBP2P_PING_SLOT_RESPONDER_WRITING;
                host_err = ping_write_stream(ping, host, slot_index);
            }
            else if (fin != 0)
            {
                if (slot->rx_len == 0U)
                {
                    (void)libp2p_host_stream_finish(host, slot->stream);
                    host_err = ping_emit_closed(ping, slot_index);
                }
                else
                {
                    host_err = ping_fail_stream(ping, host, slot_index, LIBP2P_PING_ERR_STATE);
                }
            }
            else
            {
                host_err = LIBP2P_HOST_OK;
            }
        }
        else
        {
            host_err = ping_fail_stream(ping, host, slot_index, ping_host_to_err(host_err));
        }
    }

    return host_err;
}

static libp2p_host_err_t ping_read_initiator(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    size_t slot_index)
{
    libp2p_ping_stream_state_t *slot = ping_slot_at(ping, slot_index);
    size_t read_len = 0U;
    int fin = 0;
    libp2p_host_time_us_t now_us = 0U;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;

    if ((ping == NULL) || (host == NULL) || (slot == NULL))
    {
        host_err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        host_err = libp2p_host_stream_read(
            host,
            slot->stream,
            &slot->rx[slot->rx_len],
            LIBP2P_PING_PAYLOAD_BYTES - slot->rx_len,
            &read_len,
            &fin);
        if (host_err == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            host_err = LIBP2P_HOST_OK;
        }
        else if (host_err == LIBP2P_HOST_OK)
        {
            slot->rx_len += read_len;
            if (slot->rx_len == LIBP2P_PING_PAYLOAD_BYTES)
            {
                if (memcmp(slot->rx, slot->tx, LIBP2P_PING_PAYLOAD_BYTES) == 0)
                {
                    libp2p_ping_err_t err;

                    err = ping_now(ping, &now_us);
                    if (err == LIBP2P_PING_OK)
                    {
                        host_err = ping_emit_pong(ping, slot_index, now_us);
                    }
                    else
                    {
                        host_err = ping_fail_stream(ping, host, slot_index, err);
                    }
                }
                else
                {
                    host_err = ping_fail_stream(ping, host, slot_index, LIBP2P_PING_ERR_MISMATCH);
                }
            }
            else if (fin != 0)
            {
                host_err = ping_fail_stream(ping, host, slot_index, LIBP2P_PING_ERR_STATE);
            }
            else
            {
                host_err = LIBP2P_HOST_OK;
            }
        }
        else
        {
            host_err = ping_fail_stream(ping, host, slot_index, ping_host_to_err(host_err));
        }
    }

    return host_err;
}

static libp2p_host_err_t ping_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    libp2p_ping_t *ping = ping_from_user_data(protocol_user_data);
    libp2p_ping_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_PING_MAX_STREAMS;
    libp2p_ping_err_t result = LIBP2P_PING_OK;
    libp2p_host_err_t host_result = LIBP2P_HOST_OK;

    if ((host == NULL) || (stream == NULL) || (ping == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (direction == LIBP2P_HOST_STREAM_OUTBOUND)
    {
        slot = ping_find_opening(ping, &slot_index);
        if (slot == NULL)
        {
            slot = ping_alloc_slot(ping, &slot_index);
            if (slot != NULL)
            {
                result = ping_prepare_payload(ping, slot);
            }
        }
    }
    else
    {
        slot = ping_alloc_slot(ping, &slot_index);
    }

    if ((result == LIBP2P_PING_OK) && (slot == NULL))
    {
        result = LIBP2P_PING_ERR_LIMIT;
    }
    if (result == LIBP2P_PING_OK)
    {
        slot->stream = stream;
        slot->direction = direction;
        slot->state = (direction == LIBP2P_HOST_STREAM_OUTBOUND)
                          ? LIBP2P_PING_SLOT_INITIATOR_WRITING
                          : LIBP2P_PING_SLOT_RESPONDER_READING;
        result = ping_host_to_err(libp2p_host_stream_set_user_data(stream, slot));
    }
    if ((result == LIBP2P_PING_OK) && (direction == LIBP2P_HOST_STREAM_OUTBOUND))
    {
        host_result = ping_write_stream(ping, host, slot_index);
    }
    if (host_result == LIBP2P_HOST_OK)
    {
        host_result = ping_host_err(result);
    }

    return host_result;
}

static libp2p_host_err_t ping_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data)
{
    libp2p_ping_t *ping = ping_from_user_data(protocol_user_data);
    libp2p_ping_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_PING_MAX_STREAMS;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    slot = ping_find_stream(ping, stream, &slot_index);
    if ((host == NULL) || (stream == NULL) || (ping == NULL) || (slot == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (libp2p_host_stream_set_user_data(stream, slot) != LIBP2P_HOST_OK)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_READABLE)
    {
        if (slot->state == LIBP2P_PING_SLOT_INITIATOR_READING)
        {
            result = ping_read_initiator(ping, host, slot_index);
        }
        else if (slot->state == LIBP2P_PING_SLOT_RESPONDER_READING)
        {
            result = ping_read_responder(ping, host, slot_index);
        }
        else
        {
            result = LIBP2P_HOST_OK;
        }
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE)
    {
        if ((slot->state == LIBP2P_PING_SLOT_INITIATOR_WRITING) ||
            (slot->state == LIBP2P_PING_SLOT_RESPONDER_WRITING))
        {
            result = ping_write_stream(ping, host, slot_index);
        }
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_RESET)
    {
        result = ping_fail_stream(ping, host, slot_index, LIBP2P_PING_ERR_HOST);
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED)
    {
        result = ping_emit_closed(ping, slot_index);
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_config_default(libp2p_ping_config_t *config)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if (config == NULL)
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_init(libp2p_ping_t *ping, const libp2p_ping_config_t *config)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (config == NULL) || (config->random_fn == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(ping, 0, sizeof(*ping));
        ping->config = *config;
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_protocol(libp2p_ping_t *ping, libp2p_host_protocol_t *out_protocol)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (out_protocol == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_protocol, 0, sizeof(*out_protocol));
        out_protocol->id = (const uint8_t *)LIBP2P_PING_PROTOCOL_ID;
        out_protocol->id_len = LIBP2P_PING_PROTOCOL_ID_LEN;
        out_protocol->on_open = ping_on_open;
        out_protocol->on_event = ping_on_event;
        out_protocol->user_data = ping;
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_initiate(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    libp2p_ping_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_PING_MAX_STREAMS;
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (host == NULL) || (conn == NULL) || (out_open == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (ping_conn_has_outbound(ping, conn) != 0)
    {
        result = LIBP2P_PING_ERR_LIMIT;
    }
    else
    {
        slot = ping_alloc_slot(ping, &slot_index);
        if (slot == NULL)
        {
            result = LIBP2P_PING_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_PING_OK)
    {
        result = ping_prepare_payload(ping, slot);
    }
    if (result == LIBP2P_PING_OK)
    {
        slot->state = LIBP2P_PING_SLOT_OPENING;
        slot->direction = LIBP2P_HOST_STREAM_OUTBOUND;
        slot->conn = conn;
        slot->user_data = user_data;
        const libp2p_host_err_t host_err = libp2p_host_open_stream(
            host,
            conn,
            (const uint8_t *)LIBP2P_PING_PROTOCOL_ID,
            LIBP2P_PING_PROTOCOL_ID_LEN,
            slot,
            out_open);
        result = ping_host_to_err(host_err);
        if (result != LIBP2P_PING_OK)
        {
            (void)memset(slot, 0, sizeof(*slot));
        }
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_send(libp2p_ping_t *ping, const libp2p_host_stream_t *stream)
{
    libp2p_ping_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_PING_MAX_STREAMS;
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    slot = ping_find_stream(ping, stream, &slot_index);
    (void)slot_index;
    if ((ping == NULL) || (stream == NULL) || (slot == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (
        (slot->direction != LIBP2P_HOST_STREAM_OUTBOUND) ||
        (slot->state != LIBP2P_PING_SLOT_INITIATOR_IDLE))
    {
        result = LIBP2P_PING_ERR_STATE;
    }
    else
    {
        result = ping_prepare_payload(ping, slot);
        if (result == LIBP2P_PING_OK)
        {
            slot->state = LIBP2P_PING_SLOT_INITIATOR_WRITING;
        }
    }

    return result;
}

libp2p_ping_err_t libp2p_ping_next_event(libp2p_ping_t *ping, libp2p_ping_event_t *out_event)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    if ((ping == NULL) || (out_event == NULL))
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else if (ping->event_len == 0U)
    {
        (void)memset(out_event, 0, sizeof(*out_event));
        out_event->type = LIBP2P_PING_EVENT_NONE;
        result = LIBP2P_PING_ERR_STATE;
    }
    else
    {
        const size_t slot_index = ping->events[ping->event_head].slot_index;

        *out_event = ping->events[ping->event_head].event;
        ping->event_head = (ping->event_head + 1U) % LIBP2P_PING_EVENT_CAPACITY;
        ping->event_len--;
        if ((slot_index < LIBP2P_PING_MAX_STREAMS) &&
            ((out_event->type == LIBP2P_PING_EVENT_CLOSED) ||
             (out_event->type == LIBP2P_PING_EVENT_ERROR)))
        {
            (void)memset(&ping->streams[slot_index], 0, sizeof(ping->streams[slot_index]));
        }
    }

    return result;
}
