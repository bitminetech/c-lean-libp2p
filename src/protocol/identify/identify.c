#include "protocol/identify/identify.h"

#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define IDENTIFY_FIELD_PUBLIC_KEY       1U
#define IDENTIFY_FIELD_LISTEN_ADDRS     2U
#define IDENTIFY_FIELD_PROTOCOLS        3U
#define IDENTIFY_FIELD_OBSERVED_ADDR    4U
#define IDENTIFY_FIELD_PROTOCOL_VERSION 5U
#define IDENTIFY_FIELD_AGENT_VERSION    6U
#define IDENTIFY_WIRE_LEN               2U
#define IDENTIFY_MULTIADDR_BYTES        256U

static int identify_size_add(size_t a, size_t b, size_t *out)
{
    int overflow = 0;

    if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        overflow = 1;
    }
    else
    {
        *out = a + b;
    }

    return overflow;
}

static int identify_bytes_present(const libp2p_identify_bytes_t *bytes)
{
    int present = 0;

    if ((bytes != NULL) && (bytes->data != NULL) && (bytes->len != 0U))
    {
        present = 1;
    }

    return present;
}

static libp2p_identify_err_t identify_uvarint_err(libp2p_uvarint_err_t err)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_ERR_MALFORMED;

    if (err == LIBP2P_UVARINT_OK)
    {
        result = LIBP2P_IDENTIFY_OK;
    }
    else if (err == LIBP2P_UVARINT_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_UVARINT_ERR_TRUNCATED)
    {
        result = LIBP2P_IDENTIFY_ERR_TRUNCATED;
    }
    else
    {
        result = LIBP2P_IDENTIFY_ERR_MALFORMED;
    }

    return result;
}

static libp2p_host_err_t identify_host_err(libp2p_identify_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_ERR_PROTOCOL;

    if (err == LIBP2P_IDENTIFY_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (err == LIBP2P_IDENTIFY_ERR_INVALID_ARG)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_IDENTIFY_ERR_LIMIT)
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    else if (err == LIBP2P_IDENTIFY_ERR_STATE)
    {
        result = LIBP2P_HOST_ERR_STATE;
    }
    else if (err == LIBP2P_IDENTIFY_ERR_HOST)
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

static libp2p_identify_t *identify_from_user_data(void *user_data)
{
    libp2p_identify_t *identify = NULL;

    (void)memcpy((void *)&identify, (const void *)&user_data, sizeof user_data);

    return identify;
}

static libp2p_identify_err_t identify_host_to_err(libp2p_host_err_t err)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_ERR_HOST;

    if (err == LIBP2P_HOST_OK)
    {
        result = LIBP2P_IDENTIFY_OK;
    }
    else if (err == LIBP2P_HOST_ERR_INVALID_ARG)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_HOST_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_HOST_ERR_LIMIT)
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    else if (err == LIBP2P_HOST_ERR_STATE)
    {
        result = LIBP2P_IDENTIFY_ERR_STATE;
    }
    else
    {
        result = LIBP2P_IDENTIFY_ERR_HOST;
    }

    return result;
}

static libp2p_identify_err_t identify_field_size(uint32_t field, size_t data_len, size_t *total)
{
    const uint64_t key = (((uint64_t)field) << 3U) | IDENTIFY_WIRE_LEN;
    size_t next = 0U;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if (total == NULL)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (
        identify_size_add(
            *total,
            (size_t)libp2p_uvarint_size(key) + (size_t)libp2p_uvarint_size((uint64_t)data_len),
            &next) != 0)
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    else if (identify_size_add(next, data_len, total) != 0)
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    else
    {
        result = LIBP2P_IDENTIFY_OK;
    }

    return result;
}

static libp2p_identify_err_t identify_message_validate_local(
    const libp2p_identify_message_t *message)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if (message == NULL)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (
        (identify_bytes_present(&message->protocol_version) == 0) ||
        (identify_bytes_present(&message->agent_version) == 0) ||
        (identify_bytes_present(&message->public_key) == 0) ||
        (message->listen_addr_count > LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS) ||
        (message->protocol_count > LIBP2P_IDENTIFY_MAX_PROTOCOLS))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        size_t index = 0U;

        for (index = 0U; (index < message->listen_addr_count) && (result == LIBP2P_IDENTIFY_OK);
             index++)
        {
            if (identify_bytes_present(&message->listen_addrs[index]) == 0)
            {
                result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
            }
        }
        for (index = 0U; (index < message->protocol_count) && (result == LIBP2P_IDENTIFY_OK);
             index++)
        {
            if (identify_bytes_present(&message->protocols[index]) == 0)
            {
                result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
            }
        }
    }

    return result;
}

static libp2p_identify_err_t identify_write_uvarint(
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    size_t written = 0U;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((out == NULL) || (pos == NULL) || (*pos > out_len))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        result = identify_uvarint_err(
            libp2p_uvarint_encode(value, &out[*pos], out_len - *pos, &written));
        if (result == LIBP2P_IDENTIFY_OK)
        {
            *pos += written;
        }
    }

    return result;
}

static libp2p_identify_err_t identify_write_field(
    uint32_t field,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    const uint64_t key = (((uint64_t)field) << 3U) | IDENTIFY_WIRE_LEN;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((data == NULL) || (out == NULL) || (pos == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        result = identify_write_uvarint(key, out, out_len, pos);
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = identify_write_uvarint((uint64_t)data_len, out, out_len, pos);
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        if (data_len > (out_len - *pos))
        {
            result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
        }
        else
        {
            (void)memcpy(&out[*pos], data, data_len);
            *pos += data_len;
        }
    }

    return result;
}

static libp2p_identify_err_t identify_frame_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_identify_message_t *out)
{
    uint64_t body_len_u64 = 0U;
    size_t prefix_len = 0U;
    size_t body_len = 0U;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((in == NULL) || (out == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = identify_uvarint_err(
            libp2p_uvarint_decode(in, in_len, &body_len_u64, &prefix_len));
    }
    if ((result == LIBP2P_IDENTIFY_OK) &&
        (body_len_u64 > (uint64_t)LIBP2P_IDENTIFY_MAX_MESSAGE_BYTES))
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        body_len = (size_t)body_len_u64;
        if ((body_len == 0U) || (body_len > (in_len - prefix_len)))
        {
            result = LIBP2P_IDENTIFY_ERR_TRUNCATED;
        }
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = libp2p_identify_message_decode(&in[prefix_len], body_len, out);
    }

    return result;
}

static libp2p_identify_err_t identify_event_push(
    libp2p_identify_t *identify,
    size_t slot_index,
    const libp2p_identify_event_t *event)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (event == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (identify->event_len == LIBP2P_IDENTIFY_EVENT_CAPACITY)
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    else
    {
        const size_t pos =
            (identify->event_head + identify->event_len) % LIBP2P_IDENTIFY_EVENT_CAPACITY;

        identify->events[pos].event = *event;
        identify->events[pos].slot_index = slot_index;
        identify->event_len++;
    }

    return result;
}

static libp2p_identify_stream_state_t *identify_slot_at(
    libp2p_identify_t *identify,
    size_t slot_index)
{
    libp2p_identify_stream_state_t *slot = NULL;

    if ((identify != NULL) && (slot_index < LIBP2P_IDENTIFY_MAX_STREAMS))
    {
        slot = &identify->streams[slot_index];
    }

    return slot;
}

static libp2p_identify_stream_state_t *identify_alloc_slot(
    libp2p_identify_t *identify,
    size_t *out_index)
{
    libp2p_identify_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    }
    if ((identify != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_IDENTIFY_MAX_STREAMS; index++)
        {
            if (identify->streams[index].state == LIBP2P_IDENTIFY_SLOT_FREE)
            {
                slot = &identify->streams[index];
                (void)memset(slot, 0, sizeof(*slot));
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static libp2p_identify_stream_state_t *identify_find_stream(
    libp2p_identify_t *identify,
    const libp2p_host_stream_t *stream,
    size_t *out_index)
{
    libp2p_identify_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    }
    if ((identify != NULL) && (stream != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_IDENTIFY_MAX_STREAMS; index++)
        {
            if ((identify->streams[index].state != LIBP2P_IDENTIFY_SLOT_FREE) &&
                (identify->streams[index].stream == stream))
            {
                slot = &identify->streams[index];
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static libp2p_identify_stream_state_t *identify_find_opening(
    libp2p_identify_t *identify,
    libp2p_identify_slot_state_t state,
    size_t *out_index)
{
    libp2p_identify_stream_state_t *slot = NULL;

    if (out_index != NULL)
    {
        *out_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    }
    if ((identify != NULL) && (out_index != NULL))
    {
        size_t index;

        for (index = 0U; index < LIBP2P_IDENTIFY_MAX_STREAMS; index++)
        {
            if (identify->streams[index].state == state)
            {
                slot = &identify->streams[index];
                *out_index = index;
                break;
            }
        }
    }

    return slot;
}

static int identify_slot_is_reading(const libp2p_identify_t *identify, size_t slot_index)
{
    int is_reading = 0;

    if ((identify != NULL) && (slot_index < LIBP2P_IDENTIFY_MAX_STREAMS) &&
        (identify->streams[slot_index].state == LIBP2P_IDENTIFY_SLOT_READING))
    {
        is_reading = 1;
    }

    return is_reading;
}

static libp2p_identify_err_t identify_build_tx_message(
    libp2p_identify_t *identify,
    const libp2p_host_t *host,
    const libp2p_identify_stream_state_t *slot,
    libp2p_identify_message_t *message,
    uint8_t *listen_addr,
    size_t listen_addr_len,
    uint8_t *observed_addr,
    size_t observed_addr_len)
{
    const libp2p_host_protocol_t *protocols = NULL;
    libp2p_host_conn_t *conn = NULL;
    size_t protocol_count = 0U;
    size_t written = 0U;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (host == NULL) || (slot == NULL) || (message == NULL) ||
        (listen_addr == NULL) || (observed_addr == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        *message = identify->config.local_message;
        (void)memset(message->listen_addrs, 0, sizeof(message->listen_addrs));
        (void)memset(message->protocols, 0, sizeof(message->protocols));
        (void)memset(&message->observed_addr, 0, sizeof(message->observed_addr));
        message->listen_addr_count = 0U;
        message->protocol_count = 0U;
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = identify_host_to_err(
            libp2p_host_listen_multiaddr(host, listen_addr, listen_addr_len, &written));
        if (result == LIBP2P_IDENTIFY_OK)
        {
            message->listen_addrs[0].data = listen_addr;
            message->listen_addrs[0].len = written;
            message->listen_addr_count = 1U;
            result = identify_host_to_err(
                libp2p_host_registered_protocols(host, &protocols, &protocol_count));
        }
    }
    if ((result == LIBP2P_IDENTIFY_OK) && (protocol_count > LIBP2P_IDENTIFY_MAX_PROTOCOLS))
    {
        result = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    if ((result == LIBP2P_IDENTIFY_OK) && (protocol_count != 0U) && (protocols == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        size_t index = 0U;

        for (index = 0U; index < protocol_count; index++)
        {
            message->protocols[index].data = protocols[index].id;
            message->protocols[index].len = protocols[index].id_len;
        }
        message->protocol_count = protocol_count;
        result = identify_host_to_err(libp2p_host_stream_conn(slot->stream, &conn));
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = identify_host_to_err(
            libp2p_host_conn_remote_multiaddr(conn, observed_addr, observed_addr_len, &written));
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        message->observed_addr.data = observed_addr;
        message->observed_addr.len = written;
    }
    if ((result == LIBP2P_IDENTIFY_OK) &&
        ((message->listen_addr_count == 0U) || (message->protocol_count == 0U)))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        result = identify_message_validate_local(message);
    }

    return result;
}

static libp2p_identify_err_t identify_prepare_tx(
    libp2p_identify_t *identify,
    const libp2p_host_t *host,
    libp2p_identify_stream_state_t *slot)
{
    libp2p_identify_message_t message;
    uint8_t listen_addr[IDENTIFY_MULTIADDR_BYTES];
    uint8_t observed_addr[IDENTIFY_MULTIADDR_BYTES];
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    (void)memset(&message, 0, sizeof(message));
    (void)memset(listen_addr, 0, sizeof(listen_addr));
    (void)memset(observed_addr, 0, sizeof(observed_addr));
    result = identify_build_tx_message(
        identify,
        host,
        slot,
        &message,
        listen_addr,
        sizeof(listen_addr),
        observed_addr,
        sizeof(observed_addr));
    if (result == LIBP2P_IDENTIFY_OK)
    {
        size_t prefix_len = 0U;
        size_t body_len = 0U;

        result = libp2p_identify_message_size(&message, &body_len);
        if ((result == LIBP2P_IDENTIFY_OK) &&
            (libp2p_uvarint_encode(
                 (uint64_t)body_len,
                 slot->tx,
                 sizeof(slot->tx),
                 &prefix_len) != LIBP2P_UVARINT_OK))
        {
            result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
        }
        if ((result == LIBP2P_IDENTIFY_OK) && ((prefix_len > sizeof(slot->tx)) ||
                                               (body_len > (sizeof(slot->tx) - prefix_len))))
        {
            result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            result = libp2p_identify_message_encode(
                &message,
                &slot->tx[prefix_len],
                sizeof(slot->tx) - prefix_len,
                &slot->tx_len);
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            slot->tx_len += prefix_len;
        }
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        slot->tx_pos = 0U;
    }

    return result;
}

static libp2p_host_err_t identify_fail_stream(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    size_t slot_index,
    libp2p_identify_err_t reason)
{
    libp2p_identify_stream_state_t *slot = identify_slot_at(identify, slot_index);
    libp2p_identify_event_t event;
    libp2p_identify_err_t err;

    (void)memset(&event, 0, sizeof(event));
    if (slot == NULL)
    {
        err = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        event.type = LIBP2P_IDENTIFY_EVENT_ERROR;
        event.stream = slot->stream;
        event.direction = slot->direction;
        event.reason = reason;
        event.user_data = slot->user_data;
        err = identify_event_push(identify, slot_index, &event);
        slot->state = LIBP2P_IDENTIFY_SLOT_EVENTED;
        if ((host != NULL) && (slot->stream != NULL))
        {
            (void)libp2p_host_stream_reset(host, slot->stream, 0U);
        }
    }

    return identify_host_err(err);
}

static libp2p_host_err_t identify_emit_simple(
    libp2p_identify_t *identify,
    size_t slot_index,
    libp2p_identify_event_type_t type)
{
    libp2p_identify_stream_state_t *slot = identify_slot_at(identify, slot_index);
    libp2p_identify_event_t event;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    (void)memset(&event, 0, sizeof(event));
    if (slot == NULL)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        event.type = type;
        event.stream = slot->stream;
        event.direction = slot->direction;
        event.reason = LIBP2P_IDENTIFY_OK;
        event.user_data = slot->user_data;
        result = identify_event_push(identify, slot_index, &event);
        slot->state = LIBP2P_IDENTIFY_SLOT_EVENTED;
    }

    return identify_host_err(result);
}

static libp2p_host_err_t identify_read_stream(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    size_t slot_index)
{
    libp2p_identify_stream_state_t *slot = identify_slot_at(identify, slot_index);
    size_t read_len = 0U;
    int fin = 0;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;

    if ((identify == NULL) || (host == NULL) || (slot == NULL))
    {
        host_err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (slot->rx_len == sizeof(slot->rx))
    {
        host_err = identify_fail_stream(identify, host, slot_index, LIBP2P_IDENTIFY_ERR_LIMIT);
    }
    else
    {
        host_err = libp2p_host_stream_read(
            host,
            slot->stream,
            &slot->rx[slot->rx_len],
            sizeof(slot->rx) - slot->rx_len,
            &read_len,
            &fin);
        if (host_err == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            host_err = LIBP2P_HOST_OK;
        }
        else if (host_err == LIBP2P_HOST_OK)
        {
            slot->rx_len += read_len;
            if (read_len != 0U)
            {
                libp2p_identify_event_t event;
                libp2p_identify_err_t err;

                (void)memset(&event, 0, sizeof(event));
                err = identify_frame_decode(slot->rx, slot->rx_len, &slot->decoded);
                if (err == LIBP2P_IDENTIFY_OK)
                {
                    event.type = LIBP2P_IDENTIFY_EVENT_RECEIVED;
                    event.stream = slot->stream;
                    event.direction = slot->direction;
                    event.message = slot->decoded;
                    event.reason = LIBP2P_IDENTIFY_OK;
                    event.user_data = slot->user_data;
                    err = identify_event_push(identify, slot_index, &event);
                    slot->state = LIBP2P_IDENTIFY_SLOT_EVENTED;
                    (void)libp2p_host_stream_finish(host, slot->stream);
                    host_err = identify_host_err(err);
                }
                else if (err == LIBP2P_IDENTIFY_ERR_TRUNCATED)
                {
                    host_err = LIBP2P_HOST_OK;
                }
                else
                {
                    host_err = identify_fail_stream(identify, host, slot_index, err);
                }
            }
            else if (fin != 0)
            {
                libp2p_identify_event_t event;
                libp2p_identify_err_t err;

                (void)memset(&event, 0, sizeof(event));
                err = identify_frame_decode(slot->rx, slot->rx_len, &slot->decoded);
                if (err == LIBP2P_IDENTIFY_OK)
                {
                    event.type = LIBP2P_IDENTIFY_EVENT_RECEIVED;
                    event.stream = slot->stream;
                    event.direction = slot->direction;
                    event.message = slot->decoded;
                    event.reason = LIBP2P_IDENTIFY_OK;
                    event.user_data = slot->user_data;
                    err = identify_event_push(identify, slot_index, &event);
                    slot->state = LIBP2P_IDENTIFY_SLOT_EVENTED;
                    (void)libp2p_host_stream_finish(host, slot->stream);
                    host_err = identify_host_err(err);
                }
                else
                {
                    host_err = identify_fail_stream(identify, host, slot_index, err);
                }
            }
            else
            {
                host_err = LIBP2P_HOST_OK;
            }
        }
        else
        {
            host_err =
                identify_fail_stream(identify, host, slot_index, identify_host_to_err(host_err));
        }
    }

    return host_err;
}

static libp2p_host_err_t identify_write_stream(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    size_t slot_index)
{
    libp2p_identify_stream_state_t *slot = identify_slot_at(identify, slot_index);
    size_t accepted = 0U;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;

    if ((identify == NULL) || (host == NULL) || (slot == NULL))
    {
        host_err = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (slot->tx_pos >= slot->tx_len)
    {
        host_err = LIBP2P_HOST_OK;
    }
    else
    {
        host_err = libp2p_host_stream_write(
            host,
            slot->stream,
            &slot->tx[slot->tx_pos],
            slot->tx_len - slot->tx_pos,
            0,
            &accepted);
        if (host_err == LIBP2P_HOST_ERR_WOULD_BLOCK)
        {
            host_err = LIBP2P_HOST_OK;
        }
        else if (host_err == LIBP2P_HOST_OK)
        {
            slot->tx_pos += accepted;
            if (slot->tx_pos == slot->tx_len)
            {
                (void)libp2p_host_stream_finish(host, slot->stream);
                host_err = identify_emit_simple(identify, slot_index, LIBP2P_IDENTIFY_EVENT_SENT);
            }
        }
        else
        {
            host_err =
                identify_fail_stream(identify, host, slot_index, identify_host_to_err(host_err));
        }
    }

    return host_err;
}

static libp2p_host_err_t identify_open_common(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data,
    libp2p_identify_stream_kind_t kind)
{
    libp2p_identify_t *identify = identify_from_user_data(protocol_user_data);
    libp2p_identify_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    libp2p_identify_err_t err = LIBP2P_IDENTIFY_OK;
    libp2p_host_err_t host_result = LIBP2P_HOST_OK;

    if ((host == NULL) || (stream == NULL) || (identify == NULL))
    {
        err = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (direction == LIBP2P_HOST_STREAM_OUTBOUND)
    {
        const libp2p_identify_slot_state_t opening = (kind == LIBP2P_IDENTIFY_STREAM_PUSH)
                                                         ? LIBP2P_IDENTIFY_SLOT_OPENING_PUSH
                                                         : LIBP2P_IDENTIFY_SLOT_OPENING_IDENTIFY;

        slot = identify_find_opening(identify, opening, &slot_index);
        if (slot == NULL)
        {
            slot = identify_alloc_slot(identify, &slot_index);
        }
    }
    else
    {
        slot = identify_alloc_slot(identify, &slot_index);
    }

    if ((err == LIBP2P_IDENTIFY_OK) && (slot == NULL))
    {
        err = LIBP2P_IDENTIFY_ERR_LIMIT;
    }
    if (err == LIBP2P_IDENTIFY_OK)
    {
        slot->kind = kind;
        slot->direction = direction;
        slot->stream = stream;
        err = identify_host_to_err(libp2p_host_stream_set_user_data(stream, slot));
    }
    if (err == LIBP2P_IDENTIFY_OK)
    {
        if ((direction == LIBP2P_HOST_STREAM_INBOUND) && (kind == LIBP2P_IDENTIFY_STREAM_IDENTIFY))
        {
            err = identify_prepare_tx(identify, host, slot);
            if (err == LIBP2P_IDENTIFY_OK)
            {
                slot->state = LIBP2P_IDENTIFY_SLOT_WRITING;
                host_result = identify_write_stream(identify, host, slot_index);
            }
        }
        else if (
            (direction == LIBP2P_HOST_STREAM_OUTBOUND) && (kind == LIBP2P_IDENTIFY_STREAM_PUSH))
        {
            err = identify_prepare_tx(identify, host, slot);
            if (err == LIBP2P_IDENTIFY_OK)
            {
                slot->state = LIBP2P_IDENTIFY_SLOT_WRITING;
                host_result = identify_write_stream(identify, host, slot_index);
            }
        }
        else
        {
            slot->state = LIBP2P_IDENTIFY_SLOT_READING;
            if ((direction == LIBP2P_HOST_STREAM_OUTBOUND) &&
                (kind == LIBP2P_IDENTIFY_STREAM_IDENTIFY))
            {
                (void)libp2p_host_stream_finish(host, stream);
            }
        }
    }
    if (host_result == LIBP2P_HOST_OK)
    {
        host_result = identify_host_err(err);
    }

    return host_result;
}

static libp2p_host_err_t identify_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    return identify_open_common(
        host,
        stream,
        direction,
        protocol_user_data,
        LIBP2P_IDENTIFY_STREAM_IDENTIFY);
}

static libp2p_host_err_t identify_push_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    return identify_open_common(
        host,
        stream,
        direction,
        protocol_user_data,
        LIBP2P_IDENTIFY_STREAM_PUSH);
}

static libp2p_host_err_t identify_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data)
{
    libp2p_identify_t *identify = identify_from_user_data(protocol_user_data);
    libp2p_identify_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    slot = identify_find_stream(identify, stream, &slot_index);
    if ((host == NULL) || (stream == NULL) || (identify == NULL) || (slot == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (libp2p_host_stream_set_user_data(stream, slot) != LIBP2P_HOST_OK)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_READABLE)
    {
        if (slot->state == LIBP2P_IDENTIFY_SLOT_READING)
        {
            result = identify_read_stream(identify, host, slot_index);
        }
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE)
    {
        if (slot->state == LIBP2P_IDENTIFY_SLOT_WRITING)
        {
            result = identify_write_stream(identify, host, slot_index);
        }
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_RESET)
    {
        result = identify_fail_stream(identify, host, slot_index, LIBP2P_IDENTIFY_ERR_HOST);
    }
    else if (kind == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED)
    {
        if (slot->state == LIBP2P_IDENTIFY_SLOT_READING)
        {
            result = identify_read_stream(identify, host, slot_index);
            if ((result == LIBP2P_HOST_OK) && (identify_slot_is_reading(identify, slot_index) != 0))
            {
                result = identify_emit_simple(identify, slot_index, LIBP2P_IDENTIFY_EVENT_CLOSED);
            }
        }
        else
        {
            result = identify_emit_simple(identify, slot_index, LIBP2P_IDENTIFY_EVENT_CLOSED);
        }
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_config_default(libp2p_identify_config_t *config)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if (config == NULL)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_init(
    libp2p_identify_t *identify,
    const libp2p_identify_config_t *config)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (config == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        result = identify_message_validate_local(&config->local_message);
        if (result == LIBP2P_IDENTIFY_OK)
        {
            (void)memset(identify, 0, sizeof(*identify));
            identify->config = *config;
        }
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_protocol(
    libp2p_identify_t *identify,
    libp2p_host_protocol_t *out_protocol)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (out_protocol == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_protocol, 0, sizeof(*out_protocol));
        out_protocol->id = (const uint8_t *)LIBP2P_IDENTIFY_PROTOCOL_ID;
        out_protocol->id_len = LIBP2P_IDENTIFY_PROTOCOL_ID_LEN;
        out_protocol->on_open = identify_on_open;
        out_protocol->on_event = identify_on_event;
        out_protocol->user_data = identify;
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_push_protocol(
    libp2p_identify_t *identify,
    libp2p_host_protocol_t *out_protocol)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (out_protocol == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_protocol, 0, sizeof(*out_protocol));
        out_protocol->id = (const uint8_t *)LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID;
        out_protocol->id_len = LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID_LEN;
        out_protocol->on_open = identify_push_on_open;
        out_protocol->on_event = identify_on_event;
        out_protocol->user_data = identify;
    }

    return result;
}

static libp2p_identify_err_t identify_open_outbound(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open,
    libp2p_identify_slot_state_t opening_state,
    const uint8_t *protocol_id,
    size_t protocol_id_len)
{
    libp2p_identify_stream_state_t *slot = NULL;
    size_t slot_index = LIBP2P_IDENTIFY_MAX_STREAMS;
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (host == NULL) || (conn == NULL) || (out_open == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        slot = identify_alloc_slot(identify, &slot_index);
        if (slot == NULL)
        {
            result = LIBP2P_IDENTIFY_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_IDENTIFY_OK)
    {
        slot->state = opening_state;
        slot->user_data = user_data;
        const libp2p_host_err_t host_err =
            libp2p_host_open_stream(host, conn, protocol_id, protocol_id_len, slot, out_open);
        result = identify_host_to_err(host_err);
        if (result != LIBP2P_IDENTIFY_OK)
        {
            (void)memset(slot, 0, sizeof(*slot));
            slot->state = LIBP2P_IDENTIFY_SLOT_FREE;
        }
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_query(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    return identify_open_outbound(
        identify,
        host,
        conn,
        user_data,
        out_open,
        LIBP2P_IDENTIFY_SLOT_OPENING_IDENTIFY,
        (const uint8_t *)LIBP2P_IDENTIFY_PROTOCOL_ID,
        LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
}

libp2p_identify_err_t libp2p_identify_push(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    return identify_open_outbound(
        identify,
        host,
        conn,
        user_data,
        out_open,
        LIBP2P_IDENTIFY_SLOT_OPENING_PUSH,
        (const uint8_t *)LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID,
        LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID_LEN);
}

libp2p_identify_err_t libp2p_identify_next_event(
    libp2p_identify_t *identify,
    libp2p_identify_event_t *out_event)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;

    if ((identify == NULL) || (out_event == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (identify->event_len == 0U)
    {
        (void)memset(out_event, 0, sizeof(*out_event));
        out_event->type = LIBP2P_IDENTIFY_EVENT_NONE;
        result = LIBP2P_IDENTIFY_ERR_STATE;
    }
    else
    {
        const size_t slot_index = identify->events[identify->event_head].slot_index;

        *out_event = identify->events[identify->event_head].event;
        identify->event_head = (identify->event_head + 1U) % LIBP2P_IDENTIFY_EVENT_CAPACITY;
        identify->event_len--;
        if (slot_index < LIBP2P_IDENTIFY_MAX_STREAMS)
        {
            (void)memset(&identify->streams[slot_index], 0, sizeof(identify->streams[slot_index]));
        }
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_message_size(
    const libp2p_identify_message_t *message,
    size_t *out_len)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;
    size_t total = 0U;

    if ((message == NULL) || (out_len == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else if (
        (message->listen_addr_count > LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS) ||
        (message->protocol_count > LIBP2P_IDENTIFY_MAX_PROTOCOLS))
    {
        *out_len = 0U;
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        size_t index;

        *out_len = 0U;
        if (identify_bytes_present(&message->public_key) != 0)
        {
            result =
                identify_field_size(IDENTIFY_FIELD_PUBLIC_KEY, message->public_key.len, &total);
        }
        for (index = 0U; (index < message->listen_addr_count) && (result == LIBP2P_IDENTIFY_OK);
             index++)
        {
            if (identify_bytes_present(&message->listen_addrs[index]) == 0)
            {
                result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
            }
            else
            {
                result = identify_field_size(
                    IDENTIFY_FIELD_LISTEN_ADDRS,
                    message->listen_addrs[index].len,
                    &total);
            }
        }
        for (index = 0U; (index < message->protocol_count) && (result == LIBP2P_IDENTIFY_OK);
             index++)
        {
            if (identify_bytes_present(&message->protocols[index]) == 0)
            {
                result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
            }
            else
            {
                result = identify_field_size(
                    IDENTIFY_FIELD_PROTOCOLS,
                    message->protocols[index].len,
                    &total);
            }
        }
        if ((result == LIBP2P_IDENTIFY_OK) &&
            (identify_bytes_present(&message->observed_addr) != 0))
        {
            result = identify_field_size(
                IDENTIFY_FIELD_OBSERVED_ADDR,
                message->observed_addr.len,
                &total);
        }
        if ((result == LIBP2P_IDENTIFY_OK) &&
            (identify_bytes_present(&message->protocol_version) != 0))
        {
            result = identify_field_size(
                IDENTIFY_FIELD_PROTOCOL_VERSION,
                message->protocol_version.len,
                &total);
        }
        if ((result == LIBP2P_IDENTIFY_OK) &&
            (identify_bytes_present(&message->agent_version) != 0))
        {
            result = identify_field_size(
                IDENTIFY_FIELD_AGENT_VERSION,
                message->agent_version.len,
                &total);
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            *out_len = total;
        }
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_message_encode(
    const libp2p_identify_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;
    size_t required = 0U;
    size_t pos = 0U;
    size_t index = 0U;

    if (written == NULL)
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        *written = 0U;
        result = libp2p_identify_message_size(message, &required);
        if (result == LIBP2P_IDENTIFY_OK)
        {
            *written = required;
            if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL;
            }
        }
    }

    if ((result == LIBP2P_IDENTIFY_OK) && (identify_bytes_present(&message->public_key) != 0))
    {
        result = identify_write_field(
            IDENTIFY_FIELD_PUBLIC_KEY,
            message->public_key.data,
            message->public_key.len,
            out,
            out_len,
            &pos);
    }
    for (index = 0U; (index < message->listen_addr_count) && (result == LIBP2P_IDENTIFY_OK);
         index++)
    {
        result = identify_write_field(
            IDENTIFY_FIELD_LISTEN_ADDRS,
            message->listen_addrs[index].data,
            message->listen_addrs[index].len,
            out,
            out_len,
            &pos);
    }
    for (index = 0U; (index < message->protocol_count) && (result == LIBP2P_IDENTIFY_OK); index++)
    {
        result = identify_write_field(
            IDENTIFY_FIELD_PROTOCOLS,
            message->protocols[index].data,
            message->protocols[index].len,
            out,
            out_len,
            &pos);
    }
    if ((result == LIBP2P_IDENTIFY_OK) && (identify_bytes_present(&message->observed_addr) != 0))
    {
        result = identify_write_field(
            IDENTIFY_FIELD_OBSERVED_ADDR,
            message->observed_addr.data,
            message->observed_addr.len,
            out,
            out_len,
            &pos);
    }
    if ((result == LIBP2P_IDENTIFY_OK) && (identify_bytes_present(&message->protocol_version) != 0))
    {
        result = identify_write_field(
            IDENTIFY_FIELD_PROTOCOL_VERSION,
            message->protocol_version.data,
            message->protocol_version.len,
            out,
            out_len,
            &pos);
    }
    if ((result == LIBP2P_IDENTIFY_OK) && (identify_bytes_present(&message->agent_version) != 0))
    {
        result = identify_write_field(
            IDENTIFY_FIELD_AGENT_VERSION,
            message->agent_version.data,
            message->agent_version.len,
            out,
            out_len,
            &pos);
    }

    return result;
}

libp2p_identify_err_t libp2p_identify_message_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_identify_message_t *out_message)
{
    libp2p_identify_err_t result = LIBP2P_IDENTIFY_OK;
    size_t pos = 0U;

    if ((in == NULL) || (in_len == 0U) || (out_message == NULL))
    {
        result = LIBP2P_IDENTIFY_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_message, 0, sizeof(*out_message));
    }

    while ((result == LIBP2P_IDENTIFY_OK) && (pos < in_len))
    {
        uint64_t key = 0U;
        uint64_t len = 0U;
        size_t read = 0U;
        uint32_t field = 0U;

        result = identify_uvarint_err(libp2p_uvarint_decode(&in[pos], in_len - pos, &key, &read));
        if (result == LIBP2P_IDENTIFY_OK)
        {
            pos += read;
            field = (uint32_t)(key >> 3U);
            if ((field == 0U) || (((uint32_t)(key & 7U)) != IDENTIFY_WIRE_LEN))
            {
                result = LIBP2P_IDENTIFY_ERR_MALFORMED;
            }
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            result =
                identify_uvarint_err(libp2p_uvarint_decode(&in[pos], in_len - pos, &len, &read));
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            pos += read;
            if (len > (uint64_t)(in_len - pos))
            {
                result = LIBP2P_IDENTIFY_ERR_TRUNCATED;
            }
        }
        if (result == LIBP2P_IDENTIFY_OK)
        {
            libp2p_identify_bytes_t bytes;

            bytes.data = &in[pos];
            bytes.len = (size_t)len;
            if (field == IDENTIFY_FIELD_PUBLIC_KEY)
            {
                out_message->public_key = bytes;
            }
            else if (field == IDENTIFY_FIELD_LISTEN_ADDRS)
            {
                if (out_message->listen_addr_count == LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS)
                {
                    result = LIBP2P_IDENTIFY_ERR_LIMIT;
                }
                else
                {
                    out_message->listen_addrs[out_message->listen_addr_count] = bytes;
                    out_message->listen_addr_count++;
                }
            }
            else if (field == IDENTIFY_FIELD_PROTOCOLS)
            {
                if (out_message->protocol_count == LIBP2P_IDENTIFY_MAX_PROTOCOLS)
                {
                    result = LIBP2P_IDENTIFY_ERR_LIMIT;
                }
                else
                {
                    out_message->protocols[out_message->protocol_count] = bytes;
                    out_message->protocol_count++;
                }
            }
            else if (field == IDENTIFY_FIELD_OBSERVED_ADDR)
            {
                out_message->observed_addr = bytes;
            }
            else if (field == IDENTIFY_FIELD_PROTOCOL_VERSION)
            {
                out_message->protocol_version = bytes;
            }
            else if (field == IDENTIFY_FIELD_AGENT_VERSION)
            {
                out_message->agent_version = bytes;
            }
            else
            {
                result = LIBP2P_IDENTIFY_OK;
            }
            pos += (size_t)len;
        }
    }

    return result;
}
