#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t libp2p_gossipsub_protocols(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_protocol_t *out_protocols,
    size_t out_protocol_capacity,
    size_t *written)
{
    size_t required = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (written == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12) != 0U)
        {
            required++;
        }
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11) != 0U)
        {
            required++;
        }
        *written = required;
        if ((out_protocols == NULL) || (out_protocol_capacity < required))
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        size_t pos = 0U;

        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12) != 0U)
        {
            out_protocols[pos].id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12;
            out_protocols[pos].id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN;
            out_protocols[pos].on_open = gossipsub_protocol_on_open;
            out_protocols[pos].on_event = gossipsub_protocol_on_event;
            out_protocols[pos].user_data = &gossipsub->protocol_user_data[0];
            pos++;
        }
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11) != 0U)
        {
            out_protocols[pos].id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11;
            out_protocols[pos].id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN;
            out_protocols[pos].on_open = gossipsub_protocol_on_open;
            out_protocols[pos].on_event = gossipsub_protocol_on_event;
            out_protocols[pos].user_data = &gossipsub->protocol_user_data[1];
        }
        *written = required;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_start(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub->host = host;
        gossipsub->started = 1U;
        gossipsub->closing = 0U;
        gossipsub->next_heartbeat_us = now_us + gossipsub->config.mesh.heartbeat_interval_us;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_close(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    uint64_t app_error_code)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub->closing = 1U;
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < gossipsub->config.capacity.max_streams);
             index++)
        {
            if ((gossipsub->streams[index].state == GOSSIPSUB_STREAM_OPEN) &&
                (gossipsub->streams[index].stream != NULL))
            {
                result = gossipsub_host_to_err(libp2p_host_stream_reset(
                    host,
                    gossipsub->streams[index].stream,
                    app_error_code));
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_next_deadline(
    const libp2p_gossipsub_t *gossipsub,
    libp2p_host_time_us_t *out_deadline_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_deadline_us == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->started == 0U)
    {
        *out_deadline_us = 0U;
    }
    else
    {
        *out_deadline_us = gossipsub->next_heartbeat_us;
    }

    return result;
}

void gossipsub_heartbeat(libp2p_gossipsub_t *gossipsub, uint64_t now_us)
{

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if (gossipsub->peers[index].used == GOSSIPSUB_PEER_USED)
            {
                gossipsub->peers[index].idontwant_sent_this_heartbeat = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.mcache_slots; index++)
        {
            if (gossipsub->mcache[index].used != 0U)
            {
                if (gossipsub->mcache[index].window >= gossipsub->config.mesh.mcache_len)
                {
                    gossipsub->mcache[index].used = 0U;
                }
                else
                {
                    gossipsub->mcache[index].window++;
                }
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used != 0U) && (gossipsub->seen[index].expires_us < now_us))
            {
                gossipsub->seen[index].used = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used != 0U) &&
                (gossipsub->idontwant[index].expires_us < now_us))
            {
                gossipsub->idontwant[index].used = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.pending_validations; index++)
        {
            if ((gossipsub->validations[index].state == GOSSIPSUB_VALIDATION_PENDING) &&
                (gossipsub->validations[index].expires_us < now_us))
            {
                gossipsub->validations[index].state = GOSSIPSUB_VALIDATION_FREE;
            }
        }
        gossipsub->next_heartbeat_us = now_us + gossipsub->config.mesh.heartbeat_interval_us;
    }
}

libp2p_gossipsub_err_t libp2p_gossipsub_drive(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us,
    libp2p_gossipsub_drive_result_t *out_result)
{
    uint8_t made_progress = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        if (out_result != NULL)
        {
            (void)memset(out_result, 0, sizeof(*out_result));
        }
        if ((gossipsub->started != 0U) && (now_us >= gossipsub->next_heartbeat_us))
        {
            gossipsub_heartbeat(gossipsub, now_us);
            made_progress = 1U;
            if (out_result != NULL)
            {
                out_result->heartbeats = 1U;
            }
        }
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_flush_peer(gossipsub, host, peer_index, &made_progress);
            }
        }
        if (out_result != NULL)
        {
            out_result->made_progress = made_progress;
            out_result->rpcs_sent = made_progress;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_handle_host_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    const libp2p_host_event_t *event)
{
    libp2p_gossipsub_event_t gs_event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&gs_event, 0, sizeof(gs_event));
    if ((gossipsub == NULL) || (host == NULL) || (event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (event->type == LIBP2P_HOST_EVENT_CONN_CLOSED)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[index].conn == event->conn))
            {
                gs_event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED;
                gossipsub_peer_to_event(&gossipsub->peers[index], &gs_event);
                (void)gossipsub_event_push(gossipsub, &gs_event);
                gossipsub->peers[index].closed = 1U;
                gossipsub->peers[index].stream = NULL;
                gossipsub->peers[index].conn = NULL;
            }
        }
    }
    else if (event->type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED)
    {
        gs_event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_FAILED;
        gs_event.conn = event->conn;
        gs_event.reason = gossipsub_host_to_err(event->reason);
        result = gossipsub_event_push(gossipsub, &gs_event);
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    (void)host;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_open_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    libp2p_gossipsub_protocol_version_t preferred_version,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    const uint8_t *protocol_id = NULL;
    size_t protocol_id_len = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (conn == NULL) || (out_open == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        libp2p_gossipsub_protocol_version_t version = preferred_version;

        if (version == LIBP2P_GOSSIPSUB_VERSION_NONE)
        {
            version = gossipsub->config.preferred_protocol;
        }
        if (version == LIBP2P_GOSSIPSUB_VERSION_12)
        {
            protocol_id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12;
            protocol_id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN;
        }
        else if (version == LIBP2P_GOSSIPSUB_VERSION_11)
        {
            protocol_id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11;
            protocol_id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN;
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_host_to_err(
            libp2p_host_open_stream(host, conn, protocol_id, protocol_id_len, user_data, out_open));
    }

    return result;
}

libp2p_host_err_t gossipsub_protocol_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    libp2p_gossipsub_t *gossipsub = gossipsub_from_protocol_user_data(protocol_user_data);
    libp2p_gossipsub_protocol_version_t version =
        gossipsub_version_from_protocol_user_data(protocol_user_data);
    libp2p_host_conn_t *conn = NULL;
    gossipsub_peer_state_t *peer = NULL;
    gossipsub_stream_state_t *stream_state = NULL;
    size_t peer_index = 0U;
    size_t stream_index = 0U;
    size_t topic_index = 0U;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    gossipsub_keep_mutable_host_arg(host);
    gossipsub_keep_mutable_void_arg(protocol_user_data);
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (host == NULL) || (stream == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(libp2p_host_stream_conn(stream, &conn));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_peer_from_conn(gossipsub, conn, &peer, &peer_index);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        stream_state = gossipsub_alloc_stream(gossipsub, &stream_index);
        if (stream_state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        stream_state->stream = stream;
        stream_state->conn = conn;
        stream_state->direction = direction;
        stream_state->version = version;
        stream_state->peer_index = peer_index;
        peer->stream = stream;
        peer->direction = direction;
        peer->version = version;
        result = gossipsub_host_to_err(libp2p_host_stream_set_user_data(stream, stream_state));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_OPENED;
        gossipsub_peer_to_event(peer, &event);
        result = gossipsub_event_push(gossipsub, &event);
    }
    for (topic_index = 0U;
         (result == LIBP2P_GOSSIPSUB_OK) && (topic_index < gossipsub->config.capacity.max_topics);
         topic_index++)
    {
        if ((gossipsub->topics[topic_index].used == GOSSIPSUB_TOPIC_USED) &&
            (gossipsub->topics[topic_index].local_subscribed != 0U))
        {
            result = gossipsub_enqueue_subscription(
                gossipsub,
                peer_index,
                &gossipsub->topics[topic_index],
                1U);
        }
    }
    (void)stream_index;

    return gossipsub_host_err(result);
}

libp2p_host_err_t gossipsub_protocol_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data)
{
    libp2p_gossipsub_t *gossipsub = gossipsub_from_protocol_user_data(protocol_user_data);
    gossipsub_stream_state_t *stream_state = NULL;
    void *user_data = NULL;
    uint8_t made_progress = 0U;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    gossipsub_keep_mutable_stream_arg(stream);
    gossipsub_keep_mutable_void_arg(protocol_user_data);
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (host == NULL) || (stream == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(libp2p_host_stream_user_data(stream, &user_data));
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            (void)memcpy((void *)&stream_state, (const void *)&user_data, sizeof user_data);
            if (stream_state == NULL)
            {
                result = LIBP2P_GOSSIPSUB_ERR_STATE;
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (kind == LIBP2P_HOST_PROTOCOL_EVENT_READABLE))
    {
        result = gossipsub_stream_read(gossipsub, host, stream_state, gossipsub->next_heartbeat_us);
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (kind == LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE))
    {
        result = gossipsub_flush_peer(gossipsub, host, stream_state->peer_index, &made_progress);
    }
    else if (
        (result == LIBP2P_GOSSIPSUB_OK) &&
        ((kind == LIBP2P_HOST_PROTOCOL_EVENT_RESET) || (kind == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED)))
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED;
        gossipsub_peer_to_event(&gossipsub->peers[stream_state->peer_index], &event);
        (void)gossipsub_event_push(gossipsub, &event);
        gossipsub->peers[stream_state->peer_index].stream = NULL;
        stream_state->state = GOSSIPSUB_STREAM_FREE;
        stream_state->stream = NULL;
    }
    else
    {
        (void)result;
    }

    (void)made_progress;

    return gossipsub_host_err(result);
}
