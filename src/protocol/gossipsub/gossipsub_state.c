#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t gossipsub_event_push(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_event_t *event)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->event_len == gossipsub->config.capacity.event_capacity)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        const size_t pos = (gossipsub->event_head + gossipsub->event_len) %
                           gossipsub->config.capacity.event_capacity;

        gossipsub->events[pos] = *event;
        gossipsub->event_len++;
    }

    return result;
}

void gossipsub_peer_to_event(const gossipsub_peer_state_t *peer, libp2p_gossipsub_event_t *event)
{
    if ((peer != NULL) && (event != NULL))
    {
        event->conn = peer->conn;
        event->stream = peer->stream;
        event->direction = peer->direction;
        event->protocol_version = peer->version;
        event->peer.len = peer->peer_id_len;
        if (peer->peer_id_len != 0U)
        {
            (void)memcpy(event->peer.data, peer->peer_id, peer->peer_id_len);
        }
        event->user_data = peer->user_data;
    }
}

gossipsub_topic_state_t *gossipsub_find_topic(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *topic,
    size_t topic_len,
    size_t *out_index)
{
    gossipsub_topic_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_topics;
    }
    if ((gossipsub != NULL) && (topic != NULL) && (out_index != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_topics; index++)
        {
            if ((gossipsub->topics[index].used == GOSSIPSUB_TOPIC_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->topics[index].topic,
                     gossipsub->topics[index].topic_len,
                     topic,
                     topic_len) != 0))
            {
                result = &gossipsub->topics[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

gossipsub_topic_state_t *gossipsub_find_or_add_topic(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic,
    size_t *out_index)
{
    gossipsub_topic_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_topics;
    }
    if ((gossipsub != NULL) && (topic.data != NULL) &&
        (topic.len <= gossipsub->config.limits.max_topic_bytes) && (out_index != NULL))
    {
        result = gossipsub_find_topic(gossipsub, topic.data, topic.len, out_index);
        if (result == NULL)
        {
            for (size_t index = 0U; index < gossipsub->config.capacity.max_topics; index++)
            {
                if (gossipsub->topics[index].used == GOSSIPSUB_TOPIC_FREE)
                {
                    result = &gossipsub->topics[index];
                    (void)memset(result, 0, sizeof(*result));
                    result->used = GOSSIPSUB_TOPIC_USED;
                    result->validation_mode = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL;
                    result->enable_idontwant = gossipsub->config.enable_idontwant;
                    result->idontwant_min_message_bytes =
                        gossipsub->config.idontwant_min_message_bytes;
                    result->topic_len = topic.len;
                    (void)memcpy(result->topic, topic.data, topic.len);
                    *out_index = index;
                    gossipsub->topic_count++;
                    break;
                }
            }
        }
    }

    return result;
}

gossipsub_peer_state_t *gossipsub_find_peer(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index)
{
    gossipsub_peer_state_t *result = NULL;

    if ((gossipsub != NULL) && (peer_id != NULL) && (out_index != NULL))
    {
        *out_index = gossipsub->config.capacity.max_peers;
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->peers[index].peer_id,
                     gossipsub->peers[index].peer_id_len,
                     peer_id,
                     peer_id_len) != 0))
            {
                result = &gossipsub->peers[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

const gossipsub_peer_state_t *gossipsub_find_peer_const(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index)
{
    const gossipsub_peer_state_t *result = NULL;

    if ((gossipsub != NULL) && (peer_id != NULL) && (out_index != NULL))
    {
        *out_index = gossipsub->config.capacity.max_peers;
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->peers[index].peer_id,
                     gossipsub->peers[index].peer_id_len,
                     peer_id,
                     peer_id_len) != 0))
            {
                result = &gossipsub->peers[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_peer_from_conn(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_conn_t *conn,
    gossipsub_peer_state_t **out_peer,
    size_t *out_index)
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    size_t index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(peer_id, 0, sizeof(peer_id));
    if ((gossipsub == NULL) || (conn == NULL) || (out_peer == NULL) || (out_index == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(
            libp2p_host_conn_peer_id(conn, peer_id, sizeof(peer_id), &peer_id_len));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &index);
        if (peer == NULL)
        {
            for (index = 0U; index < gossipsub->config.capacity.max_peers; index++)
            {
                if (gossipsub->peers[index].used == GOSSIPSUB_PEER_FREE)
                {
                    peer = &gossipsub->peers[index];
                    (void)memset(peer, 0, sizeof(*peer));
                    peer->used = GOSSIPSUB_PEER_USED;
                    peer->tx_head = GOSSIPSUB_TX_NO_ITEM;
                    peer->tx_tail = GOSSIPSUB_TX_NO_ITEM;
                    peer->peer_id_len = peer_id_len;
                    (void)memcpy(peer->peer_id, peer_id, peer_id_len);
                    gossipsub->peer_count++;
                    break;
                }
            }
        }
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            peer->conn = conn;
            peer->closed = 0U;
            *out_peer = peer;
            *out_index = index;
        }
    }

    return result;
}

gossipsub_stream_state_t *gossipsub_alloc_stream(libp2p_gossipsub_t *gossipsub, size_t *out_index)
{
    gossipsub_stream_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_streams;
    }
    if ((gossipsub != NULL) && (out_index != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_streams; index++)
        {
            if (gossipsub->streams[index].state == GOSSIPSUB_STREAM_FREE)
            {
                result = &gossipsub->streams[index];
                result->state = GOSSIPSUB_STREAM_OPEN;
                result->rx_len = 0U;
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

gossipsub_peer_topic_state_t *gossipsub_find_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    gossipsub_peer_topic_state_t *result = NULL;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
        {
            if ((gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->peer_topics[index].peer_index == peer_index) &&
                (gossipsub->peer_topics[index].topic_index == topic_index))
            {
                result = &gossipsub->peer_topics[index];
                break;
            }
        }
    }

    return result;
}

gossipsub_peer_topic_state_t *gossipsub_find_or_add_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    gossipsub_peer_topic_state_t *result = NULL;

    if (gossipsub != NULL)
    {
        result = gossipsub_find_peer_topic(gossipsub, peer_index, topic_index);
        if (result == NULL)
        {
            for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
            {
                if (gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_FREE)
                {
                    result = &gossipsub->peer_topics[index];
                    result->used = GOSSIPSUB_EDGE_USED;
                    result->peer_index = peer_index;
                    result->topic_index = topic_index;
                    result->subscribed = 0U;
                    break;
                }
            }
        }
    }

    return result;
}

int gossipsub_peer_subscribed(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
        {
            if ((gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->peer_topics[index].peer_index == peer_index) &&
                (gossipsub->peer_topics[index].topic_index == topic_index) &&
                (gossipsub->peer_topics[index].subscribed != 0U))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

int gossipsub_mesh_contains(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].peer_index == peer_index) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

size_t gossipsub_mesh_count_topic(const libp2p_gossipsub_t *gossipsub, size_t topic_index)
{
    size_t result = 0U;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                result++;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_mesh_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (peer_index >= gossipsub->config.capacity.max_peers) ||
        (topic_index >= gossipsub->config.capacity.max_topics))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (gossipsub->peers[peer_index].used != GOSSIPSUB_PEER_USED) ||
        (gossipsub->topics[topic_index].used != GOSSIPSUB_TOPIC_USED))
    {
        result = LIBP2P_GOSSIPSUB_ERR_STATE;
    }
    else if (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) == 0)
    {
        gossipsub_mesh_edge_state_t *edge = NULL;

        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if (gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_FREE)
            {
                edge = &gossipsub->mesh_edges[index];
                break;
            }
        }
        if (edge == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            edge->used = GOSSIPSUB_EDGE_USED;
            edge->peer_index = peer_index;
            edge->topic_index = topic_index;
        }
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    return result;
}

void gossipsub_mesh_remove(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].peer_index == peer_index) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                (void)memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
                break;
            }
        }
    }
}

void gossipsub_mesh_remove_peer(libp2p_gossipsub_t *gossipsub, size_t peer_index)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].peer_index == peer_index))
            {
                (void)memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
            }
        }
    }
}

void gossipsub_mesh_remove_topic(libp2p_gossipsub_t *gossipsub, size_t topic_index)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                (void)memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
            }
        }
    }
}

libp2p_gossipsub_err_t gossipsub_mesh_fill_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index,
    size_t target,
    uint8_t queue_graft)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic_index >= gossipsub->config.capacity.max_topics))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->topics[topic_index].used != GOSSIPSUB_TOPIC_USED)
    {
        result = LIBP2P_GOSSIPSUB_ERR_STATE;
    }
    else
    {
        size_t count = gossipsub_mesh_count_topic(gossipsub, topic_index);

        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (count < target) &&
             (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL) &&
                (gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) &&
                (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) == 0))
            {
                result = gossipsub_mesh_add(gossipsub, peer_index, topic_index);
                if ((result == LIBP2P_GOSSIPSUB_OK) && (queue_graft != 0U))
                {
                    result = gossipsub_enqueue_graft(
                        gossipsub,
                        peer_index,
                        &gossipsub->topics[topic_index]);
                    if (result != LIBP2P_GOSSIPSUB_OK)
                    {
                        gossipsub_mesh_remove(gossipsub, peer_index, topic_index);
                    }
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    count++;
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_mesh_trim_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index,
    size_t target,
    uint8_t queue_prune)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic_index >= gossipsub->config.capacity.max_topics))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        size_t count = gossipsub_mesh_count_topic(gossipsub, topic_index);

        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (count > target) &&
             (index < gossipsub->config.capacity.max_mesh_edges);
             index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                const size_t peer_index = gossipsub->mesh_edges[index].peer_index;

                if (queue_prune != 0U)
                {
                    result = gossipsub_enqueue_prune(
                        gossipsub,
                        peer_index,
                        &gossipsub->topics[topic_index]);
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    (void)memset(
                        &gossipsub->mesh_edges[index],
                        0,
                        sizeof(gossipsub->mesh_edges[index]));
                    count--;
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_mesh_heartbeat(libp2p_gossipsub_t *gossipsub)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (gossipsub == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t topic_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) &&
             (topic_index < gossipsub->config.capacity.max_topics);
             topic_index++)
        {
            if ((gossipsub->topics[topic_index].used == GOSSIPSUB_TOPIC_USED) &&
                (gossipsub->topics[topic_index].local_subscribed != 0U))
            {
                const size_t count = gossipsub_mesh_count_topic(gossipsub, topic_index);

                if (count < gossipsub->config.mesh.d_low)
                {
                    result = gossipsub_mesh_fill_topic(
                        gossipsub,
                        topic_index,
                        gossipsub->config.mesh.d,
                        1U);
                }
                else if (count > gossipsub->config.mesh.d_high)
                {
                    result = gossipsub_mesh_trim_topic(
                        gossipsub,
                        topic_index,
                        gossipsub->config.mesh.d,
                        1U);
                }
                else
                {
                    result = LIBP2P_GOSSIPSUB_OK;
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_compute_message_id(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (message == NULL) || (written == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub->config.message_id_fn(
            message,
            NULL,
            0U,
            &required,
            gossipsub->config.message_id_user_data);
        if (result == LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL)
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = required;
            if ((required == 0U) || (required > gossipsub->config.limits.max_message_id_bytes))
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
            }
            else
            {
                result = gossipsub->config.message_id_fn(
                    message,
                    out,
                    out_len,
                    written,
                    gossipsub->config.message_id_user_data);
            }
        }
    }

    return result;
}

int gossipsub_seen_contains(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    int result = 0;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used != 0U) &&
                (gossipsub->seen[index].expires_us >= now_us) &&
                (gossipsub_bytes_equal(
                     gossipsub->seen[index].message_id,
                     gossipsub->seen[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

void gossipsub_seen_add(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    if ((gossipsub != NULL) && (message_id != NULL) &&
        (gossipsub->config.capacity.seen_entries != 0U) &&
        (message_id_len <= gossipsub->config.limits.max_message_id_bytes))
    {
        size_t target = 0U;
        int found = 0;

        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used == 0U) || (gossipsub->seen[index].expires_us < now_us))
            {
                target = index;
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            target = gossipsub->mcache_next % gossipsub->config.capacity.seen_entries;
        }
        gossipsub->seen[target].used = 1U;
        gossipsub->seen[target].message_id_len = message_id_len;
        (void)memcpy(gossipsub->seen[target].message_id, message_id, message_id_len);
        gossipsub->seen[target].expires_us = now_us + gossipsub->config.mesh.seen_ttl_us;
    }
}

gossipsub_mcache_entry_t *gossipsub_mcache_find(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len)
{
    gossipsub_mcache_entry_t *result = NULL;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.mcache_slots; index++)
        {
            if ((gossipsub->mcache[index].used != 0U) &&
                (gossipsub_bytes_equal(
                     gossipsub->mcache[index].message_id,
                     gossipsub->mcache[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = &gossipsub->mcache[index];
                break;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_mcache_store(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    libp2p_gossipsub_bytes_t topic,
    libp2p_gossipsub_bytes_t data,
    gossipsub_mcache_entry_t **out_entry,
    size_t *out_index)
{
    size_t slot;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (message_id == NULL) || (topic.data == NULL) ||
        ((data.data == NULL) && (data.len != 0U)) || (out_entry == NULL) || (out_index == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (message_id_len == 0U) ||
        (message_id_len > gossipsub->config.limits.max_message_id_bytes) || (topic.len == 0U) ||
        (topic.len > gossipsub->config.limits.max_topic_bytes) ||
        (data.len > gossipsub->config.capacity.mcache_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        if (data.len > (gossipsub->config.capacity.mcache_bytes - gossipsub->mcache_data_used))
        {
            (void)memset(
                gossipsub->mcache,
                0,
                gossipsub->config.capacity.mcache_slots * sizeof(gossipsub_mcache_entry_t));
            gossipsub->mcache_data_used = 0U;
        }
        slot = gossipsub->mcache_next % gossipsub->config.capacity.mcache_slots;
        entry = &gossipsub->mcache[slot];
        (void)memset(entry, 0, sizeof(*entry));
        entry->used = 1U;
        entry->window = 0U;
        entry->message_id_len = message_id_len;
        (void)memcpy(entry->message_id, message_id, message_id_len);
        entry->topic_len = topic.len;
        (void)memcpy(entry->topic, topic.data, topic.len);
        entry->data_offset = gossipsub->mcache_data_used;
        entry->data_len = data.len;
        if (data.len != 0U)
        {
            (void)memcpy(&gossipsub->mcache_data[entry->data_offset], data.data, data.len);
        }
        gossipsub->mcache_data_used += data.len;
        gossipsub->mcache_next++;
        *out_entry = entry;
        *out_index = slot;
    }

    return result;
}

void gossipsub_entry_message(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_mcache_entry_t *entry,
    libp2p_gossipsub_message_t *out)
{
    if ((gossipsub != NULL) && (entry != NULL) && (out != NULL))
    {
        (void)memset(out, 0, sizeof(*out));
        out->topic.data = entry->topic;
        out->topic.len = entry->topic_len;
        out->data.data = &gossipsub->mcache_data[entry->data_offset];
        out->data.len = entry->data_len;
    }
}

int gossipsub_peer_idontwant_contains(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    int result = 0;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used != 0U) &&
                (gossipsub->idontwant[index].peer_index == peer_index) &&
                (gossipsub->idontwant[index].expires_us >= now_us) &&
                (gossipsub_bytes_equal(
                     gossipsub->idontwant[index].message_id,
                     gossipsub->idontwant[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

void gossipsub_peer_idontwant_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    if ((gossipsub != NULL) && (message_id != NULL) &&
        (gossipsub->config.capacity.idontwant_entries != 0U) &&
        (message_id_len <= gossipsub->config.limits.max_message_id_bytes))
    {
        size_t target = 0U;
        int found = 0;

        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used == 0U) ||
                (gossipsub->idontwant[index].expires_us < now_us))
            {
                target = index;
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            target = gossipsub->mcache_next % gossipsub->config.capacity.idontwant_entries;
        }
        gossipsub->idontwant[target].used = 1U;
        gossipsub->idontwant[target].peer_index = peer_index;
        gossipsub->idontwant[target].message_id_len = message_id_len;
        (void)memcpy(gossipsub->idontwant[target].message_id, message_id, message_id_len);
        gossipsub->idontwant[target].expires_us = now_us + gossipsub->config.idontwant_ttl_us;
    }
}
