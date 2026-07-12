#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

#define GOSSIPSUB_PEER_RANK_OFFSET UINT64_C(1469598103934665603)
#define GOSSIPSUB_PEER_RANK_PRIME  UINT64_C(1099511628211)
#define GOSSIPSUB_RANK_MODE_FILL   0U
#define GOSSIPSUB_RANK_MODE_TRIM   1U

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
                    peer->tx_priority_tail = GOSSIPSUB_TX_NO_ITEM;
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
                gossipsub_stream_rx_reset(gossipsub, result);
                result->state = GOSSIPSUB_STREAM_OPEN;
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

libp2p_gossipsub_err_t libp2p_gossipsub_mesh_peer_count(
    const libp2p_gossipsub_t *gossipsub,
    size_t *out_count)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_count == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        *out_count = atomic_load_explicit(&gossipsub->mesh_peer_count, memory_order_relaxed);
    }

    return result;
}

static uint64_t gossipsub_u64_add_saturating(uint64_t left, uint64_t right)
{
    uint64_t result = UINT64_MAX;

    if ((UINT64_MAX - left) >= right)
    {
        result = left + right;
    }

    return result;
}

static uint64_t gossipsub_backoff_expires_us(
    const libp2p_gossipsub_t *gossipsub,
    uint64_t interval_us,
    uint64_t now_us)
{
    uint64_t interval_with_slack = interval_us;

    if (gossipsub != NULL)
    {
        interval_with_slack =
            gossipsub_u64_add_saturating(interval_us, gossipsub->config.mesh.backoff_slack_us);
    }

    return gossipsub_u64_add_saturating(now_us, interval_with_slack);
}

int gossipsub_backoff_active(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index,
    uint64_t now_us)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers) &&
        (topic_index < gossipsub->config.capacity.max_topics))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_backoff_entries; index++)
        {
            if ((gossipsub->backoff[index].used != 0U) &&
                (gossipsub->backoff[index].peer_index == peer_index) &&
                (gossipsub->backoff[index].topic_index == topic_index) &&
                (gossipsub->backoff[index].expires_us > now_us))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_backoff_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index,
    uint64_t interval_us,
    uint64_t now_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (peer_index >= gossipsub->config.capacity.max_peers) ||
        (topic_index >= gossipsub->config.capacity.max_topics))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        size_t slot_index = 0U;
        size_t replace_index = 0U;
        const uint64_t expires_us = gossipsub_backoff_expires_us(gossipsub, interval_us, now_us);
        uint64_t replace_expires_us = UINT64_MAX;
        uint8_t have_slot = 0U;
        uint8_t have_replace = 0U;
        uint8_t found_match = 0U;

        for (size_t index = 0U; index < gossipsub->config.capacity.max_backoff_entries; index++)
        {
            if ((gossipsub->backoff[index].used != 0U) &&
                (gossipsub->backoff[index].peer_index == peer_index) &&
                (gossipsub->backoff[index].topic_index == topic_index))
            {
                slot_index = index;
                have_slot = 1U;
                found_match = 1U;
                break;
            }
            if ((gossipsub->backoff[index].used == 0U) && (have_slot == 0U))
            {
                slot_index = index;
                have_slot = 1U;
            }
            if ((gossipsub->backoff[index].used != 0U) &&
                ((have_replace == 0U) ||
                 (gossipsub->backoff[index].expires_us < replace_expires_us)))
            {
                replace_index = index;
                replace_expires_us = gossipsub->backoff[index].expires_us;
                have_replace = 1U;
            }
        }
        if ((have_slot == 0U) && (have_replace != 0U))
        {
            slot_index = replace_index;
            have_slot = 1U;
        }
        if (have_slot == 0U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else if ((found_match == 0U) || (gossipsub->backoff[slot_index].expires_us < expires_us))
        {
            gossipsub->backoff[slot_index].used = 1U;
            gossipsub->backoff[slot_index].peer_index = peer_index;
            gossipsub->backoff[slot_index].topic_index = topic_index;
            gossipsub->backoff[slot_index].expires_us = expires_us;
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
    }

    return result;
}

void gossipsub_backoff_clear_expired(libp2p_gossipsub_t *gossipsub, uint64_t now_us)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_backoff_entries; index++)
        {
            if ((gossipsub->backoff[index].used != 0U) &&
                (gossipsub->backoff[index].expires_us <= now_us))
            {
                (void)memset(&gossipsub->backoff[index], 0, sizeof(gossipsub->backoff[index]));
            }
        }
    }
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
            (void)atomic_fetch_add_explicit(
                &gossipsub->mesh_peer_count,
                1U,
                memory_order_relaxed);
        }
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    return result;
}

void gossipsub_mesh_remove(libp2p_gossipsub_t *gossipsub, size_t peer_index, size_t topic_index)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_mesh_edges; index++)
        {
            if ((gossipsub->mesh_edges[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->mesh_edges[index].peer_index == peer_index) &&
                (gossipsub->mesh_edges[index].topic_index == topic_index))
            {
                (void)
                    memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
                (void)atomic_fetch_sub_explicit(
                    &gossipsub->mesh_peer_count,
                    1U,
                    memory_order_relaxed);
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
                (void)
                    memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
                (void)atomic_fetch_sub_explicit(
                    &gossipsub->mesh_peer_count,
                    1U,
                    memory_order_relaxed);
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
                (void)
                    memset(&gossipsub->mesh_edges[index], 0, sizeof(gossipsub->mesh_edges[index]));
                (void)atomic_fetch_sub_explicit(
                    &gossipsub->mesh_peer_count,
                    1U,
                    memory_order_relaxed);
            }
        }
    }
}

static libp2p_gossipsub_err_t gossipsub_random_u64(libp2p_gossipsub_t *gossipsub, uint64_t *out)
{
    uint8_t bytes[8];
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(bytes, 0, sizeof(bytes));
    if ((gossipsub == NULL) || (out == NULL) || (gossipsub->config.random_fn == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result =
            gossipsub->config.random_fn(bytes, sizeof(bytes), gossipsub->config.random_user_data);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out = ((uint64_t)bytes[0] << 56U) | ((uint64_t)bytes[1] << 48U) |
               ((uint64_t)bytes[2] << 40U) | ((uint64_t)bytes[3] << 32U) |
               ((uint64_t)bytes[4] << 24U) | ((uint64_t)bytes[5] << 16U) |
               ((uint64_t)bytes[6] << 8U) | (uint64_t)bytes[7];
    }

    return result;
}

static int gossipsub_peer_id_cmp(
    const gossipsub_peer_state_t *left,
    const gossipsub_peer_state_t *right)
{
    int result = 0;

    if ((left != NULL) && (right != NULL))
    {
        const size_t limit =
            (left->peer_id_len < right->peer_id_len) ? left->peer_id_len : right->peer_id_len;

        for (size_t index = 0U; (index < limit) && (result == 0); index++)
        {
            if (left->peer_id[index] < right->peer_id[index])
            {
                result = -1;
            }
            else if (left->peer_id[index] > right->peer_id[index])
            {
                result = 1;
            }
            else
            {
                result = 0;
            }
        }
        if (result == 0)
        {
            if (left->peer_id_len < right->peer_id_len)
            {
                result = -1;
            }
            else if (left->peer_id_len > right->peer_id_len)
            {
                result = 1;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

static uint64_t gossipsub_peer_rank(const gossipsub_peer_state_t *peer, uint64_t salt)
{
    uint64_t result = GOSSIPSUB_PEER_RANK_OFFSET ^ salt;

    if (peer != NULL)
    {
        for (size_t index = 0U; index < peer->peer_id_len; index++)
        {
            result ^= (uint64_t)peer->peer_id[index];
            result *= GOSSIPSUB_PEER_RANK_PRIME;
        }
    }

    return result;
}

static int gossipsub_rank_before(
    const libp2p_gossipsub_t *gossipsub,
    uint64_t rank,
    size_t peer_index,
    uint64_t best_rank,
    size_t best_peer_index)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers) &&
        (best_peer_index < gossipsub->config.capacity.max_peers))
    {
        if (rank < best_rank)
        {
            result = 1;
        }
        else if (rank > best_rank)
        {
            result = 0;
        }
        else
        {
            const int cmp = gossipsub_peer_id_cmp(
                &gossipsub->peers[peer_index],
                &gossipsub->peers[best_peer_index]);

            if (cmp < 0)
            {
                result = 1;
            }
            else if (cmp > 0)
            {
                result = 0;
            }
            else if (peer_index < best_peer_index)
            {
                result = 1;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

static int gossipsub_rank_after(
    const libp2p_gossipsub_t *gossipsub,
    uint64_t rank,
    size_t peer_index,
    uint64_t previous_rank,
    size_t previous_peer_index)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers) &&
        (previous_peer_index < gossipsub->config.capacity.max_peers))
    {
        if (rank > previous_rank)
        {
            result = 1;
        }
        else if (rank < previous_rank)
        {
            result = 0;
        }
        else
        {
            const int cmp = gossipsub_peer_id_cmp(
                &gossipsub->peers[peer_index],
                &gossipsub->peers[previous_peer_index]);

            if (cmp > 0)
            {
                result = 1;
            }
            else if (cmp < 0)
            {
                result = 0;
            }
            else if (peer_index > previous_peer_index)
            {
                result = 1;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

static int gossipsub_rank_candidate(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index,
    uint8_t mode)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        if (mode == GOSSIPSUB_RANK_MODE_TRIM)
        {
            if (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) != 0)
            {
                result = 1;
            }
        }
        else
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL) &&
                (gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) &&
                (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) == 0) &&
                (gossipsub_backoff_active(
                     gossipsub,
                     peer_index,
                     topic_index,
                     gossipsub->last_drive_us) == 0))
            {
                result = 1;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_ranked_peer(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index,
    uint64_t salt,
    uint8_t mode,
    size_t *out_peer_index)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_peer_index == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        uint8_t have_best = 0U;
        uint64_t best_rank = 0U;
        size_t best_peer_index = 0U;

        *out_peer_index = gossipsub->config.capacity.max_peers;
        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers;
             peer_index++)
        {
            if (gossipsub_rank_candidate(gossipsub, peer_index, topic_index, mode) != 0)
            {
                const uint64_t rank = gossipsub_peer_rank(&gossipsub->peers[peer_index], salt);

                if ((have_best == 0U) || (gossipsub_rank_before(
                                              gossipsub,
                                              rank,
                                              peer_index,
                                              best_rank,
                                              best_peer_index) != 0))
                {
                    best_rank = rank;
                    best_peer_index = peer_index;
                    have_best = 1U;
                }
            }
        }
        if (have_best != 0U)
        {
            *out_peer_index = best_peer_index;
        }
    }

    return result;
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
        uint64_t salt = 0U;

        if (count < target)
        {
            result = gossipsub_random_u64(gossipsub, &salt);
        }
        while ((result == LIBP2P_GOSSIPSUB_OK) && (count < target))
        {
            size_t peer_index = gossipsub->config.capacity.max_peers;

            result = gossipsub_ranked_peer(
                gossipsub,
                topic_index,
                salt,
                GOSSIPSUB_RANK_MODE_FILL,
                &peer_index);
            if ((result == LIBP2P_GOSSIPSUB_OK) &&
                (peer_index >= gossipsub->config.capacity.max_peers))
            {
                break;
            }
            if (result == LIBP2P_GOSSIPSUB_OK)
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
        uint64_t salt = 0U;

        if (count > target)
        {
            result = gossipsub_random_u64(gossipsub, &salt);
        }
        while ((result == LIBP2P_GOSSIPSUB_OK) && (count > target))
        {
            size_t peer_index = gossipsub->config.capacity.max_peers;

            result = gossipsub_ranked_peer(
                gossipsub,
                topic_index,
                salt,
                GOSSIPSUB_RANK_MODE_TRIM,
                &peer_index);
            if ((result == LIBP2P_GOSSIPSUB_OK) &&
                (peer_index >= gossipsub->config.capacity.max_peers))
            {
                break;
            }
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                if (queue_prune != 0U)
                {
                    result = gossipsub_enqueue_prune(
                        gossipsub,
                        peer_index,
                        &gossipsub->topics[topic_index]);
                }
            }
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                if (queue_prune != 0U)
                {
                    result = gossipsub_backoff_add(
                        gossipsub,
                        peer_index,
                        topic_index,
                        gossipsub->config.mesh.prune_backoff_us,
                        gossipsub->last_drive_us);
                }
            }
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                gossipsub_mesh_remove(gossipsub, peer_index, topic_index);
                count--;
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
        for (size_t topic_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
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

static size_t gossipsub_gossip_id_limit(const libp2p_gossipsub_t *gossipsub)
{
    size_t result = 0U;

    if (gossipsub != NULL)
    {
        result = gossipsub->config.limits.max_message_ids_per_rpc;
        if (result > LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC)
        {
            result = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC;
        }
    }

    return result;
}

static size_t gossipsub_collect_gossip_ids(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_topic_state_t *topic,
    libp2p_gossipsub_bytes_t *out_ids,
    size_t out_capacity)
{
    size_t result = 0U;

    if ((gossipsub != NULL) && (topic != NULL) && (out_ids != NULL) &&
        (gossipsub->config.mesh.mcache_gossip != 0U))
    {
        for (size_t index = 0U;
             (index < gossipsub->config.capacity.mcache_slots) && (result < out_capacity);
             index++)
        {
            const gossipsub_mcache_entry_t *entry = &gossipsub->mcache[index];

            if ((entry->used != 0U) && (entry->window < gossipsub->config.mesh.mcache_gossip) &&
                (gossipsub_bytes_equal(
                     entry->topic,
                     entry->topic_len,
                     topic->topic,
                     topic->topic_len) != 0))
            {
                out_ids[result].data = entry->message_id;
                out_ids[result].len = entry->message_id_len;
                result++;
            }
        }
    }

    return result;
}

static int gossipsub_peer_gossip_eligible(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];

        if ((peer->used == GOSSIPSUB_PEER_USED) && (peer->stream != NULL) &&
            (peer->explicit_peer == 0U) &&
            (gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) &&
            (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) == 0))
        {
            result = 1;
        }
    }

    return result;
}

static size_t gossipsub_gossip_eligible_count(
    const libp2p_gossipsub_t *gossipsub,
    size_t topic_index)
{
    size_t result = 0U;

    if (gossipsub != NULL)
    {
        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers;
             peer_index++)
        {
            if (gossipsub_peer_gossip_eligible(gossipsub, peer_index, topic_index) != 0)
            {
                result++;
            }
        }
    }

    return result;
}

static size_t gossipsub_gossip_target(const libp2p_gossipsub_t *gossipsub, size_t eligible_count)
{
    size_t result = 0U;

    if ((gossipsub != NULL) && (eligible_count != 0U))
    {
        size_t factor = 0U;
        const size_t ppm = (size_t)gossipsub->config.mesh.gossip_factor_ppm;
        const size_t denominator = (size_t)GOSSIPSUB_GOSSIP_FACTOR_DENOMINATOR;

        if (ppm == 0U)
        {
            factor = 0U;
        }
        else if (eligible_count > (SIZE_MAX / ppm))
        {
            factor = eligible_count;
        }
        else
        {
            const size_t product = eligible_count * ppm;

            factor = product / denominator;
            if ((product % denominator) != 0U)
            {
                factor++;
            }
        }
        result = gossipsub->config.mesh.d_lazy;
        if (factor > result)
        {
            result = factor;
        }
        if (result > eligible_count)
        {
            result = eligible_count;
        }
    }

    return result;
}

static int gossipsub_gossip_rank_candidate(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if (gossipsub_peer_gossip_eligible(gossipsub, peer_index, topic_index) != 0)
    {
        result = 1;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_emit_topic_gossip(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index)
{
    libp2p_gossipsub_bytes_t message_ids[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC];
    size_t id_count = 0U;
    size_t eligible_count = 0U;
    size_t target = 0U;
    size_t previous_peer = 0U;
    uint64_t previous_rank = 0U;
    uint64_t salt = 0U;
    size_t sent = 0U;
    uint8_t have_previous = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(message_ids, 0, sizeof(message_ids));
    if ((gossipsub == NULL) || (topic_index >= gossipsub->config.capacity.max_topics))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        id_count = gossipsub_collect_gossip_ids(
            gossipsub,
            &gossipsub->topics[topic_index],
            message_ids,
            gossipsub_gossip_id_limit(gossipsub));
        eligible_count = gossipsub_gossip_eligible_count(gossipsub, topic_index);
        target = gossipsub_gossip_target(gossipsub, eligible_count);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (id_count != 0U) && (target != 0U) &&
        (target < eligible_count))
    {
        result = gossipsub_random_u64(gossipsub, &salt);
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (sent < target))
    {
        uint8_t have_best = 0U;
        uint64_t best_rank = 0U;
        size_t best_peer = 0U;

        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers;
             peer_index++)
        {
            if (gossipsub_gossip_rank_candidate(gossipsub, peer_index, topic_index) != 0)
            {
                const uint64_t rank = gossipsub_peer_rank(&gossipsub->peers[peer_index], salt);

                if (((have_previous == 0U) || (gossipsub_rank_after(
                                                   gossipsub,
                                                   rank,
                                                   peer_index,
                                                   previous_rank,
                                                   previous_peer) != 0)) &&
                    ((have_best == 0U) ||
                     (gossipsub_rank_before(gossipsub, rank, peer_index, best_rank, best_peer) !=
                      0)))
                {
                    best_rank = rank;
                    best_peer = peer_index;
                    have_best = 1U;
                }
            }
        }
        if (have_best == 0U)
        {
            break;
        }

        result = gossipsub_enqueue_ihave(
            gossipsub,
            best_peer,
            &gossipsub->topics[topic_index],
            message_ids,
            id_count);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            previous_rank = best_rank;
            previous_peer = best_peer;
            have_previous = 1U;
            sent++;
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_emit_gossip(libp2p_gossipsub_t *gossipsub)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (gossipsub == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t topic_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
                                      (topic_index < gossipsub->config.capacity.max_topics);
             topic_index++)
        {
            if ((gossipsub->topics[topic_index].used == GOSSIPSUB_TOPIC_USED) &&
                (gossipsub->topics[topic_index].local_subscribed != 0U))
            {
                result = gossipsub_emit_topic_gossip(gossipsub, topic_index);
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
