#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

static uint64_t gossipsub_tx_effective_now_us(const libp2p_gossipsub_t *gossipsub)
{
    uint64_t result = 0U;

    if (gossipsub != NULL)
    {
        result = gossipsub->last_drive_us;
        if (result == 0U)
        {
            result = gossipsub->next_heartbeat_us;
        }
    }

    return result;
}

static uint64_t gossipsub_tx_deadline(uint64_t now_us, uint64_t lifetime_us)
{
    uint64_t result = 0U;

    if (lifetime_us != 0U)
    {
        result = UINT64_MAX;
        if (now_us <= (UINT64_MAX - lifetime_us))
        {
            result = now_us + lifetime_us;
        }
    }

    return result;
}

static uint64_t gossipsub_tx_backoff_seconds(uint64_t backoff_us)
{
    uint64_t result = backoff_us / UINT64_C(1000000);

    if ((backoff_us != 0U) && ((backoff_us % UINT64_C(1000000)) != 0U) &&
        (result != UINT64_MAX))
    {
        result++;
    }

    return result;
}

static int gossipsub_tx_is_mesh_route(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        if (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) != 0)
        {
            result = 1;
        }
        else if (
            (gossipsub->peers[peer_index].explicit_peer != 0U) &&
            (gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0))
        {
            result = 1;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

static void gossipsub_tx_set_peer_ready(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    uint8_t ready)
{
    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
        const uint8_t can_write = ((peer->used == GOSSIPSUB_PEER_USED) && (peer->stream != NULL) &&
                                   (peer->tx_queue_depth != 0U))
                                      ? 1U
                                      : 0U;
        const uint8_t next_ready = ((ready != 0U) && (can_write != 0U)) ? 1U : 0U;

        if ((next_ready != 0U) && (peer->tx_ready == 0U))
        {
            peer->tx_ready = 1U;
            gossipsub->tx_ready_count++;
        }
        else if ((next_ready == 0U) && (peer->tx_ready != 0U))
        {
            peer->tx_ready = 0U;
            if (gossipsub->tx_ready_count != 0U)
            {
                gossipsub->tx_ready_count--;
            }
        }
        else
        {
            peer->tx_ready = next_ready;
        }
    }
}

void gossipsub_tx_mark_peer_ready(libp2p_gossipsub_t *gossipsub, size_t peer_index, uint64_t now_us)
{
    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        gossipsub->peers[peer_index].tx_last_writable_us = now_us;
        gossipsub_tx_set_peer_ready(gossipsub, peer_index, 1U);
    }
}

static void gossipsub_tx_clear_item(gossipsub_tx_item_t *item)
{
    if (item != NULL)
    {
        (void)memset(item, 0, sizeof(*item));
        item->next = GOSSIPSUB_TX_NO_ITEM;
    }
}

static int gossipsub_tx_item_stale(const gossipsub_tx_item_t *item, uint64_t now_us)
{
    int result = 0;

    if ((item != NULL) && (item->deadline_us != 0U) && (item->pos == 0U) &&
        (now_us >= item->deadline_us))
    {
        result = 1;
    }

    return result;
}

static size_t gossipsub_tx_find_free(const libp2p_gossipsub_t *gossipsub)
{
    size_t result = GOSSIPSUB_TX_NO_ITEM;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; (index < gossipsub->config.capacity.max_tx_rpc_queue) &&
                                (result == GOSSIPSUB_TX_NO_ITEM);
             index++)
        {
            if (gossipsub->tx_queue[index].used == 0U)
            {
                result = index;
            }
        }
    }

    return result;
}

static void gossipsub_tx_recount_peer_queue(libp2p_gossipsub_t *gossipsub, size_t peer_index)
{
    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
        size_t current = peer->tx_head;
        size_t depth = 0U;
        size_t priority_depth = 0U;
        size_t tail = GOSSIPSUB_TX_NO_ITEM;
        size_t priority_tail = GOSSIPSUB_TX_NO_ITEM;

        while ((current != GOSSIPSUB_TX_NO_ITEM) &&
               (depth < gossipsub->config.capacity.max_tx_rpc_queue))
        {
            if ((current >= gossipsub->config.capacity.max_tx_rpc_queue) ||
                (gossipsub->tx_queue[current].used == 0U))
            {
                current = GOSSIPSUB_TX_NO_ITEM;
            }
            else
            {
                tail = current;
                if (gossipsub->tx_queue[current].priority != 0U)
                {
                    priority_tail = current;
                    priority_depth++;
                }
                depth++;
                current = gossipsub->tx_queue[current].next;
            }
        }
        peer->tx_tail = tail;
        peer->tx_priority_tail = priority_tail;
        peer->tx_queue_depth = depth;
        peer->tx_priority_depth = priority_depth;
    }
}

static void gossipsub_tx_append_peer_item(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t item_index,
    uint8_t priority)
{
    gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
    gossipsub_tx_item_t *item = &gossipsub->tx_queue[item_index];

    item->priority = (priority != 0U) ? 1U : 0U;
    if (peer->tx_queue_depth == 0U)
    {
        peer->tx_head = item_index;
        peer->tx_tail = item_index;
        peer->tx_priority_tail = (item->priority != 0U) ? item_index : GOSSIPSUB_TX_NO_ITEM;
    }
    else if (item->priority == 0U)
    {
        gossipsub->tx_queue[peer->tx_tail].next = item_index;
        peer->tx_tail = item_index;
    }
    else if (peer->tx_priority_tail == GOSSIPSUB_TX_NO_ITEM)
    {
        item->next = peer->tx_head;
        peer->tx_head = item_index;
        peer->tx_priority_tail = item_index;
    }
    else
    {
        const size_t previous_priority_tail = peer->tx_priority_tail;

        item->next = gossipsub->tx_queue[previous_priority_tail].next;
        gossipsub->tx_queue[previous_priority_tail].next = item_index;
        if (peer->tx_tail == previous_priority_tail)
        {
            peer->tx_tail = item_index;
        }
        peer->tx_priority_tail = item_index;
    }
    peer->tx_queue_depth++;
    if (item->priority != 0U)
    {
        peer->tx_priority_depth++;
    }
    gossipsub_tx_set_peer_ready(gossipsub, peer_index, 1U);
}

static libp2p_gossipsub_err_t gossipsub_tx_alloc_with_priority(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t frame_len,
    uint64_t lifetime_us,
    uint8_t priority,
    uint8_t **out,
    size_t *out_index)
{
    size_t item_index = GOSSIPSUB_TX_NO_ITEM;
    const uint64_t now_us = gossipsub_tx_effective_now_us(gossipsub);
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out == NULL) || (out_index == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->tx_queue_len >= gossipsub->config.capacity.max_tx_rpc_queue)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        if ((frame_len >
             (gossipsub->config.capacity.tx_buffer_bytes - gossipsub->tx_buffer_used)) &&
            (gossipsub->tx_queue_len == 0U))
        {
            gossipsub->tx_buffer_used = 0U;
        }
        if (frame_len > (gossipsub->config.capacity.tx_buffer_bytes - gossipsub->tx_buffer_used))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            item_index = gossipsub_tx_find_free(gossipsub);
            if (item_index == GOSSIPSUB_TX_NO_ITEM)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        gossipsub_tx_item_t *item = &gossipsub->tx_queue[item_index];

        gossipsub_tx_clear_item(item);
        item->used = 1U;
        item->peer_index = peer_index;
        item->offset = gossipsub->tx_buffer_used;
        item->len = frame_len;
        item->enqueued_us = now_us;
        item->deadline_us = gossipsub_tx_deadline(now_us, lifetime_us);
        *out = &gossipsub->tx_buffer[gossipsub->tx_buffer_used];
        *out_index = item_index;
        gossipsub->tx_buffer_used += frame_len;
        gossipsub->tx_queue_len++;
        gossipsub_tx_append_peer_item(gossipsub, peer_index, item_index, priority);
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_tx_alloc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t frame_len,
    uint64_t lifetime_us,
    uint8_t **out,
    size_t *out_index)
{
    return gossipsub_tx_alloc_with_priority(
        gossipsub,
        peer_index,
        frame_len,
        lifetime_us,
        0U,
        out,
        out_index);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_rpc_with_lifetime(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc,
    uint64_t lifetime_us,
    uint8_t priority,
    size_t *out_index)
{
    size_t frame_len = 0U;
    size_t written = 0U;
    size_t tx_index = GOSSIPSUB_TX_NO_ITEM;
    uint8_t *out = NULL;
    const gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (rpc == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = &gossipsub->peers[peer_index];
        if ((peer->used != GOSSIPSUB_PEER_USED) || (peer->stream == NULL))
        {
            result = LIBP2P_GOSSIPSUB_ERR_STATE;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_frame_size(
            peer->version,
            &gossipsub->config.limits,
            rpc,
            &frame_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_tx_alloc_with_priority(
            gossipsub,
            peer_index,
            frame_len,
            lifetime_us,
            priority,
            &out,
            &tx_index);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_frame_encode(
            peer->version,
            &gossipsub->config.limits,
            rpc,
            out,
            frame_len,
            &written);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (written != frame_len))
        {
            result = LIBP2P_GOSSIPSUB_ERR_INTERNAL;
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (out_index != NULL))
    {
        *out_index = tx_index;
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc)
{
    return gossipsub_enqueue_rpc_with_lifetime(gossipsub, peer_index, rpc, 0U, 0U, NULL);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_priority_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc)
{
    return gossipsub_enqueue_rpc_with_lifetime(gossipsub, peer_index, rpc, 0U, 1U, NULL);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_normal_rpc_with_lifetime(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc,
    uint64_t lifetime_us,
    size_t *out_index)
{
    return gossipsub_enqueue_rpc_with_lifetime(
        gossipsub,
        peer_index,
        rpc,
        lifetime_us,
        0U,
        out_index);
}

void gossipsub_tx_remove(libp2p_gossipsub_t *gossipsub, size_t index)
{
    if ((gossipsub != NULL) && (index < gossipsub->config.capacity.max_tx_rpc_queue) &&
        (gossipsub->tx_queue[index].used != 0U))
    {
        const size_t peer_index = gossipsub->tx_queue[index].peer_index;

        if (peer_index < gossipsub->config.capacity.max_peers)
        {
            gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
            size_t previous = GOSSIPSUB_TX_NO_ITEM;
            size_t current = peer->tx_head;
            uint8_t found = 0U;

            while ((current != GOSSIPSUB_TX_NO_ITEM) && (found == 0U))
            {
                if (current == index)
                {
                    const size_t next = gossipsub->tx_queue[current].next;

                    if (previous == GOSSIPSUB_TX_NO_ITEM)
                    {
                        peer->tx_head = next;
                    }
                    else
                    {
                        gossipsub->tx_queue[previous].next = next;
                    }
                    if (peer->tx_tail == current)
                    {
                        peer->tx_tail = previous;
                    }
                    if (peer->tx_queue_depth != 0U)
                    {
                        peer->tx_queue_depth--;
                    }
                    found = 1U;
                }
                else
                {
                    previous = current;
                    current = gossipsub->tx_queue[current].next;
                }
            }
            if (found != 0U)
            {
                gossipsub_tx_recount_peer_queue(gossipsub, peer_index);
            }
            if (peer->tx_queue_depth == 0U)
            {
                peer->tx_head = GOSSIPSUB_TX_NO_ITEM;
                peer->tx_tail = GOSSIPSUB_TX_NO_ITEM;
                peer->tx_priority_tail = GOSSIPSUB_TX_NO_ITEM;
                peer->tx_priority_depth = 0U;
                gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
            }
        }
        gossipsub_tx_clear_item(&gossipsub->tx_queue[index]);
        if (gossipsub->tx_queue_len != 0U)
        {
            gossipsub->tx_queue_len--;
        }
        if (gossipsub->tx_queue_len == 0U)
        {
            gossipsub->tx_buffer_used = 0U;
        }
    }
}

uint64_t gossipsub_tx_next_deadline(const libp2p_gossipsub_t *gossipsub, uint64_t current_deadline)
{
    uint64_t result = current_deadline;

    if (gossipsub != NULL)
    {
        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers;
             peer_index++)
        {
            const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
            size_t item_index = peer->tx_head;

            while (item_index != GOSSIPSUB_TX_NO_ITEM)
            {
                const gossipsub_tx_item_t *item = NULL;

                if (item_index >= gossipsub->config.capacity.max_tx_rpc_queue)
                {
                    item_index = GOSSIPSUB_TX_NO_ITEM;
                }
                else
                {
                    item = &gossipsub->tx_queue[item_index];
                    if ((item->used != 0U) && (item->deadline_us != 0U) && (item->pos == 0U) &&
                        (item->deadline_us < result))
                    {
                        result = item->deadline_us;
                    }
                    item_index = item->next;
                }
            }
        }
    }

    return result;
}

size_t gossipsub_tx_drop_stale(libp2p_gossipsub_t *gossipsub, uint64_t now_us)
{
    size_t result = 0U;

    if (gossipsub != NULL)
    {
        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers;
             peer_index++)
        {
            const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
            size_t item_index = peer->tx_head;

            while (item_index != GOSSIPSUB_TX_NO_ITEM)
            {
                if ((item_index >= gossipsub->config.capacity.max_tx_rpc_queue) ||
                    (gossipsub->tx_queue[item_index].used == 0U))
                {
                    item_index = GOSSIPSUB_TX_NO_ITEM;
                }
                else
                {
                    const size_t next = gossipsub->tx_queue[item_index].next;

                    if (gossipsub_tx_item_stale(&gossipsub->tx_queue[item_index], now_us) != 0)
                    {
                        gossipsub_tx_remove(gossipsub, item_index);
                        result++;
                    }
                    item_index = next;
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    uint8_t subscribe)
{
    libp2p_gossipsub_rpc_subscription_t sub;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&sub, 0, sizeof(sub));
    (void)memset(&rpc, 0, sizeof(rpc));
    sub.topic.data = topic->topic;
    sub.topic.len = topic->topic_len;
    sub.subscribe = subscribe;
    rpc.subscriptions = &sub;
    rpc.subscription_count = 1U;

    return gossipsub_enqueue_priority_rpc(gossipsub, peer_index, &rpc);
}

libp2p_gossipsub_err_t gossipsub_enqueue_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len)
{
    libp2p_gossipsub_bytes_t id;
    libp2p_gossipsub_control_idontwant_t idontwant;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&id, 0, sizeof(id));
    (void)memset(&idontwant, 0, sizeof(idontwant));
    (void)memset(&rpc, 0, sizeof(rpc));
    id.data = message_id;
    id.len = message_id_len;
    idontwant.message_ids = &id;
    idontwant.message_id_count = 1U;
    rpc.control.idontwant = &idontwant;
    rpc.control.idontwant_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

libp2p_gossipsub_err_t gossipsub_enqueue_iwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_bytes_t *message_id)
{
    libp2p_gossipsub_control_iwant_t iwant;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&iwant, 0, sizeof(iwant));
    (void)memset(&rpc, 0, sizeof(rpc));
    iwant.message_ids = message_id;
    iwant.message_id_count = 1U;
    rpc.control.iwant = &iwant;
    rpc.control.iwant_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

libp2p_gossipsub_err_t gossipsub_enqueue_ihave(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    const libp2p_gossipsub_bytes_t *message_ids,
    size_t message_id_count)
{
    libp2p_gossipsub_control_ihave_t ihave;
    libp2p_gossipsub_rpc_t rpc;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&ihave, 0, sizeof(ihave));
    (void)memset(&rpc, 0, sizeof(rpc));
    if ((topic == NULL) || (message_ids == NULL) || (message_id_count == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        ihave.topic.data = topic->topic;
        ihave.topic.len = topic->topic_len;
        ihave.message_ids = message_ids;
        ihave.message_id_count = message_id_count;
        rpc.control.ihave = &ihave;
        rpc.control.ihave_count = 1U;
        result = gossipsub_enqueue_normal_rpc_with_lifetime(
            gossipsub,
            peer_index,
            &rpc,
            GOSSIPSUB_TX_FORWARD_LIFETIME_US,
            NULL);
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_graft(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic)
{
    libp2p_gossipsub_control_graft_t graft;
    libp2p_gossipsub_rpc_t rpc;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&graft, 0, sizeof(graft));
    (void)memset(&rpc, 0, sizeof(rpc));
    if (topic == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        graft.topic.data = topic->topic;
        graft.topic.len = topic->topic_len;
        rpc.control.graft = &graft;
        rpc.control.graft_count = 1U;
        result = gossipsub_enqueue_priority_rpc(gossipsub, peer_index, &rpc);
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_prune(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic)
{
    libp2p_gossipsub_control_prune_t prune;
    libp2p_gossipsub_rpc_t rpc;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&prune, 0, sizeof(prune));
    (void)memset(&rpc, 0, sizeof(rpc));
    if ((gossipsub == NULL) || (topic == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        prune.topic.data = topic->topic;
        prune.topic.len = topic->topic_len;
        prune.backoff_seconds =
            gossipsub_tx_backoff_seconds(gossipsub->config.mesh.prune_backoff_us);
        rpc.control.prune = &prune;
        rpc.control.prune_count = 1U;
        result = gossipsub_enqueue_priority_rpc(gossipsub, peer_index, &rpc);
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry_with_lifetime(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry,
    uint64_t lifetime_us,
    uint8_t priority)
{
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_rpc_t rpc;
    size_t tx_index = GOSSIPSUB_TX_NO_ITEM;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&message, 0, sizeof(message));
    (void)memset(&rpc, 0, sizeof(rpc));
    if ((gossipsub == NULL) || (entry == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub_entry_message(gossipsub, entry, &message);
        rpc.publish = &message;
        rpc.publish_count = 1U;
        result = gossipsub_enqueue_rpc_with_lifetime(
            gossipsub,
            peer_index,
            &rpc,
            lifetime_us,
            priority,
            &tx_index);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (tx_index != GOSSIPSUB_TX_NO_ITEM))
    {
        gossipsub_tx_item_t *item = &gossipsub->tx_queue[tx_index];

        item->publish = 1U;
        item->message_id_len = entry->message_id_len;
        (void)memcpy(item->message_id, entry->message_id, entry->message_id_len);
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    return gossipsub_enqueue_publish_entry_with_lifetime(
        gossipsub,
        peer_index,
        entry,
        GOSSIPSUB_TX_FORWARD_LIFETIME_US,
        0U);
}

libp2p_gossipsub_err_t gossipsub_enqueue_local_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    return gossipsub_enqueue_publish_entry_with_lifetime(
        gossipsub,
        peer_index,
        entry,
        GOSSIPSUB_TX_LOCAL_PUBLISH_LIFETIME_US,
        1U);
}

libp2p_gossipsub_err_t gossipsub_enqueue_idontwant_for_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    const gossipsub_mcache_entry_t *entry)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic == NULL) || (entry == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (gossipsub->peers[peer_index].version == LIBP2P_GOSSIPSUB_VERSION_12) &&
        (gossipsub->config.enable_idontwant != 0U) && (topic->enable_idontwant != 0U) &&
        (entry->data_len >= topic->idontwant_min_message_bytes) &&
        (gossipsub->peers[peer_index].idontwant_sent_this_heartbeat <
         gossipsub->config.max_idontwant_messages_per_peer_per_heartbeat))
    {
        result = gossipsub_enqueue_idontwant(
            gossipsub,
            peer_index,
            entry->message_id,
            entry->message_id_len);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            gossipsub->peers[peer_index].idontwant_sent_this_heartbeat++;
        }
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_flush_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    size_t peer_index,
    uint64_t now_us,
    uint8_t *made_progress,
    size_t *rpcs_sent)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (made_progress == NULL) || (rpcs_sent == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->peers[peer_index].stream == NULL)
    {
        gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
    }
    else
    {
        gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
        size_t bytes_written = 0U;
        uint8_t keep_writing = 1U;
        uint8_t peer_blocked = 0U;

        while ((result == LIBP2P_GOSSIPSUB_OK) && (peer->tx_queue_depth != 0U) &&
               (keep_writing != 0U) && (bytes_written < GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE))
        {
            const size_t item_index = peer->tx_head;

            if ((item_index == GOSSIPSUB_TX_NO_ITEM) ||
                (item_index >= gossipsub->config.capacity.max_tx_rpc_queue) ||
                (gossipsub->tx_queue[item_index].used == 0U))
            {
                gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
                keep_writing = 0U;
            }
            else if (gossipsub_tx_item_stale(&gossipsub->tx_queue[item_index], now_us) != 0)
            {
                gossipsub_tx_remove(gossipsub, item_index);
                *made_progress = 1U;
            }
            else
            {
                gossipsub_tx_item_t *item = &gossipsub->tx_queue[item_index];
                const size_t remaining = item->len - item->pos;
                size_t write_len = GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE - bytes_written;
                size_t accepted = 0U;
                uint8_t blocked = 0U;

                if (write_len > remaining)
                {
                    write_len = remaining;
                }
                result = gossipsub_host_to_err(libp2p_host_stream_write(
                    host,
                    peer->stream,
                    &gossipsub->tx_buffer[item->offset + item->pos],
                    write_len,
                    0,
                    &accepted));
                if (result == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
                {
                    result = LIBP2P_GOSSIPSUB_OK;
                    blocked = 1U;
                    peer_blocked = 1U;
                    peer->tx_would_block_count++;
                    gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
                    keep_writing = 0U;
                }
                if ((result == LIBP2P_GOSSIPSUB_OK) && (blocked == 0U))
                {
                    if (accepted != 0U)
                    {
                        *made_progress = 1U;
                        item->pos += accepted;
                        bytes_written += accepted;
                        peer->tx_last_offset = item->pos;
                        peer->tx_bytes_accepted += (uint64_t)accepted;
                    }
                    if (item->pos == item->len)
                    {
                        gossipsub_tx_remove(gossipsub, item_index);
                        (*rpcs_sent)++;
                    }
                    else if (accepted == 0U)
                    {
                        peer_blocked = 1U;
                        peer->tx_would_block_count++;
                        gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
                        keep_writing = 0U;
                    }
                    else
                    {
                        keep_writing = 0U;
                    }
                }
            }
        }
        if (peer->tx_queue_depth != 0U)
        {
            if (peer_blocked != 0U)
            {
                gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
            }
            else if (bytes_written != 0U)
            {
                gossipsub_tx_set_peer_ready(gossipsub, peer_index, 1U);
            }
            else
            {
                gossipsub_tx_set_peer_ready(gossipsub, peer_index, peer->tx_ready);
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_flush_ready_peers(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    uint64_t now_us,
    uint8_t *made_progress,
    size_t *rpcs_sent)
{
    size_t visited = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (made_progress == NULL) || (rpcs_sent == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub->tx_ready_count != 0U) &&
           (visited < gossipsub->config.capacity.max_peers))
    {
        const size_t peer_index = gossipsub->tx_next_peer;
        const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];

        gossipsub->tx_next_peer =
            (gossipsub->tx_next_peer + 1U) % gossipsub->config.capacity.max_peers;
        visited++;
        if ((peer->tx_ready != 0U) && (peer->tx_queue_depth != 0U))
        {
            uint8_t peer_progress = 0U;

            result = gossipsub_flush_peer(
                gossipsub,
                host,
                peer_index,
                now_us,
                &peer_progress,
                rpcs_sent);
            if (peer_progress != 0U)
            {
                *made_progress = 1U;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_enqueue_idontwant_for_received_entry(
    libp2p_gossipsub_t *gossipsub,
    const gossipsub_topic_state_t *topic,
    const gossipsub_mcache_entry_t *entry)
{
    size_t topic_index = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic == NULL) || (entry == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub_find_topic(gossipsub, entry->topic, entry->topic_len, &topic_index) == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
    }
    else
    {
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL) &&
                (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) != 0))
            {
                result = gossipsub_enqueue_idontwant_for_entry(gossipsub, peer_index, topic, entry);
            }
        }
    }

    return result;
}

void gossipsub_drop_queued_publish(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len)
{
    if ((gossipsub != NULL) && (message_id != NULL) &&
        (peer_index < gossipsub->config.capacity.max_peers))
    {
        const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];
        size_t item_index = peer->tx_head;

        while (item_index != GOSSIPSUB_TX_NO_ITEM)
        {
            const gossipsub_tx_item_t *item = &gossipsub->tx_queue[item_index];
            const size_t next = item->next;

            if ((item->publish != 0U) && (item->pos == 0U) &&
                (item->message_id_len == message_id_len) &&
                (memcmp(item->message_id, message_id, message_id_len) == 0))
            {
                gossipsub_tx_remove(gossipsub, item_index);
            }
            item_index = next;
        }
    }
}

void gossipsub_drop_queued_peer(libp2p_gossipsub_t *gossipsub, size_t peer_index)
{
    if ((gossipsub != NULL) && (peer_index < gossipsub->config.capacity.max_peers))
    {
        const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];

        while (peer->tx_head != GOSSIPSUB_TX_NO_ITEM)
        {
            gossipsub_tx_remove(gossipsub, peer->tx_head);
        }
        gossipsub_tx_set_peer_ready(gossipsub, peer_index, 0U);
    }
}

libp2p_gossipsub_err_t gossipsub_forward_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t source_peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    size_t topic_index = 0U;
    size_t peer_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (entry == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        topic = gossipsub_find_topic(gossipsub, entry->topic, entry->topic_len, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
    }
    for (peer_index = 0U;
         (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
         peer_index++)
    {
        if ((peer_index != source_peer_index) &&
            (gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
            (gossipsub->peers[peer_index].stream != NULL) &&
            (gossipsub_tx_is_mesh_route(gossipsub, peer_index, topic_index) != 0) &&
            (gossipsub_peer_idontwant_contains(
                 gossipsub,
                 peer_index,
                 entry->message_id,
                 entry->message_id_len,
                 gossipsub_tx_effective_now_us(gossipsub)) == 0))
        {
            result = gossipsub_enqueue_idontwant_for_entry(gossipsub, peer_index, topic, entry);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_enqueue_publish_entry(gossipsub, peer_index, entry);
            }
        }
    }
    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_tx_peer_stats(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    libp2p_host_time_us_t now_us,
    libp2p_gossipsub_tx_peer_stats_t *out_stats)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_stats == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];

        (void)memset(out_stats, 0, sizeof(*out_stats));
        out_stats->used = (peer->used == GOSSIPSUB_PEER_USED) ? 1U : 0U;
        out_stats->ready = peer->tx_ready;
        out_stats->queue_depth = peer->tx_queue_depth;
        out_stats->last_writable_us = peer->tx_last_writable_us;
        out_stats->last_tx_offset = peer->tx_last_offset;
        out_stats->bytes_accepted = peer->tx_bytes_accepted;
        out_stats->would_block_count = peer->tx_would_block_count;
        if ((peer->tx_head != GOSSIPSUB_TX_NO_ITEM) &&
            (peer->tx_head < gossipsub->config.capacity.max_tx_rpc_queue))
        {
            const gossipsub_tx_item_t *item = &gossipsub->tx_queue[peer->tx_head];

            if (item->used != 0U)
            {
                out_stats->current_publish = item->publish;
                out_stats->current_pos = item->pos;
                out_stats->current_len = item->len;
                if (now_us >= item->enqueued_us)
                {
                    out_stats->oldest_age_us = now_us - item->enqueued_us;
                }
            }
        }
    }

    return result;
}

struct libp2p_gossipsub_validation *gossipsub_alloc_validation(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t mcache_index,
    uint64_t now_us)
{
    struct libp2p_gossipsub_validation *result = NULL;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.pending_validations; index++)
        {
            if (gossipsub->validations[index].state == GOSSIPSUB_VALIDATION_FREE)
            {
                result = &gossipsub->validations[index];
                result->state = GOSSIPSUB_VALIDATION_PENDING;
                result->peer_index = peer_index;
                result->mcache_index = mcache_index;
                result->expires_us = now_us + gossipsub->config.mesh.iwant_followup_us;
                break;
            }
        }
    }

    return result;
}
