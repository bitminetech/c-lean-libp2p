#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t gossipsub_tx_alloc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t frame_len,
    uint8_t **out)
{
    gossipsub_tx_item_t *item = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out == NULL))
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
            item = &gossipsub->tx_queue[gossipsub->tx_queue_len];
            item->used = 1U;
            item->peer_index = peer_index;
            item->offset = gossipsub->tx_buffer_used;
            item->len = frame_len;
            item->pos = 0U;
            *out = &gossipsub->tx_buffer[gossipsub->tx_buffer_used];
            gossipsub->tx_buffer_used += frame_len;
            gossipsub->tx_queue_len++;
        }
    }

    return result;
}

void gossipsub_tx_remove(libp2p_gossipsub_t *gossipsub, size_t index)
{
    if ((gossipsub != NULL) && (index < gossipsub->tx_queue_len))
    {
        const size_t remaining = gossipsub->tx_queue_len - index - 1U;

        if (remaining != 0U)
        {
            (void)memmove(
                &gossipsub->tx_queue[index],
                &gossipsub->tx_queue[index + 1U],
                remaining * sizeof(gossipsub_tx_item_t));
        }
        gossipsub->tx_queue_len--;
        if (gossipsub->tx_queue_len == 0U)
        {
            gossipsub->tx_buffer_used = 0U;
        }
    }
}

libp2p_gossipsub_err_t gossipsub_enqueue_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc)
{
    size_t frame_len = 0U;
    size_t written = 0U;
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
        result = gossipsub_tx_alloc(gossipsub, peer_index, frame_len, &out);
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

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
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

libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&message, 0, sizeof(message));
    (void)memset(&rpc, 0, sizeof(rpc));
    gossipsub_entry_message(gossipsub, entry, &message);
    rpc.publish = &message;
    rpc.publish_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
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
    uint8_t *made_progress)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (made_progress == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->peers[peer_index].stream == NULL)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else
    {
        size_t index = 0U;
        uint8_t keep_writing = 1U;

        while ((result == LIBP2P_GOSSIPSUB_OK) && (index < gossipsub->tx_queue_len) &&
               (keep_writing != 0U))
        {
            gossipsub_tx_item_t *item = &gossipsub->tx_queue[index];

            if (item->peer_index != peer_index)
            {
                index++;
            }
            else
            {
                size_t accepted = 0U;

                result = gossipsub_host_to_err(libp2p_host_stream_write(
                    host,
                    gossipsub->peers[peer_index].stream,
                    &gossipsub->tx_buffer[item->offset + item->pos],
                    item->len - item->pos,
                    0,
                    &accepted));
                if (result == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
                {
                    result = LIBP2P_GOSSIPSUB_OK;
                    keep_writing = 0U;
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    if (accepted != 0U)
                    {
                        *made_progress = 1U;
                        item->pos += accepted;
                    }
                    if (item->pos == item->len)
                    {
                        gossipsub_tx_remove(gossipsub, index);
                    }
                    else
                    {
                        keep_writing = 0U;
                    }
                }
            }
        }
    }

    return result;
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
            ((gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) ||
             (gossipsub->config.mesh.enable_flood_publish != 0U)) &&
            (gossipsub_peer_idontwant_contains(
                 gossipsub,
                 peer_index,
                 entry->message_id,
                 entry->message_id_len,
                 gossipsub->next_heartbeat_us) == 0))
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
