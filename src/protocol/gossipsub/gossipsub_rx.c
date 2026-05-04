#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

static uint64_t gossipsub_rx_prune_backoff_us(
    const libp2p_gossipsub_t *gossipsub,
    uint64_t backoff_seconds)
{
    static const uint64_t us_per_second = 1000000ULL;
    uint64_t result = 0U;

    if (gossipsub != NULL)
    {
        result = gossipsub->config.mesh.prune_backoff_us;
        if (backoff_seconds != 0U)
        {
            if (backoff_seconds > (UINT64_MAX / us_per_second))
            {
                result = UINT64_MAX;
            }
            else
            {
                result = backoff_seconds * us_per_second;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_process_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_subscription_t *sub)
{
    size_t topic_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_peer_topic_state_t *edge = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (sub == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        topic = gossipsub_find_or_add_topic(gossipsub, sub->topic, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        edge = gossipsub_find_or_add_peer_topic(gossipsub, peer_index, topic_index);
        if (edge == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            edge->subscribed = sub->subscribe;
            event.type = LIBP2P_GOSSIPSUB_EVENT_SUBSCRIPTION;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.topic.data = topic->topic;
            event.topic.len = topic->topic_len;
            result = gossipsub_event_push(gossipsub, &event);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (topic != NULL) && (sub->subscribe != 0U) &&
        (topic->local_subscribed != 0U) &&
        (gossipsub_mesh_count_topic(gossipsub, topic_index) < gossipsub->config.mesh.d_low))
    {
        result = gossipsub_mesh_fill_topic(gossipsub, topic_index, gossipsub->config.mesh.d, 1U);
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (sub != NULL) && (sub->subscribe == 0U))
    {
        gossipsub_mesh_remove(gossipsub, peer_index, topic_index);
    }
    else
    {
        /* No mesh change is needed for this subscription update. */
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_process_message(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_message_t *message,
    uint64_t now_us)
{
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(message_id, 0, sizeof(message_id));
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (message == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_compute_message_id(
            gossipsub,
            message,
            message_id,
            sizeof(message_id),
            &message_id_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_seen_contains(gossipsub, message_id, message_id_len, now_us) != 0)
        {
            event.type = LIBP2P_GOSSIPSUB_EVENT_DROPPED;
            event.drop_reason = LIBP2P_GOSSIPSUB_DROP_DUPLICATE_MESSAGE;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.message_id.data = message_id;
            event.message_id.len = message_id_len;
            result = gossipsub_event_push(gossipsub, &event);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = LIBP2P_GOSSIPSUB_ERR_DUPLICATE;
            }
        }
        else
        {
            gossipsub_seen_add(gossipsub, message_id, message_id_len, now_us);
            gossipsub_autopsy_observe_message(
                message_id,
                message_id_len,
                gossipsub->peers[peer_index].peer_id,
                gossipsub->peers[peer_index].peer_id_len,
                now_us);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        topic =
            gossipsub_find_topic(gossipsub, message->topic.data, message->topic.len, &topic_index);
        if ((topic == NULL) || (topic->local_subscribed == 0U))
        {
            event.type = LIBP2P_GOSSIPSUB_EVENT_DROPPED;
            event.drop_reason = LIBP2P_GOSSIPSUB_DROP_UNSUBSCRIBED_TOPIC;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.topic = message->topic;
            event.message_id.data = message_id;
            event.message_id.len = message_id_len;
            result = gossipsub_event_push(gossipsub, &event);
        }
        else
        {
            result = gossipsub_mcache_store(
                gossipsub,
                message_id,
                message_id_len,
                message->topic,
                message->data,
                &entry,
                &mcache_index);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (entry != NULL) && (topic != NULL))
    {
        result = gossipsub_enqueue_idontwant_for_received_entry(gossipsub, topic, entry);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (entry != NULL) && (topic != NULL))
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_MESSAGE;
        gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
        event.topic.data = entry->topic;
        event.topic.len = entry->topic_len;
        event.message_id.data = entry->message_id;
        event.message_id.len = entry->message_id_len;
        gossipsub_entry_message(gossipsub, entry, &event.message);
        if (topic->validation_mode == LIBP2P_GOSSIPSUB_VALIDATION_REQUIRE_APP)
        {
            event.validation =
                gossipsub_alloc_validation(gossipsub, peer_index, mcache_index, now_us);
            if (event.validation == NULL)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_event_push(gossipsub, &event);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) &&
            (topic->validation_mode == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL))
        {
            result = gossipsub_forward_entry(gossipsub, peer_index, entry);
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_process_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    uint64_t now_us)
{
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (idontwant == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < idontwant->message_id_count);
             index++)
        {
            gossipsub_peer_idontwant_add(
                gossipsub,
                peer_index,
                idontwant->message_ids[index].data,
                idontwant->message_ids[index].len,
                now_us);
            gossipsub_drop_queued_publish(
                gossipsub,
                peer_index,
                idontwant->message_ids[index].data,
                idontwant->message_ids[index].len);
            event.type = LIBP2P_GOSSIPSUB_EVENT_IDONTWANT;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.message_id = idontwant->message_ids[index];
            event.idontwant = *idontwant;
            result = gossipsub_event_push(gossipsub, &event);
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_process_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc,
    uint64_t now_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (rpc == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->subscription_count);
             index++)
        {
            result =
                gossipsub_process_subscription(gossipsub, peer_index, &rpc->subscriptions[index]);
        }
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->publish_count);
             index++)
        {
            result = gossipsub_process_message(gossipsub, peer_index, &rpc->publish[index], now_us);
            if (result == LIBP2P_GOSSIPSUB_ERR_DUPLICATE)
            {
                result = LIBP2P_GOSSIPSUB_OK;
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.idontwant_count);
             index++)
        {
            result = gossipsub_process_idontwant(
                gossipsub,
                peer_index,
                &rpc->control.idontwant[index],
                now_us);
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.graft_count);
             index++)
        {
            size_t topic_index = 0U;
            const gossipsub_topic_state_t *topic = gossipsub_find_or_add_topic(
                gossipsub,
                rpc->control.graft[index].topic,
                &topic_index);

            if (topic == NULL)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else if (topic->local_subscribed == 0U)
            {
                result = gossipsub_enqueue_prune(gossipsub, peer_index, topic);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    result = gossipsub_backoff_add(
                        gossipsub,
                        peer_index,
                        topic_index,
                        gossipsub->config.mesh.prune_backoff_us,
                        now_us);
                }
            }
            else if (gossipsub_backoff_active(gossipsub, peer_index, topic_index, now_us) != 0)
            {
                result = gossipsub_enqueue_prune(gossipsub, peer_index, topic);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    result = gossipsub_backoff_add(
                        gossipsub,
                        peer_index,
                        topic_index,
                        gossipsub->config.mesh.prune_backoff_us,
                        now_us);
                }
            }
            else if (
                (gossipsub_mesh_contains(gossipsub, peer_index, topic_index) != 0) ||
                (gossipsub_mesh_count_topic(gossipsub, topic_index) < gossipsub->config.mesh.d_high))
            {
                result = gossipsub_mesh_add(gossipsub, peer_index, topic_index);
            }
            else
            {
                result = gossipsub_enqueue_prune(gossipsub, peer_index, topic);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    result = gossipsub_backoff_add(
                        gossipsub,
                        peer_index,
                        topic_index,
                        gossipsub->config.mesh.prune_backoff_us,
                        now_us);
                }
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.prune_count);
             index++)
        {
            size_t topic_index = 0U;

            if (gossipsub_find_topic(
                    gossipsub,
                    rpc->control.prune[index].topic.data,
                    rpc->control.prune[index].topic.len,
                    &topic_index) != NULL)
            {
                gossipsub_mesh_remove(gossipsub, peer_index, topic_index);
                result = gossipsub_backoff_add(
                    gossipsub,
                    peer_index,
                    topic_index,
                    gossipsub_rx_prune_backoff_us(
                        gossipsub,
                        rpc->control.prune[index].backoff_seconds),
                    now_us);
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.iwant_count);
             index++)
        {
            for (size_t id_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
                                       (id_index < rpc->control.iwant[index].message_id_count);
                 id_index++)
            {
                const gossipsub_mcache_entry_t *entry = gossipsub_mcache_find(
                    gossipsub,
                    rpc->control.iwant[index].message_ids[id_index].data,
                    rpc->control.iwant[index].message_ids[id_index].len);

                if (entry != NULL)
                {
                    result = gossipsub_enqueue_publish_entry(gossipsub, peer_index, entry);
                }
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.ihave_count);
             index++)
        {
            for (size_t id_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
                                       (id_index < rpc->control.ihave[index].message_id_count);
                 id_index++)
            {
                if (gossipsub_seen_contains(
                        gossipsub,
                        rpc->control.ihave[index].message_ids[id_index].data,
                        rpc->control.ihave[index].message_ids[id_index].len,
                        now_us) == 0)
                {
                    result = gossipsub_enqueue_iwant(
                        gossipsub,
                        peer_index,
                        &rpc->control.ihave[index].message_ids[id_index]);
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_stream_decode_available(
    libp2p_gossipsub_t *gossipsub,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us)
{
    libp2p_gossipsub_rpc_subscription_t subs[LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC];
    libp2p_gossipsub_message_t publish[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC];
    libp2p_gossipsub_control_ihave_t ihave[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC];
    libp2p_gossipsub_control_iwant_t iwant[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC];
    libp2p_gossipsub_control_graft_t graft[LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC];
    libp2p_gossipsub_control_prune_t prune[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC];
    libp2p_gossipsub_control_idontwant_t idontwant[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC];
    libp2p_gossipsub_bytes_t ids[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC];
    libp2p_gossipsub_peer_info_t peers[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC];
    libp2p_gossipsub_rpc_decode_storage_t storage;
    libp2p_gossipsub_rpc_t rpc;
    uint8_t keep_decoding = 1U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&storage, 0, sizeof(storage));
    (void)memset(&rpc, 0, sizeof(rpc));
    (void)memset(subs, 0, sizeof(subs));
    (void)memset(publish, 0, sizeof(publish));
    (void)memset(ihave, 0, sizeof(ihave));
    (void)memset(iwant, 0, sizeof(iwant));
    (void)memset(graft, 0, sizeof(graft));
    (void)memset(prune, 0, sizeof(prune));
    (void)memset(idontwant, 0, sizeof(idontwant));
    (void)memset(ids, 0, sizeof(ids));
    (void)memset(peers, 0, sizeof(peers));
    storage.subscriptions = subs;
    storage.subscription_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC;
    storage.publish = publish;
    storage.publish_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC;
    storage.ihave = ihave;
    storage.ihave_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC;
    storage.iwant = iwant;
    storage.iwant_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC;
    storage.graft = graft;
    storage.graft_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC;
    storage.prune = prune;
    storage.prune_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC;
    storage.idontwant = idontwant;
    storage.idontwant_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC;
    storage.message_ids = ids;
    storage.message_id_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC;
    storage.peer_infos = peers;
    storage.peer_info_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC;

    if ((gossipsub == NULL) || (stream_state == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (stream_state->rx_len != 0U) && (keep_decoding != 0U))
    {
        uint64_t body_len = 0U;
        size_t read_pos = 0U;

        result =
            gossipsub_read_uvarint(stream_state->rx, stream_state->rx_len, &read_pos, &body_len);
        if (result == LIBP2P_GOSSIPSUB_ERR_TRUNCATED)
        {
            result = LIBP2P_GOSSIPSUB_OK;
            keep_decoding = 0U;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const size_t header_len = read_pos;

            if (body_len > (uint64_t)gossipsub->config.limits.max_rpc_bytes)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else if ((stream_state->rx_len - header_len) < (size_t)body_len)
            {
                keep_decoding = 0U;
            }
            else
            {
                (void)memset(&rpc, 0, sizeof(rpc));
                result = libp2p_gossipsub_rpc_body_decode(
                    stream_state->version,
                    &gossipsub->config.limits,
                    &stream_state->rx[header_len],
                    (size_t)body_len,
                    &storage,
                    &rpc);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    result =
                        gossipsub_process_rpc(gossipsub, stream_state->peer_index, &rpc, now_us);
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    const size_t pos = header_len + (size_t)body_len;

                    if (pos < stream_state->rx_len)
                    {
                        const size_t remaining = stream_state->rx_len - pos;

                        (void)memmove(stream_state->rx, &stream_state->rx[pos], remaining);
                        stream_state->rx_len = remaining;
                    }
                    else
                    {
                        stream_state->rx_len = 0U;
                    }
                }
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_stream_read(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us)
{
    size_t read_len = 0U;
    uint8_t keep_reading = 1U;
    int fin = 0;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (stream_state == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub->last_drive_us = now_us;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (keep_reading != 0U))
    {
        if (stream_state->rx_len >=
            (gossipsub->config.limits.max_rpc_bytes + LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_host_to_err(libp2p_host_stream_read(
                host,
                stream_state->stream,
                &stream_state->rx[stream_state->rx_len],
                (gossipsub->config.limits.max_rpc_bytes + LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES) -
                    stream_state->rx_len,
                &read_len,
                &fin));
        }
        if (result == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
        {
            result = LIBP2P_GOSSIPSUB_OK;
            keep_reading = 0U;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            stream_state->rx_len += read_len;
            if (read_len != 0U)
            {
                result = gossipsub_stream_decode_available(gossipsub, stream_state, now_us);
            }
            if ((fin != 0) || (read_len == 0U))
            {
                keep_reading = 0U;
            }
        }
    }

    return result;
}
