#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t libp2p_gossipsub_subscribe(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_topic_config_t *topic)
{
    size_t topic_index = 0U;
    gossipsub_topic_state_t *state = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic == NULL) || (topic->topic.data == NULL) ||
        (topic->topic.len == 0U) || (topic->topic.len > gossipsub->config.limits.max_topic_bytes) ||
        (topic->idontwant_min_message_bytes > gossipsub->config.limits.max_message_data_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        state = gossipsub_find_or_add_topic(gossipsub, topic->topic, &topic_index);
        if (state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        state->local_subscribed = 1U;
        state->validation_mode = topic->validation_mode;
        state->enable_idontwant = topic->enable_idontwant;
        state->idontwant_min_message_bytes = topic->idontwant_min_message_bytes;
        if (state->idontwant_min_message_bytes == 0U)
        {
            state->idontwant_min_message_bytes = gossipsub->config.idontwant_min_message_bytes;
        }
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_enqueue_subscription(gossipsub, peer_index, state, 1U);
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_unsubscribe(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic)
{
    size_t topic_index = 0U;
    gossipsub_topic_state_t *state = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic.data == NULL) || (topic.len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        state = gossipsub_find_topic(gossipsub, topic.data, topic.len, &topic_index);
        if (state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        state->local_subscribed = 0U;
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_enqueue_subscription(gossipsub, peer_index, state, 0U);
            }
        }
    }
    (void)topic_index;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_publish(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_publish_t *publish,
    uint8_t *out_message_id,
    size_t out_message_id_len,
    size_t *written)
{
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(message_id, 0, sizeof(message_id));
    (void)memset(&message, 0, sizeof(message));
    if ((gossipsub == NULL) || (publish == NULL) || (publish->topic.data == NULL) ||
        (publish->topic.len == 0U) ||
        (publish->topic.len > gossipsub->config.limits.max_topic_bytes) ||
        ((publish->data.data == NULL) && (publish->data.len != 0U)) ||
        (publish->data.len > gossipsub->config.limits.max_message_data_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        message.topic = publish->topic;
        message.data = publish->data;
        if (gossipsub_bytes_present(&publish->message_id) != 0)
        {
            if (publish->message_id.len > gossipsub->config.limits.max_message_id_bytes)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else
            {
                message_id_len = publish->message_id.len;
                (void)memcpy(message_id, publish->message_id.data, message_id_len);
            }
        }
        else
        {
            result = gossipsub_compute_message_id(
                gossipsub,
                &message,
                message_id,
                sizeof(message_id),
                &message_id_len);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (written != NULL)
        {
            *written = message_id_len;
        }
        if ((out_message_id != NULL) && (out_message_id_len < message_id_len))
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
        else if (out_message_id != NULL)
        {
            (void)memcpy(out_message_id, message_id, message_id_len);
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        topic = gossipsub_find_or_add_topic(gossipsub, publish->topic, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_mcache_store(
            gossipsub,
            message_id,
            message_id_len,
            publish->topic,
            publish->data,
            &entry,
            &mcache_index);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        gossipsub_seen_add(gossipsub, message_id, message_id_len, gossipsub->next_heartbeat_us);
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_enqueue_idontwant_for_entry(gossipsub, peer_index, topic, entry);
                if ((result == LIBP2P_GOSSIPSUB_OK) &&
                    ((gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) ||
                     (gossipsub->config.mesh.enable_flood_publish != 0U)))
                {
                    result = gossipsub_enqueue_local_publish_entry(gossipsub, peer_index, entry);
                }
            }
        }
    }
    (void)mcache_index;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_report_validation(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_validation_t *validation,
    libp2p_gossipsub_validation_result_t result_value)
{
    const gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (validation == NULL) ||
        (validation->state != GOSSIPSUB_VALIDATION_PENDING) ||
        (validation->mcache_index >= gossipsub->config.capacity.mcache_slots))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        entry = &gossipsub->mcache[validation->mcache_index];
        if (entry->used == 0U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_STATE;
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (result_value == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT))
    {
        result = gossipsub_forward_entry(gossipsub, validation->peer_index, entry);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        validation->state = GOSSIPSUB_VALIDATION_FREE;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_next_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_event_t *out_event)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->event_len == 0U)
    {
        result = LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK;
    }
    else
    {
        *out_event = gossipsub->events[gossipsub->event_head];
        gossipsub->event_head =
            (gossipsub->event_head + 1U) % gossipsub->config.capacity.event_capacity;
        gossipsub->event_len--;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_set_peer_explicit(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    uint8_t is_explicit)
{
    size_t peer_index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            peer->explicit_peer = (is_explicit != 0U) ? 1U : 0U;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_peer_protocol_version(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_gossipsub_protocol_version_t *out_version)
{
    size_t peer_index = 0U;
    const gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (out_version != NULL)
    {
        *out_version = LIBP2P_GOSSIPSUB_VERSION_NONE;
    }
    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U) || (out_version == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer_const(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            *out_version = peer->version;
        }
    }

    return result;
}
