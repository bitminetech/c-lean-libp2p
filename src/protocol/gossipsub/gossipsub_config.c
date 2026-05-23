#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t gossipsub_config_validate_storage(const libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (config == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_limits_validate(&config->limits);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if ((config->capacity.max_topics == 0U) || (config->capacity.max_peers == 0U) ||
            (config->capacity.max_peer_topics == 0U) || (config->capacity.max_streams == 0U) ||
            (config->capacity.max_mesh_edges == 0U) ||
            (config->capacity.max_backoff_entries == 0U) ||
            (config->capacity.max_peer_tx_queue == 0U) ||
            (config->capacity.max_tx_rpc_queue == 0U) || (config->capacity.tx_buffer_bytes == 0U) ||
            (config->capacity.mcache_slots == 0U) || (config->capacity.mcache_bytes == 0U) ||
            (config->capacity.seen_entries == 0U) || (config->capacity.pending_validations == 0U) ||
            (config->capacity.idontwant_entries == 0U) || (config->capacity.event_capacity == 0U) ||
            (config->capacity.max_drive_steps == 0U) || (config->mesh.mcache_len == 0U) ||
            (config->mesh.mcache_len > UINT8_MAX) ||
            (config->mesh.mcache_gossip > config->mesh.mcache_len) ||
            (config->protocol_mask == 0U) ||
            ((config->protocol_mask & ~LIBP2P_GOSSIPSUB_PROTOCOL_MASK_ALL) != 0U) ||
            (config->idontwant_min_message_bytes > config->limits.max_message_data_bytes))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_config_validate_init(const libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = gossipsub_config_validate_storage(config);

    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((config->random_fn == NULL) || (config->message_id_fn == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_storage_layout(
    const libp2p_gossipsub_config_t *config,
    gossipsub_storage_layout_t *layout)
{
    size_t cursor = 0U;
    size_t bytes = 0U;
    libp2p_gossipsub_err_t result = gossipsub_config_validate_storage(config);

    if ((result == LIBP2P_GOSSIPSUB_OK) && (layout == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        (void)memset(layout, 0, sizeof(*layout));
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            sizeof(libp2p_gossipsub_t),
            &layout->router_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_topics,
                sizeof(gossipsub_topic_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->topics_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_peers,
                sizeof(gossipsub_peer_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->peers_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_peer_topics,
                sizeof(gossipsub_peer_topic_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->peer_topics_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_mesh_edges,
                sizeof(gossipsub_mesh_edge_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->mesh_edges_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_backoff_entries,
                sizeof(gossipsub_backoff_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->backoff_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_streams,
                sizeof(gossipsub_stream_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->streams_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_add(
                config->limits.max_rpc_bytes,
                LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES,
                &layout->stream_rx_max_cap) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            layout->stream_rx_stride = GOSSIPSUB_STREAM_RX_SMALL_CAP;
            if (layout->stream_rx_stride > layout->stream_rx_max_cap)
            {
                layout->stream_rx_stride = layout->stream_rx_max_cap;
            }
            if (gossipsub_size_mul(
                    config->capacity.max_streams,
                    layout->stream_rx_stride,
                    &bytes) != 0)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->stream_rx_offset);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (layout->stream_rx_max_cap > layout->stream_rx_stride))
    {
        size_t pool_streams = config->capacity.max_streams;

        if (pool_streams > GOSSIPSUB_STREAM_RX_LARGE_POOL_STREAMS)
        {
            pool_streams = GOSSIPSUB_STREAM_RX_LARGE_POOL_STREAMS;
        }
        if (gossipsub_size_mul(pool_streams, layout->stream_rx_max_cap, &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            layout->stream_rx_buffer_cap = bytes;
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                layout->stream_rx_buffer_cap,
                &layout->stream_rx_buffer_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_tx_rpc_queue,
                sizeof(gossipsub_tx_item_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->tx_queue_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            config->capacity.tx_buffer_bytes,
            &layout->tx_buffer_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.mcache_slots,
                sizeof(gossipsub_mcache_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->mcache_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            config->capacity.mcache_bytes,
            &layout->mcache_data_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.seen_entries,
                sizeof(gossipsub_seen_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->seen_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.pending_validations,
                sizeof(struct libp2p_gossipsub_validation),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->validations_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.idontwant_entries,
                sizeof(gossipsub_idontwant_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->idontwant_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.event_capacity,
                sizeof(libp2p_gossipsub_event_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->events_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        layout->total = cursor;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_config_default(libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (config == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
        config->limits.max_rpc_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_RPC_BYTES;
        config->limits.max_message_data_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_DATA_BYTES;
        config->limits.max_topic_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES;
        config->limits.max_message_id_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES;
        config->limits.max_signed_peer_record_bytes =
            LIBP2P_GOSSIPSUB_DEFAULT_MAX_SIGNED_PEER_REC_BYTES;
        config->limits.max_subscriptions_per_rpc =
            LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC;
        config->limits.max_publish_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC;
        config->limits.max_ihave_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC;
        config->limits.max_iwant_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC;
        config->limits.max_graft_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC;
        config->limits.max_prune_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC;
        config->limits.max_idontwant_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC;
        config->limits.max_message_ids_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC;
        config->limits.max_px_peers_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC;

        config->mesh.d = LIBP2P_GOSSIPSUB_DEFAULT_D;
        config->mesh.d_low = LIBP2P_GOSSIPSUB_DEFAULT_D_LOW;
        config->mesh.d_high = LIBP2P_GOSSIPSUB_DEFAULT_D_HIGH;
        config->mesh.d_lazy = LIBP2P_GOSSIPSUB_DEFAULT_D_LAZY;
        config->mesh.d_out = LIBP2P_GOSSIPSUB_DEFAULT_D_OUT;
        config->mesh.mcache_len = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_LEN;
        config->mesh.mcache_gossip = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_GOSSIP;
        config->mesh.gossip_factor_ppm = LIBP2P_GOSSIPSUB_DEFAULT_GOSSIP_FACTOR_PPM;
        config->mesh.heartbeat_interval_us = LIBP2P_GOSSIPSUB_DEFAULT_HEARTBEAT_US;
        config->mesh.fanout_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_FANOUT_TTL_US;
        config->mesh.seen_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_SEEN_TTL_US;
        config->mesh.prune_backoff_us = LIBP2P_GOSSIPSUB_DEFAULT_PRUNE_BACKOFF_US;
        config->mesh.unsubscribe_backoff_us = LIBP2P_GOSSIPSUB_DEFAULT_UNSUBSCRIBE_BACKOFF_US;
        config->mesh.backoff_slack_us = LIBP2P_GOSSIPSUB_DEFAULT_BACKOFF_SLACK_US;
        config->mesh.iwant_followup_us = LIBP2P_GOSSIPSUB_DEFAULT_IWANT_FOLLOWUP_US;
        config->mesh.enable_flood_publish = 1U;
        config->mesh.enable_px = 0U;

        config->capacity.max_topics = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPICS;
        config->capacity.max_peers = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEERS;
        config->capacity.max_peer_topics = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEER_TOPICS;
        config->capacity.max_mesh_edges = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESH_EDGES;
        config->capacity.max_fanout_edges = LIBP2P_GOSSIPSUB_DEFAULT_MAX_FANOUT_EDGES;
        config->capacity.max_backoff_entries = LIBP2P_GOSSIPSUB_DEFAULT_MAX_BACKOFF_ENTRIES;
        config->capacity.max_streams = LIBP2P_GOSSIPSUB_DEFAULT_MAX_STREAMS;
        config->capacity.max_pending_opens = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PENDING_OPENS;
        config->capacity.max_peer_tx_queue = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEER_TX_QUEUE;
        config->capacity.max_tx_rpc_queue = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TX_RPC_QUEUE;
        config->capacity.tx_buffer_bytes = LIBP2P_GOSSIPSUB_DEFAULT_TX_BUFFER_BYTES;
        config->capacity.mcache_slots = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_SLOTS;
        config->capacity.mcache_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_BYTES;
        config->capacity.seen_entries = LIBP2P_GOSSIPSUB_DEFAULT_SEEN_ENTRIES;
        config->capacity.pending_validations = LIBP2P_GOSSIPSUB_DEFAULT_PENDING_VALIDATIONS;
        config->capacity.idontwant_entries = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_ENTRIES;
        config->capacity.event_capacity = LIBP2P_GOSSIPSUB_DEFAULT_EVENT_CAPACITY;
        config->capacity.max_drive_steps = LIBP2P_GOSSIPSUB_DEFAULT_MAX_DRIVE_STEPS;

        config->protocol_mask = LIBP2P_GOSSIPSUB_PROTOCOL_MASK_ALL;
        config->preferred_protocol = LIBP2P_GOSSIPSUB_VERSION_12;
        config->enable_idontwant = 1U;
        config->idontwant_min_message_bytes = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_MIN_BYTES;
        config->max_idontwant_messages_per_peer_per_heartbeat =
            LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_PER_PEER;
        config->idontwant_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_TTL_US;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_storage_size(
    const libp2p_gossipsub_config_t *config,
    size_t *out_len)
{
    gossipsub_storage_layout_t layout;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&layout, 0, sizeof(layout));
    if (out_len == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_storage_layout(config, &layout);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *out_len = layout.total;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_storage_align(size_t *out_align)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (out_align == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        *out_align = GOSSIPSUB_STORAGE_ALIGN;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_init(
    void *storage,
    size_t storage_len,
    const libp2p_gossipsub_config_t *config,
    libp2p_gossipsub_t **out_gossipsub)
{
    gossipsub_storage_layout_t layout;
    libp2p_gossipsub_t *gossipsub = NULL;
    uint8_t *rx_base = NULL;
    uint8_t *rx_buffer = NULL;
    const void *storage_ptr = NULL;
    libp2p_gossipsub_err_t result = gossipsub_config_validate_init(config);

    (void)memset(&layout, 0, sizeof(layout));
    if (out_gossipsub != NULL)
    {
        *out_gossipsub = NULL;
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((storage == NULL) || (out_gossipsub == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_storage_layout(config, &layout);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (storage_len < layout.total))
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        (void)memset(storage, 0, layout.total);
        gossipsub = gossipsub_storage_router(storage);
        storage_ptr = gossipsub_storage_at(storage, layout.stream_rx_offset);
        gossipsub_pointer_store((void *)&rx_base, storage_ptr);
        if (layout.stream_rx_buffer_cap != 0U)
        {
            storage_ptr = gossipsub_storage_at(storage, layout.stream_rx_buffer_offset);
            gossipsub_pointer_store((void *)&rx_buffer, storage_ptr);
        }
        gossipsub->config = *config;
        gossipsub->storage_base = gossipsub_storage_bytes(storage);
        gossipsub->storage_len = storage_len;
        storage_ptr = gossipsub_storage_at(storage, layout.topics_offset);
        gossipsub_pointer_store((void *)&gossipsub->topics, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.peers_offset);
        gossipsub_pointer_store((void *)&gossipsub->peers, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.peer_topics_offset);
        gossipsub_pointer_store((void *)&gossipsub->peer_topics, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.mesh_edges_offset);
        gossipsub_pointer_store((void *)&gossipsub->mesh_edges, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.backoff_offset);
        gossipsub_pointer_store((void *)&gossipsub->backoff, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.streams_offset);
        gossipsub_pointer_store((void *)&gossipsub->streams, storage_ptr);
        gossipsub->stream_rx_small = rx_base;
        gossipsub->stream_rx_buffer = rx_buffer;
        gossipsub->stream_rx_small_stride = layout.stream_rx_stride;
        gossipsub->stream_rx_max_cap = layout.stream_rx_max_cap;
        gossipsub->stream_rx_buffer_cap = layout.stream_rx_buffer_cap;
        gossipsub->stream_rx_buffer_used = 0U;
        storage_ptr = gossipsub_storage_at(storage, layout.tx_queue_offset);
        gossipsub_pointer_store((void *)&gossipsub->tx_queue, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.tx_buffer_offset);
        gossipsub_pointer_store((void *)&gossipsub->tx_buffer, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.mcache_offset);
        gossipsub_pointer_store((void *)&gossipsub->mcache, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.mcache_data_offset);
        gossipsub_pointer_store((void *)&gossipsub->mcache_data, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.seen_offset);
        gossipsub_pointer_store((void *)&gossipsub->seen, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.validations_offset);
        gossipsub_pointer_store((void *)&gossipsub->validations, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.idontwant_offset);
        gossipsub_pointer_store((void *)&gossipsub->idontwant, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.events_offset);
        gossipsub_pointer_store((void *)&gossipsub->events, storage_ptr);
        gossipsub->protocol_user_data[0].gossipsub = gossipsub;
        gossipsub->protocol_user_data[0].version = LIBP2P_GOSSIPSUB_VERSION_12;
        gossipsub->protocol_user_data[1].gossipsub = gossipsub;
        gossipsub->protocol_user_data[1].version = LIBP2P_GOSSIPSUB_VERSION_11;
        for (size_t index = 0U; index < config->capacity.max_streams; index++)
        {
            gossipsub->streams[index].stream_index = index;
            gossipsub->streams[index].rx = &rx_base[index * layout.stream_rx_stride];
            gossipsub->streams[index].rx_cap = layout.stream_rx_stride;
            gossipsub->streams[index].rx_offset = GOSSIPSUB_RX_NO_OFFSET;
        }
        for (size_t index = 0U; index < config->capacity.max_peers; index++)
        {
            gossipsub->peers[index].tx_head = GOSSIPSUB_TX_NO_ITEM;
            gossipsub->peers[index].tx_tail = GOSSIPSUB_TX_NO_ITEM;
            gossipsub->peers[index].tx_priority_tail = GOSSIPSUB_TX_NO_ITEM;
        }
        for (size_t index = 0U; index < config->capacity.max_tx_rpc_queue; index++)
        {
            gossipsub->tx_queue[index].next = GOSSIPSUB_TX_NO_ITEM;
        }
        *out_gossipsub = gossipsub;
    }

    return result;
}

void libp2p_gossipsub_deinit(libp2p_gossipsub_t *gossipsub)
{
    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_streams; index++)
        {
            gossipsub_stream_rx_reset(gossipsub, &gossipsub->streams[index]);
        }
        gossipsub->started = 0U;
        gossipsub->closing = 1U;
    }
}
