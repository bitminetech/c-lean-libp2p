#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../src/libp2p/libp2p_host_internal.h"
#include "../../../../src/protocol/gossipsub/gossipsub_internal.h"
#include "protocol_loopback_support.h"

typedef struct
{
    uint8_t value;
} gossipsub_test_runtime_t;

typedef struct
{
    uint8_t would_block;
    size_t max_accept;
    size_t calls;
    size_t bytes;
} gossipsub_test_write_stream_t;

static libp2p_host_err_t gossipsub_test_stream_write(
    void *transport,
    void *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    gossipsub_test_write_stream_t *state = (gossipsub_test_write_stream_t *)stream;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    (void)transport;
    (void)data;
    (void)fin;
    if ((state == NULL) || (accepted == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (state->would_block != 0U)
    {
        *accepted = 0U;
        state->calls++;
        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    else
    {
        size_t count = data_len;

        if ((state->max_accept != 0U) && (count > state->max_accept))
        {
            count = state->max_accept;
        }
        *accepted = count;
        state->calls++;
        state->bytes += count;
    }

    return result;
}

static void gossipsub_test_fake_host_stream(
    libp2p_host_t *host,
    libp2p_host_transport_vtable_t *transport,
    libp2p_host_stream_t *stream,
    gossipsub_test_write_stream_t *write_state)
{
    assert(host != NULL);
    assert(transport != NULL);
    assert(stream != NULL);
    assert(write_state != NULL);
    (void)memset(host, 0, sizeof(*host));
    (void)memset(transport, 0, sizeof(*transport));
    (void)memset(stream, 0, sizeof(*stream));
    host->magic = HOST_MAGIC;
    host->state = HOST_STATE_STARTED;
    transport->stream_write = gossipsub_test_stream_write;
    host->config.transport = transport;
    stream->host = host;
    stream->state = HOST_STREAM_OPEN;
    stream->transport_stream = write_state;
}

static void gossipsub_test_attach_peer(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    libp2p_host_stream_t *stream)
{
    assert(gossipsub != NULL);
    assert(peer_index < gossipsub->config.capacity.max_peers);
    gossipsub->peers[peer_index].used = GOSSIPSUB_PEER_USED;
    gossipsub->peers[peer_index].stream = stream;
    gossipsub->peers[peer_index].direction = LIBP2P_HOST_STREAM_OUTBOUND;
    gossipsub->peers[peer_index].version = LIBP2P_GOSSIPSUB_VERSION_12;
}

static void gossipsub_test_mark_peer_subscribed(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    gossipsub_peer_topic_state_t *edge = NULL;

    assert(gossipsub != NULL);
    edge = gossipsub_find_or_add_peer_topic(gossipsub, peer_index, topic_index);
    assert(edge != NULL);
    edge->subscribed = 1U;
}

static void gossipsub_test_decode_peer_head(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    libp2p_gossipsub_rpc_decode_storage_t *decode_storage,
    libp2p_gossipsub_rpc_t *out_rpc)
{
    size_t item_index = GOSSIPSUB_TX_NO_ITEM;

    assert(gossipsub != NULL);
    assert(peer_index < gossipsub->config.capacity.max_peers);
    assert(decode_storage != NULL);
    assert(out_rpc != NULL);
    item_index = gossipsub->peers[peer_index].tx_head;
    assert(item_index != GOSSIPSUB_TX_NO_ITEM);
    assert(item_index < gossipsub->config.capacity.max_tx_rpc_queue);
    assert(
        libp2p_gossipsub_rpc_frame_decode(
            gossipsub->peers[peer_index].version,
            &gossipsub->config.limits,
            &gossipsub->tx_buffer[gossipsub->tx_queue[item_index].offset],
            gossipsub->tx_queue[item_index].len,
            decode_storage,
            out_rpc) == LIBP2P_GOSSIPSUB_OK);
}

static libp2p_gossipsub_err_t gossipsub_test_random(uint8_t *out, size_t out_len, void *user_data)
{
    gossipsub_test_runtime_t *runtime = (gossipsub_test_runtime_t *)user_data;
    size_t index = 0U;

    assert(out != NULL);
    assert(runtime != NULL);
    for (index = 0U; index < out_len; index++)
    {
        out[index] = runtime->value;
        runtime->value = (uint8_t)(runtime->value + 19U);
    }
    return LIBP2P_GOSSIPSUB_OK;
}

static libp2p_gossipsub_err_t gossipsub_test_message_id(
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    void *user_data)
{
    uint32_t hash = 2166136261U;
    size_t index = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)user_data;
    assert(message != NULL);
    assert(written != NULL);
    for (index = 0U; index < message->topic.len; index++)
    {
        hash ^= (uint32_t)message->topic.data[index];
        hash *= 16777619U;
    }
    for (index = 0U; index < message->data.len; index++)
    {
        hash ^= (uint32_t)message->data.data[index];
        hash *= 16777619U;
    }
    *written = 4U;
    if ((out == NULL) || (out_len < 4U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else
    {
        out[0] = (uint8_t)((hash >> 24U) & 0xFFU);
        out[1] = (uint8_t)((hash >> 16U) & 0xFFU);
        out[2] = (uint8_t)((hash >> 8U) & 0xFFU);
        out[3] = (uint8_t)(hash & 0xFFU);
    }
    return result;
}

static void gossipsub_test_config_small(
    libp2p_gossipsub_config_t *config,
    gossipsub_test_runtime_t *runtime)
{
    assert(libp2p_gossipsub_config_default(config) == LIBP2P_GOSSIPSUB_OK);
    config->limits.max_rpc_bytes = 4096U;
    config->limits.max_message_data_bytes = 2048U;
    config->limits.max_topic_bytes = 64U;
    config->limits.max_message_id_bytes = 32U;
    config->limits.max_subscriptions_per_rpc = 8U;
    config->limits.max_publish_per_rpc = 4U;
    config->limits.max_ihave_per_rpc = 4U;
    config->limits.max_iwant_per_rpc = 4U;
    config->limits.max_graft_per_rpc = 4U;
    config->limits.max_prune_per_rpc = 4U;
    config->limits.max_idontwant_per_rpc = 4U;
    config->limits.max_message_ids_per_rpc = 32U;
    config->limits.max_px_peers_per_rpc = 4U;
    config->capacity.max_topics = 8U;
    config->capacity.max_peers = 4U;
    config->capacity.max_peer_topics = 16U;
    config->capacity.max_mesh_edges = 16U;
    config->capacity.max_fanout_edges = 16U;
    config->capacity.max_backoff_entries = 16U;
    config->capacity.max_streams = 8U;
    config->capacity.max_pending_opens = 4U;
    config->capacity.max_tx_rpc_queue = 32U;
    config->capacity.tx_buffer_bytes = 32768U;
    config->capacity.mcache_slots = 32U;
    config->capacity.mcache_bytes = 8192U;
    config->capacity.seen_entries = 64U;
    config->capacity.pending_validations = 8U;
    config->capacity.idontwant_entries = 64U;
    config->capacity.event_capacity = 64U;
    config->capacity.max_drive_steps = 64U;
    config->random_fn = gossipsub_test_random;
    config->random_user_data = runtime;
    config->message_id_fn = gossipsub_test_message_id;
}

static void gossipsub_test_defaults_and_required_message_id(void)
{
    gossipsub_test_runtime_t runtime = {1U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;

    assert(libp2p_gossipsub_config_default(&config) == LIBP2P_GOSSIPSUB_OK);
    assert(config.mesh.d == 8U);
    assert(config.mesh.heartbeat_interval_us == 700000ULL);
    assert(config.idontwant_min_message_bytes == 1024U);
    config.random_fn = gossipsub_test_random;
    config.random_user_data = &runtime;
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(
        libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) ==
        LIBP2P_GOSSIPSUB_ERR_INVALID_ARG);
    free(storage);
}

static void gossipsub_test_publish_requires_capacity_and_writes_id(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t data[] = {1U, 2U, 3U};
    gossipsub_test_runtime_t runtime = {7U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_gossipsub_publish_t publish;
    uint8_t id[4];
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t written = 0U;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    (void)memset(&publish, 0, sizeof(publish));
    publish.topic.data = topic;
    publish.topic.len = sizeof(topic) - 1U;
    publish.data.data = data;
    publish.data.len = sizeof(data);
    assert(
        libp2p_gossipsub_publish(gossipsub, &publish, id, sizeof(id), &written) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(written == 4U);
    assert(
        libp2p_gossipsub_publish(gossipsub, &publish, id, 3U, &written) ==
        LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL);
    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_register_protocols(libp2p_host_t *host, libp2p_gossipsub_t *gossipsub)
{
    libp2p_host_protocol_t protocols[LIBP2P_GOSSIPSUB_PROTOCOL_COUNT];
    size_t count = 0U;
    size_t index = 0U;

    assert(
        libp2p_gossipsub_protocols(gossipsub, protocols, LIBP2P_GOSSIPSUB_PROTOCOL_COUNT, &count) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(count == 2U);
    for (index = 0U; index < count; index++)
    {
        assert(libp2p_host_handle(host, &protocols[index]) == LIBP2P_HOST_OK);
    }
}

static void gossipsub_test_drain_host_events(
    protocol_loopback_pair_t *pair,
    libp2p_gossipsub_t *client_gossipsub,
    libp2p_gossipsub_t *server_gossipsub)
{
    libp2p_host_event_t event;

    while (libp2p_host_next_event(pair->client, &event) == LIBP2P_HOST_OK)
    {
        if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
        {
            pair->client_conn = event.conn;
        }
        assert(
            libp2p_gossipsub_handle_host_event(client_gossipsub, pair->client, &event) ==
            LIBP2P_GOSSIPSUB_OK);
    }
    while (libp2p_host_next_event(pair->server, &event) == LIBP2P_HOST_OK)
    {
        if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
        {
            pair->server_conn = event.conn;
        }
        assert(
            libp2p_gossipsub_handle_host_event(server_gossipsub, pair->server, &event) ==
            LIBP2P_GOSSIPSUB_OK);
    }
}

static void gossipsub_test_quic_loopback_publish_and_idontwant(void)
{
    static const uint8_t topic[] = "blocks";
    static uint8_t payload[1200];
    gossipsub_test_runtime_t client_runtime = {11U};
    gossipsub_test_runtime_t server_runtime = {41U};
    libp2p_gossipsub_config_t client_config;
    libp2p_gossipsub_config_t server_config;
    libp2p_gossipsub_t *client_gossipsub = NULL;
    libp2p_gossipsub_t *server_gossipsub = NULL;
    libp2p_gossipsub_topic_config_t topic_config;
    libp2p_gossipsub_publish_t publish;
    protocol_loopback_pair_t pair;
    libp2p_host_config_t client_host_config;
    libp2p_host_config_t server_host_config;
    libp2p_quic_service_config_t client_service_config;
    libp2p_quic_service_config_t server_service_config;
    libp2p_quic_addr_t server_addr;
    uint8_t server_dial[160];
    void *client_storage = NULL;
    void *server_storage = NULL;
    size_t server_dial_len = 0U;
    size_t client_storage_len = 0U;
    size_t server_storage_len = 0U;
    size_t round = 0U;
    int opened = 0;
    int server_opened = 0;
    int saw_subscription = 0;
    int published = 0;
    int client_saw_idontwant = 0;
    int saw_message = 0;
    int saw_idontwant = 0;

    (void)memset(payload, 0xA5, sizeof(payload));
    gossipsub_test_config_small(&client_config, &client_runtime);
    gossipsub_test_config_small(&server_config, &server_runtime);
    assert(
        libp2p_gossipsub_storage_size(&client_config, &client_storage_len) == LIBP2P_GOSSIPSUB_OK);
    assert(
        libp2p_gossipsub_storage_size(&server_config, &server_storage_len) == LIBP2P_GOSSIPSUB_OK);
    client_storage = calloc(1U, client_storage_len);
    server_storage = calloc(1U, server_storage_len);
    assert(client_storage != NULL);
    assert(server_storage != NULL);
    assert(
        libp2p_gossipsub_init(
            client_storage,
            client_storage_len,
            &client_config,
            &client_gossipsub) == LIBP2P_GOSSIPSUB_OK);
    assert(
        libp2p_gossipsub_init(
            server_storage,
            server_storage_len,
            &server_config,
            &server_gossipsub) == LIBP2P_GOSSIPSUB_OK);

    protocol_loopback_init(
        &pair,
        39110U,
        39111U,
        4U,
        &client_host_config,
        &server_host_config,
        &client_service_config,
        &server_service_config,
        &server_addr,
        server_dial,
        sizeof(server_dial),
        &server_dial_len);
    gossipsub_test_register_protocols(pair.client, client_gossipsub);
    gossipsub_test_register_protocols(pair.server, server_gossipsub);
    assert(libp2p_host_start(pair.client) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.server) == LIBP2P_HOST_OK);
    assert(
        libp2p_gossipsub_start(client_gossipsub, pair.client, pair.now_us) == LIBP2P_GOSSIPSUB_OK);
    assert(
        libp2p_gossipsub_start(server_gossipsub, pair.server, pair.now_us) == LIBP2P_GOSSIPSUB_OK);

    (void)memset(&topic_config, 0, sizeof(topic_config));
    topic_config.topic.data = topic;
    topic_config.topic.len = sizeof(topic) - 1U;
    topic_config.validation_mode = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL;
    topic_config.enable_idontwant = 1U;
    topic_config.idontwant_min_message_bytes = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_MIN_BYTES;
    assert(libp2p_gossipsub_subscribe(client_gossipsub, &topic_config) == LIBP2P_GOSSIPSUB_OK);
    assert(libp2p_gossipsub_subscribe(server_gossipsub, &topic_config) == LIBP2P_GOSSIPSUB_OK);

    {
        libp2p_host_dial_t *dial = NULL;

        assert(
            libp2p_host_dial(pair.client, server_dial, server_dial_len, NULL, &dial) ==
            LIBP2P_HOST_OK);
    }

    for (round = 0U; round < 5000U; round++)
    {
        libp2p_gossipsub_event_t event;

        protocol_loopback_drive(&pair);
        gossipsub_test_drain_host_events(&pair, client_gossipsub, server_gossipsub);
        assert(
            libp2p_gossipsub_drive(client_gossipsub, pair.client, pair.now_us, NULL) ==
            LIBP2P_GOSSIPSUB_OK);
        assert(
            libp2p_gossipsub_drive(server_gossipsub, pair.server, pair.now_us, NULL) ==
            LIBP2P_GOSSIPSUB_OK);
        if ((pair.client_conn != NULL) && (opened == 0))
        {
            libp2p_host_stream_open_t *open = NULL;

            assert(
                libp2p_gossipsub_open_peer(
                    client_gossipsub,
                    pair.client,
                    pair.client_conn,
                    LIBP2P_GOSSIPSUB_VERSION_12,
                    NULL,
                    &open) == LIBP2P_GOSSIPSUB_OK);
            opened = 1;
        }
        if ((pair.server_conn != NULL) && (server_opened == 0))
        {
            libp2p_host_stream_open_t *open = NULL;

            assert(
                libp2p_gossipsub_open_peer(
                    server_gossipsub,
                    pair.server,
                    pair.server_conn,
                    LIBP2P_GOSSIPSUB_VERSION_12,
                    NULL,
                    &open) == LIBP2P_GOSSIPSUB_OK);
            server_opened = 1;
        }
        while (libp2p_gossipsub_next_event(client_gossipsub, &event) == LIBP2P_GOSSIPSUB_OK)
        {
            if (event.type == LIBP2P_GOSSIPSUB_EVENT_IDONTWANT)
            {
                client_saw_idontwant = 1;
            }
            if ((event.type == LIBP2P_GOSSIPSUB_EVENT_SUBSCRIPTION) &&
                (event.topic.len == (sizeof(topic) - 1U)) &&
                (memcmp(event.topic.data, topic, sizeof(topic) - 1U) == 0))
            {
                saw_subscription = 1;
            }
        }
        if ((opened != 0) && (saw_subscription != 0) && (published == 0))
        {
            (void)memset(&publish, 0, sizeof(publish));
            publish.topic.data = topic;
            publish.topic.len = sizeof(topic) - 1U;
            publish.data.data = payload;
            publish.data.len = sizeof(payload);
            assert(
                libp2p_gossipsub_publish(client_gossipsub, &publish, NULL, 0U, NULL) ==
                LIBP2P_GOSSIPSUB_OK);
            published = 1;
        }
        while (libp2p_gossipsub_next_event(server_gossipsub, &event) == LIBP2P_GOSSIPSUB_OK)
        {
            if (event.type == LIBP2P_GOSSIPSUB_EVENT_IDONTWANT)
            {
                saw_idontwant = 1;
            }
            if (event.type == LIBP2P_GOSSIPSUB_EVENT_MESSAGE)
            {
                assert(event.message.data.len == sizeof(payload));
                saw_message = 1;
            }
        }
        if ((saw_message != 0) && (saw_idontwant != 0) && (client_saw_idontwant != 0))
        {
            break;
        }
    }

    assert(saw_message != 0);
    assert(saw_idontwant != 0);
    assert(client_saw_idontwant != 0);
    protocol_loopback_deinit(&pair);
    libp2p_gossipsub_deinit(client_gossipsub);
    libp2p_gossipsub_deinit(server_gossipsub);
    free(client_storage);
    free(server_storage);
}

static void gossipsub_test_per_peer_queue_state(void)
{
    gossipsub_test_runtime_t runtime = {17U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    libp2p_gossipsub_tx_peer_stats_t stats;
    uint8_t *out = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item0 = GOSSIPSUB_TX_NO_ITEM;
    size_t item1 = GOSSIPSUB_TX_NO_ITEM;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 8U, 0U, &out, &item0) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    assert(gossipsub_tx_alloc(gossipsub, 1U, 6U, 0U, &out, &item1) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);

    assert(gossipsub->tx_queue_len == 2U);
    assert(gossipsub->peers[0].tx_head == item0);
    assert(gossipsub->peers[0].tx_tail == item0);
    assert(gossipsub->peers[0].tx_queue_depth == 1U);
    assert(gossipsub->peers[1].tx_head == item1);
    assert(gossipsub->peers[1].tx_tail == item1);
    assert(gossipsub->peers[1].tx_queue_depth == 1U);
    assert(gossipsub->tx_ready_count == 2U);
    assert(libp2p_gossipsub_tx_peer_stats(gossipsub, 1U, 0U, &stats) == LIBP2P_GOSSIPSUB_OK);
    assert(stats.queue_depth == 1U);
    assert(stats.current_len == 6U);
    assert(stats.ready != 0U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_priority_queue_precedes_normal_items(void)
{
    static const uint8_t topic[] = "blocks";
    gossipsub_test_runtime_t runtime = {18U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_gossipsub_bytes_t topic_bytes;
    gossipsub_topic_state_t *topic_state = NULL;
    uint8_t *out = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t normal = GOSSIPSUB_TX_NO_ITEM;
    size_t priority = GOSSIPSUB_TX_NO_ITEM;
    size_t topic_index = 0U;

    (void)memset(&topic_bytes, 0, sizeof(topic_bytes));
    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 8U, 0U, &out, &normal) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    topic_bytes.data = topic;
    topic_bytes.len = sizeof(topic) - 1U;
    topic_state = gossipsub_find_or_add_topic(gossipsub, topic_bytes, &topic_index);
    assert(topic_state != NULL);
    assert(gossipsub_enqueue_subscription(gossipsub, 0U, topic_state, 1U) == LIBP2P_GOSSIPSUB_OK);

    priority = gossipsub->peers[0].tx_head;
    assert(priority != GOSSIPSUB_TX_NO_ITEM);
    assert(priority != normal);
    assert(gossipsub->tx_queue[priority].priority != 0U);
    assert(gossipsub->tx_queue[priority].next == normal);
    assert(gossipsub->peers[0].tx_tail == normal);
    assert(gossipsub->peers[0].tx_priority_tail == priority);
    assert(gossipsub->peers[0].tx_queue_depth == 2U);
    assert(gossipsub->peers[0].tx_priority_depth == 1U);

    (void)topic_index;
    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_fair_scheduler_skips_blocked_peer(void)
{
    gossipsub_test_runtime_t runtime = {19U};
    gossipsub_test_write_stream_t write0 = {1U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 12U, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0xA5, 12U);
    assert(gossipsub_tx_alloc(gossipsub, 1U, 10U, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0x5A, 10U);

    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 100U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(write0.calls == 1U);
    assert(write0.bytes == 0U);
    assert(write1.calls == 1U);
    assert(write1.bytes == 10U);
    assert(gossipsub->peers[0].tx_queue_depth == 1U);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(gossipsub->peers[0].tx_would_block_count == 1U);
    assert(gossipsub->peers[1].tx_queue_depth == 0U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_writable_event_requires_selected_outbound_stream(void)
{
    gossipsub_test_runtime_t runtime = {24U};
    gossipsub_test_write_stream_t write0 = {1U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write_in = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream_in;
    gossipsub_stream_state_t outbound_state;
    gossipsub_stream_state_t inbound_state;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    (void)memset(&outbound_state, 0, sizeof(outbound_state));
    (void)memset(&inbound_state, 0, sizeof(inbound_state));
    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    (void)memset(&stream_in, 0, sizeof(stream_in));
    stream_in.host = &host;
    stream_in.state = HOST_STREAM_OPEN;
    stream_in.transport_stream = &write_in;
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    outbound_state.stream = &stream0;
    outbound_state.direction = LIBP2P_HOST_STREAM_OUTBOUND;
    outbound_state.peer_index = 0U;
    inbound_state.stream = &stream_in;
    inbound_state.direction = LIBP2P_HOST_STREAM_INBOUND;
    inbound_state.peer_index = 0U;
    stream0.user_data = &outbound_state;
    stream_in.user_data = &inbound_state;

    assert(gossipsub_tx_alloc(gossipsub, 0U, 9U, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 100U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub->peers[0].tx_ready == 0U);

    gossipsub->last_drive_us = 200U;
    assert(
        gossipsub_protocol_on_event(
            &host,
            &stream_in,
            LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE,
            &gossipsub->protocol_user_data[0]) == LIBP2P_HOST_OK);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(gossipsub->peers[0].tx_last_writable_us == 0U);

    assert(
        gossipsub_protocol_on_event(
            &host,
            &stream0,
            LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE,
            &gossipsub->protocol_user_data[0]) == LIBP2P_HOST_OK);
    assert(gossipsub->peers[0].tx_ready != 0U);
    assert(gossipsub->peers[0].tx_last_writable_us == 200U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_readiness_flips_on_writable(void)
{
    gossipsub_test_runtime_t runtime = {23U};
    gossipsub_test_write_stream_t write0 = {1U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_gossipsub_tx_peer_stats_t stats;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    assert(gossipsub_tx_alloc(gossipsub, 0U, 9U, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0xC3, 9U);

    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 100U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub->peers[0].tx_ready == 0U);
    write0.would_block = 0U;
    gossipsub_tx_mark_peer_ready(gossipsub, 0U, 200U);
    assert(gossipsub->peers[0].tx_ready != 0U);
    assert(gossipsub->peers[0].tx_last_writable_us == 200U);
    made_progress = 0U;
    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 201U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(libp2p_gossipsub_tx_peer_stats(gossipsub, 0U, 201U, &stats) == LIBP2P_GOSSIPSUB_OK);
    assert(stats.last_writable_us == 200U);
    assert(stats.bytes_accepted == 9U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_slice_progress_waits_for_writable(void)
{
    const size_t frame_len = GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE + 17U;
    gossipsub_test_runtime_t runtime = {31U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_gossipsub_tx_peer_stats_t stats;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    assert(gossipsub_tx_alloc(gossipsub, 0U, frame_len, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0x4DU, frame_len);

    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 100U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(rpcs_sent == 0U);
    assert(write0.calls == 1U);
    assert(write0.bytes == GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE);
    assert(gossipsub->peers[0].tx_queue_depth == 1U);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(gossipsub->tx_ready_count == 0U);
    assert(libp2p_gossipsub_tx_peer_stats(gossipsub, 0U, 100U, &stats) == LIBP2P_GOSSIPSUB_OK);
    assert(stats.current_pos == GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE);

    gossipsub_tx_mark_peer_ready(gossipsub, 0U, 200U);
    assert(gossipsub->peers[0].tx_ready != 0U);
    made_progress = 0U;
    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 201U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(rpcs_sent == 1U);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(write0.bytes == frame_len);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_append_to_blocked_peer_keeps_readiness_off(void)
{
    const size_t frame_len = GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE + 21U;
    gossipsub_test_runtime_t runtime = {44U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    assert(gossipsub_tx_alloc(gossipsub, 0U, frame_len, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0xB4, frame_len);

    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 100U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(gossipsub->peers[0].tx_queue_depth == 1U);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(gossipsub->tx_ready_count == 0U);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 11U, 0U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    (void)memset(out, 0x3CU, 11U);
    assert(gossipsub->peers[0].tx_queue_depth == 2U);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(gossipsub->tx_ready_count == 0U);

    gossipsub_tx_mark_peer_ready(gossipsub, 0U, 200U);
    assert(gossipsub->peers[0].tx_ready != 0U);
    made_progress = 0U;
    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 201U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(gossipsub->peers[0].tx_ready == 0U);
    assert(write0.bytes == (frame_len + 11U));
    assert(rpcs_sent == 2U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_stale_head_message_drops_without_write(void)
{
    gossipsub_test_runtime_t runtime = {29U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_time_us_t deadline = 0U;
    uint8_t *out = NULL;
    uint8_t made_progress = 0U;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t item = GOSSIPSUB_TX_NO_ITEM;
    size_t rpcs_sent = 0U;

    gossipsub_test_config_small(&config, &runtime);
    config.mesh.heartbeat_interval_us = 1000U;
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    assert(libp2p_gossipsub_start(gossipsub, &host, 100U) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 16U, 10U, &out, &item) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    assert(libp2p_gossipsub_next_deadline(gossipsub, &deadline) == LIBP2P_GOSSIPSUB_OK);
    assert(deadline == 110U);
    assert(
        gossipsub_flush_ready_peers(gossipsub, &host, 111U, &made_progress, &rpcs_sent) ==
        LIBP2P_GOSSIPSUB_OK);
    assert(made_progress != 0U);
    assert(write0.calls == 0U);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(gossipsub->tx_queue_len == 0U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_stale_follower_message_drops_behind_partial_head(void)
{
    gossipsub_test_runtime_t runtime = {33U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    uint8_t *out = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t head = GOSSIPSUB_TX_NO_ITEM;
    size_t stale = GOSSIPSUB_TX_NO_ITEM;

    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);

    assert(gossipsub_tx_alloc(gossipsub, 0U, 16U, 0U, &out, &head) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    gossipsub->tx_queue[head].pos = 4U;
    assert(gossipsub_tx_alloc(gossipsub, 0U, 8U, 10U, &out, &stale) == LIBP2P_GOSSIPSUB_OK);
    assert(out != NULL);
    assert(gossipsub->peers[0].tx_queue_depth == 2U);
    assert(gossipsub_tx_drop_stale(gossipsub, 11U) == 1U);
    assert(gossipsub->peers[0].tx_queue_depth == 1U);
    assert(gossipsub->peers[0].tx_head == head);
    assert(gossipsub->peers[0].tx_tail == head);
    assert(gossipsub->tx_queue[stale].used == 0U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_remote_subscriptions_fill_mesh(void)
{
    static const uint8_t topic[] = "blocks";
    gossipsub_test_runtime_t runtime = {37U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    libp2p_gossipsub_topic_config_t topic_config;
    libp2p_gossipsub_rpc_subscription_t sub;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t topic_index = 0U;

    gossipsub_test_config_small(&config, &runtime);
    config.mesh.d = 2U;
    config.mesh.d_low = 2U;
    config.mesh.d_high = 3U;
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);

    (void)memset(&topic_config, 0, sizeof(topic_config));
    topic_config.topic.data = topic;
    topic_config.topic.len = sizeof(topic) - 1U;
    topic_config.validation_mode = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL;
    topic_config.enable_idontwant = 1U;
    assert(libp2p_gossipsub_subscribe(gossipsub, &topic_config) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_find_topic(gossipsub, topic, sizeof(topic) - 1U, &topic_index) != NULL);
    assert(gossipsub_mesh_count_topic(gossipsub, topic_index) == 0U);

    (void)memset(&sub, 0, sizeof(sub));
    sub.topic.data = topic;
    sub.topic.len = sizeof(topic) - 1U;
    sub.subscribe = 1U;
    assert(gossipsub_process_subscription(gossipsub, 0U, &sub) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_mesh_contains(gossipsub, 0U, topic_index) != 0);
    assert(gossipsub_process_subscription(gossipsub, 1U, &sub) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_mesh_contains(gossipsub, 1U, topic_index) != 0);
    assert(gossipsub_mesh_count_topic(gossipsub, topic_index) == 2U);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_forward_uses_mesh_not_all_subscribers(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t message_id[] = {1U, 2U, 3U, 4U};
    uint8_t data[1300];
    gossipsub_test_runtime_t runtime = {41U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write2 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    libp2p_host_stream_t stream2;
    libp2p_gossipsub_bytes_t topic_bytes;
    libp2p_gossipsub_bytes_t data_bytes;
    gossipsub_topic_state_t *topic_state = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;

    (void)memset(data, 0xB5, sizeof(data));
    (void)memset(&topic_bytes, 0, sizeof(topic_bytes));
    (void)memset(&data_bytes, 0, sizeof(data_bytes));
    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_fake_host_stream(&host, &transport, &stream2, &write2);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);
    gossipsub_test_attach_peer(gossipsub, 2U, &stream2);
    topic_bytes.data = topic;
    topic_bytes.len = sizeof(topic) - 1U;
    data_bytes.data = data;
    data_bytes.len = sizeof(data);
    topic_state = gossipsub_find_or_add_topic(gossipsub, topic_bytes, &topic_index);
    assert(topic_state != NULL);
    topic_state->local_subscribed = 1U;
    gossipsub_test_mark_peer_subscribed(gossipsub, 0U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 1U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 2U, topic_index);
    assert(gossipsub_mesh_add(gossipsub, 0U, topic_index) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_mesh_add(gossipsub, 1U, topic_index) == LIBP2P_GOSSIPSUB_OK);
    assert(
        gossipsub_mcache_store(
            gossipsub,
            message_id,
            sizeof(message_id),
            topic_bytes,
            data_bytes,
            &entry,
            &mcache_index) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_forward_entry(gossipsub, 0U, entry) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(gossipsub->peers[1].tx_queue_depth != 0U);
    assert(gossipsub->peers[2].tx_queue_depth == 0U);

    (void)mcache_index;
    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_heartbeat_gossip_ihave_to_non_mesh_peers(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t message_id[] = {9U, 8U, 7U, 6U};
    static const uint8_t data[] = {1U};
    gossipsub_test_runtime_t runtime = {47U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write2 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write3 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    libp2p_host_stream_t stream2;
    libp2p_host_stream_t stream3;
    libp2p_gossipsub_bytes_t topic_bytes;
    libp2p_gossipsub_bytes_t data_bytes;
    gossipsub_topic_state_t *topic_state = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_rpc_decode_storage_t decode_storage;
    libp2p_gossipsub_control_ihave_t ihave[2];
    libp2p_gossipsub_bytes_t decoded_ids[4];
    libp2p_gossipsub_rpc_t rpc;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;

    (void)memset(&topic_bytes, 0, sizeof(topic_bytes));
    (void)memset(&data_bytes, 0, sizeof(data_bytes));
    (void)memset(&decode_storage, 0, sizeof(decode_storage));
    (void)memset(ihave, 0, sizeof(ihave));
    (void)memset(decoded_ids, 0, sizeof(decoded_ids));
    (void)memset(&rpc, 0, sizeof(rpc));
    gossipsub_test_config_small(&config, &runtime);
    config.mesh.d_low = 0U;
    config.mesh.d_lazy = 4U;
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_fake_host_stream(&host, &transport, &stream2, &write2);
    gossipsub_test_fake_host_stream(&host, &transport, &stream3, &write3);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);
    gossipsub_test_attach_peer(gossipsub, 2U, &stream2);
    gossipsub_test_attach_peer(gossipsub, 3U, &stream3);
    gossipsub->peers[3].explicit_peer = 1U;

    topic_bytes.data = topic;
    topic_bytes.len = sizeof(topic) - 1U;
    data_bytes.data = data;
    data_bytes.len = sizeof(data);
    topic_state = gossipsub_find_or_add_topic(gossipsub, topic_bytes, &topic_index);
    assert(topic_state != NULL);
    topic_state->local_subscribed = 1U;
    gossipsub_test_mark_peer_subscribed(gossipsub, 0U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 1U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 2U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 3U, topic_index);
    assert(gossipsub_mesh_add(gossipsub, 0U, topic_index) == LIBP2P_GOSSIPSUB_OK);
    assert(
        gossipsub_mcache_store(
            gossipsub,
            message_id,
            sizeof(message_id),
            topic_bytes,
            data_bytes,
            &entry,
            &mcache_index) == LIBP2P_GOSSIPSUB_OK);

    gossipsub_heartbeat(gossipsub, 100U);
    assert(gossipsub->peers[0].tx_queue_depth == 0U);
    assert(gossipsub->peers[1].tx_queue_depth == 1U);
    assert(gossipsub->peers[2].tx_queue_depth == 1U);
    assert(gossipsub->peers[3].tx_queue_depth == 0U);
    decode_storage.ihave = ihave;
    decode_storage.ihave_capacity = 2U;
    decode_storage.message_ids = decoded_ids;
    decode_storage.message_id_capacity = 4U;
    gossipsub_test_decode_peer_head(gossipsub, 1U, &decode_storage, &rpc);
    assert(rpc.control.ihave_count == 1U);
    assert(rpc.control.ihave[0].message_id_count == 1U);
    assert(rpc.control.ihave[0].topic.len == sizeof(topic) - 1U);
    assert(memcmp(rpc.control.ihave[0].topic.data, topic, sizeof(topic) - 1U) == 0);
    assert(rpc.control.ihave[0].message_ids[0].len == sizeof(message_id));
    assert(memcmp(rpc.control.ihave[0].message_ids[0].data, message_id, sizeof(message_id)) == 0);

    (void)entry;
    (void)mcache_index;
    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_gossip_ihave_caps_message_ids(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t id0[] = {0U, 0U, 0U, 0U};
    static const uint8_t id1[] = {0U, 0U, 0U, 1U};
    static const uint8_t id2[] = {0U, 0U, 0U, 2U};
    static const uint8_t data[] = {3U};
    gossipsub_test_runtime_t runtime = {53U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    gossipsub_test_write_stream_t write1 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_host_stream_t stream1;
    libp2p_gossipsub_bytes_t topic_bytes;
    libp2p_gossipsub_bytes_t data_bytes;
    gossipsub_topic_state_t *topic_state = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_rpc_decode_storage_t decode_storage;
    libp2p_gossipsub_control_ihave_t ihave[1];
    libp2p_gossipsub_bytes_t decoded_ids[4];
    libp2p_gossipsub_rpc_t rpc;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;

    (void)memset(&topic_bytes, 0, sizeof(topic_bytes));
    (void)memset(&data_bytes, 0, sizeof(data_bytes));
    (void)memset(&decode_storage, 0, sizeof(decode_storage));
    (void)memset(ihave, 0, sizeof(ihave));
    (void)memset(decoded_ids, 0, sizeof(decoded_ids));
    (void)memset(&rpc, 0, sizeof(rpc));
    gossipsub_test_config_small(&config, &runtime);
    config.limits.max_message_ids_per_rpc = 2U;
    config.mesh.d_lazy = 4U;
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_fake_host_stream(&host, &transport, &stream1, &write1);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    gossipsub_test_attach_peer(gossipsub, 1U, &stream1);

    topic_bytes.data = topic;
    topic_bytes.len = sizeof(topic) - 1U;
    data_bytes.data = data;
    data_bytes.len = sizeof(data);
    topic_state = gossipsub_find_or_add_topic(gossipsub, topic_bytes, &topic_index);
    assert(topic_state != NULL);
    topic_state->local_subscribed = 1U;
    gossipsub_test_mark_peer_subscribed(gossipsub, 0U, topic_index);
    gossipsub_test_mark_peer_subscribed(gossipsub, 1U, topic_index);
    assert(gossipsub_mesh_add(gossipsub, 0U, topic_index) == LIBP2P_GOSSIPSUB_OK);
    assert(
        gossipsub_mcache_store(
            gossipsub,
            id0,
            sizeof(id0),
            topic_bytes,
            data_bytes,
            &entry,
            &mcache_index) == LIBP2P_GOSSIPSUB_OK);
    assert(
        gossipsub_mcache_store(
            gossipsub,
            id1,
            sizeof(id1),
            topic_bytes,
            data_bytes,
            &entry,
            &mcache_index) == LIBP2P_GOSSIPSUB_OK);
    assert(
        gossipsub_mcache_store(
            gossipsub,
            id2,
            sizeof(id2),
            topic_bytes,
            data_bytes,
            &entry,
            &mcache_index) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_emit_gossip(gossipsub) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub->peers[1].tx_queue_depth == 1U);
    decode_storage.ihave = ihave;
    decode_storage.ihave_capacity = 1U;
    decode_storage.message_ids = decoded_ids;
    decode_storage.message_id_capacity = 4U;
    gossipsub_test_decode_peer_head(gossipsub, 1U, &decode_storage, &rpc);
    assert(rpc.control.ihave_count == 1U);
    assert(rpc.control.ihave[0].message_id_count == 2U);
    assert(memcmp(rpc.control.ihave[0].message_ids[0].data, id0, sizeof(id0)) == 0);
    assert(memcmp(rpc.control.ihave[0].message_ids[1].data, id1, sizeof(id1)) == 0);

    (void)entry;
    (void)mcache_index;
    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

static void gossipsub_test_prune_removes_mesh_peer(void)
{
    static const uint8_t topic[] = "blocks";
    gossipsub_test_runtime_t runtime = {43U};
    gossipsub_test_write_stream_t write0 = {0U, 0U, 0U, 0U};
    libp2p_gossipsub_config_t config;
    libp2p_gossipsub_t *gossipsub = NULL;
    libp2p_host_t host;
    libp2p_host_transport_vtable_t transport;
    libp2p_host_stream_t stream0;
    libp2p_gossipsub_bytes_t topic_bytes;
    gossipsub_topic_state_t *topic_state = NULL;
    libp2p_gossipsub_control_prune_t prune;
    libp2p_gossipsub_rpc_t rpc;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t topic_index = 0U;

    (void)memset(&topic_bytes, 0, sizeof(topic_bytes));
    (void)memset(&prune, 0, sizeof(prune));
    (void)memset(&rpc, 0, sizeof(rpc));
    gossipsub_test_config_small(&config, &runtime);
    assert(libp2p_gossipsub_storage_size(&config, &storage_len) == LIBP2P_GOSSIPSUB_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_gossipsub_init(storage, storage_len, &config, &gossipsub) == LIBP2P_GOSSIPSUB_OK);
    gossipsub_test_fake_host_stream(&host, &transport, &stream0, &write0);
    gossipsub_test_attach_peer(gossipsub, 0U, &stream0);
    topic_bytes.data = topic;
    topic_bytes.len = sizeof(topic) - 1U;
    topic_state = gossipsub_find_or_add_topic(gossipsub, topic_bytes, &topic_index);
    assert(topic_state != NULL);
    topic_state->local_subscribed = 1U;
    assert(gossipsub_mesh_add(gossipsub, 0U, topic_index) == LIBP2P_GOSSIPSUB_OK);
    prune.topic = topic_bytes;
    rpc.control.prune = &prune;
    rpc.control.prune_count = 1U;
    assert(gossipsub_process_rpc(gossipsub, 0U, &rpc, 100U) == LIBP2P_GOSSIPSUB_OK);
    assert(gossipsub_mesh_contains(gossipsub, 0U, topic_index) == 0);

    libp2p_gossipsub_deinit(gossipsub);
    free(storage);
}

int main(void)
{
    gossipsub_test_defaults_and_required_message_id();
    gossipsub_test_publish_requires_capacity_and_writes_id();
    gossipsub_test_quic_loopback_publish_and_idontwant();
    gossipsub_test_per_peer_queue_state();
    gossipsub_test_priority_queue_precedes_normal_items();
    gossipsub_test_fair_scheduler_skips_blocked_peer();
    gossipsub_test_writable_event_requires_selected_outbound_stream();
    gossipsub_test_readiness_flips_on_writable();
    gossipsub_test_slice_progress_waits_for_writable();
    gossipsub_test_append_to_blocked_peer_keeps_readiness_off();
    gossipsub_test_stale_head_message_drops_without_write();
    gossipsub_test_stale_follower_message_drops_behind_partial_head();
    gossipsub_test_remote_subscriptions_fill_mesh();
    gossipsub_test_forward_uses_mesh_not_all_subscribers();
    gossipsub_test_heartbeat_gossip_ihave_to_non_mesh_peers();
    gossipsub_test_gossip_ihave_caps_message_ids();
    gossipsub_test_prune_removes_mesh_peer();
    return 0;
}
