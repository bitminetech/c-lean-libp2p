#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol/gossipsub/gossipsub.h"
#include "protocol_loopback_support.h"

typedef struct
{
    uint8_t value;
} gossipsub_test_runtime_t;

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
    assert(config.score.gossip_threshold == 0);
    assert(config.score.publish_threshold == 0);
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
    int saw_subscription = 0;
    int published = 0;
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
        while (libp2p_gossipsub_next_event(client_gossipsub, &event) == LIBP2P_GOSSIPSUB_OK)
        {
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
        if ((saw_message != 0) && (saw_idontwant != 0))
        {
            break;
        }
    }

    assert(saw_message != 0);
    assert(saw_idontwant != 0);
    protocol_loopback_deinit(&pair);
    libp2p_gossipsub_deinit(client_gossipsub);
    libp2p_gossipsub_deinit(server_gossipsub);
    free(client_storage);
    free(server_storage);
}

int main(void)
{
    gossipsub_test_defaults_and_required_message_id();
    gossipsub_test_publish_requires_capacity_and_writes_id();
    gossipsub_test_quic_loopback_publish_and_idontwant();
    return 0;
}
