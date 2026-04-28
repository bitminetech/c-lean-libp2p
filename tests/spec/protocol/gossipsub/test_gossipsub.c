#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol/gossipsub/gossipsub.h"

static void gossipsub_spec_limits(libp2p_gossipsub_limits_t *limits)
{
    libp2p_gossipsub_config_t config;

    assert(libp2p_gossipsub_config_default(&config) == LIBP2P_GOSSIPSUB_OK);
    *limits = config.limits;
}

static void gossipsub_spec_protocol_ids(void)
{
    assert(strlen(LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11) == LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN);
    assert(strlen(LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12) == LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN);
    assert(strcmp(LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11, "/meshsub/1.1.0") == 0);
    assert(strcmp(LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12, "/meshsub/1.2.0") == 0);
}

static void gossipsub_spec_subscription_vector(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t expected[] =
        {0x0AU, 0x0AU, 0x08U, 0x01U, 0x12U, 0x06U, 'b', 'l', 'o', 'c', 'k', 's'};
    libp2p_gossipsub_limits_t limits;
    libp2p_gossipsub_rpc_subscription_t sub;
    libp2p_gossipsub_rpc_t rpc;
    libp2p_gossipsub_rpc_subscription_t decoded_subs[2];
    libp2p_gossipsub_message_t decoded_publish[1];
    libp2p_gossipsub_control_ihave_t ihave[1];
    libp2p_gossipsub_control_iwant_t iwant[1];
    libp2p_gossipsub_control_graft_t graft[1];
    libp2p_gossipsub_control_prune_t prune[1];
    libp2p_gossipsub_control_idontwant_t idontwant[1];
    libp2p_gossipsub_bytes_t ids[8];
    libp2p_gossipsub_peer_info_t peers[1];
    libp2p_gossipsub_rpc_decode_storage_t storage;
    libp2p_gossipsub_rpc_t decoded;
    uint8_t encoded[32];
    size_t written = 0U;

    gossipsub_spec_limits(&limits);
    (void)memset(&sub, 0, sizeof(sub));
    (void)memset(&rpc, 0, sizeof(rpc));
    (void)memset(&storage, 0, sizeof(storage));
    sub.topic.data = topic;
    sub.topic.len = sizeof(topic) - 1U;
    sub.subscribe = 1U;
    rpc.subscriptions = &sub;
    rpc.subscription_count = 1U;

    assert(
        libp2p_gossipsub_rpc_body_encode(
            LIBP2P_GOSSIPSUB_VERSION_11,
            &limits,
            &rpc,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_GOSSIPSUB_OK);
    assert(written == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);

    storage.subscriptions = decoded_subs;
    storage.subscription_capacity = 2U;
    storage.publish = decoded_publish;
    storage.publish_capacity = 1U;
    storage.ihave = ihave;
    storage.ihave_capacity = 1U;
    storage.iwant = iwant;
    storage.iwant_capacity = 1U;
    storage.graft = graft;
    storage.graft_capacity = 1U;
    storage.prune = prune;
    storage.prune_capacity = 1U;
    storage.idontwant = idontwant;
    storage.idontwant_capacity = 1U;
    storage.message_ids = ids;
    storage.message_id_capacity = 8U;
    storage.peer_infos = peers;
    storage.peer_info_capacity = 1U;
    assert(
        libp2p_gossipsub_rpc_body_decode(
            LIBP2P_GOSSIPSUB_VERSION_11,
            &limits,
            expected,
            sizeof(expected),
            &storage,
            &decoded) == LIBP2P_GOSSIPSUB_OK);
    assert(decoded.subscription_count == 1U);
    assert(decoded.subscriptions[0].subscribe == 1U);
    assert(decoded.subscriptions[0].topic.len == (sizeof(topic) - 1U));
}

static void gossipsub_spec_publish_vector(void)
{
    static const uint8_t topic[] = "blocks";
    static const uint8_t data[] = {0xDEU, 0xADU};
    static const uint8_t expected[] =
        {0x12U, 0x0CU, 0x12U, 0x02U, 0xDEU, 0xADU, 0x22U, 0x06U, 'b', 'l', 'o', 'c', 'k', 's'};
    libp2p_gossipsub_limits_t limits;
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_rpc_t rpc;
    uint8_t encoded[32];
    size_t written = 0U;

    gossipsub_spec_limits(&limits);
    (void)memset(&message, 0, sizeof(message));
    (void)memset(&rpc, 0, sizeof(rpc));
    message.topic.data = topic;
    message.topic.len = sizeof(topic) - 1U;
    message.data.data = data;
    message.data.len = sizeof(data);
    rpc.publish = &message;
    rpc.publish_count = 1U;

    assert(
        libp2p_gossipsub_rpc_body_encode(
            LIBP2P_GOSSIPSUB_VERSION_12,
            &limits,
            &rpc,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_GOSSIPSUB_OK);
    assert(written == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
}

static void gossipsub_spec_idontwant_vector(void)
{
    static const uint8_t id[] = "abcd";
    static const uint8_t expected[] =
        {0x1AU, 0x08U, 0x2AU, 0x06U, 0x0AU, 0x04U, 'a', 'b', 'c', 'd'};
    libp2p_gossipsub_limits_t limits;
    libp2p_gossipsub_bytes_t id_span;
    libp2p_gossipsub_control_idontwant_t idontwant;
    libp2p_gossipsub_rpc_t rpc;
    uint8_t encoded[32];
    size_t written = 0U;

    gossipsub_spec_limits(&limits);
    (void)memset(&id_span, 0, sizeof(id_span));
    (void)memset(&idontwant, 0, sizeof(idontwant));
    (void)memset(&rpc, 0, sizeof(rpc));
    id_span.data = id;
    id_span.len = sizeof(id) - 1U;
    idontwant.message_ids = &id_span;
    idontwant.message_id_count = 1U;
    rpc.control.idontwant = &idontwant;
    rpc.control.idontwant_count = 1U;

    assert(
        libp2p_gossipsub_rpc_body_encode(
            LIBP2P_GOSSIPSUB_VERSION_12,
            &limits,
            &rpc,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_GOSSIPSUB_OK);
    assert(written == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(
        libp2p_gossipsub_rpc_body_size(LIBP2P_GOSSIPSUB_VERSION_11, &limits, &rpc, &written) ==
        LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION);
}

static void gossipsub_spec_prune_px_decode_and_no_encode(void)
{
    static const uint8_t body[] = {0x1AU, 0x16U, 0x22U, 0x14U, 0x0AU, 0x06U, 'b',   'l',
                                   'o',   'c',   'k',   's',   0x12U, 0x08U, 0x0AU, 0x02U,
                                   'p',   '1',   0x12U, 0x02U, 's',   'r',   0x18U, 0x3CU};
    static const uint8_t expected_no_px[] =
        {0x1AU, 0x0AU, 0x22U, 0x08U, 0x0AU, 0x06U, 'b', 'l', 'o', 'c', 'k', 's'};
    libp2p_gossipsub_limits_t limits;
    libp2p_gossipsub_rpc_subscription_t subs[1];
    libp2p_gossipsub_message_t publish[1];
    libp2p_gossipsub_control_ihave_t ihave[1];
    libp2p_gossipsub_control_iwant_t iwant[1];
    libp2p_gossipsub_control_graft_t graft[1];
    libp2p_gossipsub_control_prune_t prune[1];
    libp2p_gossipsub_control_idontwant_t idontwant[1];
    libp2p_gossipsub_bytes_t ids[8];
    libp2p_gossipsub_peer_info_t peers[2];
    libp2p_gossipsub_rpc_decode_storage_t storage;
    libp2p_gossipsub_rpc_t decoded;
    uint8_t encoded[64];
    size_t written = 0U;

    gossipsub_spec_limits(&limits);
    (void)memset(&storage, 0, sizeof(storage));
    storage.subscriptions = subs;
    storage.subscription_capacity = 1U;
    storage.publish = publish;
    storage.publish_capacity = 1U;
    storage.ihave = ihave;
    storage.ihave_capacity = 1U;
    storage.iwant = iwant;
    storage.iwant_capacity = 1U;
    storage.graft = graft;
    storage.graft_capacity = 1U;
    storage.prune = prune;
    storage.prune_capacity = 1U;
    storage.idontwant = idontwant;
    storage.idontwant_capacity = 1U;
    storage.message_ids = ids;
    storage.message_id_capacity = 8U;
    storage.peer_infos = peers;
    storage.peer_info_capacity = 2U;

    assert(
        libp2p_gossipsub_rpc_body_decode(
            LIBP2P_GOSSIPSUB_VERSION_11,
            &limits,
            body,
            sizeof(body),
            &storage,
            &decoded) == LIBP2P_GOSSIPSUB_OK);
    assert(decoded.control.prune_count == 1U);
    assert(decoded.control.prune[0].peer_count == 1U);
    assert(decoded.control.prune[0].backoff_seconds == 60U);
    (void)memset(&decoded, 0, sizeof(decoded));
    prune[0].backoff_seconds = 0U;
    decoded.control.prune = prune;
    decoded.control.prune_count = 1U;
    assert(
        libp2p_gossipsub_rpc_body_encode(
            LIBP2P_GOSSIPSUB_VERSION_11,
            &limits,
            &decoded,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_GOSSIPSUB_OK);
    assert(written == sizeof(expected_no_px));
    assert(memcmp(encoded, expected_no_px, sizeof(expected_no_px)) == 0);
}

int main(void)
{
    gossipsub_spec_protocol_ids();
    gossipsub_spec_subscription_vector();
    gossipsub_spec_publish_vector();
    gossipsub_spec_idontwant_vector();
    gossipsub_spec_prune_px_decode_and_no_encode();
    return 0;
}
