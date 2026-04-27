#ifndef LIBP2P_TEST_PROTOCOL_LOOPBACK_SUPPORT_H
#define LIBP2P_TEST_PROTOCOL_LOOPBACK_SUPPORT_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "quic_test_support.h"
#include "transport/quic/quic_addr.h"
#include "transport/quic/quic_service.h"

typedef struct
{
    libp2p_host_t *client;
    libp2p_host_t *server;
    void *client_storage;
    void *server_storage;
    uint8_t client_random;
    uint8_t server_random;
    uint64_t unix_time;
    libp2p_host_time_us_t now_us;
    libp2p_host_conn_t *client_conn;
    libp2p_host_conn_t *server_conn;
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    libp2p_quic_host_key_t ignored_host_key;
    quic_test_identity_fixture_t quic_identity;
    libp2p_host_secp256k1_identity_t host_identity_storage;
    libp2p_host_identity_t host_identity;
    uint8_t client_listen[128];
    uint8_t server_listen[128];
    size_t client_listen_len;
    size_t server_listen_len;
} protocol_loopback_pair_t;

static inline void protocol_loopback_config(
    libp2p_host_config_t *host_config,
    libp2p_quic_service_config_t *service_config,
    const libp2p_quic_local_identity_t *identity,
    const libp2p_host_identity_t *host_identity,
    const uint8_t *listen_multiaddr,
    size_t listen_multiaddr_len,
    libp2p_quic_role_t role,
    uint8_t *random_state,
    uint64_t *unix_time,
    size_t max_protocols)
{
    assert(libp2p_quic_service_config_default(service_config) == LIBP2P_QUIC_OK);
    service_config->endpoint.role = role;
    service_config->endpoint.allocator = quic_test_allocator();
    service_config->endpoint.identity = *identity;
    service_config->endpoint.random_fn = quic_test_random;
    service_config->endpoint.random_user_data = random_state;
    service_config->endpoint.unix_time_fn = quic_test_unix_time;
    service_config->endpoint.unix_time_user_data = unix_time;
    service_config->endpoint.max_connections = 4U;
    service_config->endpoint.max_incoming_connections = 4U;
    service_config->endpoint.max_outgoing_connections = 4U;
    service_config->endpoint.max_bidi_streams = 8U;
    service_config->max_rx_datagrams_per_drive = 16U;
    service_config->max_tx_datagrams_per_drive = 16U;

    assert(libp2p_host_config_default(host_config) == LIBP2P_HOST_OK);
    host_config->identity = *host_identity;
    host_config->listen_multiaddr = listen_multiaddr;
    host_config->listen_multiaddr_len = listen_multiaddr_len;
    host_config->transport = libp2p_host_quic_transport();
    host_config->transport_config = service_config;
    host_config->max_protocols = max_protocols;
    host_config->max_connections = 4U;
    host_config->max_streams_per_conn = 8U;
    host_config->max_pending_dials = 4U;
    host_config->max_pending_stream_opens = 4U;
    host_config->event_capacity = 16U;
    host_config->max_negotiation_steps = 64U;
}

static inline void protocol_loopback_drive(protocol_loopback_pair_t *pair)
{
    assert(
        libp2p_host_drive(pair->client, pair->now_us, LIBP2P_HOST_READY_ALL, NULL) ==
        LIBP2P_HOST_OK);
    assert(
        libp2p_host_drive(pair->server, pair->now_us, LIBP2P_HOST_READY_ALL, NULL) ==
        LIBP2P_HOST_OK);
    pair->now_us += 1000U;
}

static inline void protocol_loopback_init(
    protocol_loopback_pair_t *pair,
    uint16_t client_port,
    uint16_t server_port,
    size_t max_protocols,
    libp2p_host_config_t *client_host_config,
    libp2p_host_config_t *server_host_config,
    libp2p_quic_service_config_t *client_service_config,
    libp2p_quic_service_config_t *server_service_config,
    libp2p_quic_addr_t *server_addr,
    uint8_t *server_dial,
    size_t server_dial_cap,
    size_t *server_dial_len)
{
    libp2p_quic_addr_t client_addr;
    size_t client_listen_len = 0U;
    size_t server_listen_len = 0U;
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    size_t client_storage_len = 0U;
    size_t server_storage_len = 0U;

    (void)memset(pair, 0, sizeof(*pair));
    quic_test_load_host_key(pair->private_key, pair->public_key_message, &pair->ignored_host_key);
    quic_test_make_identity(&pair->quic_identity, 121U);
    assert(
        libp2p_host_secp256k1_identity_init(
            &pair->host_identity_storage,
            pair->private_key,
            sizeof(pair->private_key),
            &pair->host_identity) == LIBP2P_HOST_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, client_port, &client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, server_port, server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(
            &client_addr,
            pair->client_listen,
            sizeof(pair->client_listen),
            &client_listen_len) == LIBP2P_QUIC_OK);
    pair->client_listen_len = client_listen_len;
    assert(
        libp2p_quic_addr_to_multiaddr(
            server_addr,
            pair->server_listen,
            sizeof(pair->server_listen),
            &server_listen_len) == LIBP2P_QUIC_OK);
    pair->server_listen_len = server_listen_len;
    assert(
        libp2p_quic_addr_set_peer_id(
            server_addr,
            pair->quic_identity.peer_id,
            pair->quic_identity.peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(server_addr, server_dial, server_dial_cap, server_dial_len) ==
        LIBP2P_QUIC_OK);

    pair->client_random = 31U;
    pair->server_random = 181U;
    pair->unix_time = UINT64_C(1750000000);
    protocol_loopback_config(
        client_host_config,
        client_service_config,
        &pair->quic_identity.identity,
        &pair->host_identity,
        pair->client_listen,
        client_listen_len,
        LIBP2P_QUIC_ROLE_CLIENT,
        &pair->client_random,
        &pair->unix_time,
        max_protocols);
    protocol_loopback_config(
        server_host_config,
        server_service_config,
        &pair->quic_identity.identity,
        &pair->host_identity,
        pair->server_listen,
        server_listen_len,
        LIBP2P_QUIC_ROLE_SERVER,
        &pair->server_random,
        &pair->unix_time,
        max_protocols);

    assert(libp2p_host_storage_size(client_host_config, &client_storage_len) == LIBP2P_HOST_OK);
    assert(libp2p_host_storage_size(server_host_config, &server_storage_len) == LIBP2P_HOST_OK);
    pair->client_storage = calloc(1U, client_storage_len);
    pair->server_storage = calloc(1U, server_storage_len);
    assert(pair->client_storage != NULL);
    assert(pair->server_storage != NULL);
    assert(
        libp2p_host_init(
            pair->client_storage,
            client_storage_len,
            client_host_config,
            &pair->client) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_init(
            pair->server_storage,
            server_storage_len,
            server_host_config,
            &pair->server) == LIBP2P_HOST_OK);
}

static inline void protocol_loopback_deinit(protocol_loopback_pair_t *pair)
{
    if (pair->client != NULL)
    {
        libp2p_host_deinit(pair->client);
    }
    if (pair->server != NULL)
    {
        libp2p_host_deinit(pair->server);
    }
    free(pair->client_storage);
    free(pair->server_storage);
}

#endif /* LIBP2P_TEST_PROTOCOL_LOOPBACK_SUPPORT_H */
