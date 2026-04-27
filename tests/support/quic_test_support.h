#ifndef LIBP2P_TEST_QUIC_TEST_SUPPORT_H
#define LIBP2P_TEST_QUIC_TEST_SUPPORT_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peer_id/peer_id.h"
#include "transport/quic/quic.h"

typedef struct
{
    uint8_t cert[LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES];
    uint8_t key[LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES];
    size_t cert_len;
    size_t key_len;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
    libp2p_quic_local_identity_t identity;
} quic_test_identity_fixture_t;

typedef struct
{
    libp2p_quic_endpoint_t *client;
    libp2p_quic_endpoint_t *server;
    libp2p_quic_conn_t *client_conn;
    libp2p_quic_conn_t *server_conn;
    libp2p_quic_addr_t client_addr;
    libp2p_quic_addr_t server_addr;
    void *client_storage;
    void *server_storage;
    uint8_t client_random;
    uint8_t server_random;
    uint64_t unix_time;
    libp2p_quic_time_us_t now_us;
} quic_test_pair_t;

typedef struct
{
    libp2p_quic_conn_t *incoming_conn;
    libp2p_quic_conn_t *closed_conn;
    libp2p_quic_stream_t *incoming_stream;
    libp2p_quic_stream_t *readable_stream;
    libp2p_quic_stream_t *closed_stream;
    size_t established_count;
    size_t readable_count;
    size_t closed_conn_count;
    size_t closed_stream_count;
    uint64_t last_app_error_code;
    uint64_t last_transport_error_code;
} quic_test_events_t;

static inline void *quic_test_malloc(size_t size, void *user_data)
{
    (void)user_data;
    return malloc(size);
}

static inline void *quic_test_calloc(size_t nmemb, size_t size, void *user_data)
{
    (void)user_data;
    return calloc(nmemb, size);
}

static inline void *quic_test_realloc(void *ptr, size_t size, void *user_data)
{
    (void)user_data;
    return realloc(ptr, size);
}

static inline void quic_test_free(void *ptr, void *user_data)
{
    (void)user_data;
    free(ptr);
}

static inline libp2p_quic_allocator_t quic_test_allocator(void)
{
    libp2p_quic_allocator_t allocator;

    allocator.malloc_fn = quic_test_malloc;
    allocator.calloc_fn = quic_test_calloc;
    allocator.realloc_fn = quic_test_realloc;
    allocator.free_fn = quic_test_free;
    allocator.user_data = NULL;
    return allocator;
}

static inline int quic_test_hex_nibble(char character, uint8_t *value)
{
    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'a'));
        return 1;
    }
    if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'A'));
        return 1;
    }

    *value = 0U;
    return 0;
}

static inline void quic_test_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = strlen(text);
    size_t index = 0U;

    assert((text_len % 2U) == 0U);
    assert((text_len / 2U) <= out_capacity);

    for (index = 0U; index < text_len; index += 2U)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        assert(quic_test_hex_nibble(text[index], &high) != 0);
        assert(quic_test_hex_nibble(text[index + 1U], &low) != 0);
        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
}

static inline libp2p_quic_err_t quic_test_random(uint8_t *out, size_t out_len, void *user_data)
{
    size_t index = 0U;
    uint8_t *state = (uint8_t *)user_data;

    assert(out != NULL);
    assert(state != NULL);

    for (index = 0U; index < out_len; index++)
    {
        out[index] = *state;
        *state = (uint8_t)(*state + 29U);
    }

    return LIBP2P_QUIC_OK;
}

static inline libp2p_quic_err_t quic_test_unix_time(uint64_t *out_unix_seconds, void *user_data)
{
    uint64_t *now = (uint64_t *)user_data;

    assert(out_unix_seconds != NULL);
    assert(now != NULL);
    *out_unix_seconds = *now;
    return LIBP2P_QUIC_OK;
}

static inline void quic_test_load_host_key(
    uint8_t private_key[32],
    uint8_t public_key_message[37],
    libp2p_quic_host_key_t *host_key)
{
    static const char private_key_hex[] =
        "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    static const char public_key_message_hex[] =
        "08021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
    size_t written = 0U;

    quic_test_parse_hex(private_key_hex, private_key, 32U, &written);
    assert(written == 32U);
    quic_test_parse_hex(public_key_message_hex, public_key_message, 37U, &written);
    assert(written == 37U);

    host_key->type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
    host_key->private_key = private_key;
    host_key->private_key_len = 32U;
    host_key->public_key_message = public_key_message;
    host_key->public_key_message_len = 37U;
}

static inline void quic_test_make_identity(
    quic_test_identity_fixture_t *fixture,
    uint8_t random_seed)
{
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    uint8_t random_state = random_seed;
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t cert_config;

    assert(fixture != NULL);
    (void)memset(fixture, 0, sizeof(*fixture));
    quic_test_load_host_key(private_key, public_key_message, &host_key);

    cert_config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
    cert_config.not_before_unix_seconds = UINT64_C(1700000000);
    cert_config.not_after_unix_seconds = UINT64_C(1800000000);
    cert_config.random_fn = quic_test_random;
    cert_config.random_user_data = &random_state;

    assert(
        libp2p_quic_identity_write_certificate_der(
            &host_key,
            &cert_config,
            fixture->cert,
            sizeof(fixture->cert),
            &fixture->cert_len,
            fixture->key,
            sizeof(fixture->key),
            &fixture->key_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_host_key_peer_id(
            &host_key,
            fixture->peer_id,
            sizeof(fixture->peer_id),
            &fixture->peer_id_len) == LIBP2P_QUIC_OK);

    fixture->identity.certificate_der = fixture->cert;
    fixture->identity.certificate_der_len = fixture->cert_len;
    fixture->identity.certificate_private_key_der = fixture->key;
    fixture->identity.certificate_private_key_der_len = fixture->key_len;
    fixture->identity.peer_id = fixture->peer_id;
    fixture->identity.peer_id_len = fixture->peer_id_len;
}

static inline void quic_test_endpoint_init_one(
    libp2p_quic_endpoint_t **endpoint,
    void **storage,
    libp2p_quic_endpoint_config_t *config)
{
    size_t storage_len = 0U;

    assert(endpoint != NULL);
    assert(storage != NULL);
    assert(config != NULL);

    assert(libp2p_quic_endpoint_storage_size(config, &storage_len) == LIBP2P_QUIC_OK);
    *storage = calloc(1U, storage_len);
    assert(*storage != NULL);
    assert(libp2p_quic_endpoint_init(*storage, storage_len, config, endpoint) == LIBP2P_QUIC_OK);
}

static inline void quic_test_pair_init(
    quic_test_pair_t *pair,
    const libp2p_quic_local_identity_t *identity,
    uint16_t client_port,
    uint16_t server_port,
    libp2p_quic_time_us_t idle_timeout_us)
{
    libp2p_quic_endpoint_config_t client_config;
    libp2p_quic_endpoint_config_t server_config;
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};

    assert(pair != NULL);
    assert(identity != NULL);
    (void)memset(pair, 0, sizeof(*pair));
    pair->client_random = 1U;
    pair->server_random = 131U;
    pair->unix_time = UINT64_C(1750000000);

    assert(libp2p_quic_endpoint_config_default(&client_config) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_config_default(&server_config) == LIBP2P_QUIC_OK);
    client_config.allocator = quic_test_allocator();
    server_config.allocator = quic_test_allocator();
    client_config.role = LIBP2P_QUIC_ROLE_CLIENT;
    server_config.role = LIBP2P_QUIC_ROLE_SERVER;
    client_config.identity = *identity;
    server_config.identity = *identity;
    client_config.random_fn = quic_test_random;
    client_config.random_user_data = &pair->client_random;
    client_config.unix_time_fn = quic_test_unix_time;
    client_config.unix_time_user_data = &pair->unix_time;
    server_config.random_fn = quic_test_random;
    server_config.random_user_data = &pair->server_random;
    server_config.unix_time_fn = quic_test_unix_time;
    server_config.unix_time_user_data = &pair->unix_time;
    if (idle_timeout_us != 0U)
    {
        client_config.idle_timeout_us = idle_timeout_us;
        server_config.idle_timeout_us = idle_timeout_us;
    }

    quic_test_endpoint_init_one(&pair->client, &pair->client_storage, &client_config);
    quic_test_endpoint_init_one(&pair->server, &pair->server_storage, &server_config);

    assert(libp2p_quic_addr_from_ip4(ip4, client_port, &pair->client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, server_port, &pair->server_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(pair->client, &pair->client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(pair->server, &pair->server_addr) == LIBP2P_QUIC_OK);
}

static inline void quic_test_pair_deinit(quic_test_pair_t *pair)
{
    if (pair == NULL)
    {
        return;
    }
    libp2p_quic_endpoint_deinit(pair->client);
    libp2p_quic_endpoint_deinit(pair->server);
    free(pair->client_storage);
    free(pair->server_storage);
    (void)memset(pair, 0, sizeof(*pair));
}

static inline void quic_test_deliver_one(
    libp2p_quic_endpoint_t *from,
    libp2p_quic_endpoint_t *to,
    libp2p_quic_time_us_t now_us,
    int *delivered)
{
    uint8_t packet[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    libp2p_quic_tx_datagram_t tx;
    libp2p_quic_rx_datagram_t rx;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)memset(&tx, 0, sizeof(tx));
    tx.data = packet;
    tx.data_cap = sizeof(packet);

    result = libp2p_quic_endpoint_next_datagram(from, &tx, now_us);
    if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
    {
        return;
    }

    assert(result == LIBP2P_QUIC_OK);
    assert(tx.data_len > 0U);

    rx.local_addr = tx.remote_addr;
    rx.remote_addr = tx.local_addr;
    assert(libp2p_quic_addr_set_peer_id(&rx.local_addr, NULL, 0U) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_set_peer_id(&rx.remote_addr, NULL, 0U) == LIBP2P_QUIC_OK);
    rx.data = packet;
    rx.data_len = tx.data_len;
    rx.ecn = tx.ecn;
    assert(libp2p_quic_endpoint_recv_datagram(to, &rx, now_us) == LIBP2P_QUIC_OK);
    *delivered = 1;
}

static inline void quic_test_pump(
    libp2p_quic_endpoint_t *client,
    libp2p_quic_endpoint_t *server,
    libp2p_quic_time_us_t *now_us)
{
    size_t rounds = 0U;

    for (rounds = 0U; rounds < 32U; rounds++)
    {
        int delivered = 0;

        quic_test_deliver_one(client, server, *now_us, &delivered);
        quic_test_deliver_one(server, client, *now_us, &delivered);
        assert(libp2p_quic_endpoint_poll(client, *now_us) == LIBP2P_QUIC_OK);
        assert(libp2p_quic_endpoint_poll(server, *now_us) == LIBP2P_QUIC_OK);
        *now_us += 1000U;
        if (delivered == 0)
        {
            break;
        }
    }
}

static inline void quic_test_drain_events(
    libp2p_quic_endpoint_t *endpoint,
    quic_test_events_t *events)
{
    libp2p_quic_event_t event;

    assert(endpoint != NULL);
    assert(events != NULL);

    while (libp2p_quic_endpoint_next_event(endpoint, &event) == LIBP2P_QUIC_OK)
    {
        if (event.type == LIBP2P_QUIC_EVENT_CONN_INCOMING)
        {
            events->incoming_conn = event.conn;
        }
        else if (event.type == LIBP2P_QUIC_EVENT_CONN_ESTABLISHED)
        {
            events->established_count++;
        }
        else if (event.type == LIBP2P_QUIC_EVENT_CONN_CLOSED)
        {
            events->closed_conn = event.conn;
            events->closed_conn_count++;
            events->last_app_error_code = event.app_error_code;
            events->last_transport_error_code = event.transport_error_code;
        }
        else if (event.type == LIBP2P_QUIC_EVENT_STREAM_INCOMING)
        {
            events->incoming_stream = event.stream;
        }
        else if (event.type == LIBP2P_QUIC_EVENT_STREAM_READABLE)
        {
            events->readable_stream = event.stream;
            events->readable_count++;
        }
        else if (event.type == LIBP2P_QUIC_EVENT_STREAM_CLOSED)
        {
            events->closed_stream = event.stream;
            events->closed_stream_count++;
            events->last_app_error_code = event.app_error_code;
        }
        else
        {
            /* Other events are advisory for these tests. */
        }
    }
}

static inline void quic_test_wait_established(
    libp2p_quic_endpoint_t *client,
    libp2p_quic_endpoint_t *server,
    libp2p_quic_conn_t *client_conn,
    libp2p_quic_conn_t **server_conn,
    libp2p_quic_time_us_t *now_us)
{
    size_t index = 0U;
    quic_test_events_t client_events;
    quic_test_events_t server_events;

    (void)memset(&client_events, 0, sizeof(client_events));
    (void)memset(&server_events, 0, sizeof(server_events));

    for (index = 0U; index < 1000U; index++)
    {
        libp2p_quic_conn_state_t client_state = LIBP2P_QUIC_CONN_IDLE;
        libp2p_quic_conn_state_t server_state = LIBP2P_QUIC_CONN_IDLE;

        quic_test_pump(client, server, now_us);
        quic_test_drain_events(server, &server_events);
        quic_test_drain_events(client, &client_events);
        if ((server_events.incoming_conn != NULL) && (*server_conn == NULL))
        {
            *server_conn = server_events.incoming_conn;
        }

        if (*server_conn != NULL)
        {
            assert(libp2p_quic_conn_state(client_conn, &client_state) == LIBP2P_QUIC_OK);
            assert(libp2p_quic_conn_state(*server_conn, &server_state) == LIBP2P_QUIC_OK);
            if ((client_state == LIBP2P_QUIC_CONN_ESTABLISHED) &&
                (server_state == LIBP2P_QUIC_CONN_ESTABLISHED))
            {
                return;
            }
        }
    }

    assert(0 && "QUIC handshake did not complete");
}

static inline void quic_test_pair_dial(
    quic_test_pair_t *pair,
    const quic_test_identity_fixture_t *identity)
{
    libp2p_quic_addr_t remote_addr;
    libp2p_quic_dial_config_t dial_config;

    assert(pair != NULL);
    assert(identity != NULL);

    remote_addr = pair->server_addr;
    assert(
        libp2p_quic_addr_set_peer_id(&remote_addr, identity->peer_id, identity->peer_id_len) ==
        LIBP2P_QUIC_OK);
    dial_config.remote_addr = remote_addr;
    dial_config.user_data = NULL;

    assert(
        libp2p_quic_endpoint_dial(pair->client, &dial_config, &pair->client_conn) ==
        LIBP2P_QUIC_OK);
    quic_test_wait_established(
        pair->client,
        pair->server,
        pair->client_conn,
        &pair->server_conn,
        &pair->now_us);
}

#endif /* LIBP2P_TEST_QUIC_TEST_SUPPORT_H */
