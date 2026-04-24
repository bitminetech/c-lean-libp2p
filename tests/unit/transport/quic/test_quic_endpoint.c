#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
} quic_endpoint_identity_fixture_t;

static int quic_endpoint_hex_nibble(char character, uint8_t *value)
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

static void quic_endpoint_parse_hex(
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

        assert(quic_endpoint_hex_nibble(text[index], &high) != 0);
        assert(quic_endpoint_hex_nibble(text[index + 1U], &low) != 0);
        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
}

static libp2p_quic_err_t quic_endpoint_test_random(uint8_t *out, size_t out_len, void *user_data)
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

static libp2p_quic_err_t quic_endpoint_test_time(uint64_t *out_unix_seconds, void *user_data)
{
    (void)user_data;

    assert(out_unix_seconds != NULL);
    *out_unix_seconds = UINT64_C(1750000000);
    return LIBP2P_QUIC_OK;
}

static void quic_endpoint_load_host_key(
    uint8_t private_key[32],
    uint8_t public_key_message[37],
    libp2p_quic_host_key_t *host_key)
{
    static const char private_key_hex[] =
        "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    static const char public_key_message_hex[] =
        "08021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
    size_t written = 0U;

    quic_endpoint_parse_hex(private_key_hex, private_key, 32U, &written);
    assert(written == 32U);
    quic_endpoint_parse_hex(public_key_message_hex, public_key_message, 37U, &written);
    assert(written == 37U);

    host_key->type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
    host_key->private_key = private_key;
    host_key->private_key_len = 32U;
    host_key->public_key_message = public_key_message;
    host_key->public_key_message_len = 37U;
}

static void quic_endpoint_make_identity(
    quic_endpoint_identity_fixture_t *fixture,
    uint8_t random_seed)
{
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    uint8_t random_state = random_seed;
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t cert_config;

    quic_endpoint_load_host_key(private_key, public_key_message, &host_key);

    cert_config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
    cert_config.not_before_unix_seconds = UINT64_C(1700000000);
    cert_config.not_after_unix_seconds = UINT64_C(1800000000);
    cert_config.random_fn = quic_endpoint_test_random;
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

static void quic_endpoint_init_pair(
    libp2p_quic_endpoint_t **client,
    void **client_storage,
    libp2p_quic_endpoint_t **server,
    void **server_storage,
    const libp2p_quic_local_identity_t *identity)
{
    libp2p_quic_endpoint_config_t client_config;
    libp2p_quic_endpoint_config_t server_config;
    size_t storage_len = 0U;
    static uint8_t client_random;
    static uint8_t server_random;
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_addr_t client_addr;
    libp2p_quic_addr_t server_addr;

    assert(libp2p_quic_endpoint_config_default(&client_config) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_config_default(&server_config) == LIBP2P_QUIC_OK);
    client_random = 1U;
    server_random = 131U;
    client_config.role = LIBP2P_QUIC_ROLE_CLIENT;
    server_config.role = LIBP2P_QUIC_ROLE_SERVER;
    client_config.identity = *identity;
    server_config.identity = *identity;
    client_config.random_fn = quic_endpoint_test_random;
    client_config.random_user_data = &client_random;
    client_config.unix_time_fn = quic_endpoint_test_time;
    server_config.random_fn = quic_endpoint_test_random;
    server_config.random_user_data = &server_random;
    server_config.unix_time_fn = quic_endpoint_test_time;

    assert(libp2p_quic_endpoint_storage_size(&client_config, &storage_len) == LIBP2P_QUIC_OK);
    *client_storage = calloc(1U, storage_len);
    *server_storage = calloc(1U, storage_len);
    assert(*client_storage != NULL);
    assert(*server_storage != NULL);

    assert(
        libp2p_quic_endpoint_init(*client_storage, storage_len, &client_config, client) ==
        LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_endpoint_init(*server_storage, storage_len, &server_config, server) ==
        LIBP2P_QUIC_OK);

    assert(libp2p_quic_addr_from_ip4(ip4, 30000U, &client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 30001U, &server_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(*client, &client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(*server, &server_addr) == LIBP2P_QUIC_OK);
}

static void quic_endpoint_deinit_pair(
    libp2p_quic_endpoint_t *client,
    void *client_storage,
    libp2p_quic_endpoint_t *server,
    void *server_storage)
{
    libp2p_quic_endpoint_deinit(client);
    libp2p_quic_endpoint_deinit(server);
    free(client_storage);
    free(server_storage);
}

static void quic_endpoint_deliver_one(
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

static void quic_endpoint_drain_events(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_conn_t **incoming_conn,
    size_t *established_count,
    libp2p_quic_stream_t **incoming_stream,
    size_t *readable_count)
{
    libp2p_quic_event_t event;

    while (libp2p_quic_endpoint_next_event(endpoint, &event) == LIBP2P_QUIC_OK)
    {
        if ((event.type == LIBP2P_QUIC_EVENT_CONN_INCOMING) && (incoming_conn != NULL))
        {
            *incoming_conn = event.conn;
        }
        else if ((event.type == LIBP2P_QUIC_EVENT_CONN_ESTABLISHED) && (established_count != NULL))
        {
            (*established_count)++;
        }
        else if ((event.type == LIBP2P_QUIC_EVENT_STREAM_INCOMING) && (incoming_stream != NULL))
        {
            *incoming_stream = event.stream;
        }
        else if ((event.type == LIBP2P_QUIC_EVENT_STREAM_READABLE) && (readable_count != NULL))
        {
            (*readable_count)++;
            if ((incoming_stream != NULL) && (*incoming_stream == NULL))
            {
                *incoming_stream = event.stream;
            }
        }
        else
        {
            /* Other events are advisory for this unit test. */
        }
    }
}

static void quic_endpoint_pump(
    libp2p_quic_endpoint_t *client,
    libp2p_quic_endpoint_t *server,
    libp2p_quic_time_us_t *now_us)
{
    size_t rounds = 0U;

    for (rounds = 0U; rounds < 32U; rounds++)
    {
        int delivered = 0;

        quic_endpoint_deliver_one(client, server, *now_us, &delivered);
        quic_endpoint_deliver_one(server, client, *now_us, &delivered);
        assert(libp2p_quic_endpoint_poll(client, *now_us) == LIBP2P_QUIC_OK);
        assert(libp2p_quic_endpoint_poll(server, *now_us) == LIBP2P_QUIC_OK);
        *now_us += 1000U;
        if (delivered == 0)
        {
            break;
        }
    }
}

static void quic_endpoint_wait_established(
    libp2p_quic_endpoint_t *client,
    libp2p_quic_endpoint_t *server,
    libp2p_quic_conn_t *client_conn,
    libp2p_quic_conn_t **server_conn,
    libp2p_quic_time_us_t *now_us)
{
    size_t index = 0U;
    size_t established_count = 0U;

    for (index = 0U; index < 1000U; index++)
    {
        libp2p_quic_conn_state_t client_state = LIBP2P_QUIC_CONN_IDLE;
        libp2p_quic_conn_state_t server_state = LIBP2P_QUIC_CONN_IDLE;

        quic_endpoint_pump(client, server, now_us);
        quic_endpoint_drain_events(server, server_conn, &established_count, NULL, NULL);
        quic_endpoint_drain_events(client, NULL, &established_count, NULL, NULL);

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

static void quic_endpoint_test_handshake_and_stream(void)
{
    quic_endpoint_identity_fixture_t identity;
    libp2p_quic_endpoint_t *client = NULL;
    libp2p_quic_endpoint_t *server = NULL;
    libp2p_quic_conn_t *client_conn = NULL;
    libp2p_quic_conn_t *server_conn = NULL;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_stream_t *server_stream = NULL;
    void *client_storage = NULL;
    void *server_storage = NULL;
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_addr_t remote_addr;
    libp2p_quic_dial_config_t dial_config;
    libp2p_quic_time_us_t now_us = 0U;
    size_t accepted = 0U;
    size_t established_count = 0U;
    size_t readable_count = 0U;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    uint8_t read_buf[32];
    size_t read_len = 0U;
    int fin = 0;
    static const uint8_t message[] = {'h', 'e', 'l', 'l', 'o', '-', 'q', 'u', 'i', 'c'};

    quic_endpoint_make_identity(&identity, 17U);
    quic_endpoint_init_pair(&client, &client_storage, &server, &server_storage, &identity.identity);

    assert(libp2p_quic_addr_from_ip4(ip4, 30001U, &remote_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(&remote_addr, identity.peer_id, identity.peer_id_len) ==
        LIBP2P_QUIC_OK);
    dial_config.remote_addr = remote_addr;
    dial_config.user_data = NULL;

    assert(libp2p_quic_endpoint_dial(client, &dial_config, &client_conn) == LIBP2P_QUIC_OK);
    quic_endpoint_wait_established(client, server, client_conn, &server_conn, &now_us);

    assert(
        libp2p_quic_conn_peer_id(client_conn, peer_id, sizeof(peer_id), &peer_id_len) ==
        LIBP2P_QUIC_OK);
    assert(peer_id_len == identity.peer_id_len);
    assert(memcmp(peer_id, identity.peer_id, identity.peer_id_len) == 0);
    assert(
        libp2p_quic_conn_peer_id(server_conn, peer_id, sizeof(peer_id), &peer_id_len) ==
        LIBP2P_QUIC_OK);
    assert(peer_id_len == identity.peer_id_len);

    assert(libp2p_quic_conn_open_bidi_stream(client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_stream_write(client_stream, message, sizeof(message), 1, &accepted) ==
        LIBP2P_QUIC_OK);
    assert(accepted == sizeof(message));

    while ((server_stream == NULL) || (readable_count == 0U))
    {
        quic_endpoint_pump(client, server, &now_us);
        quic_endpoint_drain_events(
            server,
            &server_conn,
            &established_count,
            &server_stream,
            &readable_count);
    }

    {
        libp2p_quic_stream_t *accepted_stream = NULL;
        assert(libp2p_quic_conn_accept_stream(server_conn, &accepted_stream) == LIBP2P_QUIC_OK);
        assert(accepted_stream == server_stream);
    }

    assert(
        libp2p_quic_stream_read(server_stream, read_buf, sizeof(read_buf), &read_len, &fin) ==
        LIBP2P_QUIC_OK);
    assert(read_len == sizeof(message));
    assert(memcmp(read_buf, message, sizeof(message)) == 0);
    assert(fin == 1);

    quic_endpoint_deinit_pair(client, client_storage, server, server_storage);
}

int main(void)
{
    quic_endpoint_test_handshake_and_stream();
    return 0;
}
