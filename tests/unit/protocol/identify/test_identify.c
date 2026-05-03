#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_test_support.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "multiformats/multistream-select/multistream_select.h"
#include "protocol/identify/identify.h"
#include "protocol_loopback_support.h"

static const uint8_t identify_test_public_key[] = {0x08U, 0x02U};
static const uint8_t identify_test_addr[] =
    {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
static const uint8_t identify_test_protocol_version[] = "ipfs/0.1.0";
static const uint8_t identify_test_agent_version[] = "c-lean-libp2p/test";
static const uint8_t identify_test_protocol_id[] = LIBP2P_IDENTIFY_PROTOCOL_ID;
static const uint8_t identify_test_ping_id[] = "/ipfs/ping/1.0.0";

static void identify_test_message(libp2p_identify_message_t *message)
{
    (void)memset(message, 0, sizeof(*message));
    message->public_key.data = identify_test_public_key;
    message->public_key.len = sizeof(identify_test_public_key);
    message->listen_addrs[0].data = identify_test_addr;
    message->listen_addrs[0].len = sizeof(identify_test_addr);
    message->listen_addr_count = 1U;
    message->protocols[0].data = identify_test_protocol_id;
    message->protocols[0].len = sizeof(identify_test_protocol_id) - 1U;
    message->protocols[1].data = identify_test_ping_id;
    message->protocols[1].len = sizeof(identify_test_ping_id) - 1U;
    message->protocol_count = 2U;
    message->observed_addr.data = identify_test_addr;
    message->observed_addr.len = sizeof(identify_test_addr);
    message->protocol_version.data = identify_test_protocol_version;
    message->protocol_version.len = sizeof(identify_test_protocol_version) - 1U;
    message->agent_version.data = identify_test_agent_version;
    message->agent_version.len = sizeof(identify_test_agent_version) - 1U;
}

static void identify_test_encode_wire_message(
    const libp2p_identify_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t body[256];
    size_t body_len = 0U;
    size_t prefix_len = 0U;

    assert(message != NULL);
    assert(out != NULL);
    assert(written != NULL);
    assert(
        libp2p_identify_message_encode(message, body, sizeof(body), &body_len) ==
        LIBP2P_IDENTIFY_OK);
    assert(
        libp2p_uvarint_encode((uint64_t)body_len, out, out_len, &prefix_len) ==
        LIBP2P_UVARINT_OK);
    assert(body_len <= (out_len - prefix_len));
    (void)memcpy(&out[prefix_len], body, body_len);
    *written = prefix_len + body_len;
}

static void identify_test_decode_wire_message(
    const uint8_t *in,
    size_t in_len,
    libp2p_identify_message_t *message)
{
    uint64_t body_len_u64 = 0U;
    size_t prefix_len = 0U;
    size_t body_len = 0U;

    assert(in != NULL);
    assert(message != NULL);
    assert(
        libp2p_uvarint_decode(in, in_len, &body_len_u64, &prefix_len) ==
        LIBP2P_UVARINT_OK);
    body_len = (size_t)body_len_u64;
    assert(body_len <= (in_len - prefix_len));
    assert(
        libp2p_identify_message_decode(&in[prefix_len], body_len, message) ==
        LIBP2P_IDENTIFY_OK);
}

static libp2p_host_t *identify_test_init_mock(
    libp2p_host_config_t *config,
    host_test_transport_config_t *transport_config,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    void **storage)
{
    size_t storage_len = 0U;
    libp2p_host_t *host = NULL;

    host_test_fixture_init(fixture, conn);
    host_test_config_init(config, transport_config, fixture, host_test_transport());
    assert(libp2p_host_storage_size(config, &storage_len) == LIBP2P_HOST_OK);
    *storage = calloc(1U, storage_len);
    assert(*storage != NULL);
    assert(libp2p_host_init(*storage, storage_len, config, &host) == LIBP2P_HOST_OK);
    return host;
}

static void identify_test_establish_mock_conn(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    libp2p_host_conn_t **out_conn)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED;
    transport_event.conn = conn;
    transport_event.attempt = conn;
    host_test_event_push(fixture, &transport_event);
    assert(libp2p_host_drive(host, 1U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED);
    *out_conn = event.conn;
}

static void identify_test_push_stream_event(
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    host_test_stream_t *stream,
    libp2p_host_transport_event_type_t type)
{
    libp2p_host_transport_event_t transport_event;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = type;
    transport_event.conn = conn;
    transport_event.stream = stream;
    host_test_event_push(fixture, &transport_event);
}

static void identify_test_codec_paths(void)
{
    libp2p_identify_message_t message;
    libp2p_identify_message_t decoded;
    uint8_t encoded[256];
    size_t required = 0U;
    size_t written = 0U;
    uint8_t too_many[(LIBP2P_IDENTIFY_MAX_PROTOCOLS + 1U) * 3U];
    size_t index = 0U;
    static const uint8_t truncated[] = {0x0AU, 0x05U, 0x01U};
    static const uint8_t bad_key[] = {0x00U, 0x00U};

    identify_test_message(&message);
    assert(libp2p_identify_message_size(&message, &required) == LIBP2P_IDENTIFY_OK);
    assert(required != 0U);
    assert(
        libp2p_identify_message_encode(&message, NULL, 0U, &written) ==
        LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL);
    assert(written == required);
    assert(
        libp2p_identify_message_encode(&message, encoded, sizeof(encoded), &written) ==
        LIBP2P_IDENTIFY_OK);
    assert(written == required);
    assert(libp2p_identify_message_decode(encoded, written, &decoded) == LIBP2P_IDENTIFY_OK);
    assert(decoded.listen_addr_count == 1U);
    assert(decoded.protocol_count == 2U);
    assert(decoded.public_key.len == sizeof(identify_test_public_key));
    assert(memcmp(decoded.public_key.data, identify_test_public_key, decoded.public_key.len) == 0);
    assert(decoded.protocols[1].len == (sizeof(identify_test_ping_id) - 1U));
    assert(memcmp(decoded.protocols[1].data, identify_test_ping_id, decoded.protocols[1].len) == 0);

    assert(
        libp2p_identify_message_decode(truncated, sizeof(truncated), &decoded) ==
        LIBP2P_IDENTIFY_ERR_TRUNCATED);
    assert(
        libp2p_identify_message_decode(bad_key, sizeof(bad_key), &decoded) ==
        LIBP2P_IDENTIFY_ERR_MALFORMED);

    for (index = 0U; index < (LIBP2P_IDENTIFY_MAX_PROTOCOLS + 1U); index++)
    {
        too_many[(index * 3U)] = 0x1AU;
        too_many[(index * 3U) + 1U] = 0x01U;
        too_many[(index * 3U) + 2U] = (uint8_t)('a' + (char)(index % 26U));
    }
    assert(
        libp2p_identify_message_decode(too_many, sizeof(too_many), &decoded) ==
        LIBP2P_IDENTIFY_ERR_LIMIT);
}

static void identify_test_mock_host_round_trip(void)
{
    libp2p_identify_config_t identify_config;
    libp2p_identify_t identify;
    libp2p_host_protocol_t protocol;
    libp2p_host_config_t host_config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    host_test_stream_t inbound_stream;
    host_test_stream_t outbound_stream;
    libp2p_host_stream_open_t *open = NULL;
    libp2p_host_drive_result_t result;
    libp2p_identify_event_t identify_event;
    libp2p_identify_message_t local_message;
    uint8_t remote_message[256];
    size_t remote_message_len = 0U;
    size_t offset = 0U;
    void *storage = NULL;

    (void)memset(&inbound_stream, 0, sizeof(inbound_stream));
    (void)memset(&outbound_stream, 0, sizeof(outbound_stream));
    identify_test_message(&local_message);
    assert(libp2p_identify_config_default(&identify_config) == LIBP2P_IDENTIFY_OK);
    identify_config.local_message = local_message;
    assert(libp2p_identify_init(&identify, &identify_config) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_identify_protocol(&identify, &protocol) == LIBP2P_IDENTIFY_OK);

    host = identify_test_init_mock(&host_config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    identify_test_establish_mock_conn(host, &fixture, &conn, &host_conn);

    host_test_stream_add_message(
        &inbound_stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(
        &inbound_stream,
        (const uint8_t *)LIBP2P_IDENTIFY_PROTOCOL_ID,
        LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
    identify_test_push_stream_event(
        &fixture,
        &conn,
        &inbound_stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING);
    assert(libp2p_host_drive(host, 2U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    identify_test_push_stream_event(
        &fixture,
        &conn,
        &inbound_stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE);
    assert(libp2p_host_drive(host, 3U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    offset = host_test_encoded_message_size(LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) +
             host_test_encoded_message_size(LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
    assert(inbound_stream.write_len > offset);
    identify_test_decode_wire_message(
        &inbound_stream.write_buf[offset],
        inbound_stream.write_len - offset,
        &local_message);
    assert(local_message.protocol_count == 1U);
    assert(local_message.protocols[0].len == LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
    assert(
        memcmp(
            local_message.protocols[0].data,
            LIBP2P_IDENTIFY_PROTOCOL_ID,
            local_message.protocols[0].len) == 0);
    assert(local_message.observed_addr.len == conn.remote_multiaddr_len);
    assert(
        memcmp(local_message.observed_addr.data, conn.remote_multiaddr, conn.remote_multiaddr_len) ==
        0);
    assert(inbound_stream.finish_count == 1U);
    assert(libp2p_identify_next_event(&identify, &identify_event) == LIBP2P_IDENTIFY_OK);
    assert(identify_event.type == LIBP2P_IDENTIFY_EVENT_SENT);
    identify_test_push_stream_event(
        &fixture,
        &conn,
        &inbound_stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE);
    assert(libp2p_host_drive(host, 4U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    inbound_stream.read_fin = 1;
    identify_test_push_stream_event(
        &fixture,
        &conn,
        &inbound_stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE);
    assert(libp2p_host_drive(host, 5U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);

    host_test_stream_add_message(
        &outbound_stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(
        &outbound_stream,
        (const uint8_t *)LIBP2P_IDENTIFY_PROTOCOL_ID,
        LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
    fixture.next_stream = &outbound_stream;
    assert(
        libp2p_identify_query(&identify, host, host_conn, &identify, &open) == LIBP2P_IDENTIFY_OK);
    assert(open != NULL);
    assert(libp2p_host_drive(host, 5U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(outbound_stream.finish_count == 1U);
    identify_test_encode_wire_message(
        &identify_config.local_message,
        remote_message,
        sizeof(remote_message),
        &remote_message_len);
    assert((outbound_stream.read_len + remote_message_len) < sizeof(outbound_stream.read_buf));
    (void)memcpy(
        &outbound_stream.read_buf[outbound_stream.read_len],
        remote_message,
        remote_message_len);
    outbound_stream.read_len += remote_message_len;
    outbound_stream.read_fin = 1;
    identify_test_push_stream_event(
        &fixture,
        &conn,
        &outbound_stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE);
    assert(libp2p_host_drive(host, 6U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_identify_next_event(&identify, &identify_event) == LIBP2P_IDENTIFY_OK);
    assert(identify_event.type == LIBP2P_IDENTIFY_EVENT_RECEIVED);
    assert(identify_event.user_data == &identify);
    assert(identify_event.message.protocol_count == 2U);

    libp2p_host_deinit(host);
    free(storage);
}

static void identify_test_loopback_message(
    libp2p_identify_message_t *message,
    const protocol_loopback_pair_t *pair,
    const uint8_t *listen_addr,
    size_t listen_addr_len)
{
    (void)memset(message, 0, sizeof(*message));
    message->public_key.data = pair->host_identity.public_key_message;
    message->public_key.len = pair->host_identity.public_key_message_len;
    message->listen_addrs[0].data = listen_addr;
    message->listen_addrs[0].len = listen_addr_len;
    message->listen_addr_count = 1U;
    message->protocols[0].data = (const uint8_t *)LIBP2P_IDENTIFY_PROTOCOL_ID;
    message->protocols[0].len = LIBP2P_IDENTIFY_PROTOCOL_ID_LEN;
    message->protocol_count = 1U;
    message->observed_addr.data = pair->client_listen;
    message->observed_addr.len = pair->client_listen_len;
    message->protocol_version.data = identify_test_protocol_version;
    message->protocol_version.len = sizeof(identify_test_protocol_version) - 1U;
    message->agent_version.data = identify_test_agent_version;
    message->agent_version.len = sizeof(identify_test_agent_version) - 1U;
}

static void identify_test_quic_loopback(void)
{
    protocol_loopback_pair_t pair;
    libp2p_host_config_t client_host_config;
    libp2p_host_config_t server_host_config;
    libp2p_quic_service_config_t client_service_config;
    libp2p_quic_service_config_t server_service_config;
    libp2p_quic_addr_t server_addr;
    uint8_t server_dial[160];
    size_t server_dial_len = 0U;
    libp2p_identify_message_t client_message;
    libp2p_identify_message_t server_message;
    libp2p_identify_config_t client_identify_config;
    libp2p_identify_config_t server_identify_config;
    libp2p_identify_t client_identify;
    libp2p_identify_t server_identify;
    libp2p_host_protocol_t client_protocol;
    libp2p_host_protocol_t server_protocol;
    size_t round = 0U;
    int queried = 0;
    int received = 0;
    libp2p_identify_event_t server_event;

    protocol_loopback_init(
        &pair,
        39100U,
        39101U,
        2U,
        &client_host_config,
        &server_host_config,
        &client_service_config,
        &server_service_config,
        &server_addr,
        server_dial,
        sizeof(server_dial),
        &server_dial_len);
    identify_test_loopback_message(
        &client_message,
        &pair,
        pair.client_listen,
        pair.client_listen_len);
    identify_test_loopback_message(
        &server_message,
        &pair,
        pair.server_listen,
        pair.server_listen_len);
    assert(libp2p_identify_config_default(&client_identify_config) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_identify_config_default(&server_identify_config) == LIBP2P_IDENTIFY_OK);
    client_identify_config.local_message = client_message;
    server_identify_config.local_message = server_message;
    assert(libp2p_identify_init(&client_identify, &client_identify_config) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_identify_init(&server_identify, &server_identify_config) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_identify_protocol(&client_identify, &client_protocol) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_identify_protocol(&server_identify, &server_protocol) == LIBP2P_IDENTIFY_OK);
    assert(libp2p_host_handle(pair.client, &client_protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_handle(pair.server, &server_protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.client) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.server) == LIBP2P_HOST_OK);
    {
        libp2p_host_dial_t *dial = NULL;

        assert(
            libp2p_host_dial(pair.client, server_dial, server_dial_len, NULL, &dial) ==
            LIBP2P_HOST_OK);
    }

    for (round = 0U; round < 3000U; round++)
    {
        libp2p_host_event_t host_event;
        libp2p_identify_event_t identify_event;

        protocol_loopback_drive(&pair);
        while (libp2p_host_next_event(pair.client, &host_event) == LIBP2P_HOST_OK)
        {
            if (host_event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair.client_conn = host_event.conn;
            }
            else
            {
                assert(host_event.type != LIBP2P_HOST_EVENT_DIAL_FAILED);
            }
        }
        while (libp2p_host_next_event(pair.server, &host_event) == LIBP2P_HOST_OK)
        {
            if (host_event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair.server_conn = host_event.conn;
            }
        }
        if ((pair.client_conn != NULL) && (queried == 0))
        {
            libp2p_host_stream_open_t *open = NULL;

            assert(
                libp2p_identify_query(
                    &client_identify,
                    pair.client,
                    pair.client_conn,
                    NULL,
                    &open) == LIBP2P_IDENTIFY_OK);
            queried = 1;
        }
        if (libp2p_identify_next_event(&client_identify, &identify_event) == LIBP2P_IDENTIFY_OK)
        {
            if (identify_event.type == LIBP2P_IDENTIFY_EVENT_RECEIVED)
            {
                assert(identify_event.message.protocol_count == 1U);
                assert(
                    identify_event.message.public_key.len ==
                    pair.host_identity.public_key_message_len);
                received = 1;
                break;
            }
            assert(identify_event.type != LIBP2P_IDENTIFY_EVENT_ERROR);
        }
    }

    while (libp2p_identify_next_event(&server_identify, &server_event) == LIBP2P_IDENTIFY_OK)
    {
        assert(server_event.type != LIBP2P_IDENTIFY_EVENT_ERROR);
    }
    assert(received != 0);
    protocol_loopback_deinit(&pair);
}

int main(void)
{
    identify_test_codec_paths();
    identify_test_mock_host_round_trip();
    identify_test_quic_loopback();
    return 0;
}
