#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_test_support.h"
#include "multiformats/multistream-select/multistream_select.h"
#include "protocol/ping/ping.h"
#include "protocol_loopback_support.h"

typedef struct
{
    uint8_t random;
    libp2p_host_time_us_t now_us;
} ping_test_runtime_t;

static libp2p_ping_err_t ping_test_random(uint8_t *out, size_t out_len, void *user_data)
{
    ping_test_runtime_t *runtime = (ping_test_runtime_t *)user_data;
    size_t index = 0U;

    assert(out != NULL);
    assert(runtime != NULL);
    for (index = 0U; index < out_len; index++)
    {
        out[index] = runtime->random;
        runtime->random = (uint8_t)(runtime->random + 17U);
    }
    return LIBP2P_PING_OK;
}

static libp2p_ping_err_t ping_test_time(libp2p_host_time_us_t *out_now_us, void *user_data)
{
    ping_test_runtime_t *runtime = (ping_test_runtime_t *)user_data;

    assert(out_now_us != NULL);
    assert(runtime != NULL);
    *out_now_us = runtime->now_us;
    runtime->now_us += 100U;
    return LIBP2P_PING_OK;
}

static libp2p_host_t *ping_test_init_mock(
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

static void ping_test_establish_mock_conn(
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

static void ping_test_push_stream_event(
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

static void ping_test_config_init(libp2p_ping_config_t *config, ping_test_runtime_t *runtime)
{
    assert(libp2p_ping_config_default(config) == LIBP2P_PING_OK);
    config->random_fn = ping_test_random;
    config->random_user_data = runtime;
    config->time_fn = ping_test_time;
    config->time_user_data = runtime;
}

static void ping_test_responder_echoes_chunk(void)
{
    static const uint8_t payload[LIBP2P_PING_PAYLOAD_BYTES] = {0x00U, 0x01U, 0x02U, 0x03U, 0x04U,
                                                               0x05U, 0x06U, 0x07U, 0x08U, 0x09U,
                                                               0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU,
                                                               0x0FU, 0x10U, 0x11U, 0x12U, 0x13U,
                                                               0x14U, 0x15U, 0x16U, 0x17U, 0x18U,
                                                               0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU,
                                                               0x1EU, 0x1FU};
    ping_test_runtime_t runtime = {7U, 1000U};
    libp2p_ping_config_t ping_config;
    libp2p_ping_t ping;
    libp2p_host_protocol_t protocol;
    libp2p_host_config_t host_config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_drive_result_t result;
    size_t offset = 0U;
    void *storage = NULL;

    (void)memset(&stream, 0, sizeof(stream));
    ping_test_config_init(&ping_config, &runtime);
    assert(libp2p_ping_init(&ping, &ping_config) == LIBP2P_PING_OK);
    assert(libp2p_ping_protocol(&ping, &protocol) == LIBP2P_PING_OK);

    host = ping_test_init_mock(&host_config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    ping_test_establish_mock_conn(host, &fixture, &conn, &host_conn);
    assert(host_conn != NULL);

    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_PING_PROTOCOL_ID,
        LIBP2P_PING_PROTOCOL_ID_LEN);
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING);
    assert(libp2p_host_drive(host, 2U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);

    (void)memcpy(&stream.read_buf[stream.read_len], payload, sizeof(payload));
    stream.read_len += sizeof(payload);
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE);
    assert(libp2p_host_drive(host, 3U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE);
    assert(libp2p_host_drive(host, 4U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);

    offset = host_test_encoded_message_size(LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) +
             host_test_encoded_message_size(LIBP2P_PING_PROTOCOL_ID_LEN);
    assert(stream.write_len == (offset + LIBP2P_PING_PAYLOAD_BYTES));
    assert(memcmp(&stream.write_buf[offset], payload, sizeof(payload)) == 0);

    libp2p_host_deinit(host);
    free(storage);
}

static void ping_test_initiator_rtt_and_repeat_guard(void)
{
    ping_test_runtime_t runtime = {13U, 5000U};
    libp2p_ping_config_t ping_config;
    libp2p_ping_t ping;
    libp2p_host_protocol_t protocol;
    libp2p_host_config_t host_config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_stream_open_t *open = NULL;
    libp2p_host_drive_result_t result;
    libp2p_ping_event_t event;
    size_t offset = 0U;
    void *storage = NULL;

    (void)memset(&stream, 0, sizeof(stream));
    ping_test_config_init(&ping_config, &runtime);
    assert(libp2p_ping_init(&ping, &ping_config) == LIBP2P_PING_OK);
    assert(libp2p_ping_protocol(&ping, &protocol) == LIBP2P_PING_OK);

    host = ping_test_init_mock(&host_config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    ping_test_establish_mock_conn(host, &fixture, &conn, &host_conn);

    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_PING_PROTOCOL_ID,
        LIBP2P_PING_PROTOCOL_ID_LEN);
    fixture.next_stream = &stream;
    assert(libp2p_ping_initiate(&ping, host, host_conn, &runtime, &open) == LIBP2P_PING_OK);
    assert(open != NULL);
    assert(libp2p_ping_initiate(&ping, host, host_conn, NULL, &open) == LIBP2P_PING_ERR_LIMIT);
    assert(libp2p_host_drive(host, 5U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE);
    assert(libp2p_host_drive(host, 6U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);

    offset = host_test_encoded_message_size(LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) +
             host_test_encoded_message_size(LIBP2P_PING_PROTOCOL_ID_LEN);
    assert(stream.write_len == (offset + LIBP2P_PING_PAYLOAD_BYTES));
    (void)memcpy(
        &stream.read_buf[stream.read_len],
        &stream.write_buf[offset],
        LIBP2P_PING_PAYLOAD_BYTES);
    stream.read_len += LIBP2P_PING_PAYLOAD_BYTES;
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE);
    assert(libp2p_host_drive(host, 7U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_ping_next_event(&ping, &event) == LIBP2P_PING_OK);
    assert(event.type == LIBP2P_PING_EVENT_PONG);
    assert(event.user_data == &runtime);
    assert(event.rtt_us == 100U);

    assert(libp2p_ping_send(&ping, event.stream) == LIBP2P_PING_OK);
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE);
    assert(libp2p_host_drive(host, 8U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    (void)memset(&stream.read_buf[stream.read_len], 0xFF, LIBP2P_PING_PAYLOAD_BYTES);
    stream.read_len += LIBP2P_PING_PAYLOAD_BYTES;
    ping_test_push_stream_event(
        &fixture,
        &conn,
        &stream,
        LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE);
    assert(libp2p_host_drive(host, 9U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_ping_next_event(&ping, &event) == LIBP2P_PING_OK);
    assert(event.type == LIBP2P_PING_EVENT_ERROR);

    libp2p_host_deinit(host);
    free(storage);
}

static void ping_test_quic_loopback(void)
{
    ping_test_runtime_t client_runtime = {23U, 10000U};
    ping_test_runtime_t server_runtime = {91U, 20000U};
    libp2p_ping_config_t client_ping_config;
    libp2p_ping_config_t server_ping_config;
    libp2p_ping_t client_ping;
    libp2p_ping_t server_ping;
    libp2p_host_protocol_t client_protocol;
    libp2p_host_protocol_t server_protocol;
    protocol_loopback_pair_t pair;
    libp2p_host_config_t client_host_config;
    libp2p_host_config_t server_host_config;
    libp2p_quic_service_config_t client_service_config;
    libp2p_quic_service_config_t server_service_config;
    libp2p_quic_addr_t server_addr;
    uint8_t server_dial[160];
    size_t server_dial_len = 0U;
    size_t round = 0U;
    int initiated = 0;
    int observed_pong = 0;

    ping_test_config_init(&client_ping_config, &client_runtime);
    ping_test_config_init(&server_ping_config, &server_runtime);
    assert(libp2p_ping_init(&client_ping, &client_ping_config) == LIBP2P_PING_OK);
    assert(libp2p_ping_init(&server_ping, &server_ping_config) == LIBP2P_PING_OK);
    assert(libp2p_ping_protocol(&client_ping, &client_protocol) == LIBP2P_PING_OK);
    assert(libp2p_ping_protocol(&server_ping, &server_protocol) == LIBP2P_PING_OK);

    protocol_loopback_init(
        &pair,
        39102U,
        39103U,
        2U,
        &client_host_config,
        &server_host_config,
        &client_service_config,
        &server_service_config,
        &server_addr,
        server_dial,
        sizeof(server_dial),
        &server_dial_len);
    assert(libp2p_host_handle(pair.client, &client_protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_handle(pair.server, &server_protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.client) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.server) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_dial(pair.client, server_dial, server_dial_len, NULL, NULL) ==
        LIBP2P_HOST_ERR_INVALID_ARG);
    {
        libp2p_host_dial_t *dial = NULL;

        assert(
            libp2p_host_dial(pair.client, server_dial, server_dial_len, NULL, &dial) ==
            LIBP2P_HOST_OK);
    }

    for (round = 0U; round < 3000U; round++)
    {
        libp2p_host_event_t event;
        libp2p_ping_event_t ping_event;

        protocol_loopback_drive(&pair);
        while (libp2p_host_next_event(pair.client, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair.client_conn = event.conn;
            }
            else
            {
                assert(event.type != LIBP2P_HOST_EVENT_DIAL_FAILED);
            }
        }
        while (libp2p_host_next_event(pair.server, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair.server_conn = event.conn;
            }
        }
        if ((pair.client_conn != NULL) && (initiated == 0))
        {
            libp2p_host_stream_open_t *open = NULL;

            assert(
                libp2p_ping_initiate(&client_ping, pair.client, pair.client_conn, NULL, &open) ==
                LIBP2P_PING_OK);
            initiated = 1;
        }
        if (libp2p_ping_next_event(&client_ping, &ping_event) == LIBP2P_PING_OK)
        {
            if (ping_event.type == LIBP2P_PING_EVENT_PONG)
            {
                observed_pong = 1;
                break;
            }
            assert(ping_event.type != LIBP2P_PING_EVENT_ERROR);
        }
    }

    assert(observed_pong != 0);
    protocol_loopback_deinit(&pair);
}

int main(void)
{
    ping_test_responder_echoes_chunk();
    ping_test_initiator_rtt_and_repeat_guard();
    ping_test_quic_loopback();
    return 0;
}
