#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_test_support.h"

typedef struct
{
    size_t open_count;
} host_spec_protocol_state_t;

static libp2p_host_err_t host_spec_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    host_spec_protocol_state_t *state = (host_spec_protocol_state_t *)protocol_user_data;

    (void)host;
    (void)stream;
    (void)direction;
    assert(state != NULL);
    state->open_count++;
    return LIBP2P_HOST_OK;
}

static void host_spec_make_protocol(
    libp2p_host_protocol_t *protocol,
    const uint8_t *id,
    size_t id_len,
    host_spec_protocol_state_t *state)
{
    (void)memset(protocol, 0, sizeof(*protocol));
    protocol->id = id;
    protocol->id_len = id_len;
    protocol->on_open = host_spec_on_open;
    protocol->user_data = state;
}

static libp2p_host_t *host_spec_init(
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    host_spec_protocol_state_t *state,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    void **storage)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    size_t storage_len = 0U;

    host_test_fixture_init(fixture, conn);
    host_test_config_init(&config, &transport_config, fixture, host_test_transport());
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    *storage = calloc(1U, storage_len);
    assert(*storage != NULL);
    assert(libp2p_host_init(*storage, storage_len, &config, &host) == LIBP2P_HOST_OK);
    if (protocol_id != NULL)
    {
        host_spec_make_protocol(&protocol, protocol_id, protocol_id_len, state);
        assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    }
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    return host;
}

static libp2p_host_conn_t *host_spec_conn(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_event_t event;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED;
    transport_event.conn = conn;
    transport_event.attempt = conn;
    host_test_event_push(fixture, &transport_event);
    assert(libp2p_host_drive(host, 1U, LIBP2P_HOST_READY_APP, NULL) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED);
    return event.conn;
}

static size_t host_spec_frame(
    uint8_t *out,
    size_t out_len,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t written = 0U;

    assert(
        libp2p_multistream_select_message_encode(payload, payload_len, out, out_len, &written) ==
        LIBP2P_MULTISTREAM_SELECT_OK);
    return written;
}

static void host_spec_test_outbound_uses_multistream_protocol_id(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_spec_protocol_state_t state;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_stream_open_t *open = NULL;
    uint8_t expected[64];
    size_t expected_len = 0U;
    void *storage = NULL;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    host = host_spec_init(ping, sizeof(ping) - 1U, &state, &fixture, &conn, &storage);
    host_conn = host_spec_conn(host, &fixture, &conn);
    fixture.next_stream = &stream;
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(&stream, ping, sizeof(ping) - 1U);
    assert(
        libp2p_host_open_stream(host, host_conn, ping, sizeof(ping) - 1U, NULL, &open) ==
        LIBP2P_HOST_OK);
    assert(libp2p_host_drive(host, 2U, LIBP2P_HOST_READY_APP, NULL) == LIBP2P_HOST_OK);
    expected_len = host_spec_frame(
        expected,
        sizeof(expected),
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    assert(stream.write_len >= expected_len);
    assert(memcmp(stream.write_buf, expected, expected_len) == 0);
    assert(state.open_count == 1U);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_spec_test_outbound_na_fails_stream_open(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_spec_protocol_state_t state;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_stream_open_t *open = NULL;
    libp2p_host_event_t event;
    void *storage = NULL;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    host = host_spec_init(ping, sizeof(ping) - 1U, &state, &fixture, &conn, &storage);
    host_conn = host_spec_conn(host, &fixture, &conn);
    fixture.next_stream = &stream;
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_NA,
        LIBP2P_MULTISTREAM_SELECT_NA_LEN);
    assert(
        libp2p_host_open_stream(host, host_conn, ping, sizeof(ping) - 1U, NULL, &open) ==
        LIBP2P_HOST_OK);
    assert(libp2p_host_drive(host, 3U, LIBP2P_HOST_READY_APP, NULL) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED);
    assert(event.stream_open == open);
    assert(event.reason == LIBP2P_HOST_ERR_UNSUPPORTED);
    assert(state.open_count == 0U);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_spec_test_inbound_unregistered_gets_na(void)
{
    static const uint8_t unknown[] = "/unknown/1.0.0";
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_spec_protocol_state_t state;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    uint8_t expected[64];
    size_t expected_len = 0U;
    void *storage = NULL;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    host = host_spec_init(NULL, 0U, &state, &fixture, &conn, &storage);
    host_conn = host_spec_conn(host, &fixture, &conn);
    assert(host_conn != NULL);
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(&stream, unknown, sizeof(unknown) - 1U);
    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING;
    transport_event.conn = &conn;
    transport_event.stream = &stream;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 4U, LIBP2P_HOST_READY_APP, NULL) == LIBP2P_HOST_OK);
    expected_len = host_spec_frame(
        expected,
        sizeof(expected),
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_NA,
        LIBP2P_MULTISTREAM_SELECT_NA_LEN);
    assert(stream.write_len >= expected_len);
    assert(memcmp(&stream.write_buf[stream.write_len - expected_len], expected, expected_len) == 0);
    assert(state.open_count == 0U);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_spec_test_ping_protocol_id_negotiates(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_spec_protocol_state_t state;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    void *storage = NULL;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    host = host_spec_init(ping, sizeof(ping) - 1U, &state, &fixture, &conn, &storage);
    host_conn = host_spec_conn(host, &fixture, &conn);
    assert(host_conn != NULL);
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(&stream, ping, sizeof(ping) - 1U);
    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING;
    transport_event.conn = &conn;
    transport_event.stream = &stream;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 5U, LIBP2P_HOST_READY_APP, NULL) == LIBP2P_HOST_OK);
    assert(state.open_count == 1U);
    libp2p_host_deinit(host);
    free(storage);
}

int main(void)
{
    host_spec_test_outbound_uses_multistream_protocol_id();
    host_spec_test_outbound_na_fails_stream_open();
    host_spec_test_inbound_unregistered_gets_na();
    host_spec_test_ping_protocol_id_negotiates();
    return 0;
}
