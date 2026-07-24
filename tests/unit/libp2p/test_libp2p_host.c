#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_test_support.h"
#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "quic_test_support.h"
#include "transport/quic/quic_addr.h"
#include "transport/quic/quic_service.h"

typedef struct
{
    size_t open_count;
    size_t event_count;
    size_t closed_count;
    libp2p_host_stream_direction_t last_direction;
    libp2p_host_protocol_event_kind_t last_event;
    libp2p_host_stream_t *last_stream;
    void *stream_user_data;
} host_unit_protocol_state_t;

static libp2p_host_err_t host_unit_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    host_unit_protocol_state_t *state = (host_unit_protocol_state_t *)protocol_user_data;
    void *read_back = NULL;

    (void)host;
    assert(state != NULL);
    state->open_count++;
    state->last_direction = direction;
    state->last_stream = stream;
    state->stream_user_data = state;
    assert(libp2p_host_stream_set_user_data(stream, state) == LIBP2P_HOST_OK);
    assert(libp2p_host_stream_user_data(stream, &read_back) == LIBP2P_HOST_OK);
    assert(read_back == state);
    return LIBP2P_HOST_OK;
}

static libp2p_host_err_t host_unit_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data)
{
    host_unit_protocol_state_t *state = (host_unit_protocol_state_t *)protocol_user_data;

    (void)host;
    assert(state != NULL);
    state->event_count++;
    if (kind == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED)
    {
        state->closed_count++;
    }
    state->last_event = kind;
    state->last_stream = stream;
    return LIBP2P_HOST_OK;
}

static void host_unit_make_protocol(
    libp2p_host_protocol_t *protocol,
    const uint8_t *id,
    size_t id_len,
    host_unit_protocol_state_t *state)
{
    (void)memset(protocol, 0, sizeof(*protocol));
    protocol->id = id;
    protocol->id_len = id_len;
    protocol->on_open = host_unit_on_open;
    protocol->on_event = host_unit_on_event;
    protocol->user_data = state;
}

static libp2p_host_t *host_unit_init_mock(
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
    assert(storage_len > sizeof(libp2p_host_t *));
    *storage = calloc(1U, storage_len);
    assert(*storage != NULL);
    assert(libp2p_host_init(*storage, storage_len, config, &host) == LIBP2P_HOST_OK);
    return host;
}

static void host_unit_establish_mock_conn(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    libp2p_host_conn_t **out_conn)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_event_t event;
    libp2p_host_drive_result_t result;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED;
    transport_event.conn = conn;
    transport_event.attempt = conn;
    host_test_event_push(fixture, &transport_event);
    assert(libp2p_host_drive(host, 1U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(result.transport_events == 1U);
    assert(result.host_events == 1U);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED);
    assert(event.conn != NULL);
    *out_conn = event.conn;
}

static libp2p_host_stream_t *host_unit_open_mock_stream(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    libp2p_host_conn_t *conn,
    host_test_stream_t *stream,
    const uint8_t *protocol_id,
    size_t protocol_id_len)
{
    libp2p_host_stream_open_t *open = NULL;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;

    (void)memset(stream, 0, sizeof(*stream));
    fixture->next_stream = stream;
    host_test_stream_add_message(
        stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(stream, protocol_id, protocol_id_len);
    assert(
        libp2p_host_open_stream(host, conn, protocol_id, protocol_id_len, NULL, &open) ==
        LIBP2P_HOST_OK);
    assert(libp2p_host_drive(host, 10U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(result.host_events == 1U);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_STREAM_OPENED);
    assert(event.stream_open == open);
    assert(event.stream != NULL);
    return event.stream;
}

static void host_unit_close_mock_stream(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn,
    host_test_stream_t *stream,
    host_unit_protocol_state_t *state)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    size_t previous_closed_count = state->closed_count;

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_CLOSED;
    transport_event.conn = conn;
    transport_event.stream = stream;
    host_test_event_push(fixture, &transport_event);
    assert(libp2p_host_drive(host, 11U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(state->closed_count == (previous_closed_count + 1U));
    assert(state->last_event == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED);
}

static void host_unit_test_storage_lifecycle_and_accessors(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t align = 0U;
    libp2p_host_fd_t fd = 0U;
    libp2p_host_interest_t interest = LIBP2P_HOST_INTEREST_NONE;
    libp2p_host_time_us_t deadline = 0U;
    libp2p_host_drive_result_t drive_result;
    libp2p_host_event_t event;

    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    assert(libp2p_host_storage_align(&align) == LIBP2P_HOST_OK);
    assert(storage_len != 0U);
    assert(align == 8U);
    assert(libp2p_host_fd(host, &fd) == LIBP2P_HOST_OK);
    assert(fd == 42U);
    assert(libp2p_host_io_interest(host, &interest) == LIBP2P_HOST_OK);
    assert(interest == LIBP2P_HOST_INTEREST_READ);
    assert(libp2p_host_next_deadline(host, &deadline) == LIBP2P_HOST_OK);
    assert(deadline == 12345U);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    assert(libp2p_host_handle(host, NULL) == LIBP2P_HOST_ERR_INVALID_ARG);
    assert(libp2p_host_close(host, 7U) == LIBP2P_HOST_OK);
    assert(fixture.close_count == 0U);
    assert(libp2p_host_drive(host, 2U, LIBP2P_HOST_READY_APP, &drive_result) == LIBP2P_HOST_OK);
    assert(drive_result.host_events == 1U);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_HOST_CLOSED);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_protocol_registration_bounds(void)
{
    static const uint8_t proto_a[] = "/a/1.0.0";
    static const uint8_t proto_b[] = "/b/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_unit_protocol_state_t state;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;

    host_test_fixture_init(&fixture, &conn);
    host_test_config_init(&config, &transport_config, &fixture, host_test_transport());
    config.max_protocols = 1U;
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_host_init(storage, storage_len, &config, &host) == LIBP2P_HOST_OK);
    host_unit_make_protocol(&protocol, proto_a, sizeof(proto_a) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    host_unit_make_protocol(&protocol, proto_b, sizeof(proto_b) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_ERR_LIMIT);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_ERR_STATE);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_invalid_config(void)
{
    libp2p_host_config_t config;
    size_t storage_len = 99U;

    assert(libp2p_host_config_default(&config) == LIBP2P_HOST_OK);
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_ERR_INVALID_ARG);
    assert(storage_len == 0U);
}

static void host_unit_test_dial_completion_and_conn_peer_id(void)
{
    static const uint8_t addr[] = {9U};
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    libp2p_host_dial_t *dial = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    void *storage = NULL;
    int user_data = 17;

    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    assert(libp2p_host_dial(host, addr, sizeof(addr), &user_data, &dial) == LIBP2P_HOST_OK);
    assert(dial != NULL);
    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED;
    transport_event.conn = &conn;
    transport_event.attempt = &conn;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 1U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(result.transport_events == 1U);
    assert(result.host_events == 1U);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED);
    assert(event.dial == dial);
    assert(event.user_data == &user_data);
    host_conn = event.conn;
    assert(
        libp2p_host_conn_peer_id(host_conn, peer_id, sizeof(peer_id), &peer_id_len) ==
        LIBP2P_HOST_OK);
    assert(peer_id_len == conn.peer_id_len);
    assert(memcmp(peer_id, conn.peer_id, peer_id_len) == 0);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_outbound_stream_negotiation_and_events(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    static const uint8_t missing[] = "/missing/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_unit_protocol_state_t state;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_stream_open_t *open = NULL;
    libp2p_host_event_t event;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    void *storage = NULL;
    size_t expected_written = 0U;
    size_t initial_event_count = 0U;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    host_unit_make_protocol(&protocol, ping, sizeof(ping) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);
    assert(
        libp2p_host_open_stream(host, host_conn, missing, sizeof(missing) - 1U, NULL, &open) ==
        LIBP2P_HOST_ERR_NOT_FOUND);

    fixture.next_stream = &stream;
    host_test_stream_add_message(
        &stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(&stream, ping, sizeof(ping) - 1U);
    assert(
        libp2p_host_open_stream(host, host_conn, ping, sizeof(ping) - 1U, &state, &open) ==
        LIBP2P_HOST_OK);
    assert(libp2p_host_drive(host, 2U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(result.negotiation_steps >= 4U);
    assert(result.protocol_events >= 1U);
    assert(result.host_events == 1U);
    assert(state.open_count == 1U);
    assert(state.last_direction == LIBP2P_HOST_STREAM_OUTBOUND);
    initial_event_count = state.event_count;
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_STREAM_OPENED);
    assert(event.stream_open == open);
    assert(event.stream == state.last_stream);
    expected_written = host_test_encoded_message_size(LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN) +
                       host_test_encoded_message_size(sizeof(ping) - 1U);
    assert(stream.write_len == expected_written);

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE;
    transport_event.conn = &conn;
    transport_event.stream = &stream;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 3U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(state.event_count == (initial_event_count + 1U));
    assert(state.last_event == LIBP2P_HOST_PROTOCOL_EVENT_READABLE);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_outbound_stream_resources_reused_after_close(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t streams[8];
    host_test_stream_t overflow_streams[4];
    host_unit_protocol_state_t state;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    void *storage = NULL;
    size_t storage_len = 0U;
    size_t cycle = 0U;

    (void)memset(&state, 0, sizeof(state));
    host_test_fixture_init(&fixture, &conn);
    host_test_config_init(&config, &transport_config, &fixture, host_test_transport());
    config.max_connections = 1U;
    config.max_streams_per_conn = 2U;
    config.max_pending_stream_opens = 3U;
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_host_init(storage, storage_len, &config, &host) == LIBP2P_HOST_OK);
    host_unit_make_protocol(&protocol, ping, sizeof(ping) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);

    for (cycle = 0U; cycle < 4U; cycle++)
    {
        libp2p_host_stream_t *first = NULL;
        libp2p_host_stream_t *second = NULL;
        libp2p_host_stream_open_t *overflow_open = NULL;
        host_test_stream_t *first_transport = &streams[(cycle * 2U)];
        host_test_stream_t *second_transport = &streams[(cycle * 2U) + 1U];
        host_test_stream_t *overflow_transport = &overflow_streams[cycle];

        first = host_unit_open_mock_stream(
            host,
            &fixture,
            host_conn,
            first_transport,
            ping,
            sizeof(ping) - 1U);
        second = host_unit_open_mock_stream(
            host,
            &fixture,
            host_conn,
            second_transport,
            ping,
            sizeof(ping) - 1U);
        assert(first != NULL);
        assert(second != NULL);

        (void)memset(overflow_transport, 0, sizeof(*overflow_transport));
        fixture.next_stream = overflow_transport;
        assert(
            libp2p_host_open_stream(
                host,
                host_conn,
                ping,
                sizeof(ping) - 1U,
                NULL,
                &overflow_open) == LIBP2P_HOST_ERR_LIMIT);
        assert(overflow_open == NULL);
        assert(overflow_transport->reset_count == 1U);

        host_unit_close_mock_stream(host, &fixture, &conn, first_transport, &state);
        host_unit_close_mock_stream(host, &fixture, &conn, second_transport, &state);
    }

    assert(state.open_count == 8U);
    assert(state.closed_count == 8U);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_outbound_stream_open_cancel(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t cancelled_stream;
    host_test_stream_t replacement_stream;
    host_unit_protocol_state_t state;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_stream_open_t *open = NULL;
    void *storage = NULL;
    int waiting_context = 0;
    int open_context = 1;
    int other_context = 2;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&cancelled_stream, 0, sizeof(cancelled_stream));
    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    host_unit_make_protocol(&protocol, ping, sizeof(ping) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);

    fixture.open_stream_result = LIBP2P_HOST_ERR_WOULD_BLOCK;
    assert(
        libp2p_host_open_stream(
            host,
            host_conn,
            ping,
            sizeof(ping) - 1U,
            &waiting_context,
            &open) == LIBP2P_HOST_OK);
    assert(open != NULL);
    assert(
        libp2p_host_stream_open_cancel(host, open, &waiting_context) ==
        LIBP2P_HOST_OK);
    assert(
        libp2p_host_stream_open_cancel(host, open, &waiting_context) ==
        LIBP2P_HOST_ERR_NOT_FOUND);

    fixture.open_stream_result = LIBP2P_HOST_OK;
    fixture.next_stream = &cancelled_stream;
    assert(
        libp2p_host_open_stream(
            host,
            host_conn,
            ping,
            sizeof(ping) - 1U,
            &open_context,
            &open) == LIBP2P_HOST_OK);
    assert(open != NULL);
    assert(
        libp2p_host_stream_open_cancel(host, open, &other_context) ==
        LIBP2P_HOST_ERR_NOT_FOUND);
    assert(cancelled_stream.reset_count == 0U);
    assert(
        libp2p_host_stream_open_cancel(host, open, &open_context) ==
        LIBP2P_HOST_OK);
    assert(cancelled_stream.reset_count == 1U);
    assert(
        libp2p_host_stream_open_cancel(host, open, &open_context) ==
        LIBP2P_HOST_ERR_NOT_FOUND);

    assert(
        host_unit_open_mock_stream(
            host,
            &fixture,
            host_conn,
            &replacement_stream,
            ping,
            sizeof(ping) - 1U) != NULL);
    assert(state.open_count == 1U);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_inbound_stream_negotiation_and_na(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    static const uint8_t unknown[] = "/unknown/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    host_test_stream_t stream;
    host_test_stream_t unknown_stream;
    host_unit_protocol_state_t state;
    libp2p_host_protocol_t protocol;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    void *storage = NULL;

    (void)memset(&state, 0, sizeof(state));
    (void)memset(&stream, 0, sizeof(stream));
    (void)memset(&unknown_stream, 0, sizeof(unknown_stream));
    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    host_unit_make_protocol(&protocol, ping, sizeof(ping) - 1U, &state);
    assert(libp2p_host_handle(host, &protocol) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);

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
    assert(libp2p_host_drive(host, 4U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(state.open_count == 1U);
    assert(state.last_direction == LIBP2P_HOST_STREAM_INBOUND);

    host_test_stream_add_message(
        &unknown_stream,
        (const uint8_t *)LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID,
        LIBP2P_MULTISTREAM_SELECT_PROTOCOL_ID_LEN);
    host_test_stream_add_message(&unknown_stream, unknown, sizeof(unknown) - 1U);
    transport_event.stream = &unknown_stream;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 5U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(unknown_stream.write_len > 0U);
    assert(unknown_stream.reset_count == 0U);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_graceful_shutdown(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;
    void *storage = NULL;
    size_t closed_events = 0U;

    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);
    assert(host_conn != NULL);
    assert(libp2p_host_close(host, 55U) == LIBP2P_HOST_OK);
    assert(fixture.close_count == 1U);
    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
    transport_event.conn = &conn;
    transport_event.app_error_code = 55U;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 6U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    while (libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK)
    {
        if (event.type == LIBP2P_HOST_EVENT_CONN_CLOSED)
        {
            assert(event.conn == host_conn);
            assert(event.locally_initiated != 0U);
            closed_events++;
        }
        if (event.type == LIBP2P_HOST_EVENT_HOST_CLOSED)
        {
            closed_events++;
        }
    }
    assert(closed_events == 2U);
    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_check_connection_close_event(uint8_t request_local_close)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;
    void *storage = NULL;

    host = host_unit_init_mock(&config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_unit_establish_mock_conn(host, &fixture, &conn, &host_conn);
    assert(host_conn != NULL);
    if (request_local_close != 0U)
    {
        assert(libp2p_host_conn_close(host, host_conn, 41U) == LIBP2P_HOST_OK);
        assert(fixture.close_count == 1U);
    }

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
    transport_event.conn = &conn;
    transport_event.reason = LIBP2P_HOST_ERR_CLOSED;
    transport_event.app_error_code = 41U;
    transport_event.transport_error_code = 73U;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 7U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_CLOSED);
    assert(event.conn == host_conn);
    assert(event.reason == LIBP2P_HOST_ERR_CLOSED);
    assert(event.locally_initiated == request_local_close);
    assert(event.app_error_code == 41U);
    assert(event.transport_error_code == 73U);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_connection_close_origin_and_codes(void)
{
    host_unit_check_connection_close_event(1U);
    host_unit_check_connection_close_event(0U);
}

static void host_unit_test_closed_conn_recycles_slot_and_rejects_stale_accessors(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn1;
    host_test_conn_t conn2;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn1 = NULL;
    libp2p_host_conn_t *host_conn2 = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t written = 0U;
    libp2p_host_err_t stale_err;
    void *storage = NULL;
    size_t storage_len = 0U;

    host_test_fixture_init(&fixture, &conn1);
    conn2 = conn1;
    conn2.peer_id[2] = 9U;
    conn2.identity.peer_id[2] = 9U;
    host_test_config_init(&config, &transport_config, &fixture, host_test_transport());
    config.max_connections = 1U;
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_host_init(storage, storage_len, &config, &host) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);

    host_unit_establish_mock_conn(host, &fixture, &conn1, &host_conn1);
    assert(host_conn1 != NULL);

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
    transport_event.conn = &conn1;
    transport_event.app_error_code = 77U;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 12U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_CLOSED);
    assert(event.conn == host_conn1);
    assert(fixture.release_count == 1U);

    stale_err = libp2p_host_conn_peer_id(host_conn1, peer_id, sizeof(peer_id), &written);
    assert((stale_err == LIBP2P_HOST_ERR_INVALID_ARG) || (stale_err == LIBP2P_HOST_ERR_CLOSED));
    stale_err = libp2p_host_conn_close(host, host_conn1, 88U);
    assert((stale_err == LIBP2P_HOST_ERR_INVALID_ARG) || (stale_err == LIBP2P_HOST_ERR_CLOSED));

    host_unit_establish_mock_conn(host, &fixture, &conn2, &host_conn2);
    assert(host_conn2 != NULL);
    assert(host_conn2 == host_conn1);
    assert(fixture.release_count == 1U);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_conn_for_peer_id_skips_closed_duplicate(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn1;
    host_test_conn_t conn2;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn1 = NULL;
    libp2p_host_conn_t *host_conn2 = NULL;
    libp2p_host_conn_t *found = NULL;
    libp2p_host_transport_event_t transport_event;
    libp2p_host_drive_result_t result;
    libp2p_host_event_t event;
    void *storage = NULL;
    size_t storage_len = 0U;

    host_test_fixture_init(&fixture, &conn1);
    conn2 = conn1;
    host_test_config_init(&config, &transport_config, &fixture, host_test_transport());
    config.max_connections = 2U;
    assert(libp2p_host_storage_size(&config, &storage_len) == LIBP2P_HOST_OK);
    storage = calloc(1U, storage_len);
    assert(storage != NULL);
    assert(libp2p_host_init(storage, storage_len, &config, &host) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);

    host_unit_establish_mock_conn(host, &fixture, &conn1, &host_conn1);
    host_unit_establish_mock_conn(host, &fixture, &conn2, &host_conn2);
    assert(host_conn1 != NULL);
    assert(host_conn2 != NULL);
    assert(host_conn1 != host_conn2);

    assert(
        libp2p_host_conn_for_peer_id(host, conn1.peer_id, conn1.peer_id_len, &found) ==
        LIBP2P_HOST_OK);
    assert(found == host_conn1);

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
    transport_event.conn = &conn2;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 13U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_CLOSED);
    assert(event.conn == host_conn2);

    found = NULL;
    assert(
        libp2p_host_conn_for_peer_id(host, conn1.peer_id, conn1.peer_id_len, &found) ==
        LIBP2P_HOST_OK);
    assert(found == host_conn1);

    (void)memset(&transport_event, 0, sizeof(transport_event));
    transport_event.type = LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED;
    transport_event.conn = &conn1;
    host_test_event_push(&fixture, &transport_event);
    assert(libp2p_host_drive(host, 14U, LIBP2P_HOST_READY_APP, &result) == LIBP2P_HOST_OK);
    assert(libp2p_host_next_event(host, &event) == LIBP2P_HOST_OK);
    assert(event.type == LIBP2P_HOST_EVENT_CONN_CLOSED);
    assert(event.conn == host_conn1);

    found = host_conn1;
    assert(
        libp2p_host_conn_for_peer_id(host, conn1.peer_id, conn1.peer_id_len, &found) ==
        LIBP2P_HOST_ERR_NOT_FOUND);
    assert(found == NULL);

    libp2p_host_deinit(host);
    free(storage);
}

static void host_unit_test_secp256k1_identity_round_trip(void)
{
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    uint8_t public_key[LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES];
    uint8_t sig[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    size_t sig_len = 0U;
    size_t public_key_message_len = 0U;
    size_t public_key_len = 0U;
    libp2p_quic_host_key_t ignored_host_key;
    libp2p_host_secp256k1_identity_t identity_storage;
    libp2p_host_identity_t identity;
    static const uint8_t message[] = {'h', 'o', 's', 't'};

    quic_test_load_host_key(private_key, public_key_message, &ignored_host_key);
    assert(
        libp2p_host_secp256k1_identity_init(
            &identity_storage,
            private_key,
            sizeof(private_key),
            &identity) == LIBP2P_HOST_OK);
    assert(
        identity
            .sign_fn(identity.user_data, message, sizeof(message), sig, sizeof(sig), &sig_len) ==
        LIBP2P_HOST_OK);
    assert(sig_len != 0U);
    assert(
        libp2p_peer_id_public_key_decode(
            identity.public_key_message,
            identity.public_key_message_len,
            public_key,
            sizeof(public_key),
            &public_key_len) == LIBP2P_PEER_ID_OK);
    assert(
        libp2p_peer_id_public_key_encode(
            public_key,
            public_key_len,
            public_key_message,
            sizeof(public_key_message),
            &public_key_message_len) == LIBP2P_PEER_ID_OK);
    assert(public_key_message_len == identity.public_key_message_len);
    assert(memcmp(public_key_message, identity.public_key_message, public_key_message_len) == 0);
    assert(
        libp2p_peer_id_verify_message(
            public_key,
            public_key_len,
            message,
            sizeof(message),
            sig,
            sig_len) == LIBP2P_PEER_ID_OK);
}

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
    libp2p_host_stream_open_t *open;
    host_unit_protocol_state_t client_protocol;
    host_unit_protocol_state_t server_protocol;
} host_unit_quic_pair_t;

static void host_unit_quic_config(
    libp2p_host_config_t *host_config,
    libp2p_quic_service_config_t *service_config,
    const libp2p_quic_local_identity_t *identity,
    const libp2p_host_identity_t *host_identity,
    const uint8_t *listen_multiaddr,
    size_t listen_multiaddr_len,
    libp2p_quic_role_t role,
    uint8_t *random_state,
    uint64_t *unix_time)
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
    host_config->max_protocols = 2U;
    host_config->max_connections = 4U;
    host_config->max_streams_per_conn = 8U;
    host_config->max_pending_dials = 4U;
    host_config->max_pending_stream_opens = 4U;
    host_config->event_capacity = 16U;
    host_config->max_negotiation_steps = 64U;
}

static void host_unit_quic_drive_pair(host_unit_quic_pair_t *pair)
{
    assert(
        libp2p_host_drive(pair->client, pair->now_us, LIBP2P_HOST_READY_ALL, NULL) ==
        LIBP2P_HOST_OK);
    assert(
        libp2p_host_drive(pair->server, pair->now_us, LIBP2P_HOST_READY_ALL, NULL) ==
        LIBP2P_HOST_OK);
    pair->now_us += 1000U;
}

static void host_unit_test_quic_loopback(void)
{
    static const uint8_t ping[] = "/ipfs/ping/1.0.0";
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    libp2p_quic_host_key_t ignored_host_key;
    quic_test_identity_fixture_t quic_identity;
    libp2p_host_secp256k1_identity_t host_identity_storage;
    libp2p_host_identity_t host_identity;
    libp2p_quic_addr_t client_addr;
    libp2p_quic_addr_t server_addr;
    uint8_t client_listen[128];
    uint8_t server_listen[128];
    uint8_t server_dial[160];
    size_t client_listen_len = 0U;
    size_t server_listen_len = 0U;
    size_t server_dial_len = 0U;
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_host_config_t client_host_config;
    libp2p_host_config_t server_host_config;
    libp2p_quic_service_config_t client_service_config;
    libp2p_quic_service_config_t server_service_config;
    libp2p_host_protocol_t client_protocol;
    libp2p_host_protocol_t server_protocol;
    host_unit_quic_pair_t pair;
    size_t client_storage_len = 0U;
    size_t server_storage_len = 0U;
    size_t round = 0U;
    uint8_t client_closed = 0U;
    uint8_t server_closed = 0U;

    (void)memset(&pair, 0, sizeof(pair));
    quic_test_load_host_key(private_key, public_key_message, &ignored_host_key);
    quic_test_make_identity(&quic_identity, 91U);
    assert(
        libp2p_host_secp256k1_identity_init(
            &host_identity_storage,
            private_key,
            sizeof(private_key),
            &host_identity) == LIBP2P_HOST_OK);

    assert(libp2p_quic_addr_from_ip4(ip4, 39090U, &client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 39091U, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(
            &client_addr,
            client_listen,
            sizeof(client_listen),
            &client_listen_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(
            &server_addr,
            server_listen,
            sizeof(server_listen),
            &server_listen_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            quic_identity.peer_id,
            quic_identity.peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(
            &server_addr,
            server_dial,
            sizeof(server_dial),
            &server_dial_len) == LIBP2P_QUIC_OK);

    pair.client_random = 11U;
    pair.server_random = 211U;
    pair.unix_time = UINT64_C(1750000000);
    host_unit_quic_config(
        &client_host_config,
        &client_service_config,
        &quic_identity.identity,
        &host_identity,
        client_listen,
        client_listen_len,
        LIBP2P_QUIC_ROLE_CLIENT,
        &pair.client_random,
        &pair.unix_time);
    host_unit_quic_config(
        &server_host_config,
        &server_service_config,
        &quic_identity.identity,
        &host_identity,
        server_listen,
        server_listen_len,
        LIBP2P_QUIC_ROLE_SERVER,
        &pair.server_random,
        &pair.unix_time);

    assert(libp2p_host_storage_size(&client_host_config, &client_storage_len) == LIBP2P_HOST_OK);
    assert(libp2p_host_storage_size(&server_host_config, &server_storage_len) == LIBP2P_HOST_OK);
    pair.client_storage = calloc(1U, client_storage_len);
    pair.server_storage = calloc(1U, server_storage_len);
    assert(pair.client_storage != NULL);
    assert(pair.server_storage != NULL);
    assert(
        libp2p_host_init(
            pair.client_storage,
            client_storage_len,
            &client_host_config,
            &pair.client) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_init(
            pair.server_storage,
            server_storage_len,
            &server_host_config,
            &pair.server) == LIBP2P_HOST_OK);
    host_unit_make_protocol(&client_protocol, ping, sizeof(ping) - 1U, &pair.client_protocol);
    host_unit_make_protocol(&server_protocol, ping, sizeof(ping) - 1U, &pair.server_protocol);
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

    for (round = 0U; round < 2000U; round++)
    {
        libp2p_host_event_t event;

        host_unit_quic_drive_pair(&pair);
        while (libp2p_host_next_event(pair.client, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair.client_conn = event.conn;
            }
            else if (event.type == LIBP2P_HOST_EVENT_STREAM_OPENED)
            {
                pair.open = event.stream_open;
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
        if ((pair.client_conn != NULL) && (pair.open == NULL))
        {
            assert(
                libp2p_host_open_stream(
                    pair.client,
                    pair.client_conn,
                    ping,
                    sizeof(ping) - 1U,
                    NULL,
                    &pair.open) == LIBP2P_HOST_OK);
        }
        if ((pair.client_protocol.open_count != 0U) && (pair.server_protocol.open_count != 0U))
        {
            break;
        }
    }

    assert(pair.client_protocol.open_count != 0U);
    assert(pair.server_protocol.open_count != 0U);
    assert(pair.server_protocol.last_direction == LIBP2P_HOST_STREAM_INBOUND);

    assert(libp2p_host_conn_close(pair.client, pair.client_conn, 99U) == LIBP2P_HOST_OK);
    for (round = 0U; round < 2000U; round++)
    {
        libp2p_host_event_t event;

        host_unit_quic_drive_pair(&pair);
        while (libp2p_host_next_event(pair.client, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_CLOSED)
            {
                assert(event.reason == LIBP2P_HOST_ERR_CLOSED);
                assert(event.locally_initiated != 0U);
                assert(event.app_error_code == 99U);
                assert(event.transport_error_code == 0U);
                client_closed = 1U;
            }
        }
        while (libp2p_host_next_event(pair.server, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_CLOSED)
            {
                assert(event.reason == LIBP2P_HOST_ERR_CLOSED);
                assert(event.locally_initiated == 0U);
                assert(event.app_error_code == 99U);
                assert(event.transport_error_code == 0U);
                server_closed = 1U;
            }
        }
        if ((client_closed != 0U) && (server_closed != 0U))
        {
            break;
        }
    }
    assert(client_closed != 0U);
    assert(server_closed != 0U);

    libp2p_host_deinit(pair.client);
    libp2p_host_deinit(pair.server);
    free(pair.client_storage);
    free(pair.server_storage);
}

int main(void)
{
    host_unit_test_storage_lifecycle_and_accessors();
    host_unit_test_protocol_registration_bounds();
    host_unit_test_invalid_config();
    host_unit_test_dial_completion_and_conn_peer_id();
    host_unit_test_outbound_stream_negotiation_and_events();
    host_unit_test_outbound_stream_resources_reused_after_close();
    host_unit_test_outbound_stream_open_cancel();
    host_unit_test_inbound_stream_negotiation_and_na();
    host_unit_test_graceful_shutdown();
    host_unit_test_connection_close_origin_and_codes();
    host_unit_test_closed_conn_recycles_slot_and_rejects_stale_accessors();
    host_unit_test_conn_for_peer_id_skips_closed_duplicate();
    host_unit_test_secp256k1_identity_round_trip();
    host_unit_test_quic_loopback();
    return 0;
}
