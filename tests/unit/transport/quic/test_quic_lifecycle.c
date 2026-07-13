#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../../../src/transport/quic/quic_backend_ngtcp2_internal.h"
#include "quic_test_support.h"

static void quic_lifecycle_test_multiple_streams(void)
{
    static const uint8_t messages[4][9] = {
        {'s', 't', 'r', 'e', 'a', 'm', '-', '0', '!'},
        {'s', 't', 'r', 'e', 'a', 'm', '-', '1', '!'},
        {'s', 't', 'r', 'e', 'a', 'm', '-', '2', '!'},
        {'s', 't', 'r', 'e', 'a', 'm', '-', '3', '!'},
    };
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    libp2p_quic_stream_t *client_streams[4];
    libp2p_quic_stream_t *server_streams[4];
    uint8_t read_done[4];
    uint8_t read_bufs[4][16];
    size_t read_totals[4];
    const size_t retained_limit =
        LIBP2P_QUIC_DEFAULT_STREAM_WINDOW_BYTES * QUIC_BACKEND_STREAM_SEND_MULTIPLIER;
    size_t index = 0U;
    size_t accepted_count = 0U;
    size_t read_count = 0U;
    size_t round = 0U;

    (void)memset(client_streams, 0, sizeof(client_streams));
    (void)memset(server_streams, 0, sizeof(server_streams));
    (void)memset(read_done, 0, sizeof(read_done));
    (void)memset(read_bufs, 0, sizeof(read_bufs));
    (void)memset(read_totals, 0, sizeof(read_totals));

    quic_test_make_identity(&identity, 31U);
    quic_test_pair_init(&pair, &identity.identity, 30000U, 30001U, 0U);
    quic_test_pair_dial(&pair, &identity);

    for (index = 0U; index < 4U; index++)
    {
        size_t accepted = 0U;

        assert(
            libp2p_quic_conn_open_bidi_stream(pair.client_conn, &client_streams[index]) ==
            LIBP2P_QUIC_OK);
        assert(
            libp2p_quic_stream_write(
                client_streams[index],
                messages[index],
                sizeof(messages[index]),
                1,
                &accepted) == LIBP2P_QUIC_OK);
        assert(accepted == sizeof(messages[index]));
        assert(client_streams[index]->tx_cap >= sizeof(messages[index]));
        assert(client_streams[index]->tx_cap < retained_limit);
    }

    for (round = 0U; round < 1000U; round++)
    {
        quic_test_events_t events;

        (void)memset(&events, 0, sizeof(events));
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.server, &events);

        while (accepted_count < 4U)
        {
            libp2p_quic_stream_t *stream = NULL;
            libp2p_quic_err_t result = libp2p_quic_conn_accept_stream(pair.server_conn, &stream);

            if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
            {
                break;
            }
            assert(result == LIBP2P_QUIC_OK);
            server_streams[accepted_count] = stream;
            accepted_count++;
        }

        for (index = 0U; index < accepted_count; index++)
        {
            size_t read_len = 0U;
            int fin = 0;

            if (read_done[index] != 0U)
            {
                continue;
            }
            if (libp2p_quic_stream_read(
                    server_streams[index],
                    &read_bufs[index][read_totals[index]],
                    sizeof(read_bufs[index]) - read_totals[index],
                    &read_len,
                    &fin) == LIBP2P_QUIC_OK)
            {
                assert((read_totals[index] + read_len) <= sizeof(read_bufs[index]));
                read_totals[index] += read_len;
                if (fin != 0)
                {
                    assert(read_totals[index] == sizeof(messages[index]));
                    assert(memcmp(read_bufs[index], messages[index], sizeof(messages[index])) == 0);
                    read_done[index] = 1U;
                    read_count++;
                }
            }
        }

        if ((accepted_count == 4U) && (read_count == 4U))
        {
            quic_test_pair_deinit(&pair);
            return;
        }
    }

    assert(0 && "multiple stream transfer did not complete");
}

static void quic_lifecycle_test_stream_writable_after_tx_drain(void)
{
    static uint8_t message[4096];
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    libp2p_quic_stream_t *client_stream = NULL;
    size_t accepted = 0U;
    size_t round = 0U;

    (void)memset(message, 0xB7, sizeof(message));
    quic_test_make_identity(&identity, 35U);
    quic_test_pair_init(&pair, &identity.identity, 30010U, 30011U, 0U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_conn_open_bidi_stream(pair.client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_stream_write(client_stream, message, sizeof(message), 0, &accepted) ==
        LIBP2P_QUIC_OK);
    assert(accepted == sizeof(message));

    for (round = 0U; round < 1000U; round++)
    {
        quic_test_events_t client_events;

        (void)memset(&client_events, 0, sizeof(client_events));
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.client, &client_events);
        if (client_events.writable_count != 0U)
        {
            assert(client_events.writable_stream == client_stream);
            quic_test_pair_deinit(&pair);
            return;
        }
    }

    assert(0 && "stream writable event was not emitted after tx drain");
}

static void quic_lifecycle_test_buffered_rx_terminal(
    int reset,
    uint64_t app_error_code,
    uint16_t client_port,
    uint16_t server_port)
{
    static uint8_t response[8192];
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    quic_test_events_t client_events;
    quic_test_events_t server_events;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_stream_t *server_stream = NULL;
    libp2p_quic_stream_state_t stream_state = LIBP2P_QUIC_STREAM_OPEN;
    uint8_t request = 0xA5U;
    uint8_t read_buf[1024];
    size_t accepted = 0U;
    size_t read_total = 0U;
    size_t round = 0U;
    int fin = 0;

    for (round = 0U; round < sizeof(response); round++)
    {
        response[round] = (uint8_t)round;
    }
    quic_test_make_identity(&identity, 37U);
    quic_test_pair_init(&pair, &identity.identity, client_port, server_port, 0U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_conn_open_bidi_stream(pair.client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_stream_write(client_stream, &request, sizeof(request), 1, &accepted) ==
        LIBP2P_QUIC_OK);
    assert(accepted == sizeof(request));

    for (round = 0U; (round < 1000U) && (server_stream == NULL); round++)
    {
        libp2p_quic_err_t result = LIBP2P_QUIC_OK;

        quic_test_pump(pair.client, pair.server, &pair.now_us);
        result = libp2p_quic_conn_accept_stream(pair.server_conn, &server_stream);
        if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            server_stream = NULL;
        }
        else
        {
            assert(result == LIBP2P_QUIC_OK);
        }
    }
    assert(server_stream != NULL);

    accepted = 0U;
    assert(
        libp2p_quic_stream_write(
            server_stream,
            response,
            sizeof(response),
            (reset == 0) ? 1 : 0,
            &accepted) == LIBP2P_QUIC_OK);
    assert(accepted == sizeof(response));

    (void)memset(&client_events, 0, sizeof(client_events));
    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; (round < 1000U) && (client_stream->rx_len < sizeof(response)); round++)
    {
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.client, &client_events);
        quic_test_drain_events(pair.server, &server_events);
    }
    assert(client_stream->rx_len == sizeof(response));

    if (reset != 0)
    {
        (void)memset(&client_events, 0, sizeof(client_events));
        assert(libp2p_quic_stream_reset(server_stream, app_error_code) == LIBP2P_QUIC_OK);
    }
    for (round = 0U; (round < 1000U) && (client_events.closed_stream_count == 0U); round++)
    {
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.client, &client_events);
        quic_test_drain_events(pair.server, &server_events);
    }
    assert(client_events.closed_stream == client_stream);
    assert(client_events.last_app_error_code == app_error_code);
    assert(libp2p_quic_stream_state(client_stream, &stream_state) == LIBP2P_QUIC_OK);
    assert(stream_state == ((reset != 0) ? LIBP2P_QUIC_STREAM_RESET : LIBP2P_QUIC_STREAM_CLOSED));

    while (read_total < sizeof(response))
    {
        size_t read_len = 0U;

        assert(
            libp2p_quic_stream_read(client_stream, read_buf, sizeof(read_buf), &read_len, &fin) ==
            LIBP2P_QUIC_OK);
        assert((read_total + read_len) <= sizeof(response));
        assert(memcmp(read_buf, &response[read_total], read_len) == 0);
        read_total += read_len;
        if (reset != 0)
        {
            assert(fin == 0);
        }
    }
    assert(read_total == sizeof(response));
    assert(fin == ((reset != 0) ? 0 : 1));
    {
        size_t read_len = 1U;

        fin = 1;
        assert(
            libp2p_quic_stream_read(client_stream, read_buf, sizeof(read_buf), &read_len, &fin) ==
            LIBP2P_QUIC_ERR_CLOSED);
        assert(read_len == 0U);
        assert(fin == 0);
    }
    assert(libp2p_quic_stream_state(client_stream, &stream_state) == LIBP2P_QUIC_OK);
    assert(stream_state == ((reset != 0) ? LIBP2P_QUIC_STREAM_RESET : LIBP2P_QUIC_STREAM_CLOSED));

    quic_test_pair_deinit(&pair);
}

static void quic_lifecycle_test_stream_reset_discards_pending_tx(void)
{
    static uint8_t message[4096];
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    libp2p_quic_stream_t *client_stream = NULL;
    uint8_t packet[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    size_t accepted = 0U;
    size_t sent_before_reset = 0U;
    size_t round = 0U;

    (void)memset(message, 0xA5, sizeof(message));
    quic_test_make_identity(&identity, 39U);
    quic_test_pair_init(&pair, &identity.identity, 30012U, 30013U, 0U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_conn_open_bidi_stream(pair.client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_stream_write(client_stream, message, sizeof(message), 0, &accepted) ==
        LIBP2P_QUIC_OK);
    assert(accepted == sizeof(message));
    assert(client_stream->tx_len == sizeof(message));

    for (round = 0U; (round < 32U) && (client_stream->tx_sent_len == 0U); round++)
    {
        libp2p_quic_tx_datagram_t tx;
        libp2p_quic_err_t result = LIBP2P_QUIC_OK;

        (void)memset(&tx, 0, sizeof(tx));
        tx.data = packet;
        tx.data_cap = sizeof(packet);
        result = libp2p_quic_endpoint_next_datagram(pair.client, &tx, pair.now_us);
        if (result == LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            assert(libp2p_quic_endpoint_poll(pair.client, pair.now_us) == LIBP2P_QUIC_OK);
        }
        else
        {
            assert(result == LIBP2P_QUIC_OK);
            assert(tx.data_len > 0U);
        }
        pair.now_us += 1000U;
    }

    assert(client_stream->tx_sent_len != 0U);
    sent_before_reset = client_stream->tx_sent_len;
    assert(libp2p_quic_stream_reset(client_stream, 88U) == LIBP2P_QUIC_OK);
    assert(client_stream->tx_len == 0U);
    assert(client_stream->tx_sent_len == 0U);
    assert(client_stream->tx_data == NULL);
    assert(client_stream->tx_cap == 0U);
    assert(client_stream->tx_base_offset == (uint64_t)sent_before_reset);
    assert(client_stream->local_fin_queued == 0U);
    assert(client_stream->local_fin_sent == 0U);
    assert(client_stream->write_blocked == 0U);

    quic_test_pair_deinit(&pair);
}

static void quic_lifecycle_test_ack_tail_does_not_cover_gap(void)
{
    uint8_t tx_data[128];
    libp2p_quic_stream_t stream;
    uint8_t sent_window_acked = 1U;

    (void)memset(tx_data, 0xD3, sizeof(tx_data));
    (void)memset(&stream, 0, sizeof(stream));
    stream.magic = QUIC_BACKEND_STREAM_MAGIC;
    stream.stream_id = 7;
    stream.tx_data = tx_data;
    stream.tx_len = 80U;
    stream.tx_sent_len = 64U;
    stream.tx_base_offset = 0U;

    assert(quic_backend_stream_record_acked_range(&stream, 32U, 32U, &sent_window_acked) == 0);
    assert(sent_window_acked == 0U);
    assert(stream.tx_ack_range_count == 1U);
    assert(stream.tx_ack_ranges[0].start == 32U);
    assert(stream.tx_ack_ranges[0].end == 64U);
}

static void quic_lifecycle_test_ack_ranges_merge_to_full_window(void)
{
    uint8_t tx_data[128];
    libp2p_quic_stream_t stream;
    uint8_t sent_window_acked = 1U;

    (void)memset(tx_data, 0xE4, sizeof(tx_data));
    (void)memset(&stream, 0, sizeof(stream));
    stream.magic = QUIC_BACKEND_STREAM_MAGIC;
    stream.stream_id = 9;
    stream.tx_data = tx_data;
    stream.tx_len = 80U;
    stream.tx_sent_len = 64U;
    stream.tx_base_offset = 0U;

    assert(quic_backend_stream_record_acked_range(&stream, 0U, 32U, &sent_window_acked) == 0);
    assert(sent_window_acked == 0U);
    assert(quic_backend_stream_record_acked_range(&stream, 32U, 32U, &sent_window_acked) == 0);
    assert(sent_window_acked == 1U);
    assert(stream.tx_ack_range_count == 1U);
    assert(stream.tx_ack_ranges[0].start == 0U);
    assert(stream.tx_ack_ranges[0].end == 64U);
}

static void quic_lifecycle_test_connection_close_propagates(void)
{
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    quic_test_events_t server_events;
    libp2p_quic_conn_state_t server_state = LIBP2P_QUIC_CONN_IDLE;
    size_t round = 0U;

    quic_test_make_identity(&identity, 43U);
    quic_test_pair_init(&pair, &identity.identity, 30004U, 30005U, 0U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_conn_close(pair.client_conn, 99U) == LIBP2P_QUIC_OK);

    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.server, &server_events);
        if (server_events.closed_conn_count != 0U)
        {
            break;
        }
    }

    assert(server_events.closed_conn_count != 0U);
    assert(server_events.closed_conn == pair.server_conn);
    assert(server_events.last_app_error_code == 99U);
    assert(libp2p_quic_conn_state(pair.server_conn, &server_state) == LIBP2P_QUIC_OK);
    assert(server_state == LIBP2P_QUIC_CONN_CLOSED);

    quic_test_pair_deinit(&pair);
}

static void quic_lifecycle_test_idle_timeout_closes(void)
{
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    quic_test_events_t client_events;
    libp2p_quic_conn_state_t client_state = LIBP2P_QUIC_CONN_ESTABLISHED;
    libp2p_quic_time_us_t deadline = 0U;
    size_t round = 0U;

    quic_test_make_identity(&identity, 47U);
    quic_test_pair_init(&pair, &identity.identity, 30006U, 30007U, 100000U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_endpoint_next_deadline(pair.client, &deadline) == LIBP2P_QUIC_OK);
    assert(deadline >= pair.now_us);

    (void)memset(&client_events, 0, sizeof(client_events));
    for (round = 0U; round < 1000U; round++)
    {
        pair.now_us += 50000U;
        assert(libp2p_quic_endpoint_poll(pair.client, pair.now_us) == LIBP2P_QUIC_OK);
        quic_test_drain_events(pair.client, &client_events);
        assert(libp2p_quic_conn_state(pair.client_conn, &client_state) == LIBP2P_QUIC_OK);
        if (client_state == LIBP2P_QUIC_CONN_CLOSED)
        {
            break;
        }
    }

    assert(client_state == LIBP2P_QUIC_CONN_CLOSED);
    assert(client_events.closed_conn_count != 0U);

    quic_test_pair_deinit(&pair);
}

static void quic_lifecycle_test_closed_connection_releases_endpoint_slot(void)
{
    quic_test_identity_fixture_t identity;
    libp2p_quic_endpoint_config_t client_a_config;
    libp2p_quic_endpoint_config_t client_b_config;
    libp2p_quic_endpoint_config_t server_config;
    libp2p_quic_endpoint_t *client_a = NULL;
    libp2p_quic_endpoint_t *client_b = NULL;
    libp2p_quic_endpoint_t *server = NULL;
    libp2p_quic_conn_t *client_a_conn = NULL;
    libp2p_quic_conn_t *client_b_conn = NULL;
    libp2p_quic_conn_t *server_conn_a = NULL;
    libp2p_quic_conn_t *server_conn_b = NULL;
    libp2p_quic_addr_t client_a_addr;
    libp2p_quic_addr_t client_b_addr;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_dial_config_t dial_config;
    quic_test_events_t client_a_events;
    quic_test_events_t server_events;
    void *client_a_storage = NULL;
    void *client_b_storage = NULL;
    void *server_storage = NULL;
    uint8_t client_a_random = 11U;
    uint8_t client_b_random = 53U;
    uint8_t server_random = 197U;
    uint64_t unix_time = UINT64_C(1750000000);
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_time_us_t now_us = 0U;
    size_t round = 0U;

    quic_test_make_identity(&identity, 59U);
    assert(libp2p_quic_endpoint_config_default(&client_a_config) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_config_default(&client_b_config) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_config_default(&server_config) == LIBP2P_QUIC_OK);

    client_a_config.allocator = quic_test_allocator();
    client_b_config.allocator = quic_test_allocator();
    server_config.allocator = quic_test_allocator();
    client_a_config.role = LIBP2P_QUIC_ROLE_CLIENT;
    client_b_config.role = LIBP2P_QUIC_ROLE_CLIENT;
    server_config.role = LIBP2P_QUIC_ROLE_SERVER;
    client_a_config.identity = identity.identity;
    client_b_config.identity = identity.identity;
    server_config.identity = identity.identity;
    client_a_config.random_fn = quic_test_random;
    client_b_config.random_fn = quic_test_random;
    server_config.random_fn = quic_test_random;
    client_a_config.random_user_data = &client_a_random;
    client_b_config.random_user_data = &client_b_random;
    server_config.random_user_data = &server_random;
    client_a_config.unix_time_fn = quic_test_unix_time;
    client_b_config.unix_time_fn = quic_test_unix_time;
    server_config.unix_time_fn = quic_test_unix_time;
    client_a_config.unix_time_user_data = &unix_time;
    client_b_config.unix_time_user_data = &unix_time;
    server_config.unix_time_user_data = &unix_time;
    client_a_config.max_connections = 1U;
    client_a_config.max_incoming_connections = 1U;
    client_a_config.max_outgoing_connections = 1U;
    client_b_config.max_connections = 1U;
    client_b_config.max_incoming_connections = 1U;
    client_b_config.max_outgoing_connections = 1U;
    server_config.max_connections = 1U;
    server_config.max_incoming_connections = 1U;
    server_config.max_outgoing_connections = 1U;

    quic_test_endpoint_init_one(&client_a, &client_a_storage, &client_a_config);
    quic_test_endpoint_init_one(&client_b, &client_b_storage, &client_b_config);
    quic_test_endpoint_init_one(&server, &server_storage, &server_config);

    assert(libp2p_quic_addr_from_ip4(ip4, 30020U, &client_a_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 30021U, &server_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 30022U, &client_b_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(client_a, &client_a_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(client_b, &client_b_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(server, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(&server_addr, identity.peer_id, identity.peer_id_len) ==
        LIBP2P_QUIC_OK);

    dial_config.remote_addr = server_addr;
    dial_config.user_data = NULL;
    assert(libp2p_quic_endpoint_dial(client_a, &dial_config, &client_a_conn) == LIBP2P_QUIC_OK);
    quic_test_wait_established(client_a, server, client_a_conn, &server_conn_a, &now_us);
    assert(client_a->connection_count == 1U);
    assert(client_a->outgoing_connection_count == 1U);
    assert(server->connection_count == 1U);
    assert(server->incoming_connection_count == 1U);

    assert(libp2p_quic_conn_close(client_a_conn, 99U) == LIBP2P_QUIC_OK);
    (void)memset(&client_a_events, 0, sizeof(client_a_events));
    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_test_pump(client_a, server, &now_us);
        quic_test_drain_events(client_a, &client_a_events);
        quic_test_drain_events(server, &server_events);
        if ((client_a_events.closed_conn_count != 0U) && (server_events.closed_conn_count != 0U))
        {
            break;
        }
    }

    assert(client_a_events.closed_conn == client_a_conn);
    assert(server_events.closed_conn == server_conn_a);
    assert(client_a->connection_count == 0U);
    assert(client_a->outgoing_connection_count == 0U);
    assert(server->connection_count == 0U);
    assert(server->incoming_connection_count == 0U);

    assert(libp2p_quic_endpoint_dial(client_b, &dial_config, &client_b_conn) == LIBP2P_QUIC_OK);
    quic_test_wait_established(client_b, server, client_b_conn, &server_conn_b, &now_us);
    assert(server_conn_b != NULL);
    assert(server_conn_b != server_conn_a);
    assert(server->connection_count == 1U);
    assert(server->incoming_connection_count == 1U);

    libp2p_quic_endpoint_deinit(client_a);
    libp2p_quic_endpoint_deinit(client_b);
    libp2p_quic_endpoint_deinit(server);
    free(client_a_storage);
    free(client_b_storage);
    free(server_storage);
}

int main(void)
{
    quic_lifecycle_test_multiple_streams();
    quic_lifecycle_test_stream_writable_after_tx_drain();
    quic_lifecycle_test_buffered_rx_terminal(0, 0U, 30002U, 30003U);
    quic_lifecycle_test_buffered_rx_terminal(1, 0U, 30014U, 30015U);
    quic_lifecycle_test_buffered_rx_terminal(1, 77U, 30016U, 30017U);
    quic_lifecycle_test_stream_reset_discards_pending_tx();
    quic_lifecycle_test_ack_tail_does_not_cover_gap();
    quic_lifecycle_test_ack_ranges_merge_to_full_window();
    quic_lifecycle_test_connection_close_propagates();
    quic_lifecycle_test_idle_timeout_closes();
    quic_lifecycle_test_closed_connection_releases_endpoint_slot();

    return 0;
}
