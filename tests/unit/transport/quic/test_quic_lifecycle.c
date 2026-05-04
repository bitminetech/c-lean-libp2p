#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

static void quic_lifecycle_test_stream_reset_propagates(void)
{
    quic_test_identity_fixture_t identity;
    quic_test_pair_t pair;
    quic_test_events_t server_events;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_stream_state_t stream_state = LIBP2P_QUIC_STREAM_OPEN;
    size_t round = 0U;

    quic_test_make_identity(&identity, 37U);
    quic_test_pair_init(&pair, &identity.identity, 30002U, 30003U, 0U);
    quic_test_pair_dial(&pair, &identity);

    assert(libp2p_quic_conn_open_bidi_stream(pair.client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_stream_reset(client_stream, 77U) == LIBP2P_QUIC_OK);

    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_test_pump(pair.client, pair.server, &pair.now_us);
        quic_test_drain_events(pair.server, &server_events);
        if (server_events.closed_stream_count != 0U)
        {
            break;
        }
    }

    assert(server_events.closed_stream_count != 0U);
    assert(server_events.closed_stream != NULL);
    assert(server_events.last_app_error_code == 77U);
    assert(libp2p_quic_stream_state(server_events.closed_stream, &stream_state) == LIBP2P_QUIC_OK);
    assert(stream_state == LIBP2P_QUIC_STREAM_RESET);

    quic_test_pair_deinit(&pair);
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

int main(void)
{
    quic_lifecycle_test_multiple_streams();
    quic_lifecycle_test_stream_writable_after_tx_drain();
    quic_lifecycle_test_stream_reset_propagates();
    quic_lifecycle_test_connection_close_propagates();
    quic_lifecycle_test_idle_timeout_closes();

    return 0;
}
