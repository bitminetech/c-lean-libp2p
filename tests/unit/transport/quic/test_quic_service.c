#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "quic_test_support.h"
#include "transport/quic/quic_service.h"

typedef struct
{
    quic_test_identity_fixture_t identity;
    libp2p_quic_service_t *client;
    libp2p_quic_service_t *server;
    libp2p_quic_conn_t *client_conn;
    libp2p_quic_conn_t *server_conn;
    void *client_storage;
    void *server_storage;
    uint8_t client_random;
    uint8_t server_random;
    uint64_t unix_time;
    libp2p_quic_time_us_t now_us;
} quic_service_fixture_t;

typedef struct
{
    libp2p_quic_conn_t *incoming_conn;
    libp2p_quic_conn_t *established_conn;
    libp2p_quic_conn_t *closed_conn;
    libp2p_quic_stream_t *incoming_stream;
    libp2p_quic_stream_t *readable_stream;
    size_t incoming_count;
    size_t established_count;
    size_t closed_count;
    size_t readable_count;
    uint64_t app_error_code;
} quic_service_events_t;

static void quic_service_init_one(
    libp2p_quic_service_t **service,
    void **storage,
    const libp2p_quic_local_identity_t *identity,
    libp2p_quic_role_t role,
    uint8_t *random_state,
    uint64_t *unix_time)
{
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_service_config_t config;
    size_t storage_len = 0U;
    size_t storage_align = 0U;

    assert(service != NULL);
    assert(storage != NULL);
    assert(identity != NULL);

    assert(libp2p_quic_service_config_default(&config) == LIBP2P_QUIC_OK);
    config.endpoint.role = role;
    config.endpoint.allocator = quic_test_allocator();
    config.endpoint.identity = *identity;
    config.endpoint.random_fn = quic_test_random;
    config.endpoint.random_user_data = random_state;
    config.endpoint.unix_time_fn = quic_test_unix_time;
    config.endpoint.unix_time_user_data = unix_time;
    config.max_rx_datagrams_per_drive = 16U;
    config.max_tx_datagrams_per_drive = 16U;
    assert(libp2p_quic_addr_from_ip4(ip4, 0U, &config.local_addr) == LIBP2P_QUIC_OK);

    assert(libp2p_quic_service_storage_size(&config, &storage_len) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_service_storage_align(&storage_align) == LIBP2P_QUIC_OK);
    assert(storage_len > sizeof(libp2p_quic_service_t *));
    assert(storage_align != 0U);

    *storage = calloc(1U, storage_len);
    assert(*storage != NULL);
    assert(libp2p_quic_service_init(*storage, storage_len, &config, service) == LIBP2P_QUIC_OK);
}

static void quic_service_fixture_init(quic_service_fixture_t *fixture)
{
    assert(fixture != NULL);
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->client_random = 71U;
    fixture->server_random = 173U;
    fixture->unix_time = UINT64_C(1750000000);

    quic_test_make_identity(&fixture->identity, 67U);
    quic_service_init_one(
        &fixture->client,
        &fixture->client_storage,
        &fixture->identity.identity,
        LIBP2P_QUIC_ROLE_CLIENT,
        &fixture->client_random,
        &fixture->unix_time);
    quic_service_init_one(
        &fixture->server,
        &fixture->server_storage,
        &fixture->identity.identity,
        LIBP2P_QUIC_ROLE_SERVER,
        &fixture->server_random,
        &fixture->unix_time);
}

static void quic_service_fixture_deinit(quic_service_fixture_t *fixture)
{
    if (fixture == NULL)
    {
        return;
    }

    libp2p_quic_service_deinit(fixture->client);
    libp2p_quic_service_deinit(fixture->server);
    free(fixture->client_storage);
    free(fixture->server_storage);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static void quic_service_drain_events(libp2p_quic_service_t *service, quic_service_events_t *events)
{
    libp2p_quic_service_event_t event;

    assert(service != NULL);
    assert(events != NULL);

    while (libp2p_quic_service_next_event(service, &event) == LIBP2P_QUIC_OK)
    {
        if (event.type == LIBP2P_QUIC_SERVICE_EVENT_CONN_INCOMING)
        {
            events->incoming_conn = event.conn;
            events->incoming_count++;
        }
        else if (event.type == LIBP2P_QUIC_SERVICE_EVENT_CONN_ESTABLISHED)
        {
            events->established_conn = event.conn;
            events->established_count++;
        }
        else if (event.type == LIBP2P_QUIC_SERVICE_EVENT_CONN_CLOSED)
        {
            events->closed_conn = event.conn;
            events->closed_count++;
            events->app_error_code = event.app_error_code;
        }
        else if (event.type == LIBP2P_QUIC_SERVICE_EVENT_STREAM_INCOMING)
        {
            events->incoming_stream = event.stream;
        }
        else if (event.type == LIBP2P_QUIC_SERVICE_EVENT_STREAM_READABLE)
        {
            events->readable_stream = event.stream;
            events->readable_count++;
        }
        else
        {
            /* Other events are advisory for these service tests. */
        }
    }
}

static uint8_t quic_service_drive_pair_once(quic_service_fixture_t *fixture)
{
    libp2p_quic_service_drive_result_t client_result;
    libp2p_quic_service_drive_result_t server_result;
    uint8_t made_progress = 0U;

    assert(fixture != NULL);
    assert(
        libp2p_quic_service_drive(
            fixture->client,
            fixture->now_us,
            LIBP2P_QUIC_SERVICE_READY_ALL,
            &client_result) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_drive(
            fixture->server,
            fixture->now_us,
            LIBP2P_QUIC_SERVICE_READY_ALL,
            &server_result) == LIBP2P_QUIC_OK);
    fixture->now_us += 1000U;

    if ((client_result.made_progress != 0U) || (server_result.made_progress != 0U))
    {
        made_progress = 1U;
    }

    return made_progress;
}

static void quic_service_drive_pair(quic_service_fixture_t *fixture)
{
    size_t round = 0U;

    for (round = 0U; round < 64U; round++)
    {
        if (quic_service_drive_pair_once(fixture) == 0U)
        {
            break;
        }
    }
}

static void quic_service_wait_established(quic_service_fixture_t *fixture)
{
    quic_service_events_t client_events;
    quic_service_events_t server_events;
    size_t round = 0U;

    (void)memset(&client_events, 0, sizeof(client_events));
    (void)memset(&server_events, 0, sizeof(server_events));

    for (round = 0U; round < 1000U; round++)
    {
        libp2p_quic_conn_state_t client_state = LIBP2P_QUIC_CONN_IDLE;
        libp2p_quic_conn_state_t server_state = LIBP2P_QUIC_CONN_IDLE;
        libp2p_quic_conn_t *accepted = NULL;

        quic_service_drive_pair(fixture);
        quic_service_drain_events(fixture->client, &client_events);
        quic_service_drain_events(fixture->server, &server_events);

        if (fixture->server_conn == NULL)
        {
            libp2p_quic_err_t accept_result =
                libp2p_quic_service_accept_conn(fixture->server, &accepted);

            if (accept_result == LIBP2P_QUIC_OK)
            {
                fixture->server_conn = accepted;
            }
            else
            {
                assert(accept_result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
            }
        }

        if (fixture->server_conn != NULL)
        {
            assert(libp2p_quic_conn_state(fixture->client_conn, &client_state) == LIBP2P_QUIC_OK);
            assert(libp2p_quic_conn_state(fixture->server_conn, &server_state) == LIBP2P_QUIC_OK);
            if ((client_state == LIBP2P_QUIC_CONN_ESTABLISHED) &&
                (server_state == LIBP2P_QUIC_CONN_ESTABLISHED))
            {
                assert(client_events.established_count != 0U);
                assert(server_events.incoming_count != 0U);
                assert(server_events.established_count != 0U);
                return;
            }
        }
    }

    assert(0 && "service handshake did not complete");
}

static uint64_t quic_service_total_write_zero(const libp2p_quic_service_t *service)
{
    uint64_t total = 0U;
    size_t index = 0U;

    for (index = 0U; index < LIBP2P_QUIC_DEFAULT_MAX_CONNECTIONS; index++)
    {
        libp2p_quic_service_autopsy_conn_t snapshot;

        (void)memset(&snapshot, 0, sizeof(snapshot));
        if (libp2p_quic_service_autopsy_conn(service, index, 0U, &snapshot) == LIBP2P_QUIC_OK)
        {
            total += snapshot.write_zero_count;
        }
    }

    return total;
}

static int quic_service_write_interest_is_settled(const quic_service_fixture_t *fixture)
{
    libp2p_quic_service_interest_t client_interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    libp2p_quic_service_interest_t server_interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    libp2p_quic_time_us_t client_deadline = 0U;
    libp2p_quic_time_us_t server_deadline = 0U;
    int client_timer_pending = 0;
    int server_timer_pending = 0;
    int settled = 0;

    assert(fixture != NULL);
    assert(libp2p_quic_service_io_interest(fixture->client, &client_interest) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_service_io_interest(fixture->server, &server_interest) == LIBP2P_QUIC_OK);

    if (libp2p_quic_service_next_deadline(fixture->client, &client_deadline) == LIBP2P_QUIC_OK)
    {
        client_timer_pending = (client_deadline <= fixture->now_us) ? 1 : 0;
    }
    if (libp2p_quic_service_next_deadline(fixture->server, &server_deadline) == LIBP2P_QUIC_OK)
    {
        server_timer_pending = (server_deadline <= fixture->now_us) ? 1 : 0;
    }

    if (((client_interest & LIBP2P_QUIC_SERVICE_INTEREST_WRITE) == 0U) &&
        ((server_interest & LIBP2P_QUIC_SERVICE_INTEREST_WRITE) == 0U) &&
        (client_timer_pending == 0) && (server_timer_pending == 0))
    {
        settled = 1;
    }

    return settled;
}

static void quic_service_wait_write_idle(quic_service_fixture_t *fixture)
{
    size_t round = 0U;
    size_t quiet_rounds = 0U;

    assert(fixture != NULL);
    for (round = 0U; round < 5000U; round++)
    {
        quic_service_events_t events;
        const uint8_t made_progress = quic_service_drive_pair_once(fixture);

        (void)memset(&events, 0, sizeof(events));
        quic_service_drain_events(fixture->client, &events);
        (void)memset(&events, 0, sizeof(events));
        quic_service_drain_events(fixture->server, &events);

        if ((made_progress == 0U) && (quic_service_write_interest_is_settled(fixture) != 0))
        {
            quiet_rounds++;
            if (quiet_rounds >= 32U)
            {
                return;
            }
        }
        else
        {
            quiet_rounds = 0U;
        }
    }

    assert(0 && "service write interest did not settle");
}

static void quic_service_test_idle_app_timer_does_not_probe_tx(void)
{
    quic_service_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    size_t round = 0U;

    quic_service_fixture_init(&fixture);
    assert(libp2p_quic_service_local_addr(fixture.server, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_dial(fixture.client, &server_addr, NULL, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);
    quic_service_wait_established(&fixture);
    quic_service_wait_write_idle(&fixture);

    for (round = 0U; round < 1000U; round++)
    {
        libp2p_quic_service_drive_result_t client_result;
        libp2p_quic_service_drive_result_t server_result;
        quic_service_events_t events;
        const uint64_t client_zero_before = quic_service_total_write_zero(fixture.client);
        const uint64_t server_zero_before = quic_service_total_write_zero(fixture.server);

        (void)memset(&client_result, 0, sizeof(client_result));
        assert(
            libp2p_quic_service_drive(
                fixture.client,
                fixture.now_us,
                LIBP2P_QUIC_SERVICE_READY_APP | LIBP2P_QUIC_SERVICE_READY_TIMER,
                &client_result) == LIBP2P_QUIC_OK);
        (void)memset(&server_result, 0, sizeof(server_result));
        assert(
            libp2p_quic_service_drive(
                fixture.server,
                fixture.now_us,
                LIBP2P_QUIC_SERVICE_READY_APP | LIBP2P_QUIC_SERVICE_READY_TIMER,
                &server_result) == LIBP2P_QUIC_OK);

        if ((client_result.made_progress == 0U) && (server_result.made_progress == 0U))
        {
            assert(quic_service_total_write_zero(fixture.client) == client_zero_before);
            assert(quic_service_total_write_zero(fixture.server) == server_zero_before);
            quic_service_fixture_deinit(&fixture);
            return;
        }

        (void)memset(&events, 0, sizeof(events));
        quic_service_drain_events(fixture.client, &events);
        (void)memset(&events, 0, sizeof(events));
        quic_service_drain_events(fixture.server, &events);
        quic_service_wait_write_idle(&fixture);
    }

    assert(0 && "service idle app/timer probe did not settle");

    quic_service_fixture_deinit(&fixture);
}

static void quic_service_test_runtime_driver_and_stream_api(void)
{
    static const uint8_t message[] = {'s', 'e', 'r', 'v', 'i', 'c', 'e'};
    quic_service_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_stream_t *server_stream = NULL;
    quic_service_events_t server_events;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t read_buf[16];
    size_t peer_id_len = 0U;
    size_t accepted = 0U;
    size_t read_len = 0U;
    size_t total_read = 0U;
    libp2p_quic_service_interest_t interest = LIBP2P_QUIC_SERVICE_INTEREST_NONE;
    libp2p_quic_udp_fd_t fd = LIBP2P_QUIC_UDP_INVALID_FD;
    int fin = 0;
    size_t round = 0U;

    quic_service_fixture_init(&fixture);

    assert(libp2p_quic_service_fd(fixture.client, &fd) == LIBP2P_QUIC_OK);
    assert(fd != LIBP2P_QUIC_UDP_INVALID_FD);
    assert(libp2p_quic_service_io_interest(fixture.client, &interest) == LIBP2P_QUIC_OK);
    assert((interest & LIBP2P_QUIC_SERVICE_INTEREST_READ) != 0U);
    assert((interest & LIBP2P_QUIC_SERVICE_INTEREST_WRITE) == 0U);

    assert(libp2p_quic_service_local_addr(fixture.server, &server_addr) == LIBP2P_QUIC_OK);
    assert(server_addr.port != 0U);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);

    assert(
        libp2p_quic_service_accept_conn(fixture.server, &fixture.server_conn) ==
        LIBP2P_QUIC_ERR_WOULD_BLOCK);
    assert(
        libp2p_quic_service_dial(fixture.client, &server_addr, NULL, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);
    assert(libp2p_quic_service_io_interest(fixture.client, &interest) == LIBP2P_QUIC_OK);
    assert((interest & LIBP2P_QUIC_SERVICE_INTEREST_WRITE) != 0U);

    quic_service_wait_established(&fixture);

    assert(
        libp2p_quic_service_conn_peer_id(
            fixture.client_conn,
            peer_id,
            sizeof(peer_id),
            &peer_id_len) == LIBP2P_QUIC_OK);
    assert(peer_id_len == fixture.identity.peer_id_len);
    assert(memcmp(peer_id, fixture.identity.peer_id, peer_id_len) == 0);

    assert(
        libp2p_quic_service_open_stream(fixture.client, fixture.client_conn, &client_stream) ==
        LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_stream_write(
            fixture.client,
            client_stream,
            message,
            sizeof(message),
            1,
            &accepted) == LIBP2P_QUIC_OK);
    assert(accepted == sizeof(message));

    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_service_drive_pair(&fixture);
        quic_service_drain_events(fixture.server, &server_events);

        if ((server_events.readable_count != 0U) && (server_stream == NULL))
        {
            assert(
                libp2p_quic_service_accept_stream(fixture.server_conn, &server_stream) ==
                LIBP2P_QUIC_OK);
        }
        if (server_stream != NULL)
        {
            libp2p_quic_err_t result = libp2p_quic_service_stream_read(
                fixture.server,
                server_stream,
                &read_buf[total_read],
                sizeof(read_buf) - total_read,
                &read_len,
                &fin);

            if (result == LIBP2P_QUIC_OK)
            {
                assert((total_read + read_len) <= sizeof(read_buf));
                total_read += read_len;
                if (fin != 0)
                {
                    break;
                }
            }
            else
            {
                assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
            }
        }
    }

    assert(total_read == sizeof(message));
    assert(memcmp(read_buf, message, sizeof(message)) == 0);
    assert(fin == 1);

    quic_service_fixture_deinit(&fixture);
}

static void quic_service_test_drive_batches_stream_datagrams(void)
{
    static uint8_t payload[64U * 1024U];
    quic_service_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_service_drive_result_t client_result;
    size_t accepted = 0U;

    for (size_t index = 0U; index < sizeof(payload); index++)
    {
        payload[index] = (uint8_t)(index & 0xffU);
    }

    quic_service_fixture_init(&fixture);
    assert(libp2p_quic_service_local_addr(fixture.server, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_dial(fixture.client, &server_addr, NULL, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);
    quic_service_wait_established(&fixture);
    quic_service_wait_write_idle(&fixture);

    assert(
        libp2p_quic_service_open_stream(fixture.client, fixture.client_conn, &client_stream) ==
        LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_stream_write(
            fixture.client,
            client_stream,
            payload,
            sizeof(payload),
            0,
            &accepted) == LIBP2P_QUIC_OK);
    assert(accepted == sizeof(payload));

    (void)memset(&client_result, 0, sizeof(client_result));
    assert(
        libp2p_quic_service_drive(
            fixture.client,
            fixture.now_us,
            LIBP2P_QUIC_SERVICE_READY_ALL,
            &client_result) == LIBP2P_QUIC_OK);
    assert(client_result.tx_datagrams > 1U);

    fixture.now_us += 1000U;
    quic_service_wait_write_idle(&fixture);
    quic_service_fixture_deinit(&fixture);
}

static void quic_service_test_close_event(void)
{
    quic_service_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    quic_service_events_t server_events;
    size_t round = 0U;

    quic_service_fixture_init(&fixture);
    assert(libp2p_quic_service_local_addr(fixture.server, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_service_dial(fixture.client, &server_addr, NULL, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);
    quic_service_wait_established(&fixture);

    assert(
        libp2p_quic_service_conn_close(fixture.client, fixture.client_conn, 1234U) ==
        LIBP2P_QUIC_OK);

    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_service_drive_pair(&fixture);
        quic_service_drain_events(fixture.server, &server_events);
        if (server_events.closed_count != 0U)
        {
            break;
        }
    }

    assert(server_events.closed_count != 0U);
    assert(server_events.closed_conn == fixture.server_conn);
    assert(server_events.app_error_code == 1234U);

    quic_service_fixture_deinit(&fixture);
}

int main(void)
{
    quic_service_test_idle_app_timer_does_not_probe_tx();
    quic_service_test_runtime_driver_and_stream_api();
    quic_service_test_drive_batches_stream_datagrams();
    quic_service_test_close_event();
    return 0;
}
