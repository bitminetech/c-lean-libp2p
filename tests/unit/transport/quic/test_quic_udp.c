#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(_WIN32)
#include <poll.h>
#endif

#include "quic_test_support.h"
#include "transport/quic/quic_udp.h"

typedef struct
{
    quic_test_identity_fixture_t identity;
    libp2p_quic_udp_socket_t client_socket;
    libp2p_quic_udp_socket_t server_socket;
    libp2p_quic_endpoint_t *client;
    libp2p_quic_endpoint_t *server;
    libp2p_quic_conn_t *client_conn;
    libp2p_quic_conn_t *server_conn;
    void *client_storage;
    void *server_storage;
    uint8_t client_random;
    uint8_t server_random;
    uint64_t unix_time;
    libp2p_quic_time_us_t now_us;
} quic_udp_fixture_t;

static void quic_udp_fixture_init(quic_udp_fixture_t *fixture)
{
    uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_addr_t any_client;
    libp2p_quic_addr_t any_server;
    libp2p_quic_addr_t client_addr;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_endpoint_config_t client_config;
    libp2p_quic_endpoint_config_t server_config;

    assert(fixture != NULL);
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->client_random = 59U;
    fixture->server_random = 149U;
    fixture->unix_time = UINT64_C(1750000000);

    quic_test_make_identity(&fixture->identity, 53U);
    assert(libp2p_quic_udp_socket_init(&fixture->client_socket) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_udp_socket_init(&fixture->server_socket) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 0U, &any_client) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_ip4(ip4, 0U, &any_server) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_udp_socket_open(&fixture->client_socket, &any_client, 1) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_udp_socket_open(&fixture->server_socket, &any_server, 1) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_udp_socket_local_addr(&fixture->client_socket, &client_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_udp_socket_local_addr(&fixture->server_socket, &server_addr) == LIBP2P_QUIC_OK);
    assert(client_addr.port != 0U);
    assert(server_addr.port != 0U);

    assert(libp2p_quic_endpoint_config_default(&client_config) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_config_default(&server_config) == LIBP2P_QUIC_OK);
    client_config.allocator = quic_test_allocator();
    server_config.allocator = quic_test_allocator();
    client_config.role = LIBP2P_QUIC_ROLE_CLIENT;
    server_config.role = LIBP2P_QUIC_ROLE_SERVER;
    client_config.identity = fixture->identity.identity;
    server_config.identity = fixture->identity.identity;
    client_config.random_fn = quic_test_random;
    client_config.random_user_data = &fixture->client_random;
    client_config.unix_time_fn = quic_test_unix_time;
    client_config.unix_time_user_data = &fixture->unix_time;
    server_config.random_fn = quic_test_random;
    server_config.random_user_data = &fixture->server_random;
    server_config.unix_time_fn = quic_test_unix_time;
    server_config.unix_time_user_data = &fixture->unix_time;

    quic_test_endpoint_init_one(&fixture->client, &fixture->client_storage, &client_config);
    quic_test_endpoint_init_one(&fixture->server, &fixture->server_storage, &server_config);
    assert(libp2p_quic_endpoint_bind(fixture->client, &client_addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_bind(fixture->server, &server_addr) == LIBP2P_QUIC_OK);
}

static void quic_udp_fixture_deinit(quic_udp_fixture_t *fixture)
{
    if (fixture == NULL)
    {
        return;
    }

    libp2p_quic_endpoint_deinit(fixture->client);
    libp2p_quic_endpoint_deinit(fixture->server);
    free(fixture->client_storage);
    free(fixture->server_storage);
    libp2p_quic_udp_socket_close(&fixture->client_socket);
    libp2p_quic_udp_socket_close(&fixture->server_socket);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static void quic_udp_drive_once(quic_udp_fixture_t *fixture, int *progress)
{
    uint8_t client_tx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    uint8_t server_tx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    uint8_t client_rx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    uint8_t server_rx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    result = libp2p_quic_udp_socket_send(
        &fixture->client_socket,
        fixture->client,
        client_tx,
        sizeof(client_tx),
        fixture->now_us);
    if (result == LIBP2P_QUIC_OK)
    {
        *progress = 1;
    }
    else
    {
        assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
    }

    result = libp2p_quic_udp_socket_send(
        &fixture->server_socket,
        fixture->server,
        server_tx,
        sizeof(server_tx),
        fixture->now_us);
    if (result == LIBP2P_QUIC_OK)
    {
        *progress = 1;
    }
    else
    {
        assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
    }

    result = libp2p_quic_udp_socket_recv(
        &fixture->server_socket,
        fixture->server,
        server_rx,
        sizeof(server_rx),
        fixture->now_us);
    if (result == LIBP2P_QUIC_OK)
    {
        *progress = 1;
    }
    else
    {
        assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
    }

    result = libp2p_quic_udp_socket_recv(
        &fixture->client_socket,
        fixture->client,
        client_rx,
        sizeof(client_rx),
        fixture->now_us);
    if (result == LIBP2P_QUIC_OK)
    {
        *progress = 1;
    }
    else
    {
        assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
    }

    assert(libp2p_quic_endpoint_poll(fixture->client, fixture->now_us) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_endpoint_poll(fixture->server, fixture->now_us) == LIBP2P_QUIC_OK);
    fixture->now_us += 1000U;
}

static void quic_udp_drive(quic_udp_fixture_t *fixture)
{
    size_t round = 0U;

    for (round = 0U; round < 64U; round++)
    {
        int progress = 0;

        quic_udp_drive_once(fixture, &progress);
        if (progress == 0)
        {
            break;
        }
    }
}

static void quic_udp_wait_established(quic_udp_fixture_t *fixture)
{
    quic_test_events_t client_events;
    quic_test_events_t server_events;
    size_t round = 0U;

    (void)memset(&client_events, 0, sizeof(client_events));
    (void)memset(&server_events, 0, sizeof(server_events));

    for (round = 0U; round < 1000U; round++)
    {
        libp2p_quic_conn_state_t client_state = LIBP2P_QUIC_CONN_IDLE;
        libp2p_quic_conn_state_t server_state = LIBP2P_QUIC_CONN_IDLE;

        quic_udp_drive(fixture);
        quic_test_drain_events(fixture->server, &server_events);
        quic_test_drain_events(fixture->client, &client_events);
        if ((server_events.incoming_conn != NULL) && (fixture->server_conn == NULL))
        {
            fixture->server_conn = server_events.incoming_conn;
        }
        if (fixture->server_conn != NULL)
        {
            assert(libp2p_quic_conn_state(fixture->client_conn, &client_state) == LIBP2P_QUIC_OK);
            assert(libp2p_quic_conn_state(fixture->server_conn, &server_state) == LIBP2P_QUIC_OK);
            if ((client_state == LIBP2P_QUIC_CONN_ESTABLISHED) &&
                (server_state == LIBP2P_QUIC_CONN_ESTABLISHED))
            {
                return;
            }
        }
    }

    assert(0 && "real UDP QUIC handshake did not complete");
}

static void quic_udp_wait_server_readable(const quic_udp_fixture_t *fixture)
{
#if !defined(_WIN32)
    struct pollfd pfd;

    assert(fixture != NULL);
    assert(fixture->server_socket.fd <= (libp2p_quic_udp_fd_t)INT_MAX);
    pfd.fd = (int)fixture->server_socket.fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    assert(poll(&pfd, (nfds_t)1, 1000) > 0);
    assert((pfd.revents & POLLIN) != 0);
#else
    (void)fixture;
#endif
}

static void quic_udp_test_real_socket_handshake_and_stream(void)
{
    static const uint8_t message[] = {'u', 'd', 'p', '-', 'q', 'u', 'i', 'c'};
    quic_udp_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_dial_config_t dial_config;
    libp2p_quic_stream_t *client_stream = NULL;
    libp2p_quic_stream_t *server_stream = NULL;
    quic_test_events_t server_events;
    uint8_t read_buf[16];
    size_t accepted = 0U;
    size_t read_len = 0U;
    int fin = 0;
    size_t round = 0U;

    quic_udp_fixture_init(&fixture);
    assert(
        libp2p_quic_udp_socket_local_addr(&fixture.server_socket, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);
    dial_config.remote_addr = server_addr;
    dial_config.user_data = NULL;

    assert(
        libp2p_quic_endpoint_dial(fixture.client, &dial_config, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);
    quic_udp_wait_established(&fixture);

    assert(
        libp2p_quic_conn_open_bidi_stream(fixture.client_conn, &client_stream) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_stream_write(client_stream, message, sizeof(message), 1, &accepted) ==
        LIBP2P_QUIC_OK);
    assert(accepted == sizeof(message));

    (void)memset(&server_events, 0, sizeof(server_events));
    for (round = 0U; round < 1000U; round++)
    {
        quic_udp_drive(&fixture);
        quic_test_drain_events(fixture.server, &server_events);
        if ((server_events.readable_count != 0U) && (server_stream == NULL))
        {
            assert(
                libp2p_quic_conn_accept_stream(fixture.server_conn, &server_stream) ==
                LIBP2P_QUIC_OK);
        }
        if (server_stream != NULL)
        {
            libp2p_quic_err_t result =
                libp2p_quic_stream_read(server_stream, read_buf, sizeof(read_buf), &read_len, &fin);

            if (result == LIBP2P_QUIC_OK)
            {
                break;
            }
            assert(result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
        }
    }

    assert(read_len == sizeof(message));
    assert(memcmp(read_buf, message, sizeof(message)) == 0);
    assert(fin == 1);

    quic_udp_fixture_deinit(&fixture);
}

static void quic_udp_test_send_prepared_datagram(void)
{
    quic_udp_fixture_t fixture;
    libp2p_quic_addr_t server_addr;
    libp2p_quic_dial_config_t dial_config;
    libp2p_quic_tx_datagram_t datagram;
    libp2p_quic_rx_datagram_t received = {0};
    uint8_t tx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    uint8_t rx[LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES];
    libp2p_quic_err_t recv_result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
    size_t round = 0U;

    quic_udp_fixture_init(&fixture);
    assert(
        libp2p_quic_udp_socket_local_addr(&fixture.server_socket, &server_addr) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_set_peer_id(
            &server_addr,
            fixture.identity.peer_id,
            fixture.identity.peer_id_len) == LIBP2P_QUIC_OK);
    dial_config.remote_addr = server_addr;
    dial_config.user_data = NULL;

    assert(
        libp2p_quic_endpoint_dial(fixture.client, &dial_config, &fixture.client_conn) ==
        LIBP2P_QUIC_OK);

    (void)memset(&datagram, 0, sizeof(datagram));
    datagram.data = tx;
    datagram.data_cap = sizeof(tx);
    assert(
        libp2p_quic_endpoint_next_datagram(fixture.client, &datagram, fixture.now_us) ==
        LIBP2P_QUIC_OK);
    assert(datagram.data_len != 0U);

    assert(
        libp2p_quic_udp_socket_send_datagram(&fixture.client_socket, &datagram) ==
        LIBP2P_QUIC_OK);
    quic_udp_wait_server_readable(&fixture);
    for (round = 0U; (round < 64U) && (recv_result == LIBP2P_QUIC_ERR_WOULD_BLOCK); round++)
    {
        recv_result = libp2p_quic_udp_socket_recv_datagram(
            &fixture.server_socket,
            &received,
            rx,
            sizeof(rx));
        fixture.now_us += 1000U;
    }
    assert(recv_result == LIBP2P_QUIC_OK);
    assert(received.data == rx);
    assert(received.data_len == datagram.data_len);
    assert(memcmp(rx, tx, datagram.data_len) == 0);

    quic_udp_fixture_deinit(&fixture);
}

int main(void)
{
    quic_udp_test_send_prepared_datagram();
    quic_udp_test_real_socket_handshake_and_stream();
    return 0;
}
