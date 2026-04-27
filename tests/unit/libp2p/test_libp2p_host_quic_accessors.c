#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol_loopback_support.h"
#include "transport/quic/quic_addr.h"

static void quic_accessor_read_listen(
    const libp2p_host_t *host,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    libp2p_quic_addr_t *addr)
{
    size_t required = 0U;

    assert(
        libp2p_host_listen_multiaddr(host, NULL, 0U, &required) ==
        LIBP2P_HOST_ERR_BUF_TOO_SMALL);
    assert(required != 0U);
    assert(required <= out_len);
    assert(libp2p_host_listen_multiaddr(host, out, out_len, written) == LIBP2P_HOST_OK);
    assert(*written == required);
    assert(libp2p_quic_addr_from_multiaddr(out, *written, addr) == LIBP2P_QUIC_OK);
    assert(addr->port != 0U);
    assert(addr->has_peer_id != 0U);
    assert(addr->peer_id_len != 0U);
}

static void quic_accessor_drive_until_connected(protocol_loopback_pair_t *pair)
{
    size_t round = 0U;

    for (round = 0U; round < 2000U; round++)
    {
        libp2p_host_event_t event;

        protocol_loopback_drive(pair);
        while (libp2p_host_next_event(pair->client, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair->client_conn = event.conn;
            }
            else
            {
                assert(event.type != LIBP2P_HOST_EVENT_DIAL_FAILED);
            }
        }
        while (libp2p_host_next_event(pair->server, &event) == LIBP2P_HOST_OK)
        {
            if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
            {
                pair->server_conn = event.conn;
            }
        }
        if ((pair->client_conn != NULL) && (pair->server_conn != NULL))
        {
            break;
        }
    }
    assert(pair->client_conn != NULL);
    assert(pair->server_conn != NULL);
}

static void quic_accessor_read_remote(
    const libp2p_host_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    libp2p_quic_addr_t *addr)
{
    size_t required = 0U;

    assert(
        libp2p_host_conn_remote_multiaddr(conn, NULL, 0U, &required) ==
        LIBP2P_HOST_ERR_BUF_TOO_SMALL);
    assert(required != 0U);
    assert(required <= out_len);
    assert(
        libp2p_host_conn_remote_multiaddr(conn, out, out_len, written) ==
        LIBP2P_HOST_OK);
    assert(*written == required);
    assert(libp2p_quic_addr_from_multiaddr(out, *written, addr) == LIBP2P_QUIC_OK);
    assert(addr->has_peer_id != 0U);
    assert(addr->peer_id_len != 0U);
}

static void quic_accessor_test_port_zero_and_remote_multiaddrs(void)
{
    protocol_loopback_pair_t pair;
    libp2p_host_config_t client_host_config;
    libp2p_host_config_t server_host_config;
    libp2p_quic_service_config_t client_service_config;
    libp2p_quic_service_config_t server_service_config;
    libp2p_quic_addr_t unused_server_addr;
    libp2p_quic_addr_t client_bound_addr;
    libp2p_quic_addr_t server_bound_addr;
    libp2p_quic_addr_t client_remote_addr;
    libp2p_quic_addr_t server_remote_addr;
    uint8_t unused_server_dial[256];
    uint8_t client_bound[256];
    uint8_t server_bound[256];
    uint8_t client_remote[256];
    uint8_t server_remote[256];
    size_t unused_server_dial_len = 0U;
    size_t client_bound_len = 0U;
    size_t server_bound_len = 0U;
    size_t client_remote_len = 0U;
    size_t server_remote_len = 0U;
    libp2p_host_dial_t *dial = NULL;

    protocol_loopback_init(
        &pair,
        0U,
        0U,
        1U,
        &client_host_config,
        &server_host_config,
        &client_service_config,
        &server_service_config,
        &unused_server_addr,
        unused_server_dial,
        sizeof(unused_server_dial),
        &unused_server_dial_len);

    quic_accessor_read_listen(
        pair.client,
        client_bound,
        sizeof(client_bound),
        &client_bound_len,
        &client_bound_addr);
    quic_accessor_read_listen(
        pair.server,
        server_bound,
        sizeof(server_bound),
        &server_bound_len,
        &server_bound_addr);
    assert(libp2p_host_start(pair.client) == LIBP2P_HOST_OK);
    assert(libp2p_host_start(pair.server) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_dial(pair.client, server_bound, server_bound_len, NULL, &dial) ==
        LIBP2P_HOST_OK);
    assert(dial != NULL);

    quic_accessor_drive_until_connected(&pair);
    quic_accessor_read_remote(
        pair.client_conn,
        client_remote,
        sizeof(client_remote),
        &client_remote_len,
        &client_remote_addr);
    quic_accessor_read_remote(
        pair.server_conn,
        server_remote,
        sizeof(server_remote),
        &server_remote_len,
        &server_remote_addr);
    assert(client_remote_addr.port == server_bound_addr.port);
    assert(server_remote_addr.port == client_bound_addr.port);
    assert(client_remote_addr.has_peer_id != 0U);
    assert(server_remote_addr.has_peer_id != 0U);

    protocol_loopback_deinit(&pair);
}

int main(void)
{
    quic_accessor_test_port_zero_and_remote_multiaddrs();
    return 0;
}
