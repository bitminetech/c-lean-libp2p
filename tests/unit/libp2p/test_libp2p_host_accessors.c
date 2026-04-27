#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_test_support.h"

static libp2p_host_err_t accessor_test_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    (void)host;
    (void)stream;
    (void)direction;
    (void)protocol_user_data;
    return LIBP2P_HOST_OK;
}

static void accessor_test_protocol(
    libp2p_host_protocol_t *protocol,
    const uint8_t *id,
    size_t id_len)
{
    (void)memset(protocol, 0, sizeof(*protocol));
    protocol->id = id;
    protocol->id_len = id_len;
    protocol->on_open = accessor_test_on_open;
}

static libp2p_host_t *accessor_test_init_host(
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

static libp2p_host_conn_t *accessor_test_establish_conn(
    libp2p_host_t *host,
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn)
{
    libp2p_host_transport_event_t transport_event;
    libp2p_host_event_t event;
    libp2p_host_drive_result_t result;
    libp2p_host_conn_t *host_conn = NULL;

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
    host_conn = event.conn;
    assert(host_conn != NULL);
    return host_conn;
}

static void accessor_test_listen_multiaddr_measure_then_write(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    void *storage = NULL;
    uint8_t out[HOST_TEST_MULTIADDR_CAP];
    size_t written = 0U;

    host = accessor_test_init_host(&config, &transport_config, &fixture, &conn, &storage);
    assert(
        libp2p_host_listen_multiaddr(host, NULL, 0U, &written) ==
        LIBP2P_HOST_ERR_BUF_TOO_SMALL);
    assert(written == config.listen_multiaddr_len);
    assert(
        libp2p_host_listen_multiaddr(host, out, sizeof(out), &written) == LIBP2P_HOST_OK);
    assert(written == config.listen_multiaddr_len);
    assert(memcmp(out, config.listen_multiaddr, written) == 0);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_listen_multiaddr(host, out, sizeof(out), &written) == LIBP2P_HOST_OK);
    assert(written == config.listen_multiaddr_len);
    libp2p_host_deinit(host);
    free(storage);
}

static void accessor_test_registered_protocols_before_and_after_start(void)
{
    static const uint8_t proto_a[] = "/accessor/a/1.0.0";
    static const uint8_t proto_b[] = "/accessor/b/1.0.0";
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_protocol_t protocol_a;
    libp2p_host_protocol_t protocol_b;
    const libp2p_host_protocol_t *protocols = NULL;
    size_t protocol_count = 99U;
    libp2p_host_t *host = NULL;
    void *storage = NULL;

    host = accessor_test_init_host(&config, &transport_config, &fixture, &conn, &storage);
    assert(
        libp2p_host_registered_protocols(host, &protocols, &protocol_count) ==
        LIBP2P_HOST_OK);
    assert(protocols == NULL);
    assert(protocol_count == 0U);
    accessor_test_protocol(&protocol_a, proto_a, sizeof(proto_a) - 1U);
    accessor_test_protocol(&protocol_b, proto_b, sizeof(proto_b) - 1U);
    assert(libp2p_host_handle(host, &protocol_a) == LIBP2P_HOST_OK);
    assert(libp2p_host_handle(host, &protocol_b) == LIBP2P_HOST_OK);
    assert(
        libp2p_host_registered_protocols(host, &protocols, &protocol_count) ==
        LIBP2P_HOST_OK);
    assert(protocol_count == 2U);
    assert(protocols[0].id_len == (sizeof(proto_a) - 1U));
    assert(memcmp(protocols[0].id, proto_a, protocols[0].id_len) == 0);
    assert(protocols[1].id_len == (sizeof(proto_b) - 1U));
    assert(memcmp(protocols[1].id, proto_b, protocols[1].id_len) == 0);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    protocols = NULL;
    protocol_count = 0U;
    assert(
        libp2p_host_registered_protocols(host, &protocols, &protocol_count) ==
        LIBP2P_HOST_OK);
    assert(protocol_count == 2U);
    assert(protocols[0].id == proto_a);
    assert(protocols[1].id == proto_b);
    libp2p_host_deinit(host);
    free(storage);
}

static void accessor_test_conn_remote_multiaddr_measure_then_write(void)
{
    libp2p_host_config_t config;
    host_test_transport_config_t transport_config;
    host_test_transport_fixture_t fixture;
    host_test_conn_t conn;
    libp2p_host_t *host = NULL;
    libp2p_host_conn_t *host_conn = NULL;
    void *storage = NULL;
    uint8_t out[HOST_TEST_MULTIADDR_CAP];
    size_t written = 0U;

    host = accessor_test_init_host(&config, &transport_config, &fixture, &conn, &storage);
    assert(libp2p_host_start(host) == LIBP2P_HOST_OK);
    host_conn = accessor_test_establish_conn(host, &fixture, &conn);
    assert(
        libp2p_host_conn_remote_multiaddr(host_conn, NULL, 0U, &written) ==
        LIBP2P_HOST_ERR_BUF_TOO_SMALL);
    assert(written == conn.remote_multiaddr_len);
    assert(
        libp2p_host_conn_remote_multiaddr(host_conn, out, sizeof(out), &written) ==
        LIBP2P_HOST_OK);
    assert(written == conn.remote_multiaddr_len);
    assert(memcmp(out, conn.remote_multiaddr, written) == 0);
    libp2p_host_deinit(host);
    free(storage);
}

int main(void)
{
    accessor_test_listen_multiaddr_measure_then_write();
    accessor_test_registered_protocols_before_and_after_start();
    accessor_test_conn_remote_multiaddr_measure_then_write();
    return 0;
}
