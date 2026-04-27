/**
 * @file quic.c
 * @brief Public QUIC endpoint and connection dispatch.
 */

#include "transport/quic/quic.h"

#include <stdalign.h>
#include <string.h>

#include "transport/quic/quic_backend.h"

static const libp2p_quic_backend_vtable_t *quic_backend(void)
{
    return libp2p_quic_backend_ngtcp2_awslc();
}

static libp2p_quic_err_t quic_backend_validate(const libp2p_quic_backend_vtable_t *backend)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((backend == NULL) || (backend->abi_version != LIBP2P_QUIC_BACKEND_ABI_VERSION))
    {
        result = LIBP2P_QUIC_ERR_BACKEND;
    }
    else if ((backend->endpoint_storage_size == NULL) || (backend->endpoint_storage_align == NULL) ||
             (backend->endpoint_init == NULL) || (backend->endpoint_deinit == NULL) ||
             (backend->endpoint_bind == NULL) || (backend->endpoint_dial == NULL) ||
             (backend->endpoint_recv_datagram == NULL) || (backend->endpoint_next_datagram == NULL) ||
             (backend->endpoint_poll == NULL) || (backend->endpoint_next_deadline == NULL) ||
             (backend->endpoint_next_event == NULL) || (backend->endpoint_close == NULL) ||
             (backend->conn_state == NULL) || (backend->conn_peer_id == NULL) ||
             (backend->conn_peer_identity == NULL) || (backend->conn_local_addr == NULL) ||
             (backend->conn_remote_addr == NULL) || (backend->conn_close == NULL))
    {
        result = LIBP2P_QUIC_ERR_BACKEND;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_config_default(libp2p_quic_endpoint_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (config == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
        config->role = LIBP2P_QUIC_ROLE_CLIENT_SERVER;
        config->max_connections = LIBP2P_QUIC_DEFAULT_MAX_CONNECTIONS;
        config->max_incoming_connections = LIBP2P_QUIC_DEFAULT_MAX_CONNECTIONS;
        config->max_outgoing_connections = LIBP2P_QUIC_DEFAULT_MAX_CONNECTIONS;
        config->max_bidi_streams = LIBP2P_QUIC_DEFAULT_MAX_BIDI_STREAMS;
        config->max_uni_streams = LIBP2P_QUIC_DEFAULT_MAX_UNI_STREAMS;
        config->max_datagram_payload_bytes = LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES;
        config->initial_conn_window_bytes = LIBP2P_QUIC_DEFAULT_CONN_WINDOW_BYTES;
        config->initial_stream_window_bytes = LIBP2P_QUIC_DEFAULT_STREAM_WINDOW_BYTES;
        config->idle_timeout_us = LIBP2P_QUIC_DEFAULT_IDLE_TIMEOUT_US;
        config->handshake_timeout_us = LIBP2P_QUIC_DEFAULT_HANDSHAKE_TIMEOUT_US;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_storage_size(
    const libp2p_quic_endpoint_config_t *config,
    size_t *out_len)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_storage_size(config, out_len);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_storage_align(size_t *out_align)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_storage_align(out_align);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_endpoint_config_t *config,
    libp2p_quic_endpoint_t **out_endpoint)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_init(storage, storage_len, config, out_endpoint);
    }

    return result;
}

void libp2p_quic_endpoint_deinit(libp2p_quic_endpoint_t *endpoint)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();

    if ((quic_backend_validate(backend) == LIBP2P_QUIC_OK) && (endpoint != NULL))
    {
        backend->endpoint_deinit(endpoint);
    }
}

libp2p_quic_err_t libp2p_quic_endpoint_bind(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_addr_t *local_addr)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_bind(endpoint, local_addr);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_dial(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *config,
    libp2p_quic_conn_t **out_conn)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_dial(endpoint, config, out_conn);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_recv_datagram(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_recv_datagram(endpoint, datagram, now_us);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_next_datagram(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_next_datagram(endpoint, datagram, now_us);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_poll(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t now_us)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_poll(endpoint, now_us);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_next_deadline(
    const libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t *out_deadline_us)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_next_deadline(endpoint, out_deadline_us);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_next_event(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_t *out_event)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_next_event(endpoint, out_event);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_endpoint_close(
    libp2p_quic_endpoint_t *endpoint,
    uint64_t app_error_code)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->endpoint_close(endpoint, app_error_code);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_state(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_conn_state_t *out_state)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_state(conn, out_state);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_peer_id(conn, out, out_len, written);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_peer_identity(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_peer_identity_t *out)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_peer_identity(conn, out);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_local_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_local_addr(conn, out);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_remote_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_remote_addr(conn, out);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_close(libp2p_quic_conn_t *conn, uint64_t app_error_code)
{
    const libp2p_quic_backend_vtable_t *backend = quic_backend();
    libp2p_quic_err_t result = quic_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_close(conn, app_error_code);
    }

    return result;
}
