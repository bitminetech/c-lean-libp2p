/**
 * @file quic_backend.h
 * @brief Internal backend contract for the mandatory QUIC implementation.
 *
 * This header is for c-lean-libp2p backend implementations and tests. Public
 * callers should include transport/quic/quic.h instead. The default production
 * backend is ngtcp2 plus AWS-LC, but backend details must not leak into the
 * main transport API.
 */

#ifndef LIBP2P_QUIC_BACKEND_H
#define LIBP2P_QUIC_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic.h"

/** Backend ABI version for vtable compatibility checks. */
#define LIBP2P_QUIC_BACKEND_ABI_VERSION 1U

/** Backend implementation vtable. */
typedef struct
{
    uint32_t abi_version;
    const char *name;

    libp2p_quic_err_t (
        *endpoint_storage_size)(const libp2p_quic_endpoint_config_t *config, size_t *out_len);

    libp2p_quic_err_t (*endpoint_storage_align)(size_t *out_align);

    libp2p_quic_err_t (*endpoint_init)(
        void *storage,
        size_t storage_len,
        const libp2p_quic_endpoint_config_t *config,
        libp2p_quic_endpoint_t **out_endpoint);

    void (*endpoint_deinit)(libp2p_quic_endpoint_t *endpoint);

    libp2p_quic_err_t (
        *endpoint_bind)(libp2p_quic_endpoint_t *endpoint, const libp2p_quic_addr_t *local_addr);

    libp2p_quic_err_t (*endpoint_dial)(
        libp2p_quic_endpoint_t *endpoint,
        const libp2p_quic_dial_config_t *config,
        libp2p_quic_conn_t **out_conn);

    libp2p_quic_err_t (*endpoint_recv_datagram)(
        libp2p_quic_endpoint_t *endpoint,
        const libp2p_quic_rx_datagram_t *datagram,
        libp2p_quic_time_us_t now_us);

    libp2p_quic_err_t (*endpoint_next_datagram)(
        libp2p_quic_endpoint_t *endpoint,
        libp2p_quic_tx_datagram_t *datagram,
        libp2p_quic_time_us_t now_us);

    libp2p_quic_err_t (
        *endpoint_poll)(libp2p_quic_endpoint_t *endpoint, libp2p_quic_time_us_t now_us);

    libp2p_quic_err_t (*endpoint_next_deadline)(
        const libp2p_quic_endpoint_t *endpoint,
        libp2p_quic_time_us_t *out_deadline_us);

    libp2p_quic_err_t (
        *endpoint_next_event)(libp2p_quic_endpoint_t *endpoint, libp2p_quic_event_t *out_event);

    libp2p_quic_err_t (*endpoint_close)(libp2p_quic_endpoint_t *endpoint, uint64_t app_error_code);

    libp2p_quic_err_t (
        *conn_state)(const libp2p_quic_conn_t *conn, libp2p_quic_conn_state_t *out_state);

    libp2p_quic_err_t (*conn_peer_id)(
        const libp2p_quic_conn_t *conn,
        uint8_t *out,
        size_t out_len,
        size_t *written);

    libp2p_quic_err_t (
        *conn_peer_identity)(const libp2p_quic_conn_t *conn, libp2p_quic_peer_identity_t *out);

    libp2p_quic_err_t (*conn_local_addr)(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out);

    libp2p_quic_err_t (*conn_remote_addr)(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out);

    libp2p_quic_err_t (*conn_close)(libp2p_quic_conn_t *conn, uint64_t app_error_code);

    libp2p_quic_err_t (
        *conn_open_bidi_stream)(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream);

    libp2p_quic_err_t (
        *conn_accept_stream)(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream);

    libp2p_quic_err_t (
        *stream_id)(const libp2p_quic_stream_t *stream, libp2p_quic_stream_id_t *out_id);

    libp2p_quic_err_t (
        *stream_state)(const libp2p_quic_stream_t *stream, libp2p_quic_stream_state_t *out_state);

    libp2p_quic_err_t (*stream_read)(
        libp2p_quic_stream_t *stream,
        uint8_t *out,
        size_t out_len,
        size_t *read_len,
        int *fin);

    libp2p_quic_err_t (*stream_write)(
        libp2p_quic_stream_t *stream,
        const uint8_t *data,
        size_t data_len,
        int fin,
        size_t *accepted);

    libp2p_quic_err_t (*stream_finish)(libp2p_quic_stream_t *stream);

    libp2p_quic_err_t (*stream_reset)(libp2p_quic_stream_t *stream, uint64_t app_error_code);

    libp2p_quic_err_t (*stream_stop_sending)(libp2p_quic_stream_t *stream, uint64_t app_error_code);

    libp2p_quic_err_t (*stream_conn)(libp2p_quic_stream_t *stream, libp2p_quic_conn_t **out_conn);
} libp2p_quic_backend_vtable_t;

/**
 * Return the production backend: ngtcp2 transport with AWS-LC TLS/crypto.
 */
const libp2p_quic_backend_vtable_t *libp2p_quic_backend_ngtcp2_awslc(void);

#endif /* LIBP2P_QUIC_BACKEND_H */
