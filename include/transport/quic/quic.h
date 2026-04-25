/**
 * @file quic.h
 * @brief Mandatory libp2p QUIC v1 transport API.
 *
 * c-lean-libp2p uses RFC 9000 QUIC v1 over UDP with ALPN "libp2p". The
 * transport is packet-driven: callers own UDP sockets and feed received UDP
 * datagrams into an endpoint, then drain outgoing UDP datagrams from it. This
 * keeps the API deterministic, testable, and independent of platform event
 * loops.
 *
 * The public API does not expose ngtcp2 or AWS-LC types. Those libraries are
 * trusted backend components behind this boundary.
 */

#ifndef LIBP2P_QUIC_H
#define LIBP2P_QUIC_H

#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic_addr.h"
#include "transport/quic/quic_identity.h"
#include "transport/quic/quic_stream.h"
#include "transport/quic/quic_types.h"

/**
 * Endpoint configuration.
 *
 * QUIC is mandatory. TLS 1.3 mutual authentication is mandatory: servers always
 * require client certificates, and all endpoints verify the libp2p public-key
 * extension before treating a connection as established.
 */
typedef struct
{
    libp2p_quic_role_t role;
    libp2p_quic_local_identity_t identity;
    libp2p_quic_allocator_t allocator;
    libp2p_quic_random_fn_t random_fn;
    void *random_user_data;
    libp2p_quic_unix_time_fn_t unix_time_fn;
    void *unix_time_user_data;
    size_t max_connections;
    size_t max_incoming_connections;
    size_t max_outgoing_connections;
    size_t max_bidi_streams;
    size_t max_uni_streams;
    size_t max_datagram_payload_bytes;
    size_t initial_conn_window_bytes;
    size_t initial_stream_window_bytes;
    libp2p_quic_time_us_t idle_timeout_us;
    libp2p_quic_time_us_t handshake_timeout_us;
    void *user_data;
} libp2p_quic_endpoint_config_t;

/** Dial parameters for an outbound QUIC connection. */
typedef struct
{
    libp2p_quic_addr_t remote_addr;
    void *user_data;
} libp2p_quic_dial_config_t;

/** UDP datagram received by the application and handed to QUIC. */
typedef struct
{
    libp2p_quic_addr_t local_addr;
    libp2p_quic_addr_t remote_addr;
    const uint8_t *data;
    size_t data_len;
    libp2p_quic_ecn_t ecn;
} libp2p_quic_rx_datagram_t;

/** UDP datagram emitted by QUIC and sent by the application. */
typedef struct
{
    libp2p_quic_addr_t local_addr;
    libp2p_quic_addr_t remote_addr;
    uint8_t *data;
    size_t data_cap;
    size_t data_len;
    libp2p_quic_ecn_t ecn;
} libp2p_quic_tx_datagram_t;

/** Events queued by an endpoint as it processes packets and timers. */
typedef enum
{
    LIBP2P_QUIC_EVENT_NONE,
    LIBP2P_QUIC_EVENT_CONN_INCOMING,
    LIBP2P_QUIC_EVENT_CONN_ESTABLISHED,
    LIBP2P_QUIC_EVENT_CONN_CLOSED,
    LIBP2P_QUIC_EVENT_STREAM_INCOMING,
    LIBP2P_QUIC_EVENT_STREAM_READABLE,
    LIBP2P_QUIC_EVENT_STREAM_WRITABLE,
    LIBP2P_QUIC_EVENT_STREAM_CLOSED,
    LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY
} libp2p_quic_event_type_t;

/** One endpoint event. Pointers are owned by the endpoint. */
typedef struct
{
    libp2p_quic_event_type_t type;
    libp2p_quic_conn_t *conn;
    libp2p_quic_stream_t *stream;
    uint64_t app_error_code;
    uint64_t transport_error_code;
} libp2p_quic_event_t;

/**
 * Fill config with production defaults.
 *
 * The caller must set identity certificate material, random_fn, and
 * unix_time_fn before initialization.
 */
libp2p_quic_err_t libp2p_quic_endpoint_config_default(libp2p_quic_endpoint_config_t *config);

/**
 * Return the caller-managed storage size required for an endpoint.
 *
 * The returned size covers c-lean-libp2p endpoint state. The backend allocator
 * in config may still be used by ngtcp2/AWS-LC for their internal state.
 */
libp2p_quic_err_t libp2p_quic_endpoint_storage_size(
    const libp2p_quic_endpoint_config_t *config,
    size_t *out_len);

/**
 * Return the alignment required for endpoint storage.
 */
libp2p_quic_err_t libp2p_quic_endpoint_storage_align(size_t *out_align);

/**
 * Initialize an endpoint in caller-provided storage.
 */
libp2p_quic_err_t libp2p_quic_endpoint_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_endpoint_config_t *config,
    libp2p_quic_endpoint_t **out_endpoint);

/**
 * Deinitialize an endpoint and release backend-owned resources.
 */
void libp2p_quic_endpoint_deinit(libp2p_quic_endpoint_t *endpoint);

/**
 * Bind an endpoint to a local QUIC UDP address.
 *
 * This does not open a socket. It records the local address used for generated
 * outgoing datagrams, client dials, and server-side connection matching.
 */
libp2p_quic_err_t libp2p_quic_endpoint_bind(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_addr_t *local_addr);

/**
 * Start an outbound QUIC connection.
 *
 * config->remote_addr must contain a /p2p peer ID. The TLS certificate's
 * authenticated peer ID must match that value or the connection is aborted.
 */
libp2p_quic_err_t libp2p_quic_endpoint_dial(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *config,
    libp2p_quic_conn_t **out_conn);

/**
 * Hand one received UDP datagram to the QUIC endpoint.
 */
libp2p_quic_err_t libp2p_quic_endpoint_recv_datagram(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us);

/**
 * Drain the next UDP datagram that should be sent by the application.
 *
 * datagram->data_cap is the caller-provided output capacity. On success,
 * datagram->data_len contains the bytes to send. Returns
 * LIBP2P_QUIC_ERR_WOULD_BLOCK if no datagram is pending. On
 * LIBP2P_QUIC_ERR_BUF_TOO_SMALL, datagram->data_len contains the required size.
 */
libp2p_quic_err_t libp2p_quic_endpoint_next_datagram(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us);

/**
 * Advance timers, retransmissions, and connection state.
 */
libp2p_quic_err_t libp2p_quic_endpoint_poll(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t now_us);

/**
 * Return the next absolute monotonic deadline for this endpoint.
 *
 * Returns LIBP2P_QUIC_ERR_WOULD_BLOCK when no timer is currently armed.
 */
libp2p_quic_err_t libp2p_quic_endpoint_next_deadline(
    const libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t *out_deadline_us);

/**
 * Pop the next queued endpoint event.
 *
 * Returns LIBP2P_QUIC_ERR_WOULD_BLOCK when no event is pending.
 */
libp2p_quic_err_t libp2p_quic_endpoint_next_event(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_t *out_event);

/**
 * Close all endpoint connections and stop accepting new work.
 */
libp2p_quic_err_t libp2p_quic_endpoint_close(
    libp2p_quic_endpoint_t *endpoint,
    uint64_t app_error_code);

/**
 * Return a connection's current high-level state.
 */
libp2p_quic_err_t libp2p_quic_conn_state(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_conn_state_t *out_state);

/**
 * Return the authenticated remote peer ID for an established connection.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Return the authenticated remote peer identity for an established connection.
 *
 * This includes the peer ID and libp2p PublicKey protobuf message extracted
 * from the peer's TLS certificate extension.
 */
libp2p_quic_err_t libp2p_quic_conn_peer_identity(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_peer_identity_t *out);

/**
 * Return the local UDP address associated with a connection.
 */
libp2p_quic_err_t libp2p_quic_conn_local_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out);

/**
 * Return the remote UDP address associated with a connection.
 */
libp2p_quic_err_t libp2p_quic_conn_remote_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out);

/**
 * Close a single connection with an application error code.
 */
libp2p_quic_err_t libp2p_quic_conn_close(libp2p_quic_conn_t *conn, uint64_t app_error_code);

#endif /* LIBP2P_QUIC_H */
