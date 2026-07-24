/**
 * @file libp2p_host.h
 * @brief Top-level pollable libp2p host API.
 *
 * A host is the only top-level object applications instantiate. It owns the
 * transport service, authenticated connections, multistream-select negotiation,
 * the bounded protocol registry, and negotiated stream dispatch. Protocols
 * such as identify, ping, gossipsub, and future modules register with the host
 * before start and are then driven synchronously by libp2p_host_drive().
 *
 * This API is deliberately data-oriented:
 *   - all storage is caller-provided
 *   - every capacity is fixed at initialization
 *   - protocol registration is frozen after libp2p_host_start()
 *   - dial and stream-open operations are pollable host-owned attempts
 *   - callbacks are synchronous protocol step functions, never thread entry
 *     points or signal handlers
 */

#ifndef LIBP2P_HOST_H
#define LIBP2P_HOST_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"

/** Default protocol registry capacity. */
#define LIBP2P_HOST_DEFAULT_MAX_PROTOCOLS 8U

/** Default authenticated connection capacity. */
#define LIBP2P_HOST_DEFAULT_MAX_CONNECTIONS 64U

/** Default negotiated stream capacity per connection. */
#define LIBP2P_HOST_DEFAULT_MAX_STREAMS_PER_CONN 128U

/** Default number of in-progress outbound dials. */
#define LIBP2P_HOST_DEFAULT_MAX_PENDING_DIALS 16U

/** Default number of in-progress outbound stream opens. */
#define LIBP2P_HOST_DEFAULT_MAX_PENDING_STREAM_OPENS 64U

/** Default host event queue capacity. */
#define LIBP2P_HOST_DEFAULT_EVENT_CAPACITY 128U

/**
 * Default maximum negotiation steps taken by one drive call.
 *
 * Lower values reduce one host's event-loop latency impact. Higher values
 * drain bursts faster when many streams are negotiating at once.
 */
#define LIBP2P_HOST_DEFAULT_MAX_NEGOTIATION_STEPS 32U

/** Opaque host object stored in caller-provided memory. */
typedef struct libp2p_host libp2p_host_t;

/** Borrowed authenticated connection handle owned by a host. */
typedef struct libp2p_host_conn libp2p_host_conn_t;

/** Borrowed negotiated stream handle owned by a host. */
typedef struct libp2p_host_stream libp2p_host_stream_t;

/** Host-owned outbound dial attempt. */
typedef struct libp2p_host_dial libp2p_host_dial_t;

/** Host-owned outbound stream-open attempt. */
typedef struct libp2p_host_stream_open libp2p_host_stream_open_t;

/** Monotonic host time in microseconds. */
typedef uint64_t libp2p_host_time_us_t;

/** Event-loop file descriptor exposed by the active transport service. */
typedef uintptr_t libp2p_host_fd_t;

/** Error codes returned by host operations. */
typedef enum
{
    LIBP2P_HOST_OK = 0,
    LIBP2P_HOST_ERR_INVALID_ARG,
    LIBP2P_HOST_ERR_BUF_TOO_SMALL,
    LIBP2P_HOST_ERR_UNSUPPORTED,
    LIBP2P_HOST_ERR_STATE,
    LIBP2P_HOST_ERR_WOULD_BLOCK,
    LIBP2P_HOST_ERR_LIMIT,
    LIBP2P_HOST_ERR_NOT_FOUND,
    LIBP2P_HOST_ERR_CLOSED,
    LIBP2P_HOST_ERR_ADDR,
    LIBP2P_HOST_ERR_IDENTITY,
    LIBP2P_HOST_ERR_TRANSPORT,
    LIBP2P_HOST_ERR_NEGOTIATION,
    LIBP2P_HOST_ERR_PROTOCOL,
    LIBP2P_HOST_ERR_INTERNAL
} libp2p_host_err_t;

/** Event-loop readiness bits passed to libp2p_host_drive(). */
typedef uint32_t libp2p_host_ready_t;
#define LIBP2P_HOST_READY_READ  (1U << 0U)
#define LIBP2P_HOST_READY_WRITE (1U << 1U)
#define LIBP2P_HOST_READY_TIMER (1U << 2U)
#define LIBP2P_HOST_READY_APP   (1U << 3U)
#define LIBP2P_HOST_READY_ALL                                                     \
    (LIBP2P_HOST_READY_READ | LIBP2P_HOST_READY_WRITE | LIBP2P_HOST_READY_TIMER | \
     LIBP2P_HOST_READY_APP)

/** File-descriptor interests requested by the host. */
typedef uint32_t libp2p_host_interest_t;
#define LIBP2P_HOST_INTEREST_NONE  0U
#define LIBP2P_HOST_INTEREST_READ  (1U << 0U)
#define LIBP2P_HOST_INTEREST_WRITE (1U << 1U)

/** Direction of a negotiated stream relative to the local host. */
typedef enum
{
    LIBP2P_HOST_STREAM_INBOUND,
    LIBP2P_HOST_STREAM_OUTBOUND
} libp2p_host_stream_direction_t;

/** Protocol stream events delivered synchronously from libp2p_host_drive(). */
typedef enum
{
    LIBP2P_HOST_PROTOCOL_EVENT_READABLE,
    LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE,
    LIBP2P_HOST_PROTOCOL_EVENT_RESET,
    LIBP2P_HOST_PROTOCOL_EVENT_CLOSED
} libp2p_host_protocol_event_kind_t;

/** Public host events drained after libp2p_host_drive(). */
typedef enum
{
    LIBP2P_HOST_EVENT_NONE,
    LIBP2P_HOST_EVENT_CONN_ESTABLISHED,
    LIBP2P_HOST_EVENT_CONN_CLOSED,
    LIBP2P_HOST_EVENT_DIAL_FAILED,
    LIBP2P_HOST_EVENT_STREAM_OPENED,
    LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED,
    LIBP2P_HOST_EVENT_HOST_CLOSED
} libp2p_host_event_type_t;

/** Supported libp2p host-key subset for c-lean-libp2p. */
typedef enum
{
    LIBP2P_HOST_KEY_SECP256K1
} libp2p_host_key_type_t;

/** Authenticated peer identity exposed by the host. */
typedef struct
{
    libp2p_host_key_type_t key_type;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
    uint8_t public_key_message[LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES];
    size_t public_key_message_len;
} libp2p_host_peer_identity_t;

/**
 * Signing callback for the local libp2p identity.
 *
 * The callback signs message bytes according to the host identity's key type
 * and writes a protocol-appropriate signature. The default secp256k1 adapter
 * uses the peer_id.h message-signing contract.
 */
typedef libp2p_host_err_t (*libp2p_host_identity_sign_fn_t)(
    void *user_data,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out_sig,
    size_t out_sig_len,
    size_t *written);

/**
 * Local libp2p identity exposed to host protocols.
 *
 * The host never needs raw private-key bytes. Protocols that require signatures
 * use sign_fn through host helper functions. peer_id and public_key_message
 * storage remains caller-owned and must outlive the host.
 */
typedef struct
{
    const uint8_t *peer_id;
    size_t peer_id_len;
    const uint8_t *public_key_message;
    size_t public_key_message_len;
    libp2p_host_identity_sign_fn_t sign_fn;
    void *user_data;
} libp2p_host_identity_t;

/**
 * Called once after an inbound or outbound stream has negotiated this protocol.
 *
 * The callback may initialize protocol-owned stream state with
 * libp2p_host_stream_set_user_data(). Returning an error resets the stream and
 * prevents future protocol events for it.
 */
typedef libp2p_host_err_t (*libp2p_host_protocol_open_fn_t)(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data);

/**
 * Called from libp2p_host_drive() for protocol-owned stream readiness.
 *
 * READABLE means bytes or a remote FIN may be available; the protocol observes
 * FIN by calling libp2p_host_stream_read(). Callbacks must finish in bounded
 * time and return control to the host.
 */
typedef libp2p_host_err_t (*libp2p_host_protocol_event_fn_t)(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data);

/** Frozen protocol registry entry. */
typedef struct
{
    const uint8_t *id;
    size_t id_len;
    libp2p_host_protocol_open_fn_t on_open;
    libp2p_host_protocol_event_fn_t on_event;
    void *user_data;
} libp2p_host_protocol_t;

/*
 * Transport adapter authors only.
 *
 * Applications should use libp2p_host_t and the host functions below. The
 * transport event and vtable types are public so additional bounded transports
 * can plug into the host without changing this header.
 */

/** Transport event type consumed internally by the host. */
typedef enum
{
    LIBP2P_HOST_TRANSPORT_EVENT_NONE,
    LIBP2P_HOST_TRANSPORT_EVENT_CONN_ESTABLISHED,
    LIBP2P_HOST_TRANSPORT_EVENT_CONN_CLOSED,
    LIBP2P_HOST_TRANSPORT_EVENT_DIAL_FAILED,
    LIBP2P_HOST_TRANSPORT_EVENT_STREAM_INCOMING,
    LIBP2P_HOST_TRANSPORT_EVENT_STREAM_READABLE,
    LIBP2P_HOST_TRANSPORT_EVENT_STREAM_WRITABLE,
    LIBP2P_HOST_TRANSPORT_EVENT_STREAM_RESET,
    LIBP2P_HOST_TRANSPORT_EVENT_STREAM_CLOSED
} libp2p_host_transport_event_type_t;

/** One service-level transport event delivered to the host core. */
typedef struct
{
    libp2p_host_transport_event_type_t type;
    void *conn;
    void *stream;
    void *attempt;
    void *user_data;
    libp2p_host_err_t reason;
    uint64_t app_error_code;
    uint64_t transport_error_code;
} libp2p_host_transport_event_t;

/** Service-level transport adapter vtable. */
typedef struct
{
    uint32_t abi_version;
    const char *name;

    libp2p_host_err_t (*storage_size)(const void *config, size_t *out_len);
    libp2p_host_err_t (*storage_align)(size_t *out_align);

    libp2p_host_err_t (*init)(
        void *storage,
        size_t storage_len,
        const void *config,
        const uint8_t *listen_multiaddr,
        size_t listen_multiaddr_len,
        void **out_transport);

    void (*deinit)(void *transport);

    libp2p_host_err_t (*fd)(const void *transport, libp2p_host_fd_t *out_fd);
    libp2p_host_err_t (*io_interest)(const void *transport, libp2p_host_interest_t *out_interest);
    libp2p_host_err_t (
        *next_deadline)(const void *transport, libp2p_host_time_us_t *out_deadline_us);

    libp2p_host_err_t (
        *drive)(void *transport, libp2p_host_time_us_t now_us, libp2p_host_ready_t ready);

    libp2p_host_err_t (*next_event)(void *transport, libp2p_host_transport_event_t *out_event);

    libp2p_host_err_t (*listen_multiaddr)(
        const void *transport,
        uint8_t *out,
        size_t out_len,
        size_t *written);

    libp2p_host_err_t (*dial)(
        void *transport,
        const uint8_t *multiaddr,
        size_t multiaddr_len,
        void *user_data,
        void **out_attempt);

    libp2p_host_err_t (*open_stream)(void *transport, void *conn, void **out_stream);

    libp2p_host_err_t (
        *conn_peer_id)(const void *conn, uint8_t *out, size_t out_len, size_t *written);

    libp2p_host_err_t (
        *conn_remote_multiaddr)(const void *conn, uint8_t *out, size_t out_len, size_t *written);

    libp2p_host_err_t (*conn_peer_identity)(const void *conn, libp2p_host_peer_identity_t *out);
    libp2p_host_err_t (*conn_close)(void *transport, void *conn, uint64_t app_error_code);
    libp2p_host_err_t (*conn_release)(void *transport, void *conn);

    libp2p_host_err_t (*stream_read)(
        void *transport,
        void *stream,
        uint8_t *out,
        size_t out_len,
        size_t *read_len,
        int *fin);

    libp2p_host_err_t (*stream_write)(
        void *transport,
        void *stream,
        const uint8_t *data,
        size_t data_len,
        int fin,
        size_t *accepted);

    libp2p_host_err_t (*stream_finish)(void *transport, void *stream);
    libp2p_host_err_t (*stream_reset)(void *transport, void *stream, uint64_t app_error_code);
    libp2p_host_err_t (
        *stream_stop_sending)(void *transport, void *stream, uint64_t app_error_code);
} libp2p_host_transport_vtable_t;

/** Host configuration. All pointed-to storage remains caller-owned. */
typedef struct
{
    libp2p_host_identity_t identity;
    const uint8_t *listen_multiaddr;
    size_t listen_multiaddr_len;
    const libp2p_host_transport_vtable_t *transport;
    const void *transport_config;
    size_t max_protocols;
    size_t max_connections;
    size_t max_streams_per_conn;
    size_t max_pending_dials;
    size_t max_pending_stream_opens;
    size_t event_capacity;
    size_t max_negotiation_steps;
} libp2p_host_config_t;

/** Drive result counters for observability, fairness, and deterministic tests. */
typedef struct
{
    size_t transport_events;
    size_t negotiation_steps;
    size_t protocol_events;
    size_t host_events;
    uint8_t made_progress;
} libp2p_host_drive_result_t;

/**
 * One public host event. Handles are borrowed from the host.
 *
 * Field validity by event type:
 *
 *   LIBP2P_HOST_EVENT_CONN_ESTABLISHED:
 *     conn and user_data are valid. dial is valid for outbound connections and
 *     NULL for inbound connections.
 *
 *   LIBP2P_HOST_EVENT_CONN_CLOSED:
 *     conn identifies the closed connection. reason, locally_initiated,
 *     app_error_code, and transport_error_code describe the closure.
 *     locally_initiated is nonzero when libp2p_host_conn_close() or
 *     libp2p_host_close() requested it. The pointer is invalid after this event
 *     is consumed; callers must drop any retained copy before draining the next
 *     host event or initiating more host work.
 *
 *   LIBP2P_HOST_EVENT_DIAL_FAILED:
 *     dial, user_data, reason, app_error_code, and transport_error_code are
 *     valid.
 *
 *   LIBP2P_HOST_EVENT_STREAM_OPENED:
 *     conn, stream, stream_open, and user_data are valid. The stream is owned
 *     by the registered protocol callbacks; the event lets application code
 *     correlate the completed open attempt.
 *
 *   LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED:
 *     conn, stream_open, user_data, reason, app_error_code, and
 *     transport_error_code are valid.
 *
 *   LIBP2P_HOST_EVENT_HOST_CLOSED:
 *     reason is valid. Other handle fields are NULL.
 */
typedef struct
{
    libp2p_host_event_type_t type;
    libp2p_host_conn_t *conn;
    libp2p_host_stream_t *stream;
    libp2p_host_dial_t *dial;
    libp2p_host_stream_open_t *stream_open;
    void *user_data;
    libp2p_host_err_t reason;
    uint8_t locally_initiated;
    uint64_t app_error_code;
    uint64_t transport_error_code;
} libp2p_host_event_t;

/**
 * Fill host config with production defaults.
 *
 * The caller must set identity, listen_multiaddr, transport, and
 * transport_config before initialization. Default capacity fields may be
 * overridden after this function returns.
 */
libp2p_host_err_t libp2p_host_config_default(libp2p_host_config_t *config);

/**
 * Return caller-managed storage required for a host.
 *
 * The returned size covers the host object, protocol registry, host event
 * queue, connection and stream bookkeeping, negotiation state, attempt tables,
 * and active transport service storage.
 */
libp2p_host_err_t libp2p_host_storage_size(const libp2p_host_config_t *config, size_t *out_len);

/**
 * Return the alignment required for host storage.
 */
libp2p_host_err_t libp2p_host_storage_align(size_t *out_align);

/**
 * Initialize a host in caller-provided storage.
 *
 * The protocol registry is empty after initialization. Call
 * libp2p_host_handle() zero or more times before libp2p_host_start().
 */
libp2p_host_err_t libp2p_host_init(
    void *storage,
    size_t storage_len,
    const libp2p_host_config_t *config,
    libp2p_host_t **out_host);

/**
 * Deinitialize a host and release backend-owned transport state.
 *
 * Deinitialization is abrupt. Call libp2p_host_close() first when protocols
 * should observe shutdown and connections should drain.
 */
void libp2p_host_deinit(libp2p_host_t *host);

/**
 * Register a protocol handler.
 *
 * Registration is allowed only after init and before start. Protocol IDs are
 * matched by exact byte equality during multistream-select negotiation.
 */
libp2p_host_err_t libp2p_host_handle(libp2p_host_t *host, const libp2p_host_protocol_t *protocol);

/**
 * Freeze the protocol registry and begin accepting transport work.
 */
libp2p_host_err_t libp2p_host_start(libp2p_host_t *host);

/**
 * Begin graceful host shutdown.
 *
 * Shutdown closes protocol streams and transport connections, then
 * libp2p_host_drive() advances the drain. A LIBP2P_HOST_EVENT_HOST_CLOSED event
 * is queued once all host-owned work is closed.
 */
libp2p_host_err_t libp2p_host_close(libp2p_host_t *host, uint64_t app_error_code);

/**
 * Return the transport file descriptor owned by the host.
 */
libp2p_host_err_t libp2p_host_fd(const libp2p_host_t *host, libp2p_host_fd_t *out_fd);

/**
 * Return file-descriptor interests for the next external event-loop wait.
 */
libp2p_host_err_t libp2p_host_io_interest(
    const libp2p_host_t *host,
    libp2p_host_interest_t *out_interest);

/**
 * Return the next absolute monotonic host deadline.
 */
libp2p_host_err_t libp2p_host_next_deadline(
    const libp2p_host_t *host,
    libp2p_host_time_us_t *out_deadline_us);

/**
 * Drive transport I/O, timers, multistream-select negotiation steps, protocol
 * step functions, and graceful shutdown.
 *
 * READY_APP should be used after local operations such as dial, open_stream,
 * write, reset, finish, close, or protocol registration before start.
 */
libp2p_host_err_t libp2p_host_drive(
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us,
    libp2p_host_ready_t ready,
    libp2p_host_drive_result_t *out_result);

/**
 * Pop the next public host event.
 *
 * Returns LIBP2P_HOST_ERR_WOULD_BLOCK when no event is pending.
 */
libp2p_host_err_t libp2p_host_next_event(libp2p_host_t *host, libp2p_host_event_t *out_event);

/**
 * Return the host's resolved dialable listen multiaddr.
 *
 * The returned address is read from the bound transport service and includes
 * the local /p2p/<peer-id> suffix when the transport can encode one. It is
 * available after libp2p_host_init(), before or after libp2p_host_start().
 * For listen configs that use UDP port 0, the returned multiaddr contains the
 * kernel-assigned port. The IP component is reported as-bound: if the caller
 * configured a wildcard IP (0.0.0.0 or ::), the returned multiaddr has the
 * same wildcard IP. Resolving a wildcard to a concrete advertise IP is an
 * application-level concern; the host does not guess.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_HOST_ERR_BUF_TOO_SMALL.
 */
libp2p_host_err_t libp2p_host_listen_multiaddr(
    const libp2p_host_t *host,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Return the host's registered protocol entries as a borrowed read-only array.
 *
 * This intentionally returns a borrowed view rather than copying protocol IDs:
 * the host registry is already bounded, caller-visible, and owned by the host
 * for its lifetime. The view works before and after libp2p_host_start(); before
 * start, later libp2p_host_handle() calls may increase the returned count.
 *
 * @param[out] out_protocols  Borrowed array of registered protocols, or NULL
 *                            when no protocols are registered.
 * @param[out] out_count      Number of entries in out_protocols.
 */
libp2p_host_err_t libp2p_host_registered_protocols(
    const libp2p_host_t *host,
    const libp2p_host_protocol_t **out_protocols,
    size_t *out_count);

/**
 * Start an outbound dial.
 *
 * multiaddr must include an authenticated /p2p component for the expected
 * remote peer. Completion is reported by LIBP2P_HOST_EVENT_CONN_ESTABLISHED or
 * LIBP2P_HOST_EVENT_DIAL_FAILED.
 */
libp2p_host_err_t libp2p_host_dial(
    libp2p_host_t *host,
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    void *user_data,
    libp2p_host_dial_t **out_dial);

/**
 * Open a new outbound stream and negotiate a protocol on it.
 *
 * protocol_id must already be registered with libp2p_host_handle(). Returns
 * LIBP2P_HOST_ERR_NOT_FOUND otherwise. Completion is reported by
 * LIBP2P_HOST_EVENT_STREAM_OPENED or LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED.
 * Once opened, the stream is driven by the registered protocol's on_open and
 * on_event callbacks.
 */
libp2p_host_err_t libp2p_host_open_stream(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

libp2p_host_err_t libp2p_host_open_stream_with_fallback(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    const uint8_t *fallback_protocol_id,
    size_t fallback_protocol_id_len,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

/**
 * Cancel an outbound stream open that has not completed.
 *
 * expected_user_data must match the value supplied to
 * libp2p_host_open_stream(). No completion event is emitted after a successful
 * cancellation. LIBP2P_HOST_ERR_NOT_FOUND means the handle no longer refers to
 * that open attempt. After any other error, the caller must keep user_data
 * valid for a possible completion event.
 */
libp2p_host_err_t libp2p_host_stream_open_cancel(
    libp2p_host_t *host,
    libp2p_host_stream_open_t *open,
    const void *expected_user_data);

/**
 * Return the local identity's peer ID.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_HOST_ERR_BUF_TOO_SMALL.
 */
libp2p_host_err_t libp2p_host_peer_id(
    const libp2p_host_t *host,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Sign message bytes with the local host identity.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_HOST_ERR_BUF_TOO_SMALL.
 */
libp2p_host_err_t libp2p_host_sign(
    libp2p_host_t *host,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out_sig,
    size_t out_sig_len,
    size_t *written);

/**
 * Return a connection's authenticated remote peer ID.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_HOST_ERR_BUF_TOO_SMALL.
 */
libp2p_host_err_t libp2p_host_conn_peer_id(
    const libp2p_host_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Return a currently-live connection for an authenticated remote peer ID.
 *
 * The returned handle is borrowed from the host and follows the same lifetime
 * rules as connection handles from LIBP2P_HOST_EVENT_CONN_ESTABLISHED.
 */
libp2p_host_err_t libp2p_host_conn_for_peer_id(
    libp2p_host_t *host,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_host_conn_t **out_conn);

/**
 * Return a connection's authenticated remote multiaddr.
 *
 * For outbound connections this is the dial target after authentication. For
 * inbound connections this is derived from the transport's remote endpoint and
 * the authenticated remote peer ID. The /p2p/<peer-id> suffix is included when
 * the peer ID is known.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_HOST_ERR_BUF_TOO_SMALL.
 */
libp2p_host_err_t libp2p_host_conn_remote_multiaddr(
    const libp2p_host_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Return a connection's authenticated remote peer identity.
 */
libp2p_host_err_t libp2p_host_conn_peer_identity(
    const libp2p_host_conn_t *conn,
    libp2p_host_peer_identity_t *out);

/**
 * Gracefully close one authenticated connection.
 */
libp2p_host_err_t libp2p_host_conn_close(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    uint64_t app_error_code);

/**
 * Associate protocol-owned state with a negotiated stream.
 */
libp2p_host_err_t libp2p_host_stream_set_user_data(libp2p_host_stream_t *stream, void *user_data);

/**
 * Return whether a negotiated stream is inbound or outbound.
 */
libp2p_host_err_t libp2p_host_stream_direction(
    const libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t *out_direction);

/**
 * Return the authenticated connection that owns a negotiated stream.
 */
libp2p_host_err_t libp2p_host_stream_conn(
    const libp2p_host_stream_t *stream,
    libp2p_host_conn_t **out_conn);

/**
 * Return protocol-owned stream state.
 */
libp2p_host_err_t libp2p_host_stream_user_data(
    const libp2p_host_stream_t *stream,
    void **out_user_data);

/**
 * Read ordered bytes from a negotiated stream.
 *
 * @param[out] read_len  Bytes copied to out.
 * @param[out] fin       Non-zero when the peer's send side has finished.
 */
libp2p_host_err_t libp2p_host_stream_read(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin);

/**
 * Queue ordered bytes for transmission on a negotiated stream.
 *
 * @param[in]  fin       Non-zero to finish the local send side after data.
 * @param[out] accepted  Bytes accepted by the transport send buffer.
 */
libp2p_host_err_t libp2p_host_stream_write(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted);

/**
 * Finish the local send side of a negotiated stream.
 */
libp2p_host_err_t libp2p_host_stream_finish(libp2p_host_t *host, libp2p_host_stream_t *stream);

/**
 * Reset the local send side with an application error code.
 */
libp2p_host_err_t libp2p_host_stream_reset(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint64_t app_error_code);

/**
 * Request that the peer stop sending on this stream.
 */
libp2p_host_err_t libp2p_host_stream_stop_sending(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    uint64_t app_error_code);

/**
 * Return the production QUIC transport adapter for hosts.
 */
const libp2p_host_transport_vtable_t *libp2p_host_quic_transport(void);

#endif /* LIBP2P_HOST_H */
