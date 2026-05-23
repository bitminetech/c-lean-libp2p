/**
 * @file quic_types.h
 * @brief Shared types and limits for the mandatory libp2p QUIC transport.
 *
 * c-lean-libp2p targets RFC 9000 QUIC v1 over UDP with ALPN "libp2p". The
 * public API deliberately exposes libp2p concepts rather than ngtcp2 or AWS-LC
 * types. Backend-specific state stays behind the transport implementation.
 */

#ifndef LIBP2P_QUIC_TYPES_H
#define LIBP2P_QUIC_TYPES_H

#include <stddef.h>
#include <stdint.h>

/** IETF QUIC version 1, as defined by RFC 9000. */
#define LIBP2P_QUIC_VERSION_RFC9000 ((uint32_t)0x00000001U)

/** Mandatory ALPN used by the libp2p QUIC transport. */
#define LIBP2P_QUIC_ALPN "libp2p"

/** Length in bytes of LIBP2P_QUIC_ALPN, excluding the trailing NUL. */
#define LIBP2P_QUIC_ALPN_LEN 6U

/** QUIC Initial packets must be carried in UDP datagrams of at least 1200 bytes. */
#define LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES 1200U

/** Conservative default UDP payload target for IPv4/IPv6 paths. */
#define LIBP2P_QUIC_DEFAULT_MAX_DATAGRAM_BYTES 1350U

/** Maximum QUIC connection ID length permitted by RFC 9000. */
#define LIBP2P_QUIC_MAX_CONN_ID_BYTES 20U

/** Initial production resource limits for the c-lean-libp2p transport surface. */
#define LIBP2P_QUIC_DEFAULT_MAX_CONNECTIONS     64U
#define LIBP2P_QUIC_DEFAULT_MAX_BIDI_STREAMS    128U
#define LIBP2P_QUIC_DEFAULT_MAX_UNI_STREAMS     0U
#define LIBP2P_QUIC_DEFAULT_STREAM_WINDOW_BYTES ((size_t)10U * 1024U * 1024U)
#define LIBP2P_QUIC_DEFAULT_CONN_WINDOW_BYTES   ((size_t)15U * 1024U * 1024U)

/** Default timers, expressed in microseconds against a monotonic clock. */
#define LIBP2P_QUIC_DEFAULT_IDLE_TIMEOUT_US      ((uint64_t)30000000U)
#define LIBP2P_QUIC_DEFAULT_HANDSHAKE_TIMEOUT_US ((uint64_t)10000000U)

/** Opaque endpoint, connection, and stream handles. */
typedef struct libp2p_quic_endpoint libp2p_quic_endpoint_t;
typedef struct libp2p_quic_conn libp2p_quic_conn_t;
typedef struct libp2p_quic_stream libp2p_quic_stream_t;

/** Monotonic time in microseconds. The API never reads the system clock. */
typedef uint64_t libp2p_quic_time_us_t;

/** QUIC stream IDs are unsigned 62-bit integers carried in a uint64_t. */
typedef uint64_t libp2p_quic_stream_id_t;

/** Error codes returned by QUIC transport operations. */
typedef enum
{
    LIBP2P_QUIC_OK,
    LIBP2P_QUIC_ERR_INVALID_ARG,
    LIBP2P_QUIC_ERR_BUF_TOO_SMALL,
    LIBP2P_QUIC_ERR_UNSUPPORTED,
    LIBP2P_QUIC_ERR_NO_MEMORY,
    LIBP2P_QUIC_ERR_STATE,
    LIBP2P_QUIC_ERR_WOULD_BLOCK,
    LIBP2P_QUIC_ERR_LIMIT,
    LIBP2P_QUIC_ERR_NOT_FOUND,
    LIBP2P_QUIC_ERR_CLOSED,
    LIBP2P_QUIC_ERR_ADDR,
    LIBP2P_QUIC_ERR_VERSION,
    LIBP2P_QUIC_ERR_TLS,
    LIBP2P_QUIC_ERR_CERTIFICATE,
    LIBP2P_QUIC_ERR_CERTIFICATE_CHAIN,
    LIBP2P_QUIC_ERR_CERTIFICATE_TIME,
    LIBP2P_QUIC_ERR_CERTIFICATE_SIGNATURE,
    LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION,
    LIBP2P_QUIC_ERR_PEER_ID_MISMATCH,
    LIBP2P_QUIC_ERR_BACKEND,
    LIBP2P_QUIC_ERR_INTERNAL
} libp2p_quic_err_t;

/** Endpoint role bits. Values may be ORed by validators. */
typedef uint32_t libp2p_quic_role_t;
#define LIBP2P_QUIC_ROLE_CLIENT        (1U << 0U)
#define LIBP2P_QUIC_ROLE_SERVER        (1U << 1U)
#define LIBP2P_QUIC_ROLE_CLIENT_SERVER (LIBP2P_QUIC_ROLE_CLIENT | LIBP2P_QUIC_ROLE_SERVER)

/** ECN codepoint carried with a UDP datagram, when the platform exposes it. */
typedef enum
{
    LIBP2P_QUIC_ECN_NOT_ECT,
    LIBP2P_QUIC_ECN_ECT0,
    LIBP2P_QUIC_ECN_ECT1,
    LIBP2P_QUIC_ECN_CE
} libp2p_quic_ecn_t;

/** High-level connection state reported by the transport API. */
typedef enum
{
    LIBP2P_QUIC_CONN_IDLE,
    LIBP2P_QUIC_CONN_HANDSHAKING,
    LIBP2P_QUIC_CONN_ESTABLISHED,
    LIBP2P_QUIC_CONN_CLOSING,
    LIBP2P_QUIC_CONN_CLOSED,
    LIBP2P_QUIC_CONN_DRAINED
} libp2p_quic_conn_state_t;

/** High-level stream state reported by the transport API. */
typedef enum
{
    LIBP2P_QUIC_STREAM_OPEN,
    LIBP2P_QUIC_STREAM_HALF_CLOSED_LOCAL,
    LIBP2P_QUIC_STREAM_HALF_CLOSED_REMOTE,
    LIBP2P_QUIC_STREAM_CLOSED,
    LIBP2P_QUIC_STREAM_RESET
} libp2p_quic_stream_state_t;

/** Debug trace record type. */
typedef enum
{
    LIBP2P_QUIC_DEBUG_EVENT_TEXT,
    LIBP2P_QUIC_DEBUG_EVENT_QLOG,
    LIBP2P_QUIC_DEBUG_EVENT_TLS_MESSAGE
} libp2p_quic_debug_event_type_t;

/** Immutable byte span. The pointed-to storage remains caller-owned. */
typedef struct
{
    const uint8_t *data;
    size_t len;
} libp2p_quic_const_buffer_t;

/**
 * Random byte callback used by endpoint and certificate generation code.
 *
 * Return LIBP2P_QUIC_OK on success.
 */
typedef libp2p_quic_err_t (*libp2p_quic_random_fn_t)(uint8_t *out, size_t out_len, void *user_data);

/**
 * Wall-clock callback used for certificate validity checks.
 *
 * Endpoint timers use monotonic libp2p_quic_time_us_t values. Certificate
 * validation needs Unix time separately so tests and embedded callers can keep
 * the two clocks explicit.
 */
typedef libp2p_quic_err_t (
    *libp2p_quic_unix_time_fn_t)(uint64_t *out_unix_seconds, void *user_data);

/**
 * Optional diagnostic callback for interop/debug tooling.
 *
 * The callback must not call back into the endpoint that emitted the record.
 */
typedef void (*libp2p_quic_debug_fn_t)(
    libp2p_quic_debug_event_type_t type,
    const void *data,
    size_t data_len,
    void *user_data);

/** Allocator hooks used by the QUIC backend. All hooks are required at init. */
typedef void *(*libp2p_quic_malloc_fn_t)(size_t size, void *user_data);
typedef void *(*libp2p_quic_calloc_fn_t)(size_t nmemb, size_t size, void *user_data);
typedef void *(*libp2p_quic_realloc_fn_t)(void *ptr, size_t size, void *user_data);
typedef void (*libp2p_quic_free_fn_t)(void *ptr, void *user_data);

typedef struct
{
    libp2p_quic_malloc_fn_t malloc_fn;
    libp2p_quic_calloc_fn_t calloc_fn;
    libp2p_quic_realloc_fn_t realloc_fn;
    libp2p_quic_free_fn_t free_fn;
    void *user_data;
} libp2p_quic_allocator_t;

#endif /* LIBP2P_QUIC_TYPES_H */
