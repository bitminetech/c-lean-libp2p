/**
 * @file quic_service.h
 * @brief Lean-facing runtime driver and connection API for libp2p QUIC.
 *
 * The low-level QUIC endpoint is packet-driven and event-loop agnostic. This
 * service layer is the minimal event-driven integration point: it owns one UDP
 * socket, drives endpoint timers and datagrams, translates endpoint events into
 * a stable client-facing queue, and exposes connection/stream operations for
 * protocol code.
 *
 * The service does not expose ngtcp2, AWS-LC, or raw UDP datagram plumbing.
 */

#ifndef LIBP2P_QUIC_SERVICE_H
#define LIBP2P_QUIC_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic.h"
#include "transport/quic/quic_udp.h"

typedef struct libp2p_quic_service libp2p_quic_service_t;

/** Event-loop readiness bits passed to libp2p_quic_service_drive(). */
typedef uint32_t libp2p_quic_service_ready_t;
#define LIBP2P_QUIC_SERVICE_READY_READ  (1U << 0U)
#define LIBP2P_QUIC_SERVICE_READY_WRITE (1U << 1U)
#define LIBP2P_QUIC_SERVICE_READY_TIMER (1U << 2U)
#define LIBP2P_QUIC_SERVICE_READY_APP   (1U << 3U)
#define LIBP2P_QUIC_SERVICE_READY_ALL \
    (LIBP2P_QUIC_SERVICE_READY_READ | LIBP2P_QUIC_SERVICE_READY_WRITE | \
     LIBP2P_QUIC_SERVICE_READY_TIMER | LIBP2P_QUIC_SERVICE_READY_APP)

/** File-descriptor interests requested by the service. */
typedef uint32_t libp2p_quic_service_interest_t;
#define LIBP2P_QUIC_SERVICE_INTEREST_NONE  0U
#define LIBP2P_QUIC_SERVICE_INTEREST_READ  (1U << 0U)
#define LIBP2P_QUIC_SERVICE_INTEREST_WRITE (1U << 1U)

/** Client-facing service events. */
typedef enum
{
    LIBP2P_QUIC_SERVICE_EVENT_NONE,
    LIBP2P_QUIC_SERVICE_EVENT_CONN_INCOMING,
    LIBP2P_QUIC_SERVICE_EVENT_CONN_ESTABLISHED,
    LIBP2P_QUIC_SERVICE_EVENT_CONN_CLOSED,
    LIBP2P_QUIC_SERVICE_EVENT_STREAM_INCOMING,
    LIBP2P_QUIC_SERVICE_EVENT_STREAM_READABLE,
    LIBP2P_QUIC_SERVICE_EVENT_STREAM_WRITABLE,
    LIBP2P_QUIC_SERVICE_EVENT_STREAM_CLOSED
} libp2p_quic_service_event_type_t;

/** One public service event. Pointers are owned by the service endpoint. */
typedef struct
{
    libp2p_quic_service_event_type_t type;
    libp2p_quic_conn_t *conn;
    libp2p_quic_stream_t *stream;
    uint64_t app_error_code;
    uint64_t transport_error_code;
} libp2p_quic_service_event_t;

/** Service configuration. */
typedef struct
{
    libp2p_quic_endpoint_config_t endpoint;
    libp2p_quic_addr_t local_addr;
    uint8_t nonblocking;
    size_t event_capacity;
    size_t max_rx_datagrams_per_drive;
    size_t max_tx_datagrams_per_drive;
} libp2p_quic_service_config_t;

/** Drive result counters for observability and deterministic tests. */
typedef struct
{
    size_t rx_datagrams;
    size_t tx_datagrams;
    size_t endpoint_events;
    size_t service_events;
    uint8_t made_progress;
    uint8_t rx_drained;
    uint8_t tx_drained;
} libp2p_quic_service_drive_result_t;

/**
 * Fill service config with production defaults.
 *
 * The caller must set endpoint identity, endpoint random/time callbacks, and
 * local_addr before initialization.
 */
libp2p_quic_err_t libp2p_quic_service_config_default(libp2p_quic_service_config_t *config);

/**
 * Return caller-managed storage required for a service.
 *
 * The returned size covers the service object, endpoint object storage, event
 * queues, connection bookkeeping, and per-drive UDP scratch buffers.
 */
libp2p_quic_err_t libp2p_quic_service_storage_size(
    const libp2p_quic_service_config_t *config,
    size_t *out_len);

/**
 * Return the alignment required for service storage.
 */
libp2p_quic_err_t libp2p_quic_service_storage_align(size_t *out_align);

/**
 * Initialize a service in caller-provided storage and bind its UDP socket.
 *
 * If config->local_addr.port is 0, the bound address reported by
 * libp2p_quic_service_local_addr() contains the kernel-assigned port.
 */
libp2p_quic_err_t libp2p_quic_service_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_service_config_t *config,
    libp2p_quic_service_t **out_service);

/**
 * Deinitialize a service, close its socket, and release backend-owned state.
 */
void libp2p_quic_service_deinit(libp2p_quic_service_t *service);

/**
 * Return the UDP socket handle owned by the service.
 */
libp2p_quic_err_t libp2p_quic_service_fd(
    const libp2p_quic_service_t *service,
    libp2p_quic_udp_fd_t *out_fd);

/**
 * Return the bound local QUIC UDP address.
 */
libp2p_quic_err_t libp2p_quic_service_local_addr(
    const libp2p_quic_service_t *service,
    libp2p_quic_addr_t *out_addr);

/**
 * Return the local QUIC UDP address to advertise for inbound dials.
 *
 * The returned address preserves the bound port. For wildcard binds it may
 * substitute the wildcard IP with the OS-selected source address for the
 * default route, falling back to libp2p_quic_service_local_addr() semantics
 * when no concrete address is available.
 */
libp2p_quic_err_t libp2p_quic_service_listen_addr(
    const libp2p_quic_service_t *service,
    libp2p_quic_addr_t *out_addr);

/**
 * Return the service's local authenticated QUIC peer ID.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_service_local_peer_id(
    const libp2p_quic_service_t *service,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Return file-descriptor interests for the next external event-loop wait.
 *
 * READ is requested while the service is open. WRITE is requested only when the
 * service knows QUIC has pending datagrams or a previous send would block.
 */
libp2p_quic_err_t libp2p_quic_service_io_interest(
    const libp2p_quic_service_t *service,
    libp2p_quic_service_interest_t *out_interest);

/**
 * Return the next absolute monotonic service deadline.
 */
libp2p_quic_err_t libp2p_quic_service_next_deadline(
    const libp2p_quic_service_t *service,
    libp2p_quic_time_us_t *out_deadline_us);

/**
 * Drive socket I/O, QUIC timers, and endpoint event translation.
 *
 * The caller passes readiness bits from its event loop. READY_APP should be
 * used after local operations such as dial, write, reset, or close so pending
 * QUIC datagrams can be flushed without waiting for socket readiness.
 */
libp2p_quic_err_t libp2p_quic_service_drive(
    libp2p_quic_service_t *service,
    libp2p_quic_time_us_t now_us,
    libp2p_quic_service_ready_t ready,
    libp2p_quic_service_drive_result_t *out_result);

/**
 * Pop the next translated service event.
 */
libp2p_quic_err_t libp2p_quic_service_next_event(
    libp2p_quic_service_t *service,
    libp2p_quic_service_event_t *out_event);

/**
 * Start an outbound connection. remote_addr must include the expected peer ID.
 */
libp2p_quic_err_t libp2p_quic_service_dial(
    libp2p_quic_service_t *service,
    const libp2p_quic_addr_t *remote_addr,
    void *user_data,
    libp2p_quic_conn_t **out_conn);

/**
 * Accept the next authenticated inbound connection.
 *
 * Returns LIBP2P_QUIC_ERR_WOULD_BLOCK when no established inbound connection is
 * waiting for the application.
 */
libp2p_quic_err_t libp2p_quic_service_accept_conn(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t **out_conn);

/**
 * Close all service connections.
 */
libp2p_quic_err_t libp2p_quic_service_close(
    libp2p_quic_service_t *service,
    uint64_t app_error_code);

/** Connection and stream convenience wrappers for protocol code. */
libp2p_quic_err_t libp2p_quic_service_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_quic_err_t libp2p_quic_service_conn_close(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    uint64_t app_error_code);

libp2p_quic_err_t libp2p_quic_service_open_stream(
    libp2p_quic_service_t *service,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream);

libp2p_quic_err_t libp2p_quic_service_accept_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream);

libp2p_quic_err_t libp2p_quic_service_stream_read(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin);

libp2p_quic_err_t libp2p_quic_service_stream_write(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted);

libp2p_quic_err_t libp2p_quic_service_stream_finish(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream);

libp2p_quic_err_t libp2p_quic_service_stream_reset(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code);

libp2p_quic_err_t libp2p_quic_service_stream_stop_sending(
    libp2p_quic_service_t *service,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code);

#endif /* LIBP2P_QUIC_SERVICE_H */
