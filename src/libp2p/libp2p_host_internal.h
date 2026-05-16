#ifndef LIBP2P_HOST_INTERNAL_H
#define LIBP2P_HOST_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"
#include "multiformats/multistream-select/multistream_select.h"

#define HOST_MAGIC                   ((uint32_t)0x6c703248U)
#define HOST_STORAGE_ALIGN           8U
#define HOST_TRANSPORT_ABI_VERSION   2U
#define HOST_NEGOTIATION_FRAME_CAP   LIBP2P_MULTISTREAM_SELECT_MAX_ENCODED_MESSAGE_BYTES
#define HOST_NEGOTIATION_PAYLOAD_CAP LIBP2P_MULTISTREAM_SELECT_MAX_PAYLOAD_BYTES

typedef enum
{
    HOST_STATE_INIT,
    HOST_STATE_STARTED,
    HOST_STATE_CLOSING,
    HOST_STATE_CLOSED
} host_state_t;

typedef enum
{
    HOST_DIAL_FREE,
    HOST_DIAL_PENDING,
    HOST_DIAL_EVENTED
} host_dial_state_t;

typedef enum
{
    HOST_OPEN_FREE,
    HOST_OPEN_WAIT_TRANSPORT,
    HOST_OPEN_NEGOTIATING,
    HOST_OPEN_EVENTED
} host_open_state_t;

typedef enum
{
    HOST_STREAM_FREE,
    HOST_STREAM_NEGOTIATING,
    HOST_STREAM_OPEN,
    HOST_STREAM_CLOSING,
    HOST_STREAM_CLOSED
} host_stream_state_t;

typedef enum
{
    HOST_NEG_NONE,
    HOST_NEG_OUT_SEND_MS,
    HOST_NEG_OUT_SEND_PROTOCOL,
    HOST_NEG_OUT_READ_MS,
    HOST_NEG_OUT_READ_PROTOCOL,
    HOST_NEG_IN_READ_MS,
    HOST_NEG_IN_READ_PROTOCOL,
    HOST_NEG_IN_SEND_PROTOCOL,
    HOST_NEG_IN_SEND_NA,
    HOST_NEG_IN_SEND_LS,
    HOST_NEG_DONE,
    HOST_NEG_FAILED
} host_negotiation_state_t;

struct libp2p_host_conn
{
    libp2p_host_t *host;
    void *transport_conn;
    size_t stream_count;
    uint8_t active;
    uint8_t closed;
};

struct libp2p_host_stream_open
{
    libp2p_host_t *host;
    host_open_state_t state;
    libp2p_host_conn_t *conn;
    void *transport_conn;
    void *transport_stream;
    const libp2p_host_protocol_t *protocol;
    void *user_data;
};

struct libp2p_host_dial
{
    libp2p_host_t *host;
    host_dial_state_t state;
    void *transport_attempt;
    void *user_data;
};

struct libp2p_host_stream
{
    libp2p_host_t *host;
    libp2p_host_conn_t *conn;
    void *transport_stream;
    const libp2p_host_protocol_t *protocol;
    libp2p_host_stream_open_t *open_attempt;
    void *user_data;
    host_stream_state_t state;
    host_negotiation_state_t neg_state;
    libp2p_host_stream_direction_t direction;
    uint8_t pending_readable;
    uint8_t pending_writable;
    uint8_t pending_reset;
    uint8_t pending_closed;
    uint8_t outbound_open_event_queued;
    uint8_t outbound_fail_event_queued;
    uint8_t in_frame[HOST_NEGOTIATION_FRAME_CAP];
    size_t in_len;
    uint8_t payload[HOST_NEGOTIATION_PAYLOAD_CAP];
    size_t payload_len;
    uint8_t out_frame[HOST_NEGOTIATION_FRAME_CAP];
    size_t out_len;
    size_t out_pos;
};

struct libp2p_host
{
    uint32_t magic;
    host_state_t state;
    libp2p_host_config_t config;
    void *transport_storage;
    size_t transport_storage_len;
    void *transport;
    libp2p_host_protocol_t *protocols;
    libp2p_multistream_select_protocol_t *ms_protocols;
    size_t protocol_count;
    size_t protocol_capacity;
    libp2p_host_event_t *events;
    size_t event_capacity;
    size_t event_head;
    size_t event_len;
    libp2p_host_conn_t *conns;
    size_t conn_capacity;
    libp2p_host_stream_t *streams;
    size_t stream_capacity;
    libp2p_host_dial_t *dials;
    size_t dial_capacity;
    libp2p_host_stream_open_t *opens;
    size_t open_capacity;
    size_t negotiation_cursor;
    size_t protocol_cursor;
    uint8_t host_closed_event_queued;
    uint64_t close_app_error_code;
};

typedef struct
{
    size_t host_offset;
    size_t protocols_offset;
    size_t ms_protocols_offset;
    size_t events_offset;
    size_t conns_offset;
    size_t streams_offset;
    size_t dials_offset;
    size_t opens_offset;
    size_t transport_offset;
    size_t total_len;
    size_t transport_len;
    size_t transport_align;
    size_t protocol_capacity;
    size_t conn_capacity;
    size_t stream_capacity;
    size_t dial_capacity;
    size_t open_capacity;
    size_t event_capacity;
    size_t max_streams_per_conn;
    size_t max_negotiation_steps;
} host_layout_t;

libp2p_host_err_t host_validate_started(const libp2p_host_t *host);
libp2p_host_err_t host_validate_any(const libp2p_host_t *host);
libp2p_host_err_t host_event_push(
    libp2p_host_t *host,
    const libp2p_host_event_t *event,
    libp2p_host_drive_result_t *result);
libp2p_host_err_t host_transport_err(libp2p_host_err_t err);
libp2p_host_err_t host_protocol_find(
    const libp2p_host_t *host,
    const uint8_t *id,
    size_t id_len,
    const libp2p_host_protocol_t **out);
libp2p_host_err_t host_protocol_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_drive_result_t *result);
libp2p_host_err_t host_protocol_event_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress);
libp2p_host_conn_t *host_conn_find(libp2p_host_t *host, const void *transport_conn);
libp2p_host_err_t host_conn_alloc(
    libp2p_host_t *host,
    void *transport_conn,
    libp2p_host_conn_t **out);
libp2p_host_dial_t *host_dial_find(libp2p_host_t *host, const void *transport_attempt);
libp2p_host_err_t host_dial_mark_evented(libp2p_host_dial_t *dial);
libp2p_host_stream_t *host_stream_find(libp2p_host_t *host, const void *transport_stream);
libp2p_host_err_t host_stream_alloc(
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *transport_stream,
    libp2p_host_stream_direction_t direction,
    const libp2p_host_protocol_t *protocol,
    libp2p_host_stream_open_t *open_attempt,
    libp2p_host_stream_t **out);
void host_stream_release(libp2p_host_stream_t *stream);
libp2p_host_err_t host_stream_negotiation_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress);
libp2p_host_err_t host_stream_fail_negotiation(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_err_t reason,
    libp2p_host_drive_result_t *result);
libp2p_host_err_t host_stream_open_retry_one(
    libp2p_host_t *host,
    libp2p_host_drive_result_t *result,
    uint8_t *out_progress);
libp2p_host_err_t host_map_peer_err(int peer_err);

#endif /* LIBP2P_HOST_INTERNAL_H */
