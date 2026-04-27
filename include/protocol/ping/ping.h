/**
 * @file ping.h
 * @brief libp2p ping protocol handler.
 */

#ifndef LIBP2P_PING_H
#define LIBP2P_PING_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"

#define LIBP2P_PING_PROTOCOL_ID     "/ipfs/ping/1.0.0"
#define LIBP2P_PING_PROTOCOL_ID_LEN 16U
#define LIBP2P_PING_PAYLOAD_BYTES   32U

#ifndef LIBP2P_PING_MAX_STREAMS
#define LIBP2P_PING_MAX_STREAMS 16U
#endif

#ifndef LIBP2P_PING_EVENT_CAPACITY
#define LIBP2P_PING_EVENT_CAPACITY 16U
#endif

typedef enum
{
    LIBP2P_PING_OK = 0,
    LIBP2P_PING_ERR_INVALID_ARG,
    LIBP2P_PING_ERR_BUF_TOO_SMALL,
    LIBP2P_PING_ERR_LIMIT,
    LIBP2P_PING_ERR_STATE,
    LIBP2P_PING_ERR_MISMATCH,
    LIBP2P_PING_ERR_HOST,
    LIBP2P_PING_ERR_RANDOM
} libp2p_ping_err_t;

typedef libp2p_ping_err_t (*libp2p_ping_random_fn_t)(uint8_t *out, size_t out_len, void *user_data);

typedef libp2p_ping_err_t (
    *libp2p_ping_time_fn_t)(libp2p_host_time_us_t *out_now_us, void *user_data);

typedef struct
{
    libp2p_ping_random_fn_t random_fn;
    void *random_user_data;
    libp2p_ping_time_fn_t time_fn;
    void *time_user_data;
} libp2p_ping_config_t;

typedef enum
{
    LIBP2P_PING_EVENT_NONE,
    LIBP2P_PING_EVENT_PONG,
    LIBP2P_PING_EVENT_CLOSED,
    LIBP2P_PING_EVENT_ERROR
} libp2p_ping_event_type_t;

typedef struct
{
    libp2p_ping_event_type_t type;
    libp2p_host_stream_t *stream;
    libp2p_host_stream_direction_t direction;
    uint8_t payload[LIBP2P_PING_PAYLOAD_BYTES];
    libp2p_host_time_us_t rtt_us;
    libp2p_ping_err_t reason;
    void *user_data;
} libp2p_ping_event_t;

typedef enum
{
    LIBP2P_PING_SLOT_FREE,
    LIBP2P_PING_SLOT_OPENING,
    LIBP2P_PING_SLOT_INITIATOR_WRITING,
    LIBP2P_PING_SLOT_INITIATOR_READING,
    LIBP2P_PING_SLOT_INITIATOR_IDLE,
    LIBP2P_PING_SLOT_RESPONDER_READING,
    LIBP2P_PING_SLOT_RESPONDER_WRITING,
    LIBP2P_PING_SLOT_EVENTED
} libp2p_ping_slot_state_t;

typedef struct
{
    libp2p_ping_slot_state_t state;
    libp2p_host_stream_direction_t direction;
    libp2p_host_conn_t *conn;
    libp2p_host_stream_t *stream;
    void *user_data;
    uint8_t tx[LIBP2P_PING_PAYLOAD_BYTES];
    uint8_t rx[LIBP2P_PING_PAYLOAD_BYTES];
    size_t tx_pos;
    size_t rx_len;
    uint8_t timer_started;
    libp2p_host_time_us_t started_us;
} libp2p_ping_stream_state_t;

typedef struct
{
    libp2p_ping_event_t event;
    size_t slot_index;
} libp2p_ping_queued_event_t;

typedef struct
{
    libp2p_ping_config_t config;
    libp2p_ping_stream_state_t streams[LIBP2P_PING_MAX_STREAMS];
    libp2p_ping_queued_event_t events[LIBP2P_PING_EVENT_CAPACITY];
    size_t event_head;
    size_t event_len;
} libp2p_ping_t;

libp2p_ping_err_t libp2p_ping_config_default(libp2p_ping_config_t *config);

libp2p_ping_err_t libp2p_ping_init(libp2p_ping_t *ping, const libp2p_ping_config_t *config);

libp2p_ping_err_t libp2p_ping_protocol(libp2p_ping_t *ping, libp2p_host_protocol_t *out_protocol);

libp2p_ping_err_t libp2p_ping_initiate(
    libp2p_ping_t *ping,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

libp2p_ping_err_t libp2p_ping_send(libp2p_ping_t *ping, const libp2p_host_stream_t *stream);

libp2p_ping_err_t libp2p_ping_next_event(libp2p_ping_t *ping, libp2p_ping_event_t *out_event);

#endif /* LIBP2P_PING_H */
