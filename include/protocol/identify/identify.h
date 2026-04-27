/**
 * @file identify.h
 * @brief libp2p identify and identify/push protocol handlers.
 *
 * The protocol module is a bounded host consumer. Callers register the
 * protocol objects returned by libp2p_identify_protocol() and, optionally,
 * libp2p_identify_push_protocol() before starting the host.
 */

#ifndef LIBP2P_IDENTIFY_H
#define LIBP2P_IDENTIFY_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"

#define LIBP2P_IDENTIFY_PROTOCOL_ID          "/ipfs/id/1.0.0"
#define LIBP2P_IDENTIFY_PROTOCOL_ID_LEN      14U
#define LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID     "/ipfs/id/push/1.0.0"
#define LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID_LEN 19U

#ifndef LIBP2P_IDENTIFY_MAX_MESSAGE_BYTES
#define LIBP2P_IDENTIFY_MAX_MESSAGE_BYTES 2048U
#endif

#ifndef LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS
#define LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS 8U
#endif

#ifndef LIBP2P_IDENTIFY_MAX_PROTOCOLS
#define LIBP2P_IDENTIFY_MAX_PROTOCOLS 16U
#endif

#ifndef LIBP2P_IDENTIFY_MAX_STREAMS
#define LIBP2P_IDENTIFY_MAX_STREAMS 16U
#endif

#ifndef LIBP2P_IDENTIFY_EVENT_CAPACITY
#define LIBP2P_IDENTIFY_EVENT_CAPACITY 16U
#endif

typedef enum
{
    LIBP2P_IDENTIFY_OK = 0,
    LIBP2P_IDENTIFY_ERR_INVALID_ARG,
    LIBP2P_IDENTIFY_ERR_BUF_TOO_SMALL,
    LIBP2P_IDENTIFY_ERR_MALFORMED,
    LIBP2P_IDENTIFY_ERR_TRUNCATED,
    LIBP2P_IDENTIFY_ERR_LIMIT,
    LIBP2P_IDENTIFY_ERR_STATE,
    LIBP2P_IDENTIFY_ERR_HOST
} libp2p_identify_err_t;

typedef struct
{
    const uint8_t *data;
    size_t len;
} libp2p_identify_bytes_t;

typedef struct
{
    libp2p_identify_bytes_t protocol_version;
    libp2p_identify_bytes_t agent_version;
    libp2p_identify_bytes_t public_key;
    libp2p_identify_bytes_t observed_addr;
    libp2p_identify_bytes_t listen_addrs[LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS];
    size_t listen_addr_count;
    libp2p_identify_bytes_t protocols[LIBP2P_IDENTIFY_MAX_PROTOCOLS];
    size_t protocol_count;
} libp2p_identify_message_t;

typedef struct
{
    /**
     * Message template used for fields the host cannot derive dynamically.
     *
     * protocol_version, agent_version, and public_key are read from this
     * template. Transmitted listen_addrs, protocols, and observed_addr are
     * sourced from libp2p_host_t accessors at stream-open time.
     */
    libp2p_identify_message_t local_message;
} libp2p_identify_config_t;

typedef enum
{
    LIBP2P_IDENTIFY_EVENT_NONE,
    LIBP2P_IDENTIFY_EVENT_RECEIVED,
    LIBP2P_IDENTIFY_EVENT_SENT,
    LIBP2P_IDENTIFY_EVENT_CLOSED,
    LIBP2P_IDENTIFY_EVENT_ERROR
} libp2p_identify_event_type_t;

typedef struct
{
    libp2p_identify_event_type_t type;
    libp2p_host_stream_t *stream;
    libp2p_host_stream_direction_t direction;
    libp2p_identify_message_t message;
    libp2p_identify_err_t reason;
    void *user_data;
} libp2p_identify_event_t;

typedef enum
{
    LIBP2P_IDENTIFY_SLOT_FREE,
    LIBP2P_IDENTIFY_SLOT_OPENING_IDENTIFY,
    LIBP2P_IDENTIFY_SLOT_OPENING_PUSH,
    LIBP2P_IDENTIFY_SLOT_READING,
    LIBP2P_IDENTIFY_SLOT_WRITING,
    LIBP2P_IDENTIFY_SLOT_EVENTED
} libp2p_identify_slot_state_t;

typedef enum
{
    LIBP2P_IDENTIFY_STREAM_IDENTIFY,
    LIBP2P_IDENTIFY_STREAM_PUSH
} libp2p_identify_stream_kind_t;

typedef struct
{
    libp2p_identify_slot_state_t state;
    libp2p_identify_stream_kind_t kind;
    libp2p_host_stream_direction_t direction;
    libp2p_host_stream_t *stream;
    void *user_data;
    uint8_t rx[LIBP2P_IDENTIFY_MAX_MESSAGE_BYTES];
    size_t rx_len;
    uint8_t tx[LIBP2P_IDENTIFY_MAX_MESSAGE_BYTES];
    size_t tx_len;
    size_t tx_pos;
    libp2p_identify_message_t decoded;
} libp2p_identify_stream_state_t;

typedef struct
{
    libp2p_identify_event_t event;
    size_t slot_index;
} libp2p_identify_queued_event_t;

typedef struct
{
    libp2p_identify_config_t config;
    libp2p_identify_stream_state_t streams[LIBP2P_IDENTIFY_MAX_STREAMS];
    libp2p_identify_queued_event_t events[LIBP2P_IDENTIFY_EVENT_CAPACITY];
    size_t event_head;
    size_t event_len;
} libp2p_identify_t;

libp2p_identify_err_t libp2p_identify_config_default(libp2p_identify_config_t *config);

libp2p_identify_err_t libp2p_identify_init(
    libp2p_identify_t *identify,
    const libp2p_identify_config_t *config);

libp2p_identify_err_t libp2p_identify_protocol(
    libp2p_identify_t *identify,
    libp2p_host_protocol_t *out_protocol);

libp2p_identify_err_t libp2p_identify_push_protocol(
    libp2p_identify_t *identify,
    libp2p_host_protocol_t *out_protocol);

libp2p_identify_err_t libp2p_identify_query(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

libp2p_identify_err_t libp2p_identify_push(
    libp2p_identify_t *identify,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

libp2p_identify_err_t libp2p_identify_next_event(
    libp2p_identify_t *identify,
    libp2p_identify_event_t *out_event);

libp2p_identify_err_t libp2p_identify_message_size(
    const libp2p_identify_message_t *message,
    size_t *out_len);

libp2p_identify_err_t libp2p_identify_message_encode(
    const libp2p_identify_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_identify_err_t libp2p_identify_message_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_identify_message_t *out_message);

#endif /* LIBP2P_IDENTIFY_H */
