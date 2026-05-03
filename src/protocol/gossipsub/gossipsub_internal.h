#ifndef GOSSIPSUB_INTERNAL_H
#define GOSSIPSUB_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/gossipsub/gossipsub.h"

#define GOSSIPSUB_STORAGE_ALIGN 8U

#define GOSSIPSUB_WIRE_VARINT  0U
#define GOSSIPSUB_WIRE_FIXED64 1U
#define GOSSIPSUB_WIRE_LEN     2U
#define GOSSIPSUB_WIRE_FIXED32 5U

#define GOSSIPSUB_FIELD_RPC_SUBSCRIPTIONS 1U
#define GOSSIPSUB_FIELD_RPC_PUBLISH       2U
#define GOSSIPSUB_FIELD_RPC_CONTROL       3U

#define GOSSIPSUB_FIELD_SUB_SUBSCRIBE 1U
#define GOSSIPSUB_FIELD_SUB_TOPIC     2U

#define GOSSIPSUB_FIELD_MSG_FROM      1U
#define GOSSIPSUB_FIELD_MSG_DATA      2U
#define GOSSIPSUB_FIELD_MSG_SEQNO     3U
#define GOSSIPSUB_FIELD_MSG_TOPIC     4U
#define GOSSIPSUB_FIELD_MSG_SIGNATURE 5U
#define GOSSIPSUB_FIELD_MSG_KEY       6U

#define GOSSIPSUB_FIELD_CONTROL_IHAVE     1U
#define GOSSIPSUB_FIELD_CONTROL_IWANT     2U
#define GOSSIPSUB_FIELD_CONTROL_GRAFT     3U
#define GOSSIPSUB_FIELD_CONTROL_PRUNE     4U
#define GOSSIPSUB_FIELD_CONTROL_IDONTWANT 5U

#define GOSSIPSUB_FIELD_IHAVE_TOPIC       1U
#define GOSSIPSUB_FIELD_IHAVE_MESSAGE_IDS 2U

#define GOSSIPSUB_FIELD_IWANT_MESSAGE_IDS 1U

#define GOSSIPSUB_FIELD_GRAFT_TOPIC 1U

#define GOSSIPSUB_FIELD_PRUNE_TOPIC   1U
#define GOSSIPSUB_FIELD_PRUNE_PEERS   2U
#define GOSSIPSUB_FIELD_PRUNE_BACKOFF 3U

#define GOSSIPSUB_FIELD_PEER_INFO_PEER_ID            1U
#define GOSSIPSUB_FIELD_PEER_INFO_SIGNED_PEER_RECORD 2U

#define GOSSIPSUB_FIELD_IDONTWANT_MESSAGE_IDS 1U

#define GOSSIPSUB_STREAM_FREE 0U
#define GOSSIPSUB_STREAM_OPEN 1U

#define GOSSIPSUB_PEER_FREE 0U
#define GOSSIPSUB_PEER_USED 1U

#define GOSSIPSUB_TOPIC_FREE 0U
#define GOSSIPSUB_TOPIC_USED 1U

#define GOSSIPSUB_EDGE_FREE 0U
#define GOSSIPSUB_EDGE_USED 1U

#define GOSSIPSUB_VALIDATION_FREE    0U
#define GOSSIPSUB_VALIDATION_PENDING 1U

#define GOSSIPSUB_TX_NO_ITEM                   SIZE_MAX
#define GOSSIPSUB_TX_BYTES_PER_PEER_PER_DRIVE  4096U
#define GOSSIPSUB_TX_LOCAL_PUBLISH_LIFETIME_US UINT64_C(5000000)
#define GOSSIPSUB_TX_FORWARD_LIFETIME_US       UINT64_C(1000000)

typedef struct
{
    uint8_t used;
    uint8_t local_subscribed;
    uint8_t enable_idontwant;
    libp2p_gossipsub_validation_mode_t validation_mode;
    size_t idontwant_min_message_bytes;
    uint8_t topic[LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES];
    size_t topic_len;
} gossipsub_topic_state_t;

typedef struct
{
    uint8_t used;
    uint8_t explicit_peer;
    uint8_t closed;
    libp2p_host_conn_t *conn;
    libp2p_host_stream_t *stream;
    libp2p_host_stream_direction_t direction;
    libp2p_gossipsub_protocol_version_t version;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
    size_t idontwant_sent_this_heartbeat;
    size_t tx_head;
    size_t tx_tail;
    size_t tx_queue_depth;
    uint8_t tx_ready;
    uint64_t tx_last_writable_us;
    uint64_t tx_last_offset;
    uint64_t tx_bytes_accepted;
    uint64_t tx_would_block_count;
    void *user_data;
} gossipsub_peer_state_t;

typedef struct
{
    uint8_t used;
    size_t peer_index;
    size_t topic_index;
    uint8_t subscribed;
} gossipsub_peer_topic_state_t;

typedef struct
{
    uint8_t used;
    size_t peer_index;
    size_t topic_index;
} gossipsub_mesh_edge_state_t;

typedef struct
{
    uint8_t state;
    libp2p_host_stream_t *stream;
    libp2p_host_conn_t *conn;
    libp2p_host_stream_direction_t direction;
    libp2p_gossipsub_protocol_version_t version;
    size_t peer_index;
    uint8_t *rx;
    size_t rx_len;
} gossipsub_stream_state_t;

typedef struct
{
    uint8_t used;
    uint8_t publish;
    size_t peer_index;
    size_t offset;
    size_t len;
    size_t pos;
    size_t next;
    uint64_t enqueued_us;
    uint64_t deadline_us;
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len;
} gossipsub_tx_item_t;

typedef struct
{
    uint8_t used;
    uint8_t window;
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len;
    uint8_t topic[LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES];
    size_t topic_len;
    size_t data_offset;
    size_t data_len;
} gossipsub_mcache_entry_t;

typedef struct
{
    uint8_t used;
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len;
    uint64_t expires_us;
} gossipsub_seen_entry_t;

typedef struct
{
    uint8_t used;
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len;
    size_t peer_index;
    uint64_t expires_us;
} gossipsub_idontwant_entry_t;

struct libp2p_gossipsub_validation
{
    uint8_t state;
    size_t peer_index;
    size_t mcache_index;
    uint64_t expires_us;
};

typedef struct
{
    libp2p_gossipsub_t *gossipsub;
    libp2p_gossipsub_protocol_version_t version;
} gossipsub_protocol_user_data_t;

struct libp2p_gossipsub
{
    libp2p_gossipsub_config_t config;
    libp2p_host_t *host;
    uint8_t started;
    uint8_t closing;
    uint64_t next_heartbeat_us;
    uint64_t last_drive_us;
    uint8_t *storage_base;
    size_t storage_len;

    gossipsub_protocol_user_data_t protocol_user_data[LIBP2P_GOSSIPSUB_PROTOCOL_COUNT];

    gossipsub_topic_state_t *topics;
    gossipsub_peer_state_t *peers;
    gossipsub_peer_topic_state_t *peer_topics;
    gossipsub_mesh_edge_state_t *mesh_edges;
    gossipsub_stream_state_t *streams;
    gossipsub_tx_item_t *tx_queue;
    uint8_t *tx_buffer;
    size_t tx_buffer_used;
    gossipsub_mcache_entry_t *mcache;
    uint8_t *mcache_data;
    size_t mcache_data_used;
    gossipsub_seen_entry_t *seen;
    struct libp2p_gossipsub_validation *validations;
    gossipsub_idontwant_entry_t *idontwant;
    libp2p_gossipsub_event_t *events;

    size_t topic_count;
    size_t peer_count;
    size_t tx_queue_len;
    size_t tx_ready_count;
    size_t tx_next_peer;
    size_t event_head;
    size_t event_len;
    size_t mcache_next;
};

typedef struct
{
    size_t message_id_next;
    size_t peer_info_next;
} gossipsub_decode_cursor_t;

typedef struct
{
    size_t router_offset;
    size_t topics_offset;
    size_t peers_offset;
    size_t peer_topics_offset;
    size_t mesh_edges_offset;
    size_t streams_offset;
    size_t stream_rx_offset;
    size_t tx_queue_offset;
    size_t tx_buffer_offset;
    size_t mcache_offset;
    size_t mcache_data_offset;
    size_t seen_offset;
    size_t validations_offset;
    size_t idontwant_offset;
    size_t events_offset;
    size_t stream_rx_stride;
    size_t total;
} gossipsub_storage_layout_t;

int gossipsub_size_add(size_t a, size_t b, size_t *out);
int gossipsub_size_mul(size_t a, size_t b, size_t *out);
libp2p_gossipsub_err_t gossipsub_align_up(size_t value, size_t alignment, size_t *out);
libp2p_gossipsub_err_t gossipsub_reserve(
    size_t *cursor,
    size_t alignment,
    size_t size,
    size_t *out_offset);
void gossipsub_pointer_store(void *destination, const void *value);
uint8_t *gossipsub_storage_bytes(const void *storage);
libp2p_gossipsub_t *gossipsub_storage_router(const void *storage);
void *gossipsub_storage_at(const void *storage, size_t offset);
int gossipsub_bytes_present(const libp2p_gossipsub_bytes_t *bytes);
int gossipsub_bytes_equal(
    const uint8_t *left,
    size_t left_len,
    const uint8_t *right,
    size_t right_len);
libp2p_gossipsub_err_t gossipsub_uvarint_err(libp2p_uvarint_err_t err);
libp2p_host_err_t gossipsub_host_err(libp2p_gossipsub_err_t err);
libp2p_gossipsub_err_t gossipsub_host_to_err(libp2p_host_err_t err);
libp2p_gossipsub_t *gossipsub_from_protocol_user_data(void *user_data);
libp2p_gossipsub_protocol_version_t gossipsub_version_from_protocol_user_data(void *user_data);
void gossipsub_keep_mutable_host_arg(libp2p_host_t *host);
void gossipsub_keep_mutable_stream_arg(libp2p_host_stream_t *stream);
void gossipsub_keep_mutable_void_arg(void *user_data);
libp2p_gossipsub_err_t gossipsub_write_uvarint(
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_read_uvarint(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint64_t *value);
libp2p_gossipsub_err_t gossipsub_field_size(
    uint32_t field,
    uint32_t wire,
    size_t data_len,
    size_t *total);
libp2p_gossipsub_err_t gossipsub_write_len_field(
    uint32_t field,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_write_varint_field(
    uint32_t field,
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_write_len_prefix(
    uint32_t field,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_skip_field(
    uint32_t wire,
    const uint8_t *in,
    size_t in_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_read_len_span(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    libp2p_gossipsub_bytes_t *out);
libp2p_gossipsub_err_t gossipsub_message_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_message_t *message,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_message_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_message_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_message_t *out);
libp2p_gossipsub_err_t gossipsub_sub_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_subscription_t *sub,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_sub_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_subscription_t *sub,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_sub_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_subscription_t *out);
libp2p_gossipsub_err_t gossipsub_message_id_list_size(
    uint32_t field,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_bytes_t *message_ids,
    size_t message_id_count,
    size_t *total);
libp2p_gossipsub_err_t gossipsub_message_id_list_encode(
    uint32_t field,
    const libp2p_gossipsub_bytes_t *message_ids,
    size_t message_id_count,
    uint8_t *out,
    size_t out_len,
    size_t *pos);
libp2p_gossipsub_err_t gossipsub_ihave_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_ihave_t *ihave,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_ihave_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_ihave_t *ihave,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_ihave_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_ihave_t *out);
libp2p_gossipsub_err_t gossipsub_iwant_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_iwant_t *iwant,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_iwant_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_iwant_t *iwant,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_iwant_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_iwant_t *out);
libp2p_gossipsub_err_t gossipsub_topic_control_size(
    const libp2p_gossipsub_limits_t *limits,
    libp2p_gossipsub_bytes_t topic,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_topic_control_encode(
    const libp2p_gossipsub_limits_t *limits,
    libp2p_gossipsub_bytes_t topic,
    uint32_t field,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_graft_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_control_graft_t *out);
libp2p_gossipsub_err_t gossipsub_peer_info_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_peer_info_t *out);
libp2p_gossipsub_err_t gossipsub_prune_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_prune_t *prune,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_prune_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_prune_t *prune,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_prune_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_prune_t *out);
libp2p_gossipsub_err_t gossipsub_idontwant_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_idontwant_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_control_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    size_t *out_len);
libp2p_gossipsub_err_t gossipsub_limits_validate(const libp2p_gossipsub_limits_t *limits);
libp2p_gossipsub_err_t gossipsub_version_validate(libp2p_gossipsub_protocol_version_t version);
libp2p_gossipsub_err_t gossipsub_config_validate_storage(const libp2p_gossipsub_config_t *config);
libp2p_gossipsub_err_t gossipsub_config_validate_init(const libp2p_gossipsub_config_t *config);
libp2p_gossipsub_err_t gossipsub_storage_layout(
    const libp2p_gossipsub_config_t *config,
    gossipsub_storage_layout_t *layout);
libp2p_gossipsub_err_t gossipsub_event_push(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_event_t *event);
void gossipsub_peer_to_event(const gossipsub_peer_state_t *peer, libp2p_gossipsub_event_t *event);
gossipsub_topic_state_t *gossipsub_find_topic(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *topic,
    size_t topic_len,
    size_t *out_index);
gossipsub_topic_state_t *gossipsub_find_or_add_topic(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic,
    size_t *out_index);
gossipsub_peer_state_t *gossipsub_find_peer(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index);
const gossipsub_peer_state_t *gossipsub_find_peer_const(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index);
libp2p_gossipsub_err_t gossipsub_peer_from_conn(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_conn_t *conn,
    gossipsub_peer_state_t **out_peer,
    size_t *out_index);
gossipsub_stream_state_t *gossipsub_alloc_stream(libp2p_gossipsub_t *gossipsub, size_t *out_index);
gossipsub_peer_topic_state_t *gossipsub_find_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
gossipsub_peer_topic_state_t *gossipsub_find_or_add_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
int gossipsub_peer_subscribed(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
int gossipsub_mesh_contains(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
size_t gossipsub_mesh_count_topic(const libp2p_gossipsub_t *gossipsub, size_t topic_index);
libp2p_gossipsub_err_t gossipsub_mesh_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
void gossipsub_mesh_remove(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index);
void gossipsub_mesh_remove_peer(libp2p_gossipsub_t *gossipsub, size_t peer_index);
void gossipsub_mesh_remove_topic(libp2p_gossipsub_t *gossipsub, size_t topic_index);
libp2p_gossipsub_err_t gossipsub_mesh_fill_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index,
    size_t target,
    uint8_t queue_graft);
libp2p_gossipsub_err_t gossipsub_mesh_trim_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t topic_index,
    size_t target,
    uint8_t queue_prune);
libp2p_gossipsub_err_t gossipsub_mesh_heartbeat(libp2p_gossipsub_t *gossipsub);
libp2p_gossipsub_err_t gossipsub_compute_message_id(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written);
int gossipsub_seen_contains(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us);
void gossipsub_seen_add(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us);
gossipsub_mcache_entry_t *gossipsub_mcache_find(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len);
libp2p_gossipsub_err_t gossipsub_mcache_store(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    libp2p_gossipsub_bytes_t topic,
    libp2p_gossipsub_bytes_t data,
    gossipsub_mcache_entry_t **out_entry,
    size_t *out_index);
void gossipsub_entry_message(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_mcache_entry_t *entry,
    libp2p_gossipsub_message_t *out);
int gossipsub_peer_idontwant_contains(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us);
void gossipsub_peer_idontwant_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_tx_alloc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t frame_len,
    uint64_t lifetime_us,
    uint8_t **out,
    size_t *out_index);
void gossipsub_tx_remove(libp2p_gossipsub_t *gossipsub, size_t index);
uint64_t gossipsub_tx_next_deadline(const libp2p_gossipsub_t *gossipsub, uint64_t current_deadline);
size_t gossipsub_tx_drop_stale(libp2p_gossipsub_t *gossipsub, uint64_t now_us);
void gossipsub_tx_mark_peer_ready(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_enqueue_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc);
libp2p_gossipsub_err_t gossipsub_enqueue_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    uint8_t subscribe);
libp2p_gossipsub_err_t gossipsub_enqueue_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len);
libp2p_gossipsub_err_t gossipsub_enqueue_iwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_bytes_t *message_id);
libp2p_gossipsub_err_t gossipsub_enqueue_graft(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic);
libp2p_gossipsub_err_t gossipsub_enqueue_prune(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic);
libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry);
libp2p_gossipsub_err_t gossipsub_enqueue_local_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry);
libp2p_gossipsub_err_t gossipsub_enqueue_idontwant_for_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    const gossipsub_mcache_entry_t *entry);
libp2p_gossipsub_err_t gossipsub_enqueue_idontwant_for_received_entry(
    libp2p_gossipsub_t *gossipsub,
    const gossipsub_topic_state_t *topic,
    const gossipsub_mcache_entry_t *entry);
void gossipsub_drop_queued_publish(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len);
void gossipsub_drop_queued_peer(libp2p_gossipsub_t *gossipsub, size_t peer_index);
libp2p_gossipsub_err_t gossipsub_flush_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    size_t peer_index,
    uint64_t now_us,
    uint8_t *made_progress,
    size_t *rpcs_sent);
libp2p_gossipsub_err_t gossipsub_flush_ready_peers(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    uint64_t now_us,
    uint8_t *made_progress,
    size_t *rpcs_sent);
libp2p_gossipsub_err_t gossipsub_forward_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t source_peer_index,
    const gossipsub_mcache_entry_t *entry);
struct libp2p_gossipsub_validation *gossipsub_alloc_validation(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t mcache_index,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_process_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_subscription_t *sub);
libp2p_gossipsub_err_t gossipsub_process_message(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_message_t *message,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_process_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_process_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_stream_decode_available(
    libp2p_gossipsub_t *gossipsub,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us);
libp2p_gossipsub_err_t gossipsub_stream_read(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us);
void gossipsub_heartbeat(libp2p_gossipsub_t *gossipsub, uint64_t now_us);
libp2p_host_err_t gossipsub_protocol_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data);
libp2p_host_err_t gossipsub_protocol_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data);
libp2p_gossipsub_err_t gossipsub_control_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    uint8_t *out,
    size_t out_len,
    size_t *written);
libp2p_gossipsub_err_t gossipsub_idontwant_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_idontwant_t *out);
libp2p_gossipsub_err_t gossipsub_control_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    libp2p_gossipsub_rpc_control_t *out);

#endif /* GOSSIPSUB_INTERNAL_H */
