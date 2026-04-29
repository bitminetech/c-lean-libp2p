/**
 * @file gossipsub.h
 * @brief libp2p gossipsub v1.1 and v1.2 protocol handler.
 *
 * The gossipsub module is a bounded host consumer. Callers register the
 * protocol objects returned by libp2p_gossipsub_protocols() before starting
 * the host, pass host events back into the module, and drive heartbeat work
 * from the same event loop that drives libp2p_host_t.
 *
 * This API models the v1.1/v1.2 wire format and consensus-client operating
 * profile. v1.0 is intentionally out of scope. Pubsub message signing is also
 * intentionally absent: the clients in scope use anonymous gossipsub messages.
 * The signature/key wire fields remain visible in decoded messages so strict
 * no-sign policy can be enforced by the implementation.
 */

#ifndef LIBP2P_GOSSIPSUB_H
#define LIBP2P_GOSSIPSUB_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"
#include "peer_id/peer_id.h"

/** gossipsub v1.1 protocol id. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11 "/meshsub/1.1.0"

/** Length of LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11, excluding the trailing NUL. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN 14U

/** gossipsub v1.2 protocol id. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12 "/meshsub/1.2.0"

/** Length of LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12, excluding the trailing NUL. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN 14U

/** Number of gossipsub protocol ids exposed by this module. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_COUNT 2U

/** Supported protocol bit for /meshsub/1.1.0. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11 (1U << 0U)

/** Supported protocol bit for /meshsub/1.2.0. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12 (1U << 1U)

/** Default supported protocol set. */
#define LIBP2P_GOSSIPSUB_PROTOCOL_MASK_ALL \
    (LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11 | LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12)

/** Maximum unsigned-varint bytes used for one RPC frame length. */
#define LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES 10U

/** Default maximum protobuf RPC body bytes. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_RPC_BYTES 1048576U

/** Default maximum data bytes in one publish message. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_DATA_BYTES 1048576U

/** Default maximum topic id bytes. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES 256U

/** Default maximum message id bytes. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES 128U

/** Default maximum v1.1 signed peer record bytes in one PX entry. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_SIGNED_PEER_REC_BYTES 512U

/** Default per-RPC decode limits. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC 64U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC       16U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC         32U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC         32U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC         32U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC         32U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC     32U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC   1024U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC      32U

/** Ethereum consensus mesh defaults used by leanSpec, zeam, and lantern. */
#define LIBP2P_GOSSIPSUB_DEFAULT_D                 8U
#define LIBP2P_GOSSIPSUB_DEFAULT_D_LOW             6U
#define LIBP2P_GOSSIPSUB_DEFAULT_D_HIGH            12U
#define LIBP2P_GOSSIPSUB_DEFAULT_D_LAZY            6U
#define LIBP2P_GOSSIPSUB_DEFAULT_D_OUT             2U
#define LIBP2P_GOSSIPSUB_DEFAULT_GOSSIP_FACTOR_PPM 250000U

/** Default heartbeat interval in microseconds. */
#define LIBP2P_GOSSIPSUB_DEFAULT_HEARTBEAT_US 700000ULL

/** Default time-to-live for fanout entries. */
#define LIBP2P_GOSSIPSUB_DEFAULT_FANOUT_TTL_US 60000000ULL

/** Default duplicate-detection window from the gossipsub spec. */
#define LIBP2P_GOSSIPSUB_DEFAULT_SEEN_TTL_US 120000000ULL

/** Default v1.1 PRUNE backoff. */
#define LIBP2P_GOSSIPSUB_DEFAULT_PRUNE_BACKOFF_US 60000000ULL

/** Default backoff used when locally unsubscribing. */
#define LIBP2P_GOSSIPSUB_DEFAULT_UNSUBSCRIBE_BACKOFF_US 10000000ULL

/** Default slack added when comparing PRUNE backoff with local heartbeats. */
#define LIBP2P_GOSSIPSUB_DEFAULT_BACKOFF_SLACK_US 1000000ULL

/** Default time to wait for IWANT follow-up. */
#define LIBP2P_GOSSIPSUB_DEFAULT_IWANT_FOLLOWUP_US 3000000ULL

/** Default message cache history windows. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_LEN 6U

/** Default message cache windows advertised as gossip. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_GOSSIP 3U

/** Default minimum message size that triggers IDONTWANT emission. */
#define LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_MIN_BYTES 1024U

/** Default maximum IDONTWANT messages sent to one peer per heartbeat. */
#define LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_PER_PEER 64U

/** Default time-to-live for remembered IDONTWANT state. */
#define LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_TTL_US 3000000ULL

/** Default caller-provided storage capacities. */
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPICS          128U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEERS           128U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEER_TOPICS     4096U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESH_EDGES      1536U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_FANOUT_EDGES    768U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_BACKOFF_ENTRIES 2048U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_STREAMS         128U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_PENDING_OPENS   128U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_TX_RPC_QUEUE    1024U
#define LIBP2P_GOSSIPSUB_DEFAULT_TX_BUFFER_BYTES     2097152U
#define LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_SLOTS        1024U
#define LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_BYTES        4194304U
#define LIBP2P_GOSSIPSUB_DEFAULT_SEEN_ENTRIES        8192U
#define LIBP2P_GOSSIPSUB_DEFAULT_PENDING_VALIDATIONS 256U
#define LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_ENTRIES   4096U
#define LIBP2P_GOSSIPSUB_DEFAULT_EVENT_CAPACITY      256U
#define LIBP2P_GOSSIPSUB_DEFAULT_MAX_DRIVE_STEPS     256U

/** Opaque gossipsub router object stored in caller-provided memory. */
typedef struct libp2p_gossipsub libp2p_gossipsub_t;

/** Opaque validation token returned with application-validated messages. */
typedef struct libp2p_gossipsub_validation libp2p_gossipsub_validation_t;

/** Bitmask of supported gossipsub protocol ids. */
typedef uint32_t libp2p_gossipsub_protocol_mask_t;

/** Error codes returned by gossipsub operations. */
typedef enum
{
    LIBP2P_GOSSIPSUB_OK = 0,
    LIBP2P_GOSSIPSUB_ERR_INVALID_ARG,
    LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL,
    LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK,
    LIBP2P_GOSSIPSUB_ERR_MALFORMED,
    LIBP2P_GOSSIPSUB_ERR_TRUNCATED,
    LIBP2P_GOSSIPSUB_ERR_LIMIT,
    LIBP2P_GOSSIPSUB_ERR_STATE,
    LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION,
    LIBP2P_GOSSIPSUB_ERR_NOT_FOUND,
    LIBP2P_GOSSIPSUB_ERR_DUPLICATE,
    LIBP2P_GOSSIPSUB_ERR_HOST,
    LIBP2P_GOSSIPSUB_ERR_RANDOM,
    LIBP2P_GOSSIPSUB_ERR_INTERNAL
} libp2p_gossipsub_err_t;

/** Negotiated protocol version for one gossipsub peer stream. */
typedef enum
{
    LIBP2P_GOSSIPSUB_VERSION_NONE = 0,
    LIBP2P_GOSSIPSUB_VERSION_11,
    LIBP2P_GOSSIPSUB_VERSION_12
} libp2p_gossipsub_protocol_version_t;

/** Whether incoming messages require application validation before forwarding. */
typedef enum
{
    LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL = 0,
    LIBP2P_GOSSIPSUB_VALIDATION_REQUIRE_APP
} libp2p_gossipsub_validation_mode_t;

/** Application validation result for one message. */
typedef enum
{
    LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT = 0,
    LIBP2P_GOSSIPSUB_VALIDATION_REJECT,
    LIBP2P_GOSSIPSUB_VALIDATION_IGNORE
} libp2p_gossipsub_validation_result_t;

/** Immutable byte span. */
typedef struct
{
    const uint8_t *data;
    size_t len;
} libp2p_gossipsub_bytes_t;

/** Copied peer ID used in queued gossipsub events. */
typedef struct
{
    uint8_t data[LIBP2P_PEER_ID_MAX_BYTES];
    size_t len;
} libp2p_gossipsub_peer_id_t;

/** Wire and decode limits applied before allocating storage from fixed pools. */
typedef struct
{
    size_t max_rpc_bytes;
    size_t max_message_data_bytes;
    size_t max_topic_bytes;
    size_t max_message_id_bytes;
    size_t max_signed_peer_record_bytes;
    size_t max_subscriptions_per_rpc;
    size_t max_publish_per_rpc;
    size_t max_ihave_per_rpc;
    size_t max_iwant_per_rpc;
    size_t max_graft_per_rpc;
    size_t max_prune_per_rpc;
    size_t max_idontwant_per_rpc;
    size_t max_message_ids_per_rpc;
    size_t max_px_peers_per_rpc;
} libp2p_gossipsub_limits_t;

/** Mesh, heartbeat, and cache-window parameters. */
typedef struct
{
    size_t d;
    size_t d_low;
    size_t d_high;
    size_t d_lazy;
    size_t d_out;
    size_t mcache_len;
    size_t mcache_gossip;
    uint32_t gossip_factor_ppm;
    uint64_t heartbeat_interval_us;
    uint64_t fanout_ttl_us;
    uint64_t seen_ttl_us;
    uint64_t prune_backoff_us;
    uint64_t unsubscribe_backoff_us;
    uint64_t backoff_slack_us;
    uint64_t iwant_followup_us;
    uint8_t enable_flood_publish;
    uint8_t enable_px;
} libp2p_gossipsub_mesh_params_t;

/** Capacity knobs for the caller-managed gossipsub storage slab. */
typedef struct
{
    size_t max_topics;
    size_t max_peers;
    size_t max_peer_topics;
    size_t max_mesh_edges;
    size_t max_fanout_edges;
    size_t max_backoff_entries;
    size_t max_streams;
    size_t max_pending_opens;
    size_t max_tx_rpc_queue;
    size_t tx_buffer_bytes;
    size_t mcache_slots;
    size_t mcache_bytes;
    size_t seen_entries;
    size_t pending_validations;
    size_t idontwant_entries;
    size_t event_capacity;
    size_t max_drive_steps;
} libp2p_gossipsub_capacity_t;

/** Randomness callback used for mesh peer selection and gossip sampling. */
typedef libp2p_gossipsub_err_t (
    *libp2p_gossipsub_random_fn_t)(uint8_t *out, size_t out_len, void *user_data);

typedef struct libp2p_gossipsub_message libp2p_gossipsub_message_t;

/**
 * Message-id callback.
 *
 * Passing out=NULL/out_len=0 follows the project measure-then-write contract
 * and returns ERR_BUF_TOO_SMALL with *written set to the required size.
 */
typedef libp2p_gossipsub_err_t (*libp2p_gossipsub_message_id_fn_t)(
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    void *user_data);

/** Borrowed view of one pubsub Message protobuf. */
struct libp2p_gossipsub_message
{
    libp2p_gossipsub_bytes_t from;
    libp2p_gossipsub_bytes_t data;
    libp2p_gossipsub_bytes_t seqno;
    libp2p_gossipsub_bytes_t topic;
    libp2p_gossipsub_bytes_t signature;
    libp2p_gossipsub_bytes_t key;
    libp2p_gossipsub_bytes_t raw_message;
};

/** Local topic configuration. topic bytes are copied into bounded module storage. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
    libp2p_gossipsub_validation_mode_t validation_mode;
    uint8_t enable_idontwant;
    size_t idontwant_min_message_bytes;
} libp2p_gossipsub_topic_config_t;

/** Application publish request. message_id is optional. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
    libp2p_gossipsub_bytes_t data;
    libp2p_gossipsub_bytes_t message_id;
    void *user_data;
} libp2p_gossipsub_publish_t;

/** Gossipsub router configuration. */
typedef struct
{
    libp2p_gossipsub_limits_t limits;
    libp2p_gossipsub_mesh_params_t mesh;
    libp2p_gossipsub_capacity_t capacity;
    libp2p_gossipsub_random_fn_t random_fn;
    void *random_user_data;
    libp2p_gossipsub_message_id_fn_t message_id_fn;
    void *message_id_user_data;
    libp2p_gossipsub_protocol_mask_t protocol_mask;
    libp2p_gossipsub_protocol_version_t preferred_protocol;
    uint8_t enable_idontwant;
    size_t idontwant_min_message_bytes;
    size_t max_idontwant_messages_per_peer_per_heartbeat;
    uint64_t idontwant_ttl_us;
} libp2p_gossipsub_config_t;

/** RPC subscription option. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
    uint8_t subscribe;
} libp2p_gossipsub_rpc_subscription_t;

/** v1.1 peer exchange entry. */
typedef struct
{
    libp2p_gossipsub_bytes_t peer_id;
    libp2p_gossipsub_bytes_t signed_peer_record;
} libp2p_gossipsub_peer_info_t;

/** IHAVE control message. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
    const libp2p_gossipsub_bytes_t *message_ids;
    size_t message_id_count;
} libp2p_gossipsub_control_ihave_t;

/** IWANT control message. */
typedef struct
{
    const libp2p_gossipsub_bytes_t *message_ids;
    size_t message_id_count;
} libp2p_gossipsub_control_iwant_t;

/** GRAFT control message. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
} libp2p_gossipsub_control_graft_t;

/** PRUNE control message, including v1.1 PX/backoff fields. */
typedef struct
{
    libp2p_gossipsub_bytes_t topic;
    /** Decoded for observability only; this module never encodes PX peers. */
    const libp2p_gossipsub_peer_info_t *peers;
    size_t peer_count;
    uint64_t backoff_seconds;
} libp2p_gossipsub_control_prune_t;

/** v1.2 IDONTWANT control message. */
typedef struct
{
    const libp2p_gossipsub_bytes_t *message_ids;
    size_t message_id_count;
} libp2p_gossipsub_control_idontwant_t;

/** Optional RPC control section. */
typedef struct
{
    const libp2p_gossipsub_control_ihave_t *ihave;
    size_t ihave_count;
    const libp2p_gossipsub_control_iwant_t *iwant;
    size_t iwant_count;
    const libp2p_gossipsub_control_graft_t *graft;
    size_t graft_count;
    const libp2p_gossipsub_control_prune_t *prune;
    size_t prune_count;
    const libp2p_gossipsub_control_idontwant_t *idontwant;
    size_t idontwant_count;
} libp2p_gossipsub_rpc_control_t;

/** Complete gossipsub RPC. */
typedef struct
{
    const libp2p_gossipsub_rpc_subscription_t *subscriptions;
    size_t subscription_count;
    const libp2p_gossipsub_message_t *publish;
    size_t publish_count;
    libp2p_gossipsub_rpc_control_t control;
} libp2p_gossipsub_rpc_t;

/** Caller-provided decode arrays. Decoded byte spans borrow from the input buffer. */
typedef struct
{
    libp2p_gossipsub_rpc_subscription_t *subscriptions;
    size_t subscription_capacity;
    libp2p_gossipsub_message_t *publish;
    size_t publish_capacity;
    libp2p_gossipsub_control_ihave_t *ihave;
    size_t ihave_capacity;
    libp2p_gossipsub_control_iwant_t *iwant;
    size_t iwant_capacity;
    libp2p_gossipsub_control_graft_t *graft;
    size_t graft_capacity;
    libp2p_gossipsub_control_prune_t *prune;
    size_t prune_capacity;
    libp2p_gossipsub_control_idontwant_t *idontwant;
    size_t idontwant_capacity;
    libp2p_gossipsub_bytes_t *message_ids;
    size_t message_id_capacity;
    libp2p_gossipsub_peer_info_t *peer_infos;
    size_t peer_info_capacity;
} libp2p_gossipsub_rpc_decode_storage_t;

/** Public events drained after host and gossipsub drive calls. */
typedef enum
{
    LIBP2P_GOSSIPSUB_EVENT_NONE = 0,
    LIBP2P_GOSSIPSUB_EVENT_PEER_OPENED,
    LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED,
    LIBP2P_GOSSIPSUB_EVENT_PEER_FAILED,
    LIBP2P_GOSSIPSUB_EVENT_SUBSCRIPTION,
    LIBP2P_GOSSIPSUB_EVENT_MESSAGE,
    LIBP2P_GOSSIPSUB_EVENT_IDONTWANT,
    LIBP2P_GOSSIPSUB_EVENT_DROPPED,
    LIBP2P_GOSSIPSUB_EVENT_ERROR
} libp2p_gossipsub_event_type_t;

/** Reason a peer RPC or message was dropped. */
typedef enum
{
    LIBP2P_GOSSIPSUB_DROP_RPC_LIMIT = 0,
    LIBP2P_GOSSIPSUB_DROP_MALFORMED_RPC,
    LIBP2P_GOSSIPSUB_DROP_DUPLICATE_MESSAGE,
    LIBP2P_GOSSIPSUB_DROP_UNSUBSCRIBED_TOPIC,
    LIBP2P_GOSSIPSUB_DROP_VALIDATION_REJECTED,
    LIBP2P_GOSSIPSUB_DROP_TX_QUEUE_FULL,
    LIBP2P_GOSSIPSUB_DROP_IDONTWANT_LIMIT
} libp2p_gossipsub_drop_reason_t;

/**
 * One public gossipsub event. Handles are borrowed from the host.
 *
 * MESSAGE events with validation != NULL require exactly one later
 * libp2p_gossipsub_report_validation() call.
 */
typedef struct
{
    libp2p_gossipsub_event_type_t type;
    libp2p_gossipsub_peer_id_t peer;
    libp2p_host_conn_t *conn;
    libp2p_host_stream_t *stream;
    libp2p_host_stream_direction_t direction;
    libp2p_gossipsub_protocol_version_t protocol_version;
    libp2p_gossipsub_bytes_t topic;
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_bytes_t message_id;
    libp2p_gossipsub_control_idontwant_t idontwant;
    libp2p_gossipsub_validation_t *validation;
    libp2p_gossipsub_drop_reason_t drop_reason;
    libp2p_gossipsub_err_t reason;
    void *user_data;
} libp2p_gossipsub_event_t;

/** Drive result counters for observability, fairness, and deterministic tests. */
typedef struct
{
    size_t heartbeats;
    size_t rpcs_encoded;
    size_t rpcs_sent;
    size_t messages_forwarded;
    size_t controls_enqueued;
    size_t validations_expired;
    uint8_t made_progress;
} libp2p_gossipsub_drive_result_t;

/**
 * Fill gossipsub config with production defaults.
 *
 * The caller must set random_fn before initialization. Defaults support v1.1
 * and v1.2, preferring v1.2 for outbound opens.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_config_default(libp2p_gossipsub_config_t *config);

/**
 * Return caller-managed storage required for a gossipsub router.
 *
 * The returned size covers the router object, peer/topic tables, mesh and
 * fanout edges, stream state, mcache, seen cache, tx queue, validation slots,
 * IDONTWANT state, and event queue.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_storage_size(
    const libp2p_gossipsub_config_t *config,
    size_t *out_len);

/**
 * Return the alignment required for gossipsub storage.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_storage_align(size_t *out_align);

/**
 * Initialize a gossipsub router in caller-provided storage.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_init(
    void *storage,
    size_t storage_len,
    const libp2p_gossipsub_config_t *config,
    libp2p_gossipsub_t **out_gossipsub);

/**
 * Deinitialize a gossipsub router.
 */
void libp2p_gossipsub_deinit(libp2p_gossipsub_t *gossipsub);

/**
 * Return protocol registry entries for enabled gossipsub versions.
 *
 * Passing out_protocols=NULL/out_protocol_capacity=0 returns ERR_BUF_TOO_SMALL
 * with *written set to the required entry count.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_protocols(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_protocol_t *out_protocols,
    size_t out_protocol_capacity,
    size_t *written);

/**
 * Start heartbeat scheduling and queue initial subscription announcements.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_start(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us);

/**
 * Begin graceful gossipsub shutdown.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_close(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    uint64_t app_error_code);

/**
 * Return the next absolute monotonic gossipsub deadline.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_next_deadline(
    const libp2p_gossipsub_t *gossipsub,
    libp2p_host_time_us_t *out_deadline_us);

/**
 * Drive heartbeat work, queued RPC writes, validation expiry, and local events.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_drive(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us,
    libp2p_gossipsub_drive_result_t *out_result);

/**
 * Feed a public host event into the gossipsub router.
 *
 * This is how outbound stream-open completion and connection closure reach the
 * protocol module without adding another callback surface to libp2p_host_t.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_handle_host_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    const libp2p_host_event_t *event);

/**
 * Open an outbound gossipsub stream to an authenticated peer.
 *
 * Passing VERSION_NONE uses config->preferred_protocol. If v1.2 negotiation
 * fails and v1.1 is enabled, libp2p_gossipsub_handle_host_event() may retry on
 * v1.1 using the same tracked peer-open attempt.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_open_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    libp2p_gossipsub_protocol_version_t preferred_version,
    void *user_data,
    libp2p_host_stream_open_t **out_open);

/**
 * Subscribe locally to a topic and join its mesh.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_subscribe(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_topic_config_t *topic);

/**
 * Unsubscribe locally from a topic and PRUNE its mesh peers.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_unsubscribe(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic);

/**
 * Publish an anonymous message.
 *
 * publish->data is sent on the wire as-is. Callers own any compression or
 * domain encoding, including snappy.
 *
 * out_message_id/written may be NULL when the caller does not need the
 * computed message id.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_publish(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_publish_t *publish,
    uint8_t *out_message_id,
    size_t out_message_id_len,
    size_t *written);

/**
 * Complete application validation for a pending message.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_report_validation(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_validation_t *validation,
    libp2p_gossipsub_validation_result_t result);

/**
 * Pop the next gossipsub event.
 *
 * Returns ERR_WOULD_BLOCK when no event is pending.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_next_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_event_t *out_event);

/**
 * Mark or unmark a peer as an explicit/direct peer.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_set_peer_explicit(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    uint8_t is_explicit);

/**
 * Return the negotiated gossipsub version for a peer.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_peer_protocol_version(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_gossipsub_protocol_version_t *out_version);

/**
 * Measure an unframed protobuf RPC body.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    size_t *out_len);

/**
 * Encode an unframed protobuf RPC body.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode an unframed protobuf RPC body.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *decode_storage,
    libp2p_gossipsub_rpc_t *out_rpc);

/**
 * Measure varint(length) + protobuf RPC bytes.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    size_t *out_len);

/**
 * Encode varint(length) + protobuf RPC bytes.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode varint(length) + protobuf RPC bytes.
 */
libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *decode_storage,
    libp2p_gossipsub_rpc_t *out_rpc);

#endif /* LIBP2P_GOSSIPSUB_H */
