#include "protocol/gossipsub/gossipsub.h"

#include <stdint.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

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

typedef struct
{
    uint8_t used;
    uint8_t local_subscribed;
    uint8_t enable_idontwant;
    libp2p_gossipsub_validation_mode_t validation_mode;
    const libp2p_gossipsub_topic_score_params_t *score_params;
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
    libp2p_gossipsub_score_t app_score;
    libp2p_gossipsub_score_t behaviour_penalty;
    size_t idontwant_sent_this_heartbeat;
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
    size_t peer_index;
    size_t offset;
    size_t len;
    size_t pos;
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
    uint8_t *storage_base;
    size_t storage_len;

    gossipsub_protocol_user_data_t protocol_user_data[LIBP2P_GOSSIPSUB_PROTOCOL_COUNT];

    gossipsub_topic_state_t *topics;
    gossipsub_peer_state_t *peers;
    gossipsub_peer_topic_state_t *peer_topics;
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
    size_t event_head;
    size_t event_len;
    size_t mcache_next;
};

typedef struct
{
    size_t message_id_next;
    size_t peer_info_next;
} gossipsub_decode_cursor_t;

static int gossipsub_size_add(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (out == NULL)
    {
        result = 1;
    }
    else if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a + b;
    }

    return result;
}

static int gossipsub_size_mul(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (out == NULL)
    {
        result = 1;
    }
    else if ((a != 0U) && (b > (SIZE_MAX / a)))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a * b;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_align_up(size_t value, size_t alignment, size_t *out)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((alignment == 0U) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        const size_t remainder = value % alignment;

        if (remainder == 0U)
        {
            *out = value;
        }
        else
        {
            const size_t adjustment = alignment - remainder;

            if (adjustment > (SIZE_MAX - value))
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else
            {
                *out = value + adjustment;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_reserve(
    size_t *cursor,
    size_t alignment,
    size_t size,
    size_t *out_offset)
{
    size_t aligned = 0U;
    size_t next = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((cursor == NULL) || (out_offset == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_align_up(*cursor, alignment, &aligned);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_size_add(aligned, size, &next) != 0))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *out_offset = aligned;
            *cursor = next;
        }
    }

    return result;
}

static void gossipsub_pointer_store(void *destination, const void *value)
{
    (void)memcpy(destination, (const void *)&value, sizeof value);
}

static uint8_t *gossipsub_storage_bytes(const void *storage)
{
    uint8_t *result = NULL;

    gossipsub_pointer_store((void *)&result, storage);

    return result;
}

static libp2p_gossipsub_t *gossipsub_storage_router(const void *storage)
{
    libp2p_gossipsub_t *result = NULL;

    gossipsub_pointer_store((void *)&result, storage);

    return result;
}

static void *gossipsub_storage_at(const void *storage, size_t offset)
{
    uint8_t *bytes = gossipsub_storage_bytes(storage);
    void *result = NULL;

    if (bytes != NULL)
    {
        result = (void *)&bytes[offset];
    }

    return result;
}

static int gossipsub_bytes_present(const libp2p_gossipsub_bytes_t *bytes)
{
    int result = 0;

    if ((bytes != NULL) && (bytes->data != NULL) && (bytes->len != 0U))
    {
        result = 1;
    }

    return result;
}

static int gossipsub_bytes_equal(
    const uint8_t *left,
    size_t left_len,
    const uint8_t *right,
    size_t right_len)
{
    int result = 0;

    if ((left != NULL) && (right != NULL) && (left_len == right_len))
    {
        if ((left_len == 0U) || (memcmp(left, right, left_len) == 0))
        {
            result = 1;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_uvarint_err(libp2p_uvarint_err_t err)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;

    if (err == LIBP2P_UVARINT_OK)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else if (err == LIBP2P_UVARINT_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_UVARINT_ERR_TRUNCATED)
    {
        result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
    }

    return result;
}

static libp2p_host_err_t gossipsub_host_err(libp2p_gossipsub_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_ERR_PROTOCOL;

    if (err == LIBP2P_GOSSIPSUB_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_INVALID_ARG)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_LIMIT)
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
    {
        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_host_to_err(libp2p_host_err_t err)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_ERR_HOST;

    if (err == LIBP2P_HOST_OK)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else if (err == LIBP2P_HOST_ERR_INVALID_ARG)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_HOST_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_HOST_ERR_LIMIT)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else if (err == LIBP2P_HOST_ERR_WOULD_BLOCK)
    {
        result = LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK;
    }
    else if (err == LIBP2P_HOST_ERR_NOT_FOUND)
    {
        result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_ERR_HOST;
    }

    return result;
}

static libp2p_gossipsub_t *gossipsub_from_protocol_user_data(void *user_data)
{
    gossipsub_protocol_user_data_t *data = NULL;
    libp2p_gossipsub_t *result = NULL;

    (void)memcpy((void *)&data, (const void *)&user_data, sizeof user_data);
    if (data != NULL)
    {
        result = data->gossipsub;
    }

    return result;
}

static libp2p_gossipsub_protocol_version_t gossipsub_version_from_protocol_user_data(
    void *user_data)
{
    gossipsub_protocol_user_data_t *data = NULL;
    libp2p_gossipsub_protocol_version_t result = LIBP2P_GOSSIPSUB_VERSION_NONE;

    (void)memcpy((void *)&data, (const void *)&user_data, sizeof user_data);
    if (data != NULL)
    {
        result = data->version;
    }

    return result;
}

static void gossipsub_keep_mutable_host_arg(libp2p_host_t *host)
{
    volatile libp2p_host_t *sink = host;

    (void)sink;
}

static void gossipsub_keep_mutable_stream_arg(libp2p_host_stream_t *stream)
{
    volatile libp2p_host_stream_t *sink = stream;

    (void)sink;
}

static void gossipsub_keep_mutable_void_arg(void *user_data)
{
    void *volatile sink = user_data;

    (void)sink;
}

static libp2p_gossipsub_err_t gossipsub_write_uvarint(
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    size_t written = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((out == NULL) || (pos == NULL) || (*pos > out_len))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_uvarint_err(
            libp2p_uvarint_encode(value, &out[*pos], out_len - *pos, &written));
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *pos += written;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_read_uvarint(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint64_t *value)
{
    size_t read_len = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((in == NULL) || (pos == NULL) || (value == NULL) || (*pos > in_len))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_uvarint_err(
            libp2p_uvarint_decode(&in[*pos], in_len - *pos, value, &read_len));
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *pos += read_len;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_field_size(
    uint32_t field,
    uint32_t wire,
    size_t data_len,
    size_t *total)
{
    const uint64_t key = (((uint64_t)field) << 3U) | ((uint64_t)wire);
    size_t next = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (total == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (wire == GOSSIPSUB_WIRE_LEN)
    {
        if (gossipsub_size_add(
                *total,
                (size_t)libp2p_uvarint_size(key) + (size_t)libp2p_uvarint_size((uint64_t)data_len),
                &next) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else if (gossipsub_size_add(next, data_len, total) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
    }
    else
    {
        if (gossipsub_size_add(
                *total,
                (size_t)libp2p_uvarint_size(key) + (size_t)libp2p_uvarint_size((uint64_t)data_len),
                total) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_write_len_field(
    uint32_t field,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    const uint64_t key = (((uint64_t)field) << 3U) | GOSSIPSUB_WIRE_LEN;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (((data == NULL) && (data_len != 0U)) || (out == NULL) || (pos == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_write_uvarint(key, out, out_len, pos);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_uvarint((uint64_t)data_len, out, out_len, pos);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (data_len > (out_len - *pos))
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
        else
        {
            if (data_len != 0U)
            {
                (void)memcpy(&out[*pos], data, data_len);
            }
            *pos += data_len;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_write_varint_field(
    uint32_t field,
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    const uint64_t key = (((uint64_t)field) << 3U) | GOSSIPSUB_WIRE_VARINT;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((out == NULL) || (pos == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_write_uvarint(key, out, out_len, pos);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_uvarint(value, out, out_len, pos);
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_write_len_prefix(
    uint32_t field,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    const uint64_t key = (((uint64_t)field) << 3U) | GOSSIPSUB_WIRE_LEN;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((out == NULL) || (pos == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_write_uvarint(key, out, out_len, pos);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_uvarint((uint64_t)data_len, out, out_len, pos);
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_skip_field(
    uint32_t wire,
    const uint8_t *in,
    size_t in_len,
    size_t *pos)
{
    uint64_t ignored = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((in == NULL) || (pos == NULL) || (*pos > in_len))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (wire == GOSSIPSUB_WIRE_VARINT)
    {
        result = gossipsub_read_uvarint(in, in_len, pos, &ignored);
    }
    else if (wire == GOSSIPSUB_WIRE_LEN)
    {
        result = gossipsub_read_uvarint(in, in_len, pos, &ignored);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            if (ignored > (uint64_t)(in_len - *pos))
            {
                result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
            }
            else
            {
                *pos += (size_t)ignored;
            }
        }
    }
    else if (wire == GOSSIPSUB_WIRE_FIXED64)
    {
        if ((in_len - *pos) < 8U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
        }
        else
        {
            *pos += 8U;
        }
    }
    else if (wire == GOSSIPSUB_WIRE_FIXED32)
    {
        if ((in_len - *pos) < 4U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
        }
        else
        {
            *pos += 4U;
        }
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_read_len_span(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    libp2p_gossipsub_bytes_t *out)
{
    uint64_t len = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((in == NULL) || (pos == NULL) || (out == NULL) || (*pos > in_len))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_read_uvarint(in, in_len, pos, &len);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            if (len > (uint64_t)(in_len - *pos))
            {
                result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
            }
            else
            {
                out->data = &in[*pos];
                out->len = (size_t)len;
                *pos += (size_t)len;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_message_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_message_t *message,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (message == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (message->topic.data == NULL) || (message->topic.len == 0U) ||
        (message->topic.len > limits->max_topic_bytes) ||
        (message->data.len > limits->max_message_data_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        if (gossipsub_bytes_present(&message->from) != 0)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_FROM,
                GOSSIPSUB_WIRE_LEN,
                message->from.len,
                &total);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->data) != 0))
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_DATA,
                GOSSIPSUB_WIRE_LEN,
                message->data.len,
                &total);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->seqno) != 0))
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_SEQNO,
                GOSSIPSUB_WIRE_LEN,
                message->seqno.len,
                &total);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_TOPIC,
                GOSSIPSUB_WIRE_LEN,
                message->topic.len,
                &total);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->signature) != 0))
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_SIGNATURE,
                GOSSIPSUB_WIRE_LEN,
                message->signature.len,
                &total);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->key) != 0))
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_MSG_KEY,
                GOSSIPSUB_WIRE_LEN,
                message->key.len,
                &total);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_message_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t pos = 0U;
    size_t required = 0U;
    libp2p_gossipsub_err_t result = gossipsub_message_size(limits, message, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_bytes_present(&message->from) != 0)
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_FROM,
                message->from.data,
                message->from.len,
                out,
                out_len,
                &pos);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->data) != 0))
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_DATA,
                message->data.data,
                message->data.len,
                out,
                out_len,
                &pos);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->seqno) != 0))
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_SEQNO,
                message->seqno.data,
                message->seqno.len,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_TOPIC,
                message->topic.data,
                message->topic.len,
                out,
                out_len,
                &pos);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->signature) != 0))
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_SIGNATURE,
                message->signature.data,
                message->signature.len,
                out,
                out_len,
                &pos);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_bytes_present(&message->key) != 0))
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_MSG_KEY,
                message->key.data,
                message->key.len,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_message_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_message_t *out)
{
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
        out->raw_message.data = in;
        out->raw_message.len = in_len;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if (wire != GOSSIPSUB_WIRE_LEN)
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
            else if (field == GOSSIPSUB_FIELD_MSG_FROM)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->from);
            }
            else if (field == GOSSIPSUB_FIELD_MSG_DATA)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->data);
                if ((result == LIBP2P_GOSSIPSUB_OK) &&
                    (out->data.len > limits->max_message_data_bytes))
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
            }
            else if (field == GOSSIPSUB_FIELD_MSG_SEQNO)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->seqno);
            }
            else if (field == GOSSIPSUB_FIELD_MSG_TOPIC)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->topic);
                if ((result == LIBP2P_GOSSIPSUB_OK) && (out->topic.len > limits->max_topic_bytes))
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
            }
            else if (field == GOSSIPSUB_FIELD_MSG_SIGNATURE)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->signature);
            }
            else if (field == GOSSIPSUB_FIELD_MSG_KEY)
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->key);
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out->topic.data == NULL) || (out->topic.len == 0U)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_sub_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_subscription_t *sub,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (sub == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (sub->topic.data == NULL) || (sub->topic.len == 0U) ||
        (sub->topic.len > limits->max_topic_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        result = gossipsub_field_size(
            GOSSIPSUB_FIELD_SUB_SUBSCRIBE,
            GOSSIPSUB_WIRE_VARINT,
            (sub->subscribe != 0U) ? 1ULL : 0ULL,
            &total);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_SUB_TOPIC,
                GOSSIPSUB_WIRE_LEN,
                sub->topic.len,
                &total);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_sub_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_subscription_t *sub,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_sub_size(limits, sub, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_varint_field(
            GOSSIPSUB_FIELD_SUB_SUBSCRIBE,
            (sub->subscribe != 0U) ? 1ULL : 0ULL,
            out,
            out_len,
            &pos);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_field(
                GOSSIPSUB_FIELD_SUB_TOPIC,
                sub->topic.data,
                sub->topic.len,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_sub_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_subscription_t *out)
{
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_SUB_SUBSCRIBE) && (wire == GOSSIPSUB_WIRE_VARINT))
            {
                uint64_t subscribe = 0U;

                result = gossipsub_read_uvarint(in, in_len, &pos, &subscribe);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    out->subscribe = (subscribe != 0U) ? 1U : 0U;
                }
            }
            else if ((field == GOSSIPSUB_FIELD_SUB_TOPIC) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->topic);
                if ((result == LIBP2P_GOSSIPSUB_OK) && (out->topic.len > limits->max_topic_bytes))
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out->topic.data == NULL) || (out->topic.len == 0U)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_message_id_list_size(
    uint32_t field,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_bytes_t *message_ids,
    size_t message_id_count,
    size_t *total)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (total == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (message_id_count > limits->max_message_ids_per_rpc)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < message_id_count);
             index++)
        {
            if ((message_ids == NULL) || (message_ids[index].data == NULL) ||
                (message_ids[index].len == 0U) ||
                (message_ids[index].len > limits->max_message_id_bytes))
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else
            {
                result =
                    gossipsub_field_size(field, GOSSIPSUB_WIRE_LEN, message_ids[index].len, total);
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_message_id_list_encode(
    uint32_t field,
    const libp2p_gossipsub_bytes_t *message_ids,
    size_t message_id_count,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((out == NULL) || (pos == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < message_id_count);
             index++)
        {
            result = gossipsub_write_len_field(
                field,
                message_ids[index].data,
                message_ids[index].len,
                out,
                out_len,
                pos);
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_ihave_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_ihave_t *ihave,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (ihave == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (ihave->topic.data == NULL) || (ihave->topic.len == 0U) ||
        (ihave->topic.len > limits->max_topic_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        result = gossipsub_field_size(
            GOSSIPSUB_FIELD_IHAVE_TOPIC,
            GOSSIPSUB_WIRE_LEN,
            ihave->topic.len,
            &total);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_message_id_list_size(
                GOSSIPSUB_FIELD_IHAVE_MESSAGE_IDS,
                limits,
                ihave->message_ids,
                ihave->message_id_count,
                &total);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_ihave_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_ihave_t *ihave,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_ihave_size(limits, ihave, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_len_field(
            GOSSIPSUB_FIELD_IHAVE_TOPIC,
            ihave->topic.data,
            ihave->topic.len,
            out,
            out_len,
            &pos);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_message_id_list_encode(
                GOSSIPSUB_FIELD_IHAVE_MESSAGE_IDS,
                ihave->message_ids,
                ihave->message_id_count,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_ihave_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_ihave_t *out)
{
    size_t pos = 0U;
    size_t start = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (storage == NULL) || (cursor == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
        start = cursor->message_id_next;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_IHAVE_TOPIC) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->topic);
            }
            else if ((field == GOSSIPSUB_FIELD_IHAVE_MESSAGE_IDS) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                if (cursor->message_id_next >= storage->message_id_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_read_len_span(
                        in,
                        in_len,
                        &pos,
                        &storage->message_ids[cursor->message_id_next]);
                    if ((result == LIBP2P_GOSSIPSUB_OK) &&
                        (storage->message_ids[cursor->message_id_next].len >
                         limits->max_message_id_bytes))
                    {
                        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                    }
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        cursor->message_id_next++;
                    }
                }
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        out->message_ids = &storage->message_ids[start];
        out->message_id_count = cursor->message_id_next - start;
        if ((out->topic.data == NULL) || (out->topic.len == 0U) ||
            (out->topic.len > limits->max_topic_bytes) ||
            (out->message_id_count > limits->max_message_ids_per_rpc))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_iwant_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_iwant_t *iwant,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (iwant == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_message_id_list_size(
            GOSSIPSUB_FIELD_IWANT_MESSAGE_IDS,
            limits,
            iwant->message_ids,
            iwant->message_id_count,
            &total);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_iwant_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_iwant_t *iwant,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_iwant_size(limits, iwant, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_message_id_list_encode(
            GOSSIPSUB_FIELD_IWANT_MESSAGE_IDS,
            iwant->message_ids,
            iwant->message_id_count,
            out,
            out_len,
            &pos);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_iwant_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_iwant_t *out)
{
    size_t pos = 0U;
    size_t start = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (storage == NULL) || (cursor == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
        start = cursor->message_id_next;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_IWANT_MESSAGE_IDS) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                if (cursor->message_id_next >= storage->message_id_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_read_len_span(
                        in,
                        in_len,
                        &pos,
                        &storage->message_ids[cursor->message_id_next]);
                    if ((result == LIBP2P_GOSSIPSUB_OK) &&
                        (storage->message_ids[cursor->message_id_next].len >
                         limits->max_message_id_bytes))
                    {
                        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                    }
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        cursor->message_id_next++;
                    }
                }
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        out->message_ids = &storage->message_ids[start];
        out->message_id_count = cursor->message_id_next - start;
        if (out->message_id_count > limits->max_message_ids_per_rpc)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_topic_control_size(
    const libp2p_gossipsub_limits_t *limits,
    libp2p_gossipsub_bytes_t topic,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((topic.data == NULL) || (topic.len == 0U) || (topic.len > limits->max_topic_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        result = gossipsub_field_size(
            GOSSIPSUB_FIELD_GRAFT_TOPIC,
            GOSSIPSUB_WIRE_LEN,
            topic.len,
            &total);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_topic_control_encode(
    const libp2p_gossipsub_limits_t *limits,
    libp2p_gossipsub_bytes_t topic,
    uint32_t field,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_topic_control_size(limits, topic, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_len_field(field, topic.data, topic.len, out, out_len, &pos);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_graft_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_control_graft_t *out)
{
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_GRAFT_TOPIC) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->topic);
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out->topic.data == NULL) || (out->topic.len == 0U) ||
                                            (out->topic.len > limits->max_topic_bytes)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_peer_info_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_peer_info_t *out)
{
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_PEER_INFO_PEER_ID) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->peer_id);
            }
            else if (
                (field == GOSSIPSUB_FIELD_PEER_INFO_SIGNED_PEER_RECORD) &&
                (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->signed_peer_record);
                if ((result == LIBP2P_GOSSIPSUB_OK) &&
                    (out->signed_peer_record.len > limits->max_signed_peer_record_bytes))
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_prune_size(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_prune_t *prune,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (prune == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (prune->topic.data == NULL) || (prune->topic.len == 0U) ||
        (prune->topic.len > limits->max_topic_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        result = gossipsub_field_size(
            GOSSIPSUB_FIELD_PRUNE_TOPIC,
            GOSSIPSUB_WIRE_LEN,
            prune->topic.len,
            &total);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (prune->backoff_seconds != 0U))
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_PRUNE_BACKOFF,
                GOSSIPSUB_WIRE_VARINT,
                (size_t)prune->backoff_seconds,
                &total);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_prune_encode(
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_prune_t *prune,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_prune_size(limits, prune, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_len_field(
            GOSSIPSUB_FIELD_PRUNE_TOPIC,
            prune->topic.data,
            prune->topic.len,
            out,
            out_len,
            &pos);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (prune->backoff_seconds != 0U))
        {
            result = gossipsub_write_varint_field(
                GOSSIPSUB_FIELD_PRUNE_BACKOFF,
                prune->backoff_seconds,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_prune_decode(
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_prune_t *out)
{
    size_t pos = 0U;
    size_t start = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (storage == NULL) || (cursor == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
        start = cursor->peer_info_next;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;

        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if ((field == GOSSIPSUB_FIELD_PRUNE_TOPIC) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &out->topic);
            }
            else if ((field == GOSSIPSUB_FIELD_PRUNE_PEERS) && (wire == GOSSIPSUB_WIRE_LEN))
            {
                libp2p_gossipsub_bytes_t peer_info_bytes;

                (void)memset(&peer_info_bytes, 0, sizeof(peer_info_bytes));
                if (cursor->peer_info_next >= storage->peer_info_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_read_len_span(in, in_len, &pos, &peer_info_bytes);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        result = gossipsub_peer_info_decode(
                            limits,
                            peer_info_bytes.data,
                            peer_info_bytes.len,
                            &storage->peer_infos[cursor->peer_info_next]);
                    }
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        cursor->peer_info_next++;
                    }
                }
            }
            else if ((field == GOSSIPSUB_FIELD_PRUNE_BACKOFF) && (wire == GOSSIPSUB_WIRE_VARINT))
            {
                result = gossipsub_read_uvarint(in, in_len, &pos, &out->backoff_seconds);
            }
            else
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        out->peers = &storage->peer_infos[start];
        out->peer_count = cursor->peer_info_next - start;
        if ((out->topic.data == NULL) || (out->topic.len == 0U) ||
            (out->topic.len > limits->max_topic_bytes) ||
            (out->peer_count > limits->max_px_peers_per_rpc))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_idontwant_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    size_t *out_len)
{
    size_t total = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (idontwant == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (version != LIBP2P_GOSSIPSUB_VERSION_12)
    {
        result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
    }
    else
    {
        result = gossipsub_message_id_list_size(
            GOSSIPSUB_FIELD_IDONTWANT_MESSAGE_IDS,
            limits,
            idontwant->message_ids,
            idontwant->message_id_count,
            &total);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_idontwant_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_idontwant_size(version, limits, idontwant, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_message_id_list_encode(
            GOSSIPSUB_FIELD_IDONTWANT_MESSAGE_IDS,
            idontwant->message_ids,
            idontwant->message_id_count,
            out,
            out_len,
            &pos);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = pos;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_control_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    size_t *out_len);

static libp2p_gossipsub_err_t gossipsub_control_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    uint8_t *out,
    size_t out_len,
    size_t *written);

static libp2p_gossipsub_err_t gossipsub_control_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    libp2p_gossipsub_rpc_control_t *out);

static libp2p_gossipsub_err_t gossipsub_control_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    size_t *out_len)
{
    size_t total = 0U;
    size_t nested = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (control == NULL) || (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (control->ihave_count > limits->max_ihave_per_rpc) ||
        (control->iwant_count > limits->max_iwant_per_rpc) ||
        (control->graft_count > limits->max_graft_per_rpc) ||
        (control->prune_count > limits->max_prune_per_rpc) ||
        (control->idontwant_count > limits->max_idontwant_per_rpc))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else if ((control->idontwant_count != 0U) && (version != LIBP2P_GOSSIPSUB_VERSION_12))
    {
        result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
    }
    else
    {
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->ihave_count);
             index++)
        {
            result = gossipsub_ihave_size(limits, &control->ihave[index], &nested);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_field_size(
                    GOSSIPSUB_FIELD_CONTROL_IHAVE,
                    GOSSIPSUB_WIRE_LEN,
                    nested,
                    &total);
            }
        }
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->iwant_count);
             index++)
        {
            result = gossipsub_iwant_size(limits, &control->iwant[index], &nested);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_field_size(
                    GOSSIPSUB_FIELD_CONTROL_IWANT,
                    GOSSIPSUB_WIRE_LEN,
                    nested,
                    &total);
            }
        }
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->graft_count);
             index++)
        {
            result = gossipsub_topic_control_size(limits, control->graft[index].topic, &nested);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_field_size(
                    GOSSIPSUB_FIELD_CONTROL_GRAFT,
                    GOSSIPSUB_WIRE_LEN,
                    nested,
                    &total);
            }
        }
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->prune_count);
             index++)
        {
            result = gossipsub_prune_size(limits, &control->prune[index], &nested);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_field_size(
                    GOSSIPSUB_FIELD_CONTROL_PRUNE,
                    GOSSIPSUB_WIRE_LEN,
                    nested,
                    &total);
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < control->idontwant_count);
             index++)
        {
            result = gossipsub_idontwant_size(version, limits, &control->idontwant[index], &nested);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = gossipsub_field_size(
                    GOSSIPSUB_FIELD_CONTROL_IDONTWANT,
                    GOSSIPSUB_WIRE_LEN,
                    nested,
                    &total);
            }
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_limits_validate(const libp2p_gossipsub_limits_t *limits)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (limits == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (limits->max_rpc_bytes == 0U) || (limits->max_message_data_bytes > limits->max_rpc_bytes) ||
        (limits->max_topic_bytes == 0U) ||
        (limits->max_topic_bytes > LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES) ||
        (limits->max_message_id_bytes == 0U) ||
        (limits->max_message_id_bytes > LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES) ||
        (limits->max_signed_peer_record_bytes >
         LIBP2P_GOSSIPSUB_DEFAULT_MAX_SIGNED_PEER_REC_BYTES) ||
        (limits->max_subscriptions_per_rpc == 0U) || (limits->max_publish_per_rpc == 0U) ||
        (limits->max_ihave_per_rpc == 0U) || (limits->max_iwant_per_rpc == 0U) ||
        (limits->max_graft_per_rpc == 0U) || (limits->max_prune_per_rpc == 0U) ||
        (limits->max_idontwant_per_rpc == 0U) || (limits->max_message_ids_per_rpc == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_version_validate(
    libp2p_gossipsub_protocol_version_t version)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((version != LIBP2P_GOSSIPSUB_VERSION_11) && (version != LIBP2P_GOSSIPSUB_VERSION_12))
    {
        result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    size_t *out_len)
{
    size_t total = 0U;
    size_t nested = 0U;
    libp2p_gossipsub_err_t result = gossipsub_version_validate(version);

    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_limits_validate(limits);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((rpc == NULL) || (out_len == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (result == LIBP2P_GOSSIPSUB_OK) &&
        ((rpc->subscription_count > limits->max_subscriptions_per_rpc) ||
         (rpc->publish_count > limits->max_publish_per_rpc)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        (void)result;
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->subscription_count);
         index++)
    {
        result = gossipsub_sub_size(limits, &rpc->subscriptions[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_RPC_SUBSCRIPTIONS,
                GOSSIPSUB_WIRE_LEN,
                nested,
                &total);
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->publish_count);
         index++)
    {
        result = gossipsub_message_size(limits, &rpc->publish[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_RPC_PUBLISH,
                GOSSIPSUB_WIRE_LEN,
                nested,
                &total);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((rpc->control.ihave_count != 0U) || (rpc->control.iwant_count != 0U) ||
         (rpc->control.graft_count != 0U) || (rpc->control.prune_count != 0U) ||
         (rpc->control.idontwant_count != 0U)))
    {
        result = gossipsub_control_size(version, limits, &rpc->control, &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_field_size(
                GOSSIPSUB_FIELD_RPC_CONTROL,
                GOSSIPSUB_WIRE_LEN,
                nested,
                &total);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (total > limits->max_rpc_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *out_len = total;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t nested = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = libp2p_gossipsub_rpc_body_size(version, limits, rpc, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else
    {
        (void)result;
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->subscription_count);
         index++)
    {
        result = gossipsub_sub_size(limits, &rpc->subscriptions[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_RPC_SUBSCRIPTIONS,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_sub_encode(
                limits,
                &rpc->subscriptions[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->publish_count);
         index++)
    {
        result = gossipsub_message_size(limits, &rpc->publish[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result =
                gossipsub_write_len_prefix(GOSSIPSUB_FIELD_RPC_PUBLISH, nested, out, out_len, &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_message_encode(
                limits,
                &rpc->publish[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((rpc->control.ihave_count != 0U) || (rpc->control.iwant_count != 0U) ||
         (rpc->control.graft_count != 0U) || (rpc->control.prune_count != 0U) ||
         (rpc->control.idontwant_count != 0U)))
    {
        result = gossipsub_control_size(version, limits, &rpc->control, &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result =
                gossipsub_write_len_prefix(GOSSIPSUB_FIELD_RPC_CONTROL, nested, out, out_len, &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_control_encode(
                version,
                limits,
                &rpc->control,
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *written = pos;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_body_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *decode_storage,
    libp2p_gossipsub_rpc_t *out_rpc)
{
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_version_validate(version);

    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_limits_validate(limits);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((in == NULL) || (decode_storage == NULL) || (out_rpc == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (in_len > limits->max_rpc_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        (void)result;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        (void)memset(out_rpc, 0, sizeof(*out_rpc));
        out_rpc->subscriptions = decode_storage->subscriptions;
        out_rpc->publish = decode_storage->publish;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;
        libp2p_gossipsub_bytes_t nested;

        (void)memset(&nested, 0, sizeof(nested));
        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if (wire != GOSSIPSUB_WIRE_LEN)
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
            else
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &nested);
            }
            if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_RPC_SUBSCRIPTIONS))
            {
                if (out_rpc->subscription_count >= decode_storage->subscription_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_sub_decode(
                        limits,
                        nested.data,
                        nested.len,
                        &decode_storage->subscriptions[out_rpc->subscription_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out_rpc->subscription_count++;
                    }
                }
            }
            else if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_RPC_PUBLISH))
            {
                if (out_rpc->publish_count >= decode_storage->publish_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_message_decode(
                        limits,
                        nested.data,
                        nested.len,
                        &decode_storage->publish[out_rpc->publish_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out_rpc->publish_count++;
                    }
                }
            }
            else if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_RPC_CONTROL))
            {
                result = gossipsub_control_decode(
                    version,
                    limits,
                    nested.data,
                    nested.len,
                    decode_storage,
                    &out_rpc->control);
            }
            else
            {
                (void)field;
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((out_rpc->subscription_count > limits->max_subscriptions_per_rpc) ||
         (out_rpc->publish_count > limits->max_publish_per_rpc)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_size(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    size_t *out_len)
{
    size_t body_len = 0U;
    libp2p_gossipsub_err_t result = libp2p_gossipsub_rpc_body_size(version, limits, rpc, &body_len);

    if ((result == LIBP2P_GOSSIPSUB_OK) && (out_len == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_add(
                (size_t)libp2p_uvarint_size((uint64_t)body_len),
                body_len,
                out_len) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    else
    {
        (void)result;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_t *rpc,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t body_len = 0U;
    size_t frame_len = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result =
        libp2p_gossipsub_rpc_frame_size(version, limits, rpc, &frame_len);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (frame_len > out_len))
    {
        *written = frame_len;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_body_size(version, limits, rpc, &body_len);
    }
    else
    {
        (void)result;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_write_uvarint((uint64_t)body_len, out, out_len, &pos);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_body_encode(
            version,
            limits,
            rpc,
            &out[pos],
            out_len - pos,
            &body_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *written = pos + body_len;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_rpc_frame_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *decode_storage,
    libp2p_gossipsub_rpc_t *out_rpc)
{
    uint64_t body_len = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_version_validate(version);

    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_limits_validate(limits);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((in == NULL) || (decode_storage == NULL) || (out_rpc == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_read_uvarint(in, in_len, &pos, &body_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if ((body_len > (uint64_t)limits->max_rpc_bytes) || (body_len > (uint64_t)(in_len - pos)))
        {
            result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
        }
        else if (((size_t)body_len + pos) != in_len)
        {
            result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
        }
        else
        {
            result = libp2p_gossipsub_rpc_body_decode(
                version,
                limits,
                &in[pos],
                (size_t)body_len,
                decode_storage,
                out_rpc);
        }
    }

    return result;
}

typedef struct
{
    size_t router_offset;
    size_t topics_offset;
    size_t peers_offset;
    size_t peer_topics_offset;
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

static libp2p_host_err_t gossipsub_protocol_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data);

static libp2p_host_err_t gossipsub_protocol_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data);

static libp2p_gossipsub_err_t gossipsub_enqueue_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    uint8_t subscribe);

static libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry);

static libp2p_gossipsub_err_t gossipsub_forward_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t source_peer_index,
    const gossipsub_mcache_entry_t *entry);

static libp2p_gossipsub_err_t gossipsub_config_validate_storage(
    const libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (config == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_limits_validate(&config->limits);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if ((config->capacity.max_topics == 0U) || (config->capacity.max_peers == 0U) ||
            (config->capacity.max_peer_topics == 0U) || (config->capacity.max_streams == 0U) ||
            (config->capacity.max_tx_rpc_queue == 0U) || (config->capacity.tx_buffer_bytes == 0U) ||
            (config->capacity.mcache_slots == 0U) || (config->capacity.mcache_bytes == 0U) ||
            (config->capacity.seen_entries == 0U) || (config->capacity.pending_validations == 0U) ||
            (config->capacity.idontwant_entries == 0U) || (config->capacity.event_capacity == 0U) ||
            (config->capacity.max_drive_steps == 0U) || (config->mesh.mcache_len == 0U) ||
            (config->mesh.mcache_len > UINT8_MAX) ||
            (config->mesh.mcache_gossip > config->mesh.mcache_len) ||
            (config->protocol_mask == 0U) ||
            ((config->protocol_mask & ~LIBP2P_GOSSIPSUB_PROTOCOL_MASK_ALL) != 0U) ||
            (config->idontwant_min_message_bytes > config->limits.max_message_data_bytes))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_config_validate_init(
    const libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = gossipsub_config_validate_storage(config);

    if ((result == LIBP2P_GOSSIPSUB_OK) &&
        ((config->random_fn == NULL) || (config->message_id_fn == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_storage_layout(
    const libp2p_gossipsub_config_t *config,
    gossipsub_storage_layout_t *layout)
{
    size_t cursor = 0U;
    size_t bytes = 0U;
    libp2p_gossipsub_err_t result = gossipsub_config_validate_storage(config);

    if ((result == LIBP2P_GOSSIPSUB_OK) && (layout == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        (void)memset(layout, 0, sizeof(*layout));
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            sizeof(libp2p_gossipsub_t),
            &layout->router_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_topics,
                sizeof(gossipsub_topic_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->topics_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_peers,
                sizeof(gossipsub_peer_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->peers_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_peer_topics,
                sizeof(gossipsub_peer_topic_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->peer_topics_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_streams,
                sizeof(gossipsub_stream_state_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->streams_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_add(
                config->limits.max_rpc_bytes,
                LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES,
                &layout->stream_rx_stride) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else if (
            gossipsub_size_mul(config->capacity.max_streams, layout->stream_rx_stride, &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->stream_rx_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.max_tx_rpc_queue,
                sizeof(gossipsub_tx_item_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->tx_queue_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            config->capacity.tx_buffer_bytes,
            &layout->tx_buffer_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.mcache_slots,
                sizeof(gossipsub_mcache_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->mcache_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_reserve(
            &cursor,
            GOSSIPSUB_STORAGE_ALIGN,
            config->capacity.mcache_bytes,
            &layout->mcache_data_offset);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.seen_entries,
                sizeof(gossipsub_seen_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->seen_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.pending_validations,
                sizeof(struct libp2p_gossipsub_validation),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->validations_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.idontwant_entries,
                sizeof(gossipsub_idontwant_entry_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_reserve(
                &cursor,
                GOSSIPSUB_STORAGE_ALIGN,
                bytes,
                &layout->idontwant_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_size_mul(
                config->capacity.event_capacity,
                sizeof(libp2p_gossipsub_event_t),
                &bytes) != 0)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result =
                gossipsub_reserve(&cursor, GOSSIPSUB_STORAGE_ALIGN, bytes, &layout->events_offset);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        layout->total = cursor;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_config_default(libp2p_gossipsub_config_t *config)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (config == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(config, 0, sizeof(*config));
        config->limits.max_rpc_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_RPC_BYTES;
        config->limits.max_message_data_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_DATA_BYTES;
        config->limits.max_topic_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPIC_BYTES;
        config->limits.max_message_id_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES;
        config->limits.max_signed_peer_record_bytes =
            LIBP2P_GOSSIPSUB_DEFAULT_MAX_SIGNED_PEER_REC_BYTES;
        config->limits.max_subscriptions_per_rpc =
            LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC;
        config->limits.max_publish_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC;
        config->limits.max_ihave_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC;
        config->limits.max_iwant_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC;
        config->limits.max_graft_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC;
        config->limits.max_prune_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC;
        config->limits.max_idontwant_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC;
        config->limits.max_message_ids_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC;
        config->limits.max_px_peers_per_rpc = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC;

        config->mesh.d = LIBP2P_GOSSIPSUB_DEFAULT_D;
        config->mesh.d_low = LIBP2P_GOSSIPSUB_DEFAULT_D_LOW;
        config->mesh.d_high = LIBP2P_GOSSIPSUB_DEFAULT_D_HIGH;
        config->mesh.d_lazy = LIBP2P_GOSSIPSUB_DEFAULT_D_LAZY;
        config->mesh.d_score = LIBP2P_GOSSIPSUB_DEFAULT_D_SCORE;
        config->mesh.d_out = LIBP2P_GOSSIPSUB_DEFAULT_D_OUT;
        config->mesh.mcache_len = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_LEN;
        config->mesh.mcache_gossip = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_GOSSIP;
        config->mesh.gossip_factor_ppm = LIBP2P_GOSSIPSUB_DEFAULT_GOSSIP_FACTOR_PPM;
        config->mesh.heartbeat_interval_us = LIBP2P_GOSSIPSUB_DEFAULT_HEARTBEAT_US;
        config->mesh.fanout_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_FANOUT_TTL_US;
        config->mesh.seen_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_SEEN_TTL_US;
        config->mesh.prune_backoff_us = LIBP2P_GOSSIPSUB_DEFAULT_PRUNE_BACKOFF_US;
        config->mesh.unsubscribe_backoff_us = LIBP2P_GOSSIPSUB_DEFAULT_UNSUBSCRIBE_BACKOFF_US;
        config->mesh.backoff_slack_us = LIBP2P_GOSSIPSUB_DEFAULT_BACKOFF_SLACK_US;
        config->mesh.iwant_followup_us = LIBP2P_GOSSIPSUB_DEFAULT_IWANT_FOLLOWUP_US;
        config->mesh.score_decay_interval_us = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_DECAY_US;
        config->mesh.retain_score_us = LIBP2P_GOSSIPSUB_DEFAULT_RETAIN_SCORE_US;
        config->mesh.opportunistic_graft_interval_us = LIBP2P_GOSSIPSUB_DEFAULT_OPPORTUNISTIC_US;
        config->mesh.opportunistic_graft_peers = LIBP2P_GOSSIPSUB_DEFAULT_OPPORTUNISTIC_PEERS;
        config->mesh.enable_flood_publish = 1U;
        config->mesh.enable_px = 0U;
        config->mesh.enable_opportunistic_graft = 0U;

        config->score.gossip_threshold = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_GOSSIP_THRESHOLD;
        config->score.publish_threshold = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_PUBLISH_THRESHOLD;
        config->score.graylist_threshold = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_GRAYLIST_THRESHOLD;
        config->score.accept_px_threshold = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_ACCEPT_PX_THRESHOLD;
        config->score.opportunistic_graft_threshold =
            LIBP2P_GOSSIPSUB_DEFAULT_SCORE_OPPORTUNISTIC_GRAFT_THRESHOLD;
        config->score.app_specific_weight = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_APP_SPECIFIC_WEIGHT;
        config->score.ip_colocation_factor_weight =
            LIBP2P_GOSSIPSUB_DEFAULT_SCORE_IP_COLOCATION_FACTOR_WEIGHT;
        config->score.ip_colocation_factor_threshold =
            LIBP2P_GOSSIPSUB_DEFAULT_SCORE_IP_COLOCATION_FACTOR_THRESHOLD;
        config->score.behaviour_penalty_weight =
            LIBP2P_GOSSIPSUB_DEFAULT_SCORE_BEHAVIOUR_PENALTY_WEIGHT;
        config->score.behaviour_penalty_decay_ppm =
            LIBP2P_GOSSIPSUB_DEFAULT_SCORE_BEHAVIOUR_PENALTY_DECAY_PPM;
        config->score.decay_to_zero_ppm = LIBP2P_GOSSIPSUB_DEFAULT_SCORE_DECAY_TO_ZERO_PPM;

        config->capacity.max_topics = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TOPICS;
        config->capacity.max_peers = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEERS;
        config->capacity.max_peer_topics = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PEER_TOPICS;
        config->capacity.max_mesh_edges = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESH_EDGES;
        config->capacity.max_fanout_edges = LIBP2P_GOSSIPSUB_DEFAULT_MAX_FANOUT_EDGES;
        config->capacity.max_backoff_entries = LIBP2P_GOSSIPSUB_DEFAULT_MAX_BACKOFF_ENTRIES;
        config->capacity.max_streams = LIBP2P_GOSSIPSUB_DEFAULT_MAX_STREAMS;
        config->capacity.max_pending_opens = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PENDING_OPENS;
        config->capacity.max_tx_rpc_queue = LIBP2P_GOSSIPSUB_DEFAULT_MAX_TX_RPC_QUEUE;
        config->capacity.tx_buffer_bytes = LIBP2P_GOSSIPSUB_DEFAULT_TX_BUFFER_BYTES;
        config->capacity.mcache_slots = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_SLOTS;
        config->capacity.mcache_bytes = LIBP2P_GOSSIPSUB_DEFAULT_MCACHE_BYTES;
        config->capacity.seen_entries = LIBP2P_GOSSIPSUB_DEFAULT_SEEN_ENTRIES;
        config->capacity.pending_validations = LIBP2P_GOSSIPSUB_DEFAULT_PENDING_VALIDATIONS;
        config->capacity.idontwant_entries = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_ENTRIES;
        config->capacity.event_capacity = LIBP2P_GOSSIPSUB_DEFAULT_EVENT_CAPACITY;
        config->capacity.max_drive_steps = LIBP2P_GOSSIPSUB_DEFAULT_MAX_DRIVE_STEPS;

        config->protocol_mask = LIBP2P_GOSSIPSUB_PROTOCOL_MASK_ALL;
        config->preferred_protocol = LIBP2P_GOSSIPSUB_VERSION_12;
        config->enable_idontwant = 1U;
        config->idontwant_min_message_bytes = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_MIN_BYTES;
        config->max_idontwant_messages_per_peer_per_heartbeat =
            LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_PER_PEER;
        config->idontwant_ttl_us = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_TTL_US;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_storage_size(
    const libp2p_gossipsub_config_t *config,
    size_t *out_len)
{
    gossipsub_storage_layout_t layout;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&layout, 0, sizeof(layout));
    if (out_len == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_storage_layout(config, &layout);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *out_len = layout.total;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_storage_align(size_t *out_align)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (out_align == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        *out_align = GOSSIPSUB_STORAGE_ALIGN;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_init(
    void *storage,
    size_t storage_len,
    const libp2p_gossipsub_config_t *config,
    libp2p_gossipsub_t **out_gossipsub)
{
    gossipsub_storage_layout_t layout;
    libp2p_gossipsub_t *gossipsub = NULL;
    uint8_t *rx_base = NULL;
    const void *storage_ptr = NULL;
    libp2p_gossipsub_err_t result = gossipsub_config_validate_init(config);

    (void)memset(&layout, 0, sizeof(layout));
    if (out_gossipsub != NULL)
    {
        *out_gossipsub = NULL;
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((storage == NULL) || (out_gossipsub == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_storage_layout(config, &layout);
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (storage_len < layout.total))
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        (void)memset(storage, 0, layout.total);
        gossipsub = gossipsub_storage_router(storage);
        storage_ptr = gossipsub_storage_at(storage, layout.stream_rx_offset);
        gossipsub_pointer_store((void *)&rx_base, storage_ptr);
        gossipsub->config = *config;
        gossipsub->storage_base = gossipsub_storage_bytes(storage);
        gossipsub->storage_len = storage_len;
        storage_ptr = gossipsub_storage_at(storage, layout.topics_offset);
        gossipsub_pointer_store((void *)&gossipsub->topics, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.peers_offset);
        gossipsub_pointer_store((void *)&gossipsub->peers, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.peer_topics_offset);
        gossipsub_pointer_store((void *)&gossipsub->peer_topics, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.streams_offset);
        gossipsub_pointer_store((void *)&gossipsub->streams, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.tx_queue_offset);
        gossipsub_pointer_store((void *)&gossipsub->tx_queue, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.tx_buffer_offset);
        gossipsub_pointer_store((void *)&gossipsub->tx_buffer, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.mcache_offset);
        gossipsub_pointer_store((void *)&gossipsub->mcache, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.mcache_data_offset);
        gossipsub_pointer_store((void *)&gossipsub->mcache_data, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.seen_offset);
        gossipsub_pointer_store((void *)&gossipsub->seen, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.validations_offset);
        gossipsub_pointer_store((void *)&gossipsub->validations, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.idontwant_offset);
        gossipsub_pointer_store((void *)&gossipsub->idontwant, storage_ptr);
        storage_ptr = gossipsub_storage_at(storage, layout.events_offset);
        gossipsub_pointer_store((void *)&gossipsub->events, storage_ptr);
        gossipsub->protocol_user_data[0].gossipsub = gossipsub;
        gossipsub->protocol_user_data[0].version = LIBP2P_GOSSIPSUB_VERSION_12;
        gossipsub->protocol_user_data[1].gossipsub = gossipsub;
        gossipsub->protocol_user_data[1].version = LIBP2P_GOSSIPSUB_VERSION_11;
        for (size_t index = 0U; index < config->capacity.max_streams; index++)
        {
            gossipsub->streams[index].rx = &rx_base[index * layout.stream_rx_stride];
        }
        *out_gossipsub = gossipsub;
    }

    return result;
}

void libp2p_gossipsub_deinit(libp2p_gossipsub_t *gossipsub)
{
    if (gossipsub != NULL)
    {
        gossipsub->started = 0U;
        gossipsub->closing = 1U;
    }
}

static libp2p_gossipsub_err_t gossipsub_event_push(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_event_t *event)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->event_len == gossipsub->config.capacity.event_capacity)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        const size_t pos = (gossipsub->event_head + gossipsub->event_len) %
                           gossipsub->config.capacity.event_capacity;

        gossipsub->events[pos] = *event;
        gossipsub->event_len++;
    }

    return result;
}

static void gossipsub_peer_to_event(
    const gossipsub_peer_state_t *peer,
    libp2p_gossipsub_event_t *event)
{
    if ((peer != NULL) && (event != NULL))
    {
        event->conn = peer->conn;
        event->stream = peer->stream;
        event->direction = peer->direction;
        event->protocol_version = peer->version;
        event->peer.len = peer->peer_id_len;
        if (peer->peer_id_len != 0U)
        {
            (void)memcpy(event->peer.data, peer->peer_id, peer->peer_id_len);
        }
        event->user_data = peer->user_data;
    }
}

static gossipsub_topic_state_t *gossipsub_find_topic(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *topic,
    size_t topic_len,
    size_t *out_index)
{
    gossipsub_topic_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_topics;
    }
    if ((gossipsub != NULL) && (topic != NULL) && (out_index != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_topics; index++)
        {
            if ((gossipsub->topics[index].used == GOSSIPSUB_TOPIC_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->topics[index].topic,
                     gossipsub->topics[index].topic_len,
                     topic,
                     topic_len) != 0))
            {
                result = &gossipsub->topics[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

static gossipsub_topic_state_t *gossipsub_find_or_add_topic(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic,
    size_t *out_index)
{
    gossipsub_topic_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_topics;
    }
    if ((gossipsub != NULL) && (topic.data != NULL) &&
        (topic.len <= gossipsub->config.limits.max_topic_bytes) && (out_index != NULL))
    {
        result = gossipsub_find_topic(gossipsub, topic.data, topic.len, out_index);
        if (result == NULL)
        {
            for (size_t index = 0U; index < gossipsub->config.capacity.max_topics; index++)
            {
                if (gossipsub->topics[index].used == GOSSIPSUB_TOPIC_FREE)
                {
                    result = &gossipsub->topics[index];
                    (void)memset(result, 0, sizeof(*result));
                    result->used = GOSSIPSUB_TOPIC_USED;
                    result->validation_mode = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL;
                    result->enable_idontwant = gossipsub->config.enable_idontwant;
                    result->idontwant_min_message_bytes =
                        gossipsub->config.idontwant_min_message_bytes;
                    result->topic_len = topic.len;
                    (void)memcpy(result->topic, topic.data, topic.len);
                    *out_index = index;
                    gossipsub->topic_count++;
                    break;
                }
            }
        }
    }

    return result;
}

static gossipsub_peer_state_t *gossipsub_find_peer(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index)
{
    gossipsub_peer_state_t *result = NULL;

    if ((gossipsub != NULL) && (peer_id != NULL) && (out_index != NULL))
    {
        *out_index = gossipsub->config.capacity.max_peers;
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->peers[index].peer_id,
                     gossipsub->peers[index].peer_id_len,
                     peer_id,
                     peer_id_len) != 0))
            {
                result = &gossipsub->peers[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

static const gossipsub_peer_state_t *gossipsub_find_peer_const(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    size_t *out_index)
{
    const gossipsub_peer_state_t *result = NULL;

    if ((gossipsub != NULL) && (peer_id != NULL) && (out_index != NULL))
    {
        *out_index = gossipsub->config.capacity.max_peers;
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub_bytes_equal(
                     gossipsub->peers[index].peer_id,
                     gossipsub->peers[index].peer_id_len,
                     peer_id,
                     peer_id_len) != 0))
            {
                result = &gossipsub->peers[index];
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_peer_from_conn(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_conn_t *conn,
    gossipsub_peer_state_t **out_peer,
    size_t *out_index)
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    size_t index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(peer_id, 0, sizeof(peer_id));
    if ((gossipsub == NULL) || (conn == NULL) || (out_peer == NULL) || (out_index == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(
            libp2p_host_conn_peer_id(conn, peer_id, sizeof(peer_id), &peer_id_len));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &index);
        if (peer == NULL)
        {
            for (index = 0U; index < gossipsub->config.capacity.max_peers; index++)
            {
                if (gossipsub->peers[index].used == GOSSIPSUB_PEER_FREE)
                {
                    peer = &gossipsub->peers[index];
                    (void)memset(peer, 0, sizeof(*peer));
                    peer->used = GOSSIPSUB_PEER_USED;
                    peer->peer_id_len = peer_id_len;
                    (void)memcpy(peer->peer_id, peer_id, peer_id_len);
                    gossipsub->peer_count++;
                    break;
                }
            }
        }
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            peer->conn = conn;
            peer->closed = 0U;
            *out_peer = peer;
            *out_index = index;
        }
    }

    return result;
}

static gossipsub_stream_state_t *gossipsub_alloc_stream(
    libp2p_gossipsub_t *gossipsub,
    size_t *out_index)
{
    gossipsub_stream_state_t *result = NULL;

    if (out_index != NULL)
    {
        *out_index = gossipsub->config.capacity.max_streams;
    }
    if ((gossipsub != NULL) && (out_index != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_streams; index++)
        {
            if (gossipsub->streams[index].state == GOSSIPSUB_STREAM_FREE)
            {
                result = &gossipsub->streams[index];
                result->state = GOSSIPSUB_STREAM_OPEN;
                result->rx_len = 0U;
                *out_index = index;
                break;
            }
        }
    }

    return result;
}

static gossipsub_peer_topic_state_t *gossipsub_find_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    gossipsub_peer_topic_state_t *result = NULL;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
        {
            if ((gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->peer_topics[index].peer_index == peer_index) &&
                (gossipsub->peer_topics[index].topic_index == topic_index))
            {
                result = &gossipsub->peer_topics[index];
                break;
            }
        }
    }

    return result;
}

static gossipsub_peer_topic_state_t *gossipsub_find_or_add_peer_topic(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    gossipsub_peer_topic_state_t *result = NULL;

    if (gossipsub != NULL)
    {
        result = gossipsub_find_peer_topic(gossipsub, peer_index, topic_index);
        if (result == NULL)
        {
            for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
            {
                if (gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_FREE)
                {
                    result = &gossipsub->peer_topics[index];
                    result->used = GOSSIPSUB_EDGE_USED;
                    result->peer_index = peer_index;
                    result->topic_index = topic_index;
                    result->subscribed = 0U;
                    break;
                }
            }
        }
    }

    return result;
}

static int gossipsub_peer_subscribed(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t topic_index)
{
    int result = 0;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peer_topics; index++)
        {
            if ((gossipsub->peer_topics[index].used == GOSSIPSUB_EDGE_USED) &&
                (gossipsub->peer_topics[index].peer_index == peer_index) &&
                (gossipsub->peer_topics[index].topic_index == topic_index) &&
                (gossipsub->peer_topics[index].subscribed != 0U))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_compute_message_id(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (message == NULL) || (written == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub->config.message_id_fn(
            message,
            NULL,
            0U,
            &required,
            gossipsub->config.message_id_user_data);
        if (result == LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL)
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *written = required;
            if ((required == 0U) || (required > gossipsub->config.limits.max_message_id_bytes))
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
            }
            else
            {
                result = gossipsub->config.message_id_fn(
                    message,
                    out,
                    out_len,
                    written,
                    gossipsub->config.message_id_user_data);
            }
        }
    }

    return result;
}

static int gossipsub_seen_contains(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    int result = 0;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used != 0U) &&
                (gossipsub->seen[index].expires_us >= now_us) &&
                (gossipsub_bytes_equal(
                     gossipsub->seen[index].message_id,
                     gossipsub->seen[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

static void gossipsub_seen_add(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    if ((gossipsub != NULL) && (message_id != NULL) &&
        (gossipsub->config.capacity.seen_entries != 0U) &&
        (message_id_len <= gossipsub->config.limits.max_message_id_bytes))
    {
        size_t target = 0U;
        int found = 0;

        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used == 0U) || (gossipsub->seen[index].expires_us < now_us))
            {
                target = index;
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            target = gossipsub->mcache_next % gossipsub->config.capacity.seen_entries;
        }
        gossipsub->seen[target].used = 1U;
        gossipsub->seen[target].message_id_len = message_id_len;
        (void)memcpy(gossipsub->seen[target].message_id, message_id, message_id_len);
        gossipsub->seen[target].expires_us = now_us + gossipsub->config.mesh.seen_ttl_us;
    }
}

static gossipsub_mcache_entry_t *gossipsub_mcache_find(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len)
{
    gossipsub_mcache_entry_t *result = NULL;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.mcache_slots; index++)
        {
            if ((gossipsub->mcache[index].used != 0U) &&
                (gossipsub_bytes_equal(
                     gossipsub->mcache[index].message_id,
                     gossipsub->mcache[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = &gossipsub->mcache[index];
                break;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_mcache_store(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *message_id,
    size_t message_id_len,
    libp2p_gossipsub_bytes_t topic,
    libp2p_gossipsub_bytes_t data,
    gossipsub_mcache_entry_t **out_entry,
    size_t *out_index)
{
    size_t slot;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (message_id == NULL) || (topic.data == NULL) ||
        ((data.data == NULL) && (data.len != 0U)) || (out_entry == NULL) || (out_index == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (
        (message_id_len == 0U) ||
        (message_id_len > gossipsub->config.limits.max_message_id_bytes) || (topic.len == 0U) ||
        (topic.len > gossipsub->config.limits.max_topic_bytes) ||
        (data.len > gossipsub->config.capacity.mcache_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        if (data.len > (gossipsub->config.capacity.mcache_bytes - gossipsub->mcache_data_used))
        {
            (void)memset(
                gossipsub->mcache,
                0,
                gossipsub->config.capacity.mcache_slots * sizeof(gossipsub_mcache_entry_t));
            gossipsub->mcache_data_used = 0U;
        }
        slot = gossipsub->mcache_next % gossipsub->config.capacity.mcache_slots;
        entry = &gossipsub->mcache[slot];
        (void)memset(entry, 0, sizeof(*entry));
        entry->used = 1U;
        entry->window = 0U;
        entry->message_id_len = message_id_len;
        (void)memcpy(entry->message_id, message_id, message_id_len);
        entry->topic_len = topic.len;
        (void)memcpy(entry->topic, topic.data, topic.len);
        entry->data_offset = gossipsub->mcache_data_used;
        entry->data_len = data.len;
        if (data.len != 0U)
        {
            (void)memcpy(&gossipsub->mcache_data[entry->data_offset], data.data, data.len);
        }
        gossipsub->mcache_data_used += data.len;
        gossipsub->mcache_next++;
        *out_entry = entry;
        *out_index = slot;
    }

    return result;
}

static void gossipsub_entry_message(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_mcache_entry_t *entry,
    libp2p_gossipsub_message_t *out)
{
    if ((gossipsub != NULL) && (entry != NULL) && (out != NULL))
    {
        (void)memset(out, 0, sizeof(*out));
        out->topic.data = entry->topic;
        out->topic.len = entry->topic_len;
        out->data.data = &gossipsub->mcache_data[entry->data_offset];
        out->data.len = entry->data_len;
    }
}

static int gossipsub_peer_idontwant_contains(
    const libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    int result = 0;

    if ((gossipsub != NULL) && (message_id != NULL))
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used != 0U) &&
                (gossipsub->idontwant[index].peer_index == peer_index) &&
                (gossipsub->idontwant[index].expires_us >= now_us) &&
                (gossipsub_bytes_equal(
                     gossipsub->idontwant[index].message_id,
                     gossipsub->idontwant[index].message_id_len,
                     message_id,
                     message_id_len) != 0))
            {
                result = 1;
                break;
            }
        }
    }

    return result;
}

static void gossipsub_peer_idontwant_add(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len,
    uint64_t now_us)
{
    if ((gossipsub != NULL) && (message_id != NULL) &&
        (gossipsub->config.capacity.idontwant_entries != 0U) &&
        (message_id_len <= gossipsub->config.limits.max_message_id_bytes))
    {
        size_t target = 0U;
        int found = 0;

        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used == 0U) ||
                (gossipsub->idontwant[index].expires_us < now_us))
            {
                target = index;
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            target = gossipsub->mcache_next % gossipsub->config.capacity.idontwant_entries;
        }
        gossipsub->idontwant[target].used = 1U;
        gossipsub->idontwant[target].peer_index = peer_index;
        gossipsub->idontwant[target].message_id_len = message_id_len;
        (void)memcpy(gossipsub->idontwant[target].message_id, message_id, message_id_len);
        gossipsub->idontwant[target].expires_us = now_us + gossipsub->config.idontwant_ttl_us;
    }
}

static libp2p_gossipsub_err_t gossipsub_tx_alloc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t frame_len,
    uint8_t **out)
{
    gossipsub_tx_item_t *item = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->tx_queue_len >= gossipsub->config.capacity.max_tx_rpc_queue)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else
    {
        if ((frame_len >
             (gossipsub->config.capacity.tx_buffer_bytes - gossipsub->tx_buffer_used)) &&
            (gossipsub->tx_queue_len == 0U))
        {
            gossipsub->tx_buffer_used = 0U;
        }
        if (frame_len > (gossipsub->config.capacity.tx_buffer_bytes - gossipsub->tx_buffer_used))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            item = &gossipsub->tx_queue[gossipsub->tx_queue_len];
            item->used = 1U;
            item->peer_index = peer_index;
            item->offset = gossipsub->tx_buffer_used;
            item->len = frame_len;
            item->pos = 0U;
            *out = &gossipsub->tx_buffer[gossipsub->tx_buffer_used];
            gossipsub->tx_buffer_used += frame_len;
            gossipsub->tx_queue_len++;
        }
    }

    return result;
}

static void gossipsub_tx_remove(libp2p_gossipsub_t *gossipsub, size_t index)
{
    if ((gossipsub != NULL) && (index < gossipsub->tx_queue_len))
    {
        const size_t remaining = gossipsub->tx_queue_len - index - 1U;

        if (remaining != 0U)
        {
            (void)memmove(
                &gossipsub->tx_queue[index],
                &gossipsub->tx_queue[index + 1U],
                remaining * sizeof(gossipsub_tx_item_t));
        }
        gossipsub->tx_queue_len--;
        if (gossipsub->tx_queue_len == 0U)
        {
            gossipsub->tx_buffer_used = 0U;
        }
    }
}

static libp2p_gossipsub_err_t gossipsub_enqueue_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc)
{
    size_t frame_len = 0U;
    size_t written = 0U;
    uint8_t *out = NULL;
    const gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (rpc == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = &gossipsub->peers[peer_index];
        if ((peer->used != GOSSIPSUB_PEER_USED) || (peer->stream == NULL))
        {
            result = LIBP2P_GOSSIPSUB_ERR_STATE;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_frame_size(
            peer->version,
            &gossipsub->config.limits,
            rpc,
            &frame_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_tx_alloc(gossipsub, peer_index, frame_len, &out);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = libp2p_gossipsub_rpc_frame_encode(
            peer->version,
            &gossipsub->config.limits,
            rpc,
            out,
            frame_len,
            &written);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (written != frame_len))
        {
            result = LIBP2P_GOSSIPSUB_ERR_INTERNAL;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_enqueue_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_topic_state_t *topic,
    uint8_t subscribe)
{
    libp2p_gossipsub_rpc_subscription_t sub;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&sub, 0, sizeof(sub));
    (void)memset(&rpc, 0, sizeof(rpc));
    sub.topic.data = topic->topic;
    sub.topic.len = topic->topic_len;
    sub.subscribe = subscribe;
    rpc.subscriptions = &sub;
    rpc.subscription_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const uint8_t *message_id,
    size_t message_id_len)
{
    libp2p_gossipsub_bytes_t id;
    libp2p_gossipsub_control_idontwant_t idontwant;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&id, 0, sizeof(id));
    (void)memset(&idontwant, 0, sizeof(idontwant));
    (void)memset(&rpc, 0, sizeof(rpc));
    id.data = message_id;
    id.len = message_id_len;
    idontwant.message_ids = &id;
    idontwant.message_id_count = 1U;
    rpc.control.idontwant = &idontwant;
    rpc.control.idontwant_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_iwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_bytes_t *message_id)
{
    libp2p_gossipsub_control_iwant_t iwant;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&iwant, 0, sizeof(iwant));
    (void)memset(&rpc, 0, sizeof(rpc));
    iwant.message_ids = message_id;
    iwant.message_id_count = 1U;
    rpc.control.iwant = &iwant;
    rpc.control.iwant_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

static libp2p_gossipsub_err_t gossipsub_enqueue_publish_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_rpc_t rpc;

    (void)memset(&message, 0, sizeof(message));
    (void)memset(&rpc, 0, sizeof(rpc));
    gossipsub_entry_message(gossipsub, entry, &message);
    rpc.publish = &message;
    rpc.publish_count = 1U;

    return gossipsub_enqueue_rpc(gossipsub, peer_index, &rpc);
}

static libp2p_gossipsub_err_t gossipsub_flush_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    size_t peer_index,
    uint8_t *made_progress)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (made_progress == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->peers[peer_index].stream == NULL)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else
    {
        size_t index = 0U;
        uint8_t keep_writing = 1U;

        while ((result == LIBP2P_GOSSIPSUB_OK) && (index < gossipsub->tx_queue_len) &&
               (keep_writing != 0U))
        {
            gossipsub_tx_item_t *item = &gossipsub->tx_queue[index];

            if (item->peer_index != peer_index)
            {
                index++;
            }
            else
            {
                size_t accepted = 0U;

                result = gossipsub_host_to_err(libp2p_host_stream_write(
                    host,
                    gossipsub->peers[peer_index].stream,
                    &gossipsub->tx_buffer[item->offset + item->pos],
                    item->len - item->pos,
                    0,
                    &accepted));
                if (result == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
                {
                    result = LIBP2P_GOSSIPSUB_OK;
                    keep_writing = 0U;
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    if (accepted != 0U)
                    {
                        *made_progress = 1U;
                        item->pos += accepted;
                    }
                    if (item->pos == item->len)
                    {
                        gossipsub_tx_remove(gossipsub, index);
                    }
                    else
                    {
                        keep_writing = 0U;
                    }
                }
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_forward_entry(
    libp2p_gossipsub_t *gossipsub,
    size_t source_peer_index,
    const gossipsub_mcache_entry_t *entry)
{
    size_t topic_index = 0U;
    size_t peer_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (entry == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        topic = gossipsub_find_topic(gossipsub, entry->topic, entry->topic_len, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
    }
    for (peer_index = 0U;
         (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
         peer_index++)
    {
        if ((peer_index != source_peer_index) &&
            (gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
            (gossipsub->peers[peer_index].stream != NULL) &&
            ((gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) ||
             (gossipsub->config.mesh.enable_flood_publish != 0U)) &&
            (gossipsub_peer_idontwant_contains(
                 gossipsub,
                 peer_index,
                 entry->message_id,
                 entry->message_id_len,
                 gossipsub->next_heartbeat_us) == 0))
        {
            result = gossipsub_enqueue_publish_entry(gossipsub, peer_index, entry);
        }
    }
    (void)topic;

    return result;
}

static struct libp2p_gossipsub_validation *gossipsub_alloc_validation(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    size_t mcache_index,
    uint64_t now_us)
{
    struct libp2p_gossipsub_validation *result = NULL;

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.pending_validations; index++)
        {
            if (gossipsub->validations[index].state == GOSSIPSUB_VALIDATION_FREE)
            {
                result = &gossipsub->validations[index];
                result->state = GOSSIPSUB_VALIDATION_PENDING;
                result->peer_index = peer_index;
                result->mcache_index = mcache_index;
                result->expires_us = now_us + gossipsub->config.mesh.iwant_followup_us;
                break;
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_process_subscription(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_subscription_t *sub)
{
    size_t topic_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_peer_topic_state_t *edge = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (sub == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        topic = gossipsub_find_or_add_topic(gossipsub, sub->topic, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        edge = gossipsub_find_or_add_peer_topic(gossipsub, peer_index, topic_index);
        if (edge == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            edge->subscribed = sub->subscribe;
            event.type = LIBP2P_GOSSIPSUB_EVENT_SUBSCRIPTION;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.topic.data = topic->topic;
            event.topic.len = topic->topic_len;
            result = gossipsub_event_push(gossipsub, &event);
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_process_message(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_message_t *message,
    uint64_t now_us)
{
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(message_id, 0, sizeof(message_id));
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (message == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_compute_message_id(
            gossipsub,
            message,
            message_id,
            sizeof(message_id),
            &message_id_len);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (gossipsub_seen_contains(gossipsub, message_id, message_id_len, now_us) != 0)
        {
            event.type = LIBP2P_GOSSIPSUB_EVENT_DROPPED;
            event.drop_reason = LIBP2P_GOSSIPSUB_DROP_DUPLICATE_MESSAGE;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.message_id.data = message_id;
            event.message_id.len = message_id_len;
            result = gossipsub_event_push(gossipsub, &event);
            if (result == LIBP2P_GOSSIPSUB_OK)
            {
                result = LIBP2P_GOSSIPSUB_ERR_DUPLICATE;
            }
        }
        else
        {
            gossipsub_seen_add(gossipsub, message_id, message_id_len, now_us);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        topic =
            gossipsub_find_topic(gossipsub, message->topic.data, message->topic.len, &topic_index);
        if ((topic == NULL) || (topic->local_subscribed == 0U))
        {
            event.type = LIBP2P_GOSSIPSUB_EVENT_DROPPED;
            event.drop_reason = LIBP2P_GOSSIPSUB_DROP_UNSUBSCRIBED_TOPIC;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.topic = message->topic;
            event.message_id.data = message_id;
            event.message_id.len = message_id_len;
            result = gossipsub_event_push(gossipsub, &event);
        }
        else
        {
            result = gossipsub_mcache_store(
                gossipsub,
                message_id,
                message_id_len,
                message->topic,
                message->data,
                &entry,
                &mcache_index);
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (entry != NULL) && (topic != NULL))
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_MESSAGE;
        gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
        event.topic.data = entry->topic;
        event.topic.len = entry->topic_len;
        event.message_id.data = entry->message_id;
        event.message_id.len = entry->message_id_len;
        gossipsub_entry_message(gossipsub, entry, &event.message);
        if (topic->validation_mode == LIBP2P_GOSSIPSUB_VALIDATION_REQUIRE_APP)
        {
            event.validation =
                gossipsub_alloc_validation(gossipsub, peer_index, mcache_index, now_us);
            if (event.validation == NULL)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_event_push(gossipsub, &event);
        }
        if ((result == LIBP2P_GOSSIPSUB_OK) &&
            (topic->validation_mode == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL))
        {
            result = gossipsub_forward_entry(gossipsub, peer_index, entry);
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_process_idontwant(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_control_idontwant_t *idontwant,
    uint64_t now_us)
{
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (idontwant == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < idontwant->message_id_count);
             index++)
        {
            gossipsub_peer_idontwant_add(
                gossipsub,
                peer_index,
                idontwant->message_ids[index].data,
                idontwant->message_ids[index].len,
                now_us);
            event.type = LIBP2P_GOSSIPSUB_EVENT_IDONTWANT;
            gossipsub_peer_to_event(&gossipsub->peers[peer_index], &event);
            event.message_id = idontwant->message_ids[index];
            event.idontwant = *idontwant;
            result = gossipsub_event_push(gossipsub, &event);
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_process_rpc(
    libp2p_gossipsub_t *gossipsub,
    size_t peer_index,
    const libp2p_gossipsub_rpc_t *rpc,
    uint64_t now_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (rpc == NULL) ||
        (peer_index >= gossipsub->config.capacity.max_peers))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->subscription_count);
             index++)
        {
            result =
                gossipsub_process_subscription(gossipsub, peer_index, &rpc->subscriptions[index]);
        }
        for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->publish_count);
             index++)
        {
            result = gossipsub_process_message(gossipsub, peer_index, &rpc->publish[index], now_us);
            if (result == LIBP2P_GOSSIPSUB_ERR_DUPLICATE)
            {
                result = LIBP2P_GOSSIPSUB_OK;
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.idontwant_count);
             index++)
        {
            result = gossipsub_process_idontwant(
                gossipsub,
                peer_index,
                &rpc->control.idontwant[index],
                now_us);
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.iwant_count);
             index++)
        {
            for (size_t id_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
                                       (id_index < rpc->control.iwant[index].message_id_count);
                 id_index++)
            {
                const gossipsub_mcache_entry_t *entry = gossipsub_mcache_find(
                    gossipsub,
                    rpc->control.iwant[index].message_ids[id_index].data,
                    rpc->control.iwant[index].message_ids[id_index].len);

                if (entry != NULL)
                {
                    result = gossipsub_enqueue_publish_entry(gossipsub, peer_index, entry);
                }
            }
        }
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < rpc->control.ihave_count);
             index++)
        {
            for (size_t id_index = 0U; (result == LIBP2P_GOSSIPSUB_OK) &&
                                       (id_index < rpc->control.ihave[index].message_id_count);
                 id_index++)
            {
                if (gossipsub_seen_contains(
                        gossipsub,
                        rpc->control.ihave[index].message_ids[id_index].data,
                        rpc->control.ihave[index].message_ids[id_index].len,
                        now_us) == 0)
                {
                    result = gossipsub_enqueue_iwant(
                        gossipsub,
                        peer_index,
                        &rpc->control.ihave[index].message_ids[id_index]);
                }
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_stream_decode_available(
    libp2p_gossipsub_t *gossipsub,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us)
{
    libp2p_gossipsub_rpc_subscription_t subs[LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC];
    libp2p_gossipsub_message_t publish[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC];
    libp2p_gossipsub_control_ihave_t ihave[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC];
    libp2p_gossipsub_control_iwant_t iwant[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC];
    libp2p_gossipsub_control_graft_t graft[LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC];
    libp2p_gossipsub_control_prune_t prune[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC];
    libp2p_gossipsub_control_idontwant_t idontwant[LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC];
    libp2p_gossipsub_bytes_t ids[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC];
    libp2p_gossipsub_peer_info_t peers[LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC];
    libp2p_gossipsub_rpc_decode_storage_t storage;
    libp2p_gossipsub_rpc_t rpc;
    uint8_t keep_decoding = 1U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&storage, 0, sizeof(storage));
    (void)memset(&rpc, 0, sizeof(rpc));
    (void)memset(subs, 0, sizeof(subs));
    (void)memset(publish, 0, sizeof(publish));
    (void)memset(ihave, 0, sizeof(ihave));
    (void)memset(iwant, 0, sizeof(iwant));
    (void)memset(graft, 0, sizeof(graft));
    (void)memset(prune, 0, sizeof(prune));
    (void)memset(idontwant, 0, sizeof(idontwant));
    (void)memset(ids, 0, sizeof(ids));
    (void)memset(peers, 0, sizeof(peers));
    storage.subscriptions = subs;
    storage.subscription_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_SUBSCRIPTIONS_PER_RPC;
    storage.publish = publish;
    storage.publish_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PUBLISH_PER_RPC;
    storage.ihave = ihave;
    storage.ihave_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IHAVE_PER_RPC;
    storage.iwant = iwant;
    storage.iwant_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IWANT_PER_RPC;
    storage.graft = graft;
    storage.graft_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_GRAFT_PER_RPC;
    storage.prune = prune;
    storage.prune_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PRUNE_PER_RPC;
    storage.idontwant = idontwant;
    storage.idontwant_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_IDONTWANT_PER_RPC;
    storage.message_ids = ids;
    storage.message_id_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_IDS_PER_RPC;
    storage.peer_infos = peers;
    storage.peer_info_capacity = LIBP2P_GOSSIPSUB_DEFAULT_MAX_PX_PEERS_PER_RPC;

    if ((gossipsub == NULL) || (stream_state == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (stream_state->rx_len != 0U) && (keep_decoding != 0U))
    {
        uint64_t body_len = 0U;
        size_t read_pos = 0U;

        result =
            gossipsub_read_uvarint(stream_state->rx, stream_state->rx_len, &read_pos, &body_len);
        if (result == LIBP2P_GOSSIPSUB_ERR_TRUNCATED)
        {
            result = LIBP2P_GOSSIPSUB_OK;
            keep_decoding = 0U;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const size_t header_len = read_pos;

            if (body_len > (uint64_t)gossipsub->config.limits.max_rpc_bytes)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else if ((stream_state->rx_len - header_len) < (size_t)body_len)
            {
                keep_decoding = 0U;
            }
            else
            {
                (void)memset(&rpc, 0, sizeof(rpc));
                result = libp2p_gossipsub_rpc_body_decode(
                    stream_state->version,
                    &gossipsub->config.limits,
                    &stream_state->rx[header_len],
                    (size_t)body_len,
                    &storage,
                    &rpc);
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    result =
                        gossipsub_process_rpc(gossipsub, stream_state->peer_index, &rpc, now_us);
                }
                if (result == LIBP2P_GOSSIPSUB_OK)
                {
                    const size_t pos = header_len + (size_t)body_len;

                    if (pos < stream_state->rx_len)
                    {
                        const size_t remaining = stream_state->rx_len - pos;

                        (void)memmove(stream_state->rx, &stream_state->rx[pos], remaining);
                        stream_state->rx_len = remaining;
                    }
                    else
                    {
                        stream_state->rx_len = 0U;
                    }
                }
            }
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_stream_read(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    gossipsub_stream_state_t *stream_state,
    uint64_t now_us)
{
    size_t read_len = 0U;
    uint8_t keep_reading = 1U;
    int fin = 0;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (stream_state == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (keep_reading != 0U))
    {
        if (stream_state->rx_len >=
            (gossipsub->config.limits.max_rpc_bytes + LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        else
        {
            result = gossipsub_host_to_err(libp2p_host_stream_read(
                host,
                stream_state->stream,
                &stream_state->rx[stream_state->rx_len],
                (gossipsub->config.limits.max_rpc_bytes + LIBP2P_GOSSIPSUB_FRAME_LEN_MAX_BYTES) -
                    stream_state->rx_len,
                &read_len,
                &fin));
        }
        if (result == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
        {
            result = LIBP2P_GOSSIPSUB_OK;
            keep_reading = 0U;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            stream_state->rx_len += read_len;
            if (read_len != 0U)
            {
                result = gossipsub_stream_decode_available(gossipsub, stream_state, now_us);
            }
            if ((fin != 0) || (read_len == 0U))
            {
                keep_reading = 0U;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_protocols(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_protocol_t *out_protocols,
    size_t out_protocol_capacity,
    size_t *written)
{
    size_t required = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (written == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12) != 0U)
        {
            required++;
        }
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11) != 0U)
        {
            required++;
        }
        *written = required;
        if ((out_protocols == NULL) || (out_protocol_capacity < required))
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        size_t pos = 0U;

        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V12) != 0U)
        {
            out_protocols[pos].id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12;
            out_protocols[pos].id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN;
            out_protocols[pos].on_open = gossipsub_protocol_on_open;
            out_protocols[pos].on_event = gossipsub_protocol_on_event;
            out_protocols[pos].user_data = &gossipsub->protocol_user_data[0];
            pos++;
        }
        if ((gossipsub->config.protocol_mask & LIBP2P_GOSSIPSUB_PROTOCOL_MASK_V11) != 0U)
        {
            out_protocols[pos].id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11;
            out_protocols[pos].id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN;
            out_protocols[pos].on_open = gossipsub_protocol_on_open;
            out_protocols[pos].on_event = gossipsub_protocol_on_event;
            out_protocols[pos].user_data = &gossipsub->protocol_user_data[1];
        }
        *written = required;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_start(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub->host = host;
        gossipsub->started = 1U;
        gossipsub->closing = 0U;
        gossipsub->next_heartbeat_us = now_us + gossipsub->config.mesh.heartbeat_interval_us;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_close(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    uint64_t app_error_code)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        gossipsub->closing = 1U;
        for (size_t index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (index < gossipsub->config.capacity.max_streams);
             index++)
        {
            if ((gossipsub->streams[index].state == GOSSIPSUB_STREAM_OPEN) &&
                (gossipsub->streams[index].stream != NULL))
            {
                result = gossipsub_host_to_err(libp2p_host_stream_reset(
                    host,
                    gossipsub->streams[index].stream,
                    app_error_code));
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_next_deadline(
    const libp2p_gossipsub_t *gossipsub,
    libp2p_host_time_us_t *out_deadline_us)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_deadline_us == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->started == 0U)
    {
        *out_deadline_us = 0U;
    }
    else
    {
        *out_deadline_us = gossipsub->next_heartbeat_us;
    }

    return result;
}

static void gossipsub_heartbeat(libp2p_gossipsub_t *gossipsub, uint64_t now_us)
{

    if (gossipsub != NULL)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if (gossipsub->peers[index].used == GOSSIPSUB_PEER_USED)
            {
                gossipsub->peers[index].idontwant_sent_this_heartbeat = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.mcache_slots; index++)
        {
            if (gossipsub->mcache[index].used != 0U)
            {
                if (gossipsub->mcache[index].window >= gossipsub->config.mesh.mcache_len)
                {
                    gossipsub->mcache[index].used = 0U;
                }
                else
                {
                    gossipsub->mcache[index].window++;
                }
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.seen_entries; index++)
        {
            if ((gossipsub->seen[index].used != 0U) && (gossipsub->seen[index].expires_us < now_us))
            {
                gossipsub->seen[index].used = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.idontwant_entries; index++)
        {
            if ((gossipsub->idontwant[index].used != 0U) &&
                (gossipsub->idontwant[index].expires_us < now_us))
            {
                gossipsub->idontwant[index].used = 0U;
            }
        }
        for (size_t index = 0U; index < gossipsub->config.capacity.pending_validations; index++)
        {
            if ((gossipsub->validations[index].state == GOSSIPSUB_VALIDATION_PENDING) &&
                (gossipsub->validations[index].expires_us < now_us))
            {
                gossipsub->validations[index].state = GOSSIPSUB_VALIDATION_FREE;
            }
        }
        gossipsub->next_heartbeat_us = now_us + gossipsub->config.mesh.heartbeat_interval_us;
    }
}

libp2p_gossipsub_err_t libp2p_gossipsub_drive(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_time_us_t now_us,
    libp2p_gossipsub_drive_result_t *out_result)
{
    uint8_t made_progress = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        if (out_result != NULL)
        {
            (void)memset(out_result, 0, sizeof(*out_result));
        }
        if ((gossipsub->started != 0U) && (now_us >= gossipsub->next_heartbeat_us))
        {
            gossipsub_heartbeat(gossipsub, now_us);
            made_progress = 1U;
            if (out_result != NULL)
            {
                out_result->heartbeats = 1U;
            }
        }
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_flush_peer(gossipsub, host, peer_index, &made_progress);
            }
        }
        if (out_result != NULL)
        {
            out_result->made_progress = made_progress;
            out_result->rpcs_sent = made_progress;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_handle_host_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    const libp2p_host_event_t *event)
{
    libp2p_gossipsub_event_t gs_event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&gs_event, 0, sizeof(gs_event));
    if ((gossipsub == NULL) || (host == NULL) || (event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (event->type == LIBP2P_HOST_EVENT_CONN_CLOSED)
    {
        for (size_t index = 0U; index < gossipsub->config.capacity.max_peers; index++)
        {
            if ((gossipsub->peers[index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[index].conn == event->conn))
            {
                gs_event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED;
                gossipsub_peer_to_event(&gossipsub->peers[index], &gs_event);
                (void)gossipsub_event_push(gossipsub, &gs_event);
                gossipsub->peers[index].closed = 1U;
                gossipsub->peers[index].stream = NULL;
                gossipsub->peers[index].conn = NULL;
            }
        }
    }
    else if (event->type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED)
    {
        gs_event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_FAILED;
        gs_event.conn = event->conn;
        gs_event.reason = gossipsub_host_to_err(event->reason);
        result = gossipsub_event_push(gossipsub, &gs_event);
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }

    (void)host;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_open_peer(
    libp2p_gossipsub_t *gossipsub,
    libp2p_host_t *host,
    libp2p_host_conn_t *conn,
    libp2p_gossipsub_protocol_version_t preferred_version,
    void *user_data,
    libp2p_host_stream_open_t **out_open)
{
    const uint8_t *protocol_id = NULL;
    size_t protocol_id_len = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (host == NULL) || (conn == NULL) || (out_open == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        libp2p_gossipsub_protocol_version_t version = preferred_version;

        if (version == LIBP2P_GOSSIPSUB_VERSION_NONE)
        {
            version = gossipsub->config.preferred_protocol;
        }
        if (version == LIBP2P_GOSSIPSUB_VERSION_12)
        {
            protocol_id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12;
            protocol_id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V12_LEN;
        }
        else if (version == LIBP2P_GOSSIPSUB_VERSION_11)
        {
            protocol_id = (const uint8_t *)LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11;
            protocol_id_len = LIBP2P_GOSSIPSUB_PROTOCOL_ID_V11_LEN;
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_host_to_err(
            libp2p_host_open_stream(host, conn, protocol_id, protocol_id_len, user_data, out_open));
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_subscribe(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_topic_config_t *topic)
{
    size_t topic_index = 0U;
    gossipsub_topic_state_t *state = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic == NULL) || (topic->topic.data == NULL) ||
        (topic->topic.len == 0U) || (topic->topic.len > gossipsub->config.limits.max_topic_bytes) ||
        (topic->idontwant_min_message_bytes > gossipsub->config.limits.max_message_data_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        state = gossipsub_find_or_add_topic(gossipsub, topic->topic, &topic_index);
        if (state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        state->local_subscribed = 1U;
        state->validation_mode = topic->validation_mode;
        state->score_params = topic->score_params;
        state->enable_idontwant = topic->enable_idontwant;
        state->idontwant_min_message_bytes = topic->idontwant_min_message_bytes;
        if (state->idontwant_min_message_bytes == 0U)
        {
            state->idontwant_min_message_bytes = gossipsub->config.idontwant_min_message_bytes;
        }
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_enqueue_subscription(gossipsub, peer_index, state, 1U);
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_unsubscribe(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_bytes_t topic)
{
    size_t topic_index = 0U;
    gossipsub_topic_state_t *state = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (topic.data == NULL) || (topic.len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        state = gossipsub_find_topic(gossipsub, topic.data, topic.len, &topic_index);
        if (state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        state->local_subscribed = 0U;
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                result = gossipsub_enqueue_subscription(gossipsub, peer_index, state, 0U);
            }
        }
    }
    (void)topic_index;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_publish(
    libp2p_gossipsub_t *gossipsub,
    const libp2p_gossipsub_publish_t *publish,
    uint8_t *out_message_id,
    size_t out_message_id_len,
    size_t *written)
{
    uint8_t message_id[LIBP2P_GOSSIPSUB_DEFAULT_MAX_MESSAGE_ID_BYTES];
    size_t message_id_len = 0U;
    size_t topic_index = 0U;
    size_t mcache_index = 0U;
    const gossipsub_topic_state_t *topic = NULL;
    gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_message_t message;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(message_id, 0, sizeof(message_id));
    (void)memset(&message, 0, sizeof(message));
    if ((gossipsub == NULL) || (publish == NULL) || (publish->topic.data == NULL) ||
        (publish->topic.len == 0U) ||
        (publish->topic.len > gossipsub->config.limits.max_topic_bytes) ||
        ((publish->data.data == NULL) && (publish->data.len != 0U)) ||
        (publish->data.len > gossipsub->config.limits.max_message_data_bytes))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        message.topic = publish->topic;
        message.data = publish->data;
        if (gossipsub_bytes_present(&publish->message_id) != 0)
        {
            if (publish->message_id.len > gossipsub->config.limits.max_message_id_bytes)
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else
            {
                message_id_len = publish->message_id.len;
                (void)memcpy(message_id, publish->message_id.data, message_id_len);
            }
        }
        else
        {
            result = gossipsub_compute_message_id(
                gossipsub,
                &message,
                message_id,
                sizeof(message_id),
                &message_id_len);
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        if (written != NULL)
        {
            *written = message_id_len;
        }
        if ((out_message_id != NULL) && (out_message_id_len < message_id_len))
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
        else if (out_message_id != NULL)
        {
            (void)memcpy(out_message_id, message_id, message_id_len);
        }
        else
        {
            result = LIBP2P_GOSSIPSUB_OK;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        topic = gossipsub_find_or_add_topic(gossipsub, publish->topic, &topic_index);
        if (topic == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_mcache_store(
            gossipsub,
            message_id,
            message_id_len,
            publish->topic,
            publish->data,
            &entry,
            &mcache_index);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        gossipsub_seen_add(gossipsub, message_id, message_id_len, gossipsub->next_heartbeat_us);
        for (size_t peer_index = 0U;
             (result == LIBP2P_GOSSIPSUB_OK) && (peer_index < gossipsub->config.capacity.max_peers);
             peer_index++)
        {
            if ((gossipsub->peers[peer_index].used == GOSSIPSUB_PEER_USED) &&
                (gossipsub->peers[peer_index].stream != NULL))
            {
                if ((gossipsub->peers[peer_index].version == LIBP2P_GOSSIPSUB_VERSION_12) &&
                    (gossipsub->config.enable_idontwant != 0U) && (topic->enable_idontwant != 0U) &&
                    (publish->data.len >= topic->idontwant_min_message_bytes) &&
                    (gossipsub->peers[peer_index].idontwant_sent_this_heartbeat <
                     gossipsub->config.max_idontwant_messages_per_peer_per_heartbeat))
                {
                    result = gossipsub_enqueue_idontwant(
                        gossipsub,
                        peer_index,
                        message_id,
                        message_id_len);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        gossipsub->peers[peer_index].idontwant_sent_this_heartbeat++;
                    }
                }
                if ((result == LIBP2P_GOSSIPSUB_OK) &&
                    ((gossipsub_peer_subscribed(gossipsub, peer_index, topic_index) != 0) ||
                     (gossipsub->config.mesh.enable_flood_publish != 0U)))
                {
                    result = gossipsub_enqueue_publish_entry(gossipsub, peer_index, entry);
                }
            }
        }
    }
    (void)mcache_index;

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_report_validation(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_validation_t *validation,
    libp2p_gossipsub_validation_result_t result_value)
{
    const gossipsub_mcache_entry_t *entry = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (validation == NULL) ||
        (validation->state != GOSSIPSUB_VALIDATION_PENDING) ||
        (validation->mcache_index >= gossipsub->config.capacity.mcache_slots))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        entry = &gossipsub->mcache[validation->mcache_index];
        if (entry->used == 0U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_STATE;
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (result_value == LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT))
    {
        result = gossipsub_forward_entry(gossipsub, validation->peer_index, entry);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        validation->state = GOSSIPSUB_VALIDATION_FREE;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_next_event(
    libp2p_gossipsub_t *gossipsub,
    libp2p_gossipsub_event_t *out_event)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (out_event == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (gossipsub->event_len == 0U)
    {
        result = LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK;
    }
    else
    {
        *out_event = gossipsub->events[gossipsub->event_head];
        gossipsub->event_head =
            (gossipsub->event_head + 1U) % gossipsub->config.capacity.event_capacity;
        gossipsub->event_len--;
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_set_peer_explicit(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    uint8_t is_explicit)
{
    size_t peer_index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            peer->explicit_peer = (is_explicit != 0U) ? 1U : 0U;
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_set_peer_application_score(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_gossipsub_score_t score)
{
    size_t peer_index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            peer->app_score = score;
            event.type = LIBP2P_GOSSIPSUB_EVENT_SCORE;
            event.score = score;
            gossipsub_peer_to_event(peer, &event);
            result = gossipsub_event_push(gossipsub, &event);
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_add_peer_behaviour_penalty(
    libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_gossipsub_score_t delta)
{
    size_t peer_index = 0U;
    gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            peer->behaviour_penalty += delta;
            event.type = LIBP2P_GOSSIPSUB_EVENT_SCORE;
            event.score = peer->app_score - peer->behaviour_penalty;
            gossipsub_peer_to_event(peer, &event);
            result = gossipsub_event_push(gossipsub, &event);
        }
    }

    return result;
}

libp2p_gossipsub_err_t libp2p_gossipsub_peer_protocol_version(
    const libp2p_gossipsub_t *gossipsub,
    const uint8_t *peer_id,
    size_t peer_id_len,
    libp2p_gossipsub_protocol_version_t *out_version)
{
    size_t peer_index = 0U;
    const gossipsub_peer_state_t *peer = NULL;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if (out_version != NULL)
    {
        *out_version = LIBP2P_GOSSIPSUB_VERSION_NONE;
    }
    if ((gossipsub == NULL) || (peer_id == NULL) || (peer_id_len == 0U) || (out_version == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        peer = gossipsub_find_peer_const(gossipsub, peer_id, peer_id_len, &peer_index);
        if (peer == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
        }
        else
        {
            *out_version = peer->version;
        }
    }

    return result;
}

static libp2p_host_err_t gossipsub_protocol_on_open(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_stream_direction_t direction,
    void *protocol_user_data)
{
    libp2p_gossipsub_t *gossipsub = gossipsub_from_protocol_user_data(protocol_user_data);
    libp2p_gossipsub_protocol_version_t version =
        gossipsub_version_from_protocol_user_data(protocol_user_data);
    libp2p_host_conn_t *conn = NULL;
    gossipsub_peer_state_t *peer = NULL;
    gossipsub_stream_state_t *stream_state = NULL;
    size_t peer_index = 0U;
    size_t stream_index = 0U;
    size_t topic_index = 0U;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    gossipsub_keep_mutable_host_arg(host);
    gossipsub_keep_mutable_void_arg(protocol_user_data);
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (host == NULL) || (stream == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(libp2p_host_stream_conn(stream, &conn));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        result = gossipsub_peer_from_conn(gossipsub, conn, &peer, &peer_index);
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        stream_state = gossipsub_alloc_stream(gossipsub, &stream_index);
        if (stream_state == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        stream_state->stream = stream;
        stream_state->conn = conn;
        stream_state->direction = direction;
        stream_state->version = version;
        stream_state->peer_index = peer_index;
        peer->stream = stream;
        peer->direction = direction;
        peer->version = version;
        result = gossipsub_host_to_err(libp2p_host_stream_set_user_data(stream, stream_state));
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_OPENED;
        gossipsub_peer_to_event(peer, &event);
        result = gossipsub_event_push(gossipsub, &event);
    }
    for (topic_index = 0U;
         (result == LIBP2P_GOSSIPSUB_OK) && (topic_index < gossipsub->config.capacity.max_topics);
         topic_index++)
    {
        if ((gossipsub->topics[topic_index].used == GOSSIPSUB_TOPIC_USED) &&
            (gossipsub->topics[topic_index].local_subscribed != 0U))
        {
            result = gossipsub_enqueue_subscription(
                gossipsub,
                peer_index,
                &gossipsub->topics[topic_index],
                1U);
        }
    }
    (void)stream_index;

    return gossipsub_host_err(result);
}

static libp2p_host_err_t gossipsub_protocol_on_event(
    libp2p_host_t *host,
    libp2p_host_stream_t *stream,
    libp2p_host_protocol_event_kind_t kind,
    void *protocol_user_data)
{
    libp2p_gossipsub_t *gossipsub = gossipsub_from_protocol_user_data(protocol_user_data);
    gossipsub_stream_state_t *stream_state = NULL;
    void *user_data = NULL;
    uint8_t made_progress = 0U;
    libp2p_gossipsub_event_t event;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    gossipsub_keep_mutable_stream_arg(stream);
    gossipsub_keep_mutable_void_arg(protocol_user_data);
    (void)memset(&event, 0, sizeof(event));
    if ((gossipsub == NULL) || (host == NULL) || (stream == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_host_to_err(libp2p_host_stream_user_data(stream, &user_data));
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            (void)memcpy((void *)&stream_state, (const void *)&user_data, sizeof user_data);
            if (stream_state == NULL)
            {
                result = LIBP2P_GOSSIPSUB_ERR_STATE;
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && (kind == LIBP2P_HOST_PROTOCOL_EVENT_READABLE))
    {
        result = gossipsub_stream_read(gossipsub, host, stream_state, gossipsub->next_heartbeat_us);
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (kind == LIBP2P_HOST_PROTOCOL_EVENT_WRITABLE))
    {
        result = gossipsub_flush_peer(gossipsub, host, stream_state->peer_index, &made_progress);
    }
    else if (
        (result == LIBP2P_GOSSIPSUB_OK) &&
        ((kind == LIBP2P_HOST_PROTOCOL_EVENT_RESET) || (kind == LIBP2P_HOST_PROTOCOL_EVENT_CLOSED)))
    {
        event.type = LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED;
        gossipsub_peer_to_event(&gossipsub->peers[stream_state->peer_index], &event);
        (void)gossipsub_event_push(gossipsub, &event);
        gossipsub->peers[stream_state->peer_index].stream = NULL;
        stream_state->state = GOSSIPSUB_STREAM_FREE;
        stream_state->stream = NULL;
    }
    else
    {
        (void)result;
    }

    (void)made_progress;

    return gossipsub_host_err(result);
}

static libp2p_gossipsub_err_t gossipsub_control_encode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const libp2p_gossipsub_rpc_control_t *control,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t nested = 0U;
    size_t pos = 0U;
    libp2p_gossipsub_err_t result = gossipsub_control_size(version, limits, control, &required);

    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out == NULL) || (written == NULL)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if ((result == LIBP2P_GOSSIPSUB_OK) && (required > out_len))
    {
        *written = required;
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else
    {
        (void)result;
    }

    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->ihave_count);
         index++)
    {
        result = gossipsub_ihave_size(limits, &control->ihave[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_CONTROL_IHAVE,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_ihave_encode(
                limits,
                &control->ihave[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->iwant_count);
         index++)
    {
        result = gossipsub_iwant_size(limits, &control->iwant[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_CONTROL_IWANT,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_iwant_encode(
                limits,
                &control->iwant[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->graft_count);
         index++)
    {
        result = gossipsub_topic_control_size(limits, control->graft[index].topic, &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_CONTROL_GRAFT,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_topic_control_encode(
                limits,
                control->graft[index].topic,
                GOSSIPSUB_FIELD_GRAFT_TOPIC,
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->prune_count);
         index++)
    {
        result = gossipsub_prune_size(limits, &control->prune[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_CONTROL_PRUNE,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_prune_encode(
                limits,
                &control->prune[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    for (size_t index = 0U; (result == LIBP2P_GOSSIPSUB_OK) && (index < control->idontwant_count);
         index++)
    {
        result = gossipsub_idontwant_size(version, limits, &control->idontwant[index], &nested);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_write_len_prefix(
                GOSSIPSUB_FIELD_CONTROL_IDONTWANT,
                nested,
                out,
                out_len,
                &pos);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            result = gossipsub_idontwant_encode(
                version,
                limits,
                &control->idontwant[index],
                &out[pos],
                out_len - pos,
                &nested);
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            pos += nested;
        }
    }
    if (result == LIBP2P_GOSSIPSUB_OK)
    {
        *written = pos;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_idontwant_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    gossipsub_decode_cursor_t *cursor,
    libp2p_gossipsub_control_idontwant_t *out)
{
    libp2p_gossipsub_control_iwant_t iwant;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)memset(&iwant, 0, sizeof(iwant));
    if (version != LIBP2P_GOSSIPSUB_VERSION_12)
    {
        result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
    }
    else if (out == NULL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_iwant_decode(limits, in, in_len, storage, cursor, &iwant);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            out->message_ids = iwant.message_ids;
            out->message_id_count = iwant.message_id_count;
        }
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_control_decode(
    libp2p_gossipsub_protocol_version_t version,
    const libp2p_gossipsub_limits_t *limits,
    const uint8_t *in,
    size_t in_len,
    libp2p_gossipsub_rpc_decode_storage_t *storage,
    libp2p_gossipsub_rpc_control_t *out)
{
    size_t pos = 0U;
    gossipsub_decode_cursor_t cursor;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((limits == NULL) || (in == NULL) || (storage == NULL) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out, 0, sizeof(*out));
        (void)memset(&cursor, 0, sizeof(cursor));
        out->ihave = storage->ihave;
        out->iwant = storage->iwant;
        out->graft = storage->graft;
        out->prune = storage->prune;
        out->idontwant = storage->idontwant;
    }
    while ((result == LIBP2P_GOSSIPSUB_OK) && (pos < in_len))
    {
        uint64_t key = 0U;
        libp2p_gossipsub_bytes_t nested;

        (void)memset(&nested, 0, sizeof(nested));
        result = gossipsub_read_uvarint(in, in_len, &pos, &key);
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            const uint32_t field = (uint32_t)(key >> 3U);
            const uint32_t wire = (uint32_t)(key & 7U);
            if (wire != GOSSIPSUB_WIRE_LEN)
            {
                result = gossipsub_skip_field(wire, in, in_len, &pos);
            }
            else
            {
                result = gossipsub_read_len_span(in, in_len, &pos, &nested);
            }
            if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_CONTROL_IHAVE))
            {
                if (out->ihave_count >= storage->ihave_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_ihave_decode(
                        limits,
                        nested.data,
                        nested.len,
                        storage,
                        &cursor,
                        &storage->ihave[out->ihave_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out->ihave_count++;
                    }
                }
            }
            else if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_CONTROL_IWANT))
            {
                if (out->iwant_count >= storage->iwant_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_iwant_decode(
                        limits,
                        nested.data,
                        nested.len,
                        storage,
                        &cursor,
                        &storage->iwant[out->iwant_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out->iwant_count++;
                    }
                }
            }
            else if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_CONTROL_GRAFT))
            {
                if (out->graft_count >= storage->graft_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_graft_decode(
                        limits,
                        nested.data,
                        nested.len,
                        &storage->graft[out->graft_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out->graft_count++;
                    }
                }
            }
            else if ((result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_CONTROL_PRUNE))
            {
                if (out->prune_count >= storage->prune_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_prune_decode(
                        limits,
                        nested.data,
                        nested.len,
                        storage,
                        &cursor,
                        &storage->prune[out->prune_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out->prune_count++;
                    }
                }
            }
            else if (
                (result == LIBP2P_GOSSIPSUB_OK) && (field == GOSSIPSUB_FIELD_CONTROL_IDONTWANT))
            {
                if (out->idontwant_count >= storage->idontwant_capacity)
                {
                    result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
                }
                else
                {
                    result = gossipsub_idontwant_decode(
                        version,
                        limits,
                        nested.data,
                        nested.len,
                        storage,
                        &cursor,
                        &storage->idontwant[out->idontwant_count]);
                    if (result == LIBP2P_GOSSIPSUB_OK)
                    {
                        out->idontwant_count++;
                    }
                }
            }
            else
            {
                (void)field;
            }
        }
    }
    if ((result == LIBP2P_GOSSIPSUB_OK) && ((out->ihave_count > limits->max_ihave_per_rpc) ||
                                            (out->iwant_count > limits->max_iwant_per_rpc) ||
                                            (out->graft_count > limits->max_graft_per_rpc) ||
                                            (out->prune_count > limits->max_prune_per_rpc) ||
                                            (out->idontwant_count > limits->max_idontwant_per_rpc)))
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }

    return result;
}
