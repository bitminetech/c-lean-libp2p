#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

libp2p_gossipsub_err_t gossipsub_write_uvarint(
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

libp2p_gossipsub_err_t gossipsub_read_uvarint(
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

libp2p_gossipsub_err_t gossipsub_field_size(
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

libp2p_gossipsub_err_t gossipsub_write_len_field(
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

libp2p_gossipsub_err_t gossipsub_write_varint_field(
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

libp2p_gossipsub_err_t gossipsub_write_len_prefix(
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

libp2p_gossipsub_err_t gossipsub_skip_field(
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

libp2p_gossipsub_err_t gossipsub_read_len_span(
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

libp2p_gossipsub_err_t gossipsub_limits_validate(const libp2p_gossipsub_limits_t *limits)
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

libp2p_gossipsub_err_t gossipsub_version_validate(libp2p_gossipsub_protocol_version_t version)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((version != LIBP2P_GOSSIPSUB_VERSION_11) && (version != LIBP2P_GOSSIPSUB_VERSION_12))
    {
        result = LIBP2P_GOSSIPSUB_ERR_UNSUPPORTED_VERSION;
    }

    return result;
}
