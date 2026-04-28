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

libp2p_gossipsub_err_t gossipsub_message_size(
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

libp2p_gossipsub_err_t gossipsub_message_encode(
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

libp2p_gossipsub_err_t gossipsub_message_decode(
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

libp2p_gossipsub_err_t gossipsub_sub_size(
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

libp2p_gossipsub_err_t gossipsub_sub_encode(
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

libp2p_gossipsub_err_t gossipsub_sub_decode(
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

libp2p_gossipsub_err_t gossipsub_message_id_list_size(
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

libp2p_gossipsub_err_t gossipsub_message_id_list_encode(
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

libp2p_gossipsub_err_t gossipsub_ihave_size(
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

libp2p_gossipsub_err_t gossipsub_ihave_encode(
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

libp2p_gossipsub_err_t gossipsub_ihave_decode(
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

libp2p_gossipsub_err_t gossipsub_iwant_size(
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

libp2p_gossipsub_err_t gossipsub_iwant_encode(
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

libp2p_gossipsub_err_t gossipsub_iwant_decode(
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

libp2p_gossipsub_err_t gossipsub_topic_control_size(
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

libp2p_gossipsub_err_t gossipsub_topic_control_encode(
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

libp2p_gossipsub_err_t gossipsub_graft_decode(
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

libp2p_gossipsub_err_t gossipsub_peer_info_decode(
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

libp2p_gossipsub_err_t gossipsub_prune_size(
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

libp2p_gossipsub_err_t gossipsub_prune_encode(
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

libp2p_gossipsub_err_t gossipsub_prune_decode(
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

libp2p_gossipsub_err_t gossipsub_idontwant_size(
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

libp2p_gossipsub_err_t gossipsub_idontwant_encode(
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

libp2p_gossipsub_err_t gossipsub_control_size(
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

libp2p_gossipsub_err_t gossipsub_control_encode(
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

libp2p_gossipsub_err_t gossipsub_idontwant_decode(
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

libp2p_gossipsub_err_t gossipsub_control_decode(
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
