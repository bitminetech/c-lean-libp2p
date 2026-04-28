#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

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
