#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

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
