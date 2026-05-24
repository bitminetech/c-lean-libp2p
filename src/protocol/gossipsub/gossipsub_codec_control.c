#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

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

    (void)version;
    (void)memset(&iwant, 0, sizeof(iwant));
    if (out == NULL)
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
