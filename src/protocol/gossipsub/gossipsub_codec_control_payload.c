#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

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
