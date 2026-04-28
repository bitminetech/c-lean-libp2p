#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

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
