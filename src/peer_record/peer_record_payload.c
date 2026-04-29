#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "peer_record_internal.h"

static libp2p_peer_record_err_t peer_record_multiaddr_err(libp2p_multiaddr_err_t err)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_ERR_MALFORMED;

    if (err == LIBP2P_MULTIADDR_OK)
    {
        result = LIBP2P_PEER_RECORD_OK;
    }
    else if (err == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL)
    {
        result = LIBP2P_PEER_RECORD_ERR_UNSUPPORTED;
    }
    else if (err == LIBP2P_MULTIADDR_ERR_TRUNCATED)
    {
        result = LIBP2P_PEER_RECORD_ERR_TRUNCATED;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_address_info_size(
    libp2p_peer_record_bytes_t multiaddr,
    size_t *out_len)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    size_t total = 0U;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result =
            peer_record_len_field_size(PEER_RECORD_FIELD_ADDRESS_MULTIADDR, multiaddr.len, &total);
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *out_len = total;
        }
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_validate_record(const libp2p_peer_record_t *record)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (record == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (
        (peer_record_bytes_present(record->peer_id) == 0) ||
        (record->peer_id.len > LIBP2P_PEER_ID_MAX_BYTES) ||
        (record->multiaddr_count > LIBP2P_PEER_RECORD_MAX_MULTIADDRS))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        size_t index = 0U;

        for (index = 0U; (index < record->multiaddr_count) && (result == LIBP2P_PEER_RECORD_OK);
             index++)
        {
            if ((peer_record_bytes_present(record->multiaddrs[index]) == 0) ||
                (record->multiaddrs[index].len > LIBP2P_PEER_RECORD_MAX_MULTIADDR_BYTES))
            {
                result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
            }
            else
            {
                result = peer_record_multiaddr_err(libp2p_multiaddr_validate(
                    record->multiaddrs[index].data,
                    record->multiaddrs[index].len));
            }
        }
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_payload_size(
    const libp2p_peer_record_t *record,
    size_t *out_len)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    size_t total = 0U;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result = peer_record_validate_record(record);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_len_field_size(
            PEER_RECORD_FIELD_RECORD_PEER_ID,
            record->peer_id.len,
            &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result =
            peer_record_varint_field_size(PEER_RECORD_FIELD_RECORD_SEQNO, record->seqno, &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        size_t index = 0U;

        for (index = 0U; (index < record->multiaddr_count) && (result == LIBP2P_PEER_RECORD_OK);
             index++)
        {
            size_t address_size = 0U;

            result = peer_record_address_info_size(record->multiaddrs[index], &address_size);
            if (result == LIBP2P_PEER_RECORD_OK)
            {
                result = peer_record_len_field_size(
                    PEER_RECORD_FIELD_RECORD_ADDRESSES,
                    address_size,
                    &total);
            }
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (total > LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            *out_len = total;
        }
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_write_address_info(
    libp2p_peer_record_bytes_t multiaddr,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    size_t address_size = 0U;
    libp2p_peer_record_err_t result = peer_record_address_info_size(multiaddr, &address_size);

    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_key(
            PEER_RECORD_FIELD_RECORD_ADDRESSES,
            PEER_RECORD_WIRE_LEN,
            out,
            out_len,
            pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_uvarint((uint64_t)address_size, out, out_len, pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_ADDRESS_MULTIADDR,
            multiaddr.data,
            multiaddr.len,
            out,
            out_len,
            pos);
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_payload_encode(
    const libp2p_peer_record_t *record,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    size_t required = 0U;
    size_t pos = 0U;

    if (written == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *written = 0U;
        result = libp2p_peer_record_payload_size(record, &required);
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *written = required;
            if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
            }
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_RECORD_PEER_ID,
            record->peer_id.data,
            record->peer_id.len,
            out,
            out_len,
            &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_varint_field(
            PEER_RECORD_FIELD_RECORD_SEQNO,
            record->seqno,
            out,
            out_len,
            &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        size_t index = 0U;

        for (index = 0U; (index < record->multiaddr_count) && (result == LIBP2P_PEER_RECORD_OK);
             index++)
        {
            result = peer_record_write_address_info(record->multiaddrs[index], out, out_len, &pos);
        }
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_address_info_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_bytes_t *out_multiaddr)
{
    size_t pos = 0U;
    uint8_t seen_multiaddr = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (out_multiaddr == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_multiaddr, 0, sizeof(*out_multiaddr));
    }
    while ((result == LIBP2P_PEER_RECORD_OK) && (pos < in_len))
    {
        uint32_t field = 0U;
        uint32_t wire_type = 0U;

        result = peer_record_read_key(in, in_len, &pos, &field, &wire_type);
        if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_ADDRESS_MULTIADDR))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_multiaddr != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, out_multiaddr);
                seen_multiaddr = 1U;
            }
        }
        else if (result == LIBP2P_PEER_RECORD_OK)
        {
            result = peer_record_skip_value(in, in_len, &pos, wire_type);
        }
        else
        {
            /* Preserve the first decode error. */
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if ((seen_multiaddr == 0U) || (out_multiaddr->len > LIBP2P_PEER_RECORD_MAX_MULTIADDR_BYTES))
        {
            result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
        }
        else
        {
            result = peer_record_multiaddr_err(
                libp2p_multiaddr_validate(out_multiaddr->data, out_multiaddr->len));
        }
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_payload_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_t *out_record)
{
    size_t pos = 0U;
    uint8_t seen_peer_id = 0U;
    uint8_t seen_seqno = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (in_len == 0U) || (out_record == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_record, 0, sizeof(*out_record));
    }
    while ((result == LIBP2P_PEER_RECORD_OK) && (pos < in_len))
    {
        uint32_t field = 0U;
        uint32_t wire_type = 0U;

        result = peer_record_read_key(in, in_len, &pos, &field, &wire_type);
        if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_RECORD_PEER_ID))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_peer_id != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &out_record->peer_id);
                seen_peer_id = 1U;
            }
        }
        else if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_RECORD_SEQNO))
        {
            if ((wire_type != PEER_RECORD_WIRE_VARINT) || (seen_seqno != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_uvarint(in, in_len, &pos, &out_record->seqno);
                seen_seqno = 1U;
            }
        }
        else if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_RECORD_ADDRESSES))
        {
            libp2p_peer_record_bytes_t address;

            (void)memset(&address, 0, sizeof(address));
            if (wire_type != PEER_RECORD_WIRE_LEN)
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else if (out_record->multiaddr_count == LIBP2P_PEER_RECORD_MAX_MULTIADDRS)
            {
                result = LIBP2P_PEER_RECORD_ERR_LIMIT;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &address);
                if (result == LIBP2P_PEER_RECORD_OK)
                {
                    result = peer_record_address_info_decode(
                        address.data,
                        address.len,
                        &out_record->multiaddrs[out_record->multiaddr_count]);
                }
                if (result == LIBP2P_PEER_RECORD_OK)
                {
                    out_record->multiaddr_count++;
                }
            }
        }
        else if (result == LIBP2P_PEER_RECORD_OK)
        {
            result = peer_record_skip_value(in, in_len, &pos, wire_type);
        }
        else
        {
            /* Preserve the first decode error. */
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if ((seen_peer_id == 0U) || (seen_seqno == 0U) ||
            (peer_record_bytes_present(out_record->peer_id) == 0) ||
            (out_record->peer_id.len > LIBP2P_PEER_ID_MAX_BYTES))
        {
            result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
        }
    }

    return result;
}
