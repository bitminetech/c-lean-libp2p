#include <string.h>

#include "peer_record_internal.h"

int peer_record_size_add(size_t a, size_t b, size_t *out)
{
    int overflow = 0;

    if (out == NULL)
    {
        overflow = 1;
    }
    else if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        overflow = 1;
    }
    else
    {
        *out = a + b;
    }

    return overflow;
}

int peer_record_bytes_present(libp2p_peer_record_bytes_t bytes)
{
    int present = 0;

    if ((bytes.data != NULL) && (bytes.len != 0U))
    {
        present = 1;
    }

    return present;
}

libp2p_peer_record_err_t peer_record_uvarint_err(libp2p_uvarint_err_t err)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_ERR_MALFORMED;

    if (err == LIBP2P_UVARINT_OK)
    {
        result = LIBP2P_PEER_RECORD_OK;
    }
    else if (err == LIBP2P_UVARINT_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_UVARINT_ERR_TRUNCATED)
    {
        result = LIBP2P_PEER_RECORD_ERR_TRUNCATED;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
    }

    return result;
}

libp2p_peer_record_err_t peer_record_peer_id_err(libp2p_peer_id_err_t err)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_ERR_UNSUPPORTED;

    if (err == LIBP2P_PEER_ID_OK)
    {
        result = LIBP2P_PEER_RECORD_OK;
    }
    else if (err == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE)
    {
        result = LIBP2P_PEER_RECORD_ERR_SIGNATURE;
    }
    else if (
        (err == LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY) ||
        (err == LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING) ||
        (err == LIBP2P_PEER_ID_ERR_INVALID_PEER_ID))
    {
        result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_ERR_UNSUPPORTED;
    }

    return result;
}

libp2p_peer_record_err_t peer_record_host_err(libp2p_host_err_t err)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_ERR_SIGNATURE;

    if (err == LIBP2P_HOST_OK)
    {
        result = LIBP2P_PEER_RECORD_OK;
    }
    else if (err == LIBP2P_HOST_ERR_INVALID_ARG)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_HOST_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_HOST_ERR_LIMIT)
    {
        result = LIBP2P_PEER_RECORD_ERR_LIMIT;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_ERR_SIGNATURE;
    }

    return result;
}

libp2p_peer_record_err_t peer_record_len_field_size(uint32_t field, size_t data_len, size_t *total)
{
    const uint64_t key = (((uint64_t)field) << 3U) | PEER_RECORD_WIRE_LEN;
    size_t next = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((field == 0U) || (total == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (
        peer_record_size_add(
            *total,
            (size_t)libp2p_uvarint_size(key) + (size_t)libp2p_uvarint_size((uint64_t)data_len),
            &next) != 0)
    {
        result = LIBP2P_PEER_RECORD_ERR_LIMIT;
    }
    else if (peer_record_size_add(next, data_len, total) != 0)
    {
        result = LIBP2P_PEER_RECORD_ERR_LIMIT;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_OK;
    }

    return result;
}

libp2p_peer_record_err_t peer_record_varint_field_size(
    uint32_t field,
    uint64_t value,
    size_t *total)
{
    const uint64_t key = (((uint64_t)field) << 3U) | PEER_RECORD_WIRE_VARINT;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((field == 0U) || (total == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (
        peer_record_size_add(
            *total,
            (size_t)libp2p_uvarint_size(key) + (size_t)libp2p_uvarint_size(value),
            total) != 0)
    {
        result = LIBP2P_PEER_RECORD_ERR_LIMIT;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_OK;
    }

    return result;
}

libp2p_peer_record_err_t peer_record_write_uvarint(
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    size_t written = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((out == NULL) || (pos == NULL) || (*pos > out_len))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = peer_record_uvarint_err(
            libp2p_uvarint_encode(value, &out[*pos], out_len - *pos, &written));
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *pos += written;
        }
    }

    return result;
}

libp2p_peer_record_err_t peer_record_write_key(
    uint32_t field,
    uint32_t wire_type,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    const uint64_t key = (((uint64_t)field) << 3U) | ((uint64_t)wire_type);
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((field == 0U) ||
        ((wire_type != PEER_RECORD_WIRE_VARINT) && (wire_type != PEER_RECORD_WIRE_LEN)))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = peer_record_write_uvarint(key, out, out_len, pos);
    }

    return result;
}

libp2p_peer_record_err_t peer_record_write_len_field(
    uint32_t field,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (((data == NULL) && (data_len != 0U)) || (out == NULL) || (pos == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = peer_record_write_key(field, PEER_RECORD_WIRE_LEN, out, out_len, pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_uvarint((uint64_t)data_len, out, out_len, pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (data_len > (out_len - *pos))
        {
            result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
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

libp2p_peer_record_err_t peer_record_write_varint_field(
    uint32_t field,
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    libp2p_peer_record_err_t result =
        peer_record_write_key(field, PEER_RECORD_WIRE_VARINT, out, out_len, pos);

    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_uvarint(value, out, out_len, pos);
    }

    return result;
}

libp2p_peer_record_err_t peer_record_read_key(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint32_t *field,
    uint32_t *wire_type)
{
    uint64_t key = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (pos == NULL) || (field == NULL) || (wire_type == NULL) || (*pos > in_len))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = peer_record_read_uvarint(in, in_len, pos, &key);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        *field = (uint32_t)(key >> 3U);
        *wire_type = (uint32_t)(key & 7U);
        if ((*field == 0U) ||
            ((*wire_type != PEER_RECORD_WIRE_VARINT) && (*wire_type != PEER_RECORD_WIRE_LEN)))
        {
            result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
        }
    }

    return result;
}

libp2p_peer_record_err_t peer_record_read_uvarint(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint64_t *value)
{
    size_t read = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (pos == NULL) || (value == NULL) || (*pos > in_len))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result =
            peer_record_uvarint_err(libp2p_uvarint_decode(&in[*pos], in_len - *pos, value, &read));
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *pos += read;
        }
    }

    return result;
}

libp2p_peer_record_err_t peer_record_read_len_span(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    libp2p_peer_record_bytes_t *out)
{
    uint64_t len = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (pos == NULL) || (out == NULL) || (*pos > in_len))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = peer_record_read_uvarint(in, in_len, pos, &len);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (len > (uint64_t)(in_len - *pos))
        {
            result = LIBP2P_PEER_RECORD_ERR_TRUNCATED;
        }
        else
        {
            out->data = &in[*pos];
            out->len = (size_t)len;
            *pos += (size_t)len;
        }
    }

    return result;
}

libp2p_peer_record_err_t peer_record_skip_value(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint32_t wire_type)
{
    uint64_t ignored = 0U;
    libp2p_peer_record_bytes_t bytes;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    (void)memset(&bytes, 0, sizeof(bytes));
    if ((in == NULL) || (pos == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (wire_type == PEER_RECORD_WIRE_VARINT)
    {
        result = peer_record_read_uvarint(in, in_len, pos, &ignored);
    }
    else if (wire_type == PEER_RECORD_WIRE_LEN)
    {
        result = peer_record_read_len_span(in, in_len, pos, &bytes);
    }
    else
    {
        result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
    }

    return result;
}

libp2p_peer_record_bytes_t peer_record_const_bytes(const char *text, size_t len)
{
    libp2p_peer_record_bytes_t bytes;

    bytes.data = (const uint8_t *)text;
    bytes.len = len;

    return bytes;
}
