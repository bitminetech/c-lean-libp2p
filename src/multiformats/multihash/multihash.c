/**
 * @file multihash.c
 * @brief Multihash subset implementation layered on unsigned varints.
 */

#include "multiformats/multihash/multihash.h"

#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_MULTIHASH_MAX_VARINT_VALUE UINT64_C(0x7FFFFFFFFFFFFFFF)

static int multihash_size_fits_varint_limit(size_t digest_len)
{
    const size_t max_len = (size_t)LIBP2P_MULTIHASH_MAX_VARINT_VALUE;

    return (digest_len <= max_len) ? 1 : 0;
}

static libp2p_multihash_err_t multihash_validate_size_input(size_t digest_len)
{
    libp2p_multihash_err_t result = LIBP2P_MULTIHASH_OK;

    if (multihash_size_fits_varint_limit(digest_len) == 0)
    {
        result = LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
    }

    return result;
}

static libp2p_multihash_err_t multihash_validate_code_and_length(
    uint64_t code,
    size_t digest_len)
{
    libp2p_multihash_err_t err = multihash_validate_size_input(digest_len);
    libp2p_multihash_err_t result = err;

    if (result == LIBP2P_MULTIHASH_OK)
    {
        switch (code)
        {
        case LIBP2P_MULTIHASH_CODE_IDENTITY:
            break;

        case LIBP2P_MULTIHASH_CODE_SHA2_256:
            if (digest_len != LIBP2P_MULTIHASH_SHA2_256_DIGEST_BYTES)
            {
                result = LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
            }
            break;

        default:
            result = LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE;
            break;
        }
    }

    return result;
}

static libp2p_multihash_err_t multihash_map_header_varint_err(libp2p_uvarint_err_t err)
{
    libp2p_multihash_err_t result = LIBP2P_MULTIHASH_ERR_INVALID_VARINT;

    switch (err)
    {
    case LIBP2P_UVARINT_ERR_TRUNCATED:
        result = LIBP2P_MULTIHASH_ERR_TRUNCATED;
        break;

    case LIBP2P_UVARINT_OK:
        result = LIBP2P_MULTIHASH_OK;
        break;

    case LIBP2P_UVARINT_ERR_BUF_TOO_SMALL:
    case LIBP2P_UVARINT_ERR_NON_MINIMAL:
    case LIBP2P_UVARINT_ERR_OVERFLOW:
    default:
        result = LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
        break;
    }

    return result;
}

libp2p_multihash_err_t libp2p_multihash_encode(
    uint64_t code,
    const uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t code_buf[LIBP2P_UVARINT_MAX_BYTES + 1U];
    uint8_t size_buf[LIBP2P_UVARINT_MAX_BYTES + 1U];
    size_t code_written = 0U;
    size_t size_written = 0U;
    size_t required = 0U;
    size_t offset = 0U;
    libp2p_multihash_err_t result = libp2p_multihash_size(code, digest_len, &required);

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((result == LIBP2P_MULTIHASH_OK) && (digest_len != 0U) && (digest == NULL))
    {
        result = LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
    }

    if ((written != NULL) && (result == LIBP2P_MULTIHASH_OK))
    {
        *written = required;
    }

    if ((result == LIBP2P_MULTIHASH_OK) && ((out == NULL) || (out_len < required)))
    {
        result = LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL;
    }
    if (result == LIBP2P_MULTIHASH_OK)
    {
        if (libp2p_uvarint_encode(code, code_buf, sizeof(code_buf), &code_written) !=
            LIBP2P_UVARINT_OK)
        {
            result = LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
        }
    }

    if (result == LIBP2P_MULTIHASH_OK)
    {
        if (libp2p_uvarint_encode(
                (uint64_t)digest_len,
                size_buf,
                sizeof(size_buf),
                &size_written) != LIBP2P_UVARINT_OK)
        {
            result = LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
        }
    }

    if (result == LIBP2P_MULTIHASH_OK)
    {
        (void)memcpy(&out[offset], code_buf, code_written);
        offset += code_written;
        (void)memcpy(&out[offset], size_buf, size_written);
        offset += size_written;

        if (digest_len != 0U)
        {
            (void)memcpy(&out[offset], digest, digest_len);
        }
    }

    return result;
}

libp2p_multihash_err_t libp2p_multihash_decode(
    const uint8_t *in,
    size_t in_len,
    uint64_t *code,
    const uint8_t **digest,
    size_t *digest_len,
    size_t *read)
{
    uint64_t parsed_code = UINT64_C(0);
    size_t parsed_digest_len = 0U;
    size_t digest_offset = 0U;
    libp2p_multihash_err_t result =
        libp2p_multihash_read_header(in, in_len, &parsed_code, &parsed_digest_len, &digest_offset);

    if (code != NULL)
    {
        *code = UINT64_C(0);
    }
    if (digest != NULL)
    {
        *digest = NULL;
    }
    if (digest_len != NULL)
    {
        *digest_len = 0U;
    }
    if (read != NULL)
    {
        *read = 0U;
    }

    if (result == LIBP2P_MULTIHASH_OK)
    {
        result = multihash_validate_code_and_length(parsed_code, parsed_digest_len);
    }

    if ((result == LIBP2P_MULTIHASH_OK) && ((in_len - digest_offset) < parsed_digest_len))
    {
        result = LIBP2P_MULTIHASH_ERR_TRUNCATED;
    }

    if (result == LIBP2P_MULTIHASH_OK)
    {
        if (code != NULL)
        {
            *code = parsed_code;
        }
        if (digest != NULL)
        {
            *digest = &in[digest_offset];
        }
        if (digest_len != NULL)
        {
            *digest_len = parsed_digest_len;
        }
        if (read != NULL)
        {
            *read = digest_offset + parsed_digest_len;
        }
    }

    return result;
}

libp2p_multihash_err_t libp2p_multihash_read_header(
    const uint8_t *in,
    size_t in_len,
    uint64_t *code,
    size_t *digest_len,
    size_t *digest_offset)
{
    uint64_t parsed_code = UINT64_C(0);
    uint64_t parsed_digest_len_u64 = UINT64_C(0);
    size_t code_read = 0U;
    size_t size_read = 0U;
    libp2p_multihash_err_t err = LIBP2P_MULTIHASH_OK;

    if (code != NULL)
    {
        *code = UINT64_C(0);
    }
    if (digest_len != NULL)
    {
        *digest_len = 0U;
    }
    if (digest_offset != NULL)
    {
        *digest_offset = 0U;
    }

    err = multihash_map_header_varint_err(
        libp2p_uvarint_decode(in, in_len, &parsed_code, &code_read));
    if (err == LIBP2P_MULTIHASH_OK)
    {
        if (code_read > in_len)
        {
            err = LIBP2P_MULTIHASH_ERR_TRUNCATED;
        }
    }

    if (err == LIBP2P_MULTIHASH_OK)
    {
        err = multihash_map_header_varint_err(libp2p_uvarint_decode(
            &in[code_read],
            in_len - code_read,
            &parsed_digest_len_u64,
            &size_read));
    }

    if ((err == LIBP2P_MULTIHASH_OK) && (parsed_digest_len_u64 > (uint64_t)SIZE_MAX))
    {
        err = LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
    }

    if (err == LIBP2P_MULTIHASH_OK)
    {
        if (code != NULL)
        {
            *code = parsed_code;
        }
        if (digest_len != NULL)
        {
            *digest_len = (size_t)parsed_digest_len_u64;
        }
        if (digest_offset != NULL)
        {
            *digest_offset = code_read + size_read;
        }
    }

    return err;
}

libp2p_multihash_err_t libp2p_multihash_size(uint64_t code, size_t digest_len, size_t *out_len)
{
    size_t total = 0U;
    libp2p_multihash_err_t result = multihash_validate_code_and_length(code, digest_len);

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (result == LIBP2P_MULTIHASH_OK)
    {
        total = (size_t)libp2p_uvarint_size(code);
        total += (size_t)libp2p_uvarint_size((uint64_t)digest_len);
        total += digest_len;

        if (out_len != NULL)
        {
            *out_len = total;
        }
    }

    return result;
}
