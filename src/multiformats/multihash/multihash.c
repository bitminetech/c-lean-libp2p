/**
 * @file multihash.c
 * @brief Multihash subset implementation layered on unsigned varints.
 */

#include "multiformats/multihash/multihash.h"

#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_MULTIHASH_MAX_VARINT_VALUE      UINT64_C(0x7FFFFFFFFFFFFFFF)
#define LIBP2P_MULTIHASH_SHA2_256_DIGEST_BYTES 32U

static libp2p_multihash_err_t multihash_validate_size_input(size_t digest_len)
{
#if SIZE_MAX > LIBP2P_MULTIHASH_MAX_VARINT_VALUE
    if ((uint64_t)digest_len > LIBP2P_MULTIHASH_MAX_VARINT_VALUE)
    {
        return LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
    }
#else
    (void)digest_len;
#endif

    return LIBP2P_MULTIHASH_OK;
}

static libp2p_multihash_err_t multihash_validate_code_and_length(
    uint64_t code,
    size_t digest_len)
{
    libp2p_multihash_err_t err = multihash_validate_size_input(digest_len);

    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    switch (code)
    {
    case LIBP2P_MULTIHASH_CODE_IDENTITY:
        return LIBP2P_MULTIHASH_OK;

    case LIBP2P_MULTIHASH_CODE_SHA2_256:
        if (digest_len != LIBP2P_MULTIHASH_SHA2_256_DIGEST_BYTES)
        {
            return LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
        }

        return LIBP2P_MULTIHASH_OK;

    default:
        return LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE;
    }
}

static libp2p_multihash_err_t multihash_map_header_varint_err(libp2p_uvarint_err_t err)
{
    switch (err)
    {
    case LIBP2P_UVARINT_ERR_TRUNCATED:
        return LIBP2P_MULTIHASH_ERR_TRUNCATED;

    case LIBP2P_UVARINT_OK:
        return LIBP2P_MULTIHASH_OK;

    case LIBP2P_UVARINT_ERR_BUF_TOO_SMALL:
    case LIBP2P_UVARINT_ERR_NON_MINIMAL:
    case LIBP2P_UVARINT_ERR_OVERFLOW:
    default:
        return LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
    }
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
    libp2p_multihash_err_t err = libp2p_multihash_size(code, digest_len, &required);

    if (written != NULL)
    {
        *written = 0U;
    }

    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    if ((digest_len != 0U) && (digest == NULL))
    {
        return LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
    }

    if (written != NULL)
    {
        *written = required;
    }

    if ((out == NULL) || (out_len < required))
    {
        return LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL;
    }

    if (libp2p_uvarint_encode(code, code_buf, sizeof(code_buf), &code_written) != LIBP2P_UVARINT_OK)
    {
        return LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
    }

    if (libp2p_uvarint_encode((uint64_t)digest_len, size_buf, sizeof(size_buf), &size_written) !=
        LIBP2P_UVARINT_OK)
    {
        return LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
    }

    (void)memcpy(out + offset, code_buf, code_written);
    offset += code_written;
    (void)memcpy(out + offset, size_buf, size_written);
    offset += size_written;

    if (digest_len != 0U)
    {
        (void)memcpy(out + offset, digest, digest_len);
    }

    return LIBP2P_MULTIHASH_OK;
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
    libp2p_multihash_err_t err =
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

    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    err = multihash_validate_code_and_length(parsed_code, parsed_digest_len);
    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    if ((in_len - digest_offset) < parsed_digest_len)
    {
        return LIBP2P_MULTIHASH_ERR_TRUNCATED;
    }

    if (code != NULL)
    {
        *code = parsed_code;
    }
    if (digest != NULL)
    {
        *digest = in + digest_offset;
    }
    if (digest_len != NULL)
    {
        *digest_len = parsed_digest_len;
    }
    if (read != NULL)
    {
        *read = digest_offset + parsed_digest_len;
    }

    return LIBP2P_MULTIHASH_OK;
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
    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    if (code_read > in_len)
    {
        return LIBP2P_MULTIHASH_ERR_TRUNCATED;
    }

    err = multihash_map_header_varint_err(libp2p_uvarint_decode(
        in + code_read,
        in_len - code_read,
        &parsed_digest_len_u64,
        &size_read));
    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    if (parsed_digest_len_u64 > (uint64_t)SIZE_MAX)
    {
        return LIBP2P_MULTIHASH_ERR_INVALID_VARINT;
    }

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

    return LIBP2P_MULTIHASH_OK;
}

libp2p_multihash_err_t libp2p_multihash_size(uint64_t code, size_t digest_len, size_t *out_len)
{
    size_t total = 0U;
    libp2p_multihash_err_t err = multihash_validate_code_and_length(code, digest_len);

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (err != LIBP2P_MULTIHASH_OK)
    {
        return err;
    }

    total = (size_t)libp2p_uvarint_size(code);
    total += (size_t)libp2p_uvarint_size((uint64_t)digest_len);
    total += digest_len;

    if (out_len != NULL)
    {
        *out_len = total;
    }

    return LIBP2P_MULTIHASH_OK;
}
