/**
 * @file unsigned_varint.c
 * @brief Unsigned varint implementation for the c-lean-libp2p multiformats subset.
 *
 * Encode and decode enforce the multiformats practical limit of 9 bytes / 63 bits.
 * The size helper reports the mathematical width of the uint64_t input so callers
 * can distinguish overflow inputs before encoding.
 */

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_UVARINT_MAX_VALUE UINT64_C(0x7FFFFFFFFFFFFFFF)

static uint8_t libp2p_uvarint_measure_unchecked(uint64_t value)
{
    uint8_t size = 1U;

    while (value >= UINT64_C(0x80))
    {
        value >>= 7U;
        size++;
    }

    return size;
}

libp2p_uvarint_err_t libp2p_uvarint_encode(
    uint64_t value,
    uint8_t *buf,
    size_t buf_len,
    size_t *written)
{
    size_t index = 0U;
    size_t required = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    required = (size_t)libp2p_uvarint_measure_unchecked(value);

    if (written != NULL)
    {
        *written = required;
    }

    if (value > LIBP2P_UVARINT_MAX_VALUE)
    {
        return LIBP2P_UVARINT_ERR_OVERFLOW;
    }

    if ((buf == NULL) || (buf_len < required))
    {
        return LIBP2P_UVARINT_ERR_BUF_TOO_SMALL;
    }

    do
    {
        uint8_t byte = (uint8_t)(value & UINT64_C(0x7f));

        value >>= 7U;
        if (value != UINT64_C(0))
        {
            byte = (uint8_t)(byte | 0x80U);
        }

        buf[index] = byte;
        index++;
    } while (value != UINT64_C(0));

    return LIBP2P_UVARINT_OK;
}

libp2p_uvarint_err_t libp2p_uvarint_decode(
    const uint8_t *buf,
    size_t buf_len,
    uint64_t *value,
    size_t *read)
{
    uint64_t decoded_value = UINT64_C(0);
    uint32_t shift = 0U;
    size_t index = 0U;

    if (value != NULL)
    {
        *value = UINT64_C(0);
    }
    if (read != NULL)
    {
        *read = 0U;
    }

    if ((buf == NULL) && (buf_len != 0U))
    {
        return LIBP2P_UVARINT_ERR_TRUNCATED;
    }

    for (index = 0U; index < buf_len; index++)
    {
        const uint8_t byte = buf[index];

        if (index >= (size_t)LIBP2P_UVARINT_MAX_BYTES)
        {
            return LIBP2P_UVARINT_ERR_OVERFLOW;
        }

        if ((index == ((size_t)LIBP2P_UVARINT_MAX_BYTES - 1U)) && ((byte & 0x80U) != 0U))
        {
            return LIBP2P_UVARINT_ERR_OVERFLOW;
        }

        decoded_value |= ((uint64_t)(byte & 0x7fU)) << shift;

        if ((byte & 0x80U) == 0U)
        {
            if ((index > 0U) && (byte == 0U))
            {
                return LIBP2P_UVARINT_ERR_NON_MINIMAL;
            }

            if (value != NULL)
            {
                *value = decoded_value;
            }
            if (read != NULL)
            {
                *read = index + 1U;
            }

            return LIBP2P_UVARINT_OK;
        }

        shift += 7U;
    }

    return LIBP2P_UVARINT_ERR_TRUNCATED;
}

uint8_t libp2p_uvarint_size(uint64_t value)
{
    return libp2p_uvarint_measure_unchecked(value);
}
