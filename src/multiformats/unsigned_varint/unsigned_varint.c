/**
 * @file unsigned_varint.c
 * @brief Unsigned varint implementation for the c-lean-libp2p multiformats subset.
 *
 * Encode and decode enforce the multiformats practical limit of 9 bytes / 63 bits.
 * The size helper reports the mathematical width of the uint64_t input so callers
 * can distinguish overflow inputs before encoding.
 */

#include "multiformats/unsigned_varint/unsigned_varint.h"

static uint8_t uvarint_measure_unchecked(uint64_t value)
{
    uint8_t size = 1U;
    uint64_t remaining = value;

    while (remaining >= 0x80ULL)
    {
        remaining >>= 7U;
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
    uint64_t remaining = value;
    libp2p_uvarint_err_t result = LIBP2P_UVARINT_OK;
    int done = 0;

    if (written != NULL)
    {
        *written = 0U;
    }

    required = (size_t)uvarint_measure_unchecked(value);

    if (written != NULL)
    {
        *written = required;
    }

    if (value > 0x7FFFFFFFFFFFFFFFULL)
    {
        result = LIBP2P_UVARINT_ERR_OVERFLOW;
    }
    else if ((buf == NULL) || (buf_len < required))
    {
        result = LIBP2P_UVARINT_ERR_BUF_TOO_SMALL;
    }
    else
    {
        while (done == 0)
        {
            uint8_t byte = (uint8_t)(remaining & UINT64_C(0x7f));

            remaining >>= 7U;
            if (remaining != 0ULL)
            {
                byte = (uint8_t)(byte | 0x80U);
            }

            buf[index] = byte;
            index++;

            if (remaining == 0ULL)
            {
                done = 1;
            }
        }
    }

    return result;
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
    libp2p_uvarint_err_t result = LIBP2P_UVARINT_ERR_TRUNCATED;
    int done = 0;

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
        result = LIBP2P_UVARINT_ERR_TRUNCATED;
    }
    else
    {
        for (index = 0U; (index < buf_len) && (done == 0); index++)
        {
            const uint8_t byte = buf[index];

            if (index >= (size_t)LIBP2P_UVARINT_MAX_BYTES)
            {
                result = LIBP2P_UVARINT_ERR_OVERFLOW;
                done = 1;
            }
            else if ((index == ((size_t)LIBP2P_UVARINT_MAX_BYTES - 1U)) && ((byte & 0x80U) != 0U))
            {
                result = LIBP2P_UVARINT_ERR_OVERFLOW;
                done = 1;
            }
            else
            {
                uint64_t payload = (uint64_t)byte;

                payload &= UINT64_C(0x7f);
                payload <<= shift;
                decoded_value |= payload;

                if ((byte & 0x80U) == 0U)
                {
                    if ((index > 0U) && (byte == 0U))
                    {
                        result = LIBP2P_UVARINT_ERR_NON_MINIMAL;
                    }
                    else
                    {
                        result = LIBP2P_UVARINT_OK;
                        if (value != NULL)
                        {
                            *value = decoded_value;
                        }
                        if (read != NULL)
                        {
                            *read = index + 1U;
                        }
                    }

                    done = 1;
                }
                else
                {
                    shift += 7U;
                }
            }
        }
    }

    return result;
}

uint8_t libp2p_uvarint_size(uint64_t value)
{
    return uvarint_measure_unchecked(value);
}
