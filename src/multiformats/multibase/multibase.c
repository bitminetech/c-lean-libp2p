/**
 * @file multibase.c
 * @brief Multibase subset implementation for base58btc and base64url.
 *
 * Base64 sizing is exact. For base58btc, APIs that only receive lengths can
 * return a safe bound because the exact character count depends on the input
 * value as well as its byte length.
 */

#include "multiformats/multibase/multibase.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const char libp2p_multibase_base58btc_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const char libp2p_multibase_base64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int libp2p_multibase_add_overflow(size_t a, size_t b, size_t *out)
{
    if (SIZE_MAX - a < b)
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a + b;
    return 0;
}

static int libp2p_multibase_mul_overflow(size_t a, size_t b, size_t *out)
{
    if ((a != 0U) && ((SIZE_MAX / a) < b))
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a * b;
    return 0;
}

static size_t libp2p_multibase_base58_encoded_upper_bound(size_t in_len)
{
    size_t scaled = 0U;

    if (in_len == 0U)
    {
        return 0U;
    }

    if (libp2p_multibase_mul_overflow(in_len, 138U, &scaled) != 0)
    {
        return SIZE_MAX;
    }

    if (scaled == SIZE_MAX)
    {
        return SIZE_MAX;
    }

    scaled /= 100U;
    if (scaled == SIZE_MAX)
    {
        return SIZE_MAX;
    }

    if (scaled == SIZE_MAX)
    {
        return SIZE_MAX;
    }

    if (scaled == SIZE_MAX)
    {
        return SIZE_MAX;
    }

    return scaled + 1U;
}

static size_t libp2p_multibase_base64_encoded_exact_size(size_t in_len)
{
    size_t full_groups = in_len / 3U;
    size_t total = 0U;
    const size_t remainder = in_len % 3U;

    if (libp2p_multibase_mul_overflow(full_groups, 4U, &total) != 0)
    {
        return SIZE_MAX;
    }

    switch (remainder)
    {
    case 0U:
        return total;

    case 1U:
        if (libp2p_multibase_add_overflow(total, 2U, &total) != 0)
        {
            return SIZE_MAX;
        }
        return total;

    default:
        if (libp2p_multibase_add_overflow(total, 3U, &total) != 0)
        {
            return SIZE_MAX;
        }
        return total;
    }
}

static size_t libp2p_multibase_base64_decoded_upper_bound(size_t text_len)
{
    size_t groups = 0U;
    size_t total = 0U;

    if (libp2p_multibase_add_overflow(text_len, 3U, &groups) != 0)
    {
        return SIZE_MAX;
    }

    groups /= 4U;

    if (libp2p_multibase_mul_overflow(groups, 3U, &total) != 0)
    {
        return SIZE_MAX;
    }

    return total;
}

static int libp2p_multibase_base64_decoded_exact_size(size_t text_len, size_t *decoded_len)
{
    size_t total = 0U;
    size_t full_groups = 0U;
    const size_t remainder = text_len % 4U;

    if (remainder == 1U)
    {
        *decoded_len = 0U;
        return 0;
    }

    full_groups = text_len / 4U;
    if (libp2p_multibase_mul_overflow(full_groups, 3U, &total) != 0)
    {
        *decoded_len = SIZE_MAX;
        return 1;
    }

    switch (remainder)
    {
    case 0U:
        *decoded_len = total;
        return 1;

    case 2U:
        if (libp2p_multibase_add_overflow(total, 1U, &total) != 0)
        {
            *decoded_len = SIZE_MAX;
            return 1;
        }
        *decoded_len = total;
        return 1;

    default:
        if (libp2p_multibase_add_overflow(total, 2U, &total) != 0)
        {
            *decoded_len = SIZE_MAX;
            return 1;
        }
        *decoded_len = total;
        return 1;
    }
}

static libp2p_multibase_err_t libp2p_multibase_prefix_for_base(
    libp2p_multibase_t base,
    char *prefix)
{
    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        *prefix = 'z';
        return LIBP2P_MULTIBASE_OK;

    case LIBP2P_MULTIBASE_BASE64URL:
        *prefix = 'u';
        return LIBP2P_MULTIBASE_OK;

    default:
        *prefix = '\0';
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}

static libp2p_multibase_err_t libp2p_multibase_base_from_prefix(
    char prefix,
    libp2p_multibase_t *base)
{
    switch (prefix)
    {
    case 'z':
        if (base != NULL)
        {
            *base = LIBP2P_MULTIBASE_BASE58BTC;
        }
        return LIBP2P_MULTIBASE_OK;

    case 'u':
        if (base != NULL)
        {
            *base = LIBP2P_MULTIBASE_BASE64URL;
        }
        return LIBP2P_MULTIBASE_OK;

    case '\0':
    case '/':
    case '1':
    case 'Q':
        return LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX;

    default:
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}

static int libp2p_multibase_base58_value(char character, uint8_t *value)
{
    size_t index = 0U;

    for (index = 0U; index < 58U; index++)
    {
        if (libp2p_multibase_base58btc_alphabet[index] == character)
        {
            *value = (uint8_t)index;
            return 1;
        }
    }

    *value = 0U;
    return 0;
}

static int libp2p_multibase_base64url_value(char character, uint8_t *value)
{
    if ((character >= 'A') && (character <= 'Z'))
    {
        *value = (uint8_t)(character - 'A');
        return 1;
    }
    if ((character >= 'a') && (character <= 'z'))
    {
        *value = (uint8_t)(26U + (uint8_t)(character - 'a'));
        return 1;
    }
    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(52U + (uint8_t)(character - '0'));
        return 1;
    }
    if (character == '-')
    {
        *value = 62U;
        return 1;
    }
    if (character == '_')
    {
        *value = 63U;
        return 1;
    }

    *value = 0U;
    return 0;
}

static libp2p_multibase_err_t libp2p_multibase_encode_base64url(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    const size_t exact_payload_len = libp2p_multibase_base64_encoded_exact_size(in_len);
    size_t exact_total_len = 0U;
    size_t in_index = 0U;
    size_t out_index = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (libp2p_multibase_add_overflow(1U, exact_payload_len, &exact_total_len) != 0)
    {
        exact_total_len = SIZE_MAX;
    }

    if (written != NULL)
    {
        *written = exact_total_len;
    }

    if (((in_len != 0U) && (in == NULL)) || (out == NULL) || (out_len < exact_total_len))
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    out[out_index] = 'u';
    out_index++;

    while ((in_index + 3U) <= in_len)
    {
        const uint32_t chunk = ((uint32_t)in[in_index] << 16U) |
                               ((uint32_t)in[in_index + 1U] << 8U) | (uint32_t)in[in_index + 2U];

        out[out_index] = libp2p_multibase_base64url_alphabet[(chunk >> 18U) & 0x3fU];
        out[out_index + 1U] = libp2p_multibase_base64url_alphabet[(chunk >> 12U) & 0x3fU];
        out[out_index + 2U] = libp2p_multibase_base64url_alphabet[(chunk >> 6U) & 0x3fU];
        out[out_index + 3U] = libp2p_multibase_base64url_alphabet[chunk & 0x3fU];

        in_index += 3U;
        out_index += 4U;
    }

    if ((in_len - in_index) == 1U)
    {
        const uint8_t byte0 = in[in_index];

        out[out_index] = libp2p_multibase_base64url_alphabet[byte0 >> 2U];
        out[out_index + 1U] = libp2p_multibase_base64url_alphabet[(byte0 & 0x03U) << 4U];
    }
    else if ((in_len - in_index) == 2U)
    {
        const uint8_t byte0 = in[in_index];
        const uint8_t byte1 = in[in_index + 1U];

        out[out_index] = libp2p_multibase_base64url_alphabet[byte0 >> 2U];
        out[out_index + 1U] =
            libp2p_multibase_base64url_alphabet[((byte0 & 0x03U) << 4U) | (byte1 >> 4U)];
        out[out_index + 2U] = libp2p_multibase_base64url_alphabet[(byte1 & 0x0fU) << 2U];
    }

    return LIBP2P_MULTIBASE_OK;
}

static libp2p_multibase_err_t libp2p_multibase_encode_base58btc(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    size_t zero_count = 0U;
    size_t significant_len = 0U;
    size_t required_bound = 0U;
    size_t digits_capacity = 0U;
    size_t used = 0U;
    size_t in_index = 0U;
    size_t out_index = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in_len != 0U) && (in == NULL))
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    while ((zero_count < in_len) && (in[zero_count] == 0U))
    {
        zero_count++;
    }

    significant_len = in_len - zero_count;
    required_bound = 1U + zero_count;

    if (significant_len != 0U)
    {
        size_t digits_bound = libp2p_multibase_base58_encoded_upper_bound(significant_len);

        if (digits_bound == SIZE_MAX)
        {
            required_bound = SIZE_MAX;
        }
        else if (libp2p_multibase_add_overflow(required_bound, digits_bound, &required_bound) != 0)
        {
            required_bound = SIZE_MAX;
        }
    }

    if (written != NULL)
    {
        *written = required_bound;
    }

    if (significant_len == 0U)
    {
        if ((out == NULL) || (out_len < (1U + zero_count)))
        {
            if (written != NULL)
            {
                *written = 1U + zero_count;
            }
            return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
        }

        out[0] = 'z';
        for (out_index = 0U; out_index < zero_count; out_index++)
        {
            out[1U + out_index] = '1';
        }

        if (written != NULL)
        {
            *written = 1U + zero_count;
        }
        return LIBP2P_MULTIBASE_OK;
    }

    if (out == NULL)
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    if (out_len <= (1U + zero_count))
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    digits_capacity = out_len - (1U + zero_count);
    (void)memset(out + 1U + zero_count, 0, digits_capacity);

    for (in_index = zero_count; in_index < in_len; in_index++)
    {
        uint32_t carry = (uint32_t)in[in_index];
        size_t digit_index = 0U;

        while ((carry != 0U) || (digit_index < used))
        {
            size_t array_index = 0U;

            if (digit_index >= digits_capacity)
            {
                return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
            }

            array_index = digits_capacity - 1U - digit_index;
            carry += ((uint32_t)(uint8_t)out[1U + zero_count + array_index]) << 8U;
            out[1U + zero_count + array_index] = (char)(carry % 58U);
            carry /= 58U;
            digit_index++;
        }

        used = digit_index;
    }

    out[0] = 'z';
    for (out_index = 0U; out_index < zero_count; out_index++)
    {
        out[1U + out_index] = '1';
    }

    if (used != 0U)
    {
        const size_t start_index = digits_capacity - used;

        for (out_index = 0U; out_index < used; out_index++)
        {
            const uint8_t digit = (uint8_t)out[1U + zero_count + start_index + out_index];
            out[1U + zero_count + out_index] = libp2p_multibase_base58btc_alphabet[digit];
        }
    }

    if (written != NULL)
    {
        *written = 1U + zero_count + used;
    }

    return LIBP2P_MULTIBASE_OK;
}

static libp2p_multibase_err_t libp2p_multibase_decode_base64url(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const size_t payload_len = in_len - 1U;
    size_t exact_size = 0U;
    size_t in_index = 1U;
    size_t out_index = 0U;
    int size_is_valid = libp2p_multibase_base64_decoded_exact_size(payload_len, &exact_size);

    if (written != NULL)
    {
        *written = 0U;
    }

    if (size_is_valid == 0)
    {
        return LIBP2P_MULTIBASE_ERR_INVALID_LENGTH;
    }

    if (written != NULL)
    {
        *written = exact_size;
    }

    while ((in_index + 4U) <= in_len)
    {
        uint8_t v0 = 0U;
        uint8_t v1 = 0U;
        uint8_t v2 = 0U;
        uint8_t v3 = 0U;
        uint32_t chunk = 0U;

        if ((libp2p_multibase_base64url_value(in[in_index], &v0) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 1U], &v1) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 2U], &v2) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 3U], &v3) == 0))
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        chunk = ((uint32_t)v0 << 18U) | ((uint32_t)v1 << 12U) | ((uint32_t)v2 << 6U) | (uint32_t)v3;

        if ((out != NULL) && (out_len >= exact_size))
        {
            out[out_index] = (uint8_t)(chunk >> 16U);
            out[out_index + 1U] = (uint8_t)(chunk >> 8U);
            out[out_index + 2U] = (uint8_t)chunk;
        }

        in_index += 4U;
        out_index += 3U;
    }

    if ((payload_len % 4U) == 2U)
    {
        uint8_t v0 = 0U;
        uint8_t v1 = 0U;

        if ((libp2p_multibase_base64url_value(in[in_index], &v0) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 1U], &v1) == 0))
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        if ((v1 & 0x0fU) != 0U)
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        if ((out != NULL) && (out_len >= exact_size))
        {
            out[out_index] = (uint8_t)((v0 << 2U) | (v1 >> 4U));
        }
    }
    else if ((payload_len % 4U) == 3U)
    {
        uint8_t v0 = 0U;
        uint8_t v1 = 0U;
        uint8_t v2 = 0U;

        if ((libp2p_multibase_base64url_value(in[in_index], &v0) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 1U], &v1) == 0) ||
            (libp2p_multibase_base64url_value(in[in_index + 2U], &v2) == 0))
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        if ((v2 & 0x03U) != 0U)
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        if ((out != NULL) && (out_len >= exact_size))
        {
            out[out_index] = (uint8_t)((v0 << 2U) | (v1 >> 4U));
            out[out_index + 1U] = (uint8_t)((v1 << 4U) | (v2 >> 2U));
        }
    }

    if ((out == NULL) || (out_len < exact_size))
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    return LIBP2P_MULTIBASE_OK;
}

static libp2p_multibase_err_t libp2p_multibase_decode_base58btc(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const size_t payload_len = in_len - 1U;
    size_t zero_count = 0U;
    size_t text_index = 0U;
    size_t used = 0U;
    int buffer_too_small = 0;

    if (written != NULL)
    {
        *written = payload_len;
    }

    if ((out != NULL) && (out_len != 0U))
    {
        (void)memset(out, 0, out_len);
    }

    while (((1U + zero_count) < in_len) && (in[1U + zero_count] == '1'))
    {
        zero_count++;
    }

    if (out == NULL)
    {
        buffer_too_small = 1;
    }

    for (text_index = 1U + zero_count; text_index < in_len; text_index++)
    {
        uint8_t value = 0U;

        if (libp2p_multibase_base58_value(in[text_index], &value) == 0)
        {
            return LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
        }

        if (buffer_too_small == 0)
        {
            uint32_t carry = (uint32_t)value;
            size_t byte_index = 0U;

            while ((carry != 0U) || (byte_index < used))
            {
                size_t array_index = 0U;

                if (byte_index >= out_len)
                {
                    buffer_too_small = 1;
                    break;
                }

                array_index = out_len - 1U - byte_index;
                carry += (uint32_t)out[array_index] * 58U;
                out[array_index] = (uint8_t)(carry & 0xffU);
                carry >>= 8U;
                byte_index++;
            }

            if (buffer_too_small == 0)
            {
                used = byte_index;
            }
        }
    }

    if (buffer_too_small != 0)
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    if ((zero_count + used) > out_len)
    {
        return LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }

    if (used != 0U)
    {
        const size_t source_start = out_len - used;
        size_t move_index = 0U;

        for (move_index = 0U; move_index < used; move_index++)
        {
            out[zero_count + move_index] = out[source_start + move_index];
        }
    }

    for (text_index = 0U; text_index < zero_count; text_index++)
    {
        out[text_index] = 0U;
    }

    if (written != NULL)
    {
        *written = zero_count + used;
    }

    return LIBP2P_MULTIBASE_OK;
}

libp2p_multibase_err_t libp2p_multibase_encode(
    libp2p_multibase_t base,
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        return libp2p_multibase_encode_base58btc(in, in_len, out, out_len, written);

    case LIBP2P_MULTIBASE_BASE64URL:
        return libp2p_multibase_encode_base64url(in, in_len, out, out_len, written);

    default:
        if (written != NULL)
        {
            *written = 0U;
        }
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}

libp2p_multibase_err_t libp2p_multibase_decode(
    const char *in,
    size_t in_len,
    libp2p_multibase_t *base,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_multibase_t parsed_base = LIBP2P_MULTIBASE_BASE58BTC;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U))
    {
        return LIBP2P_MULTIBASE_ERR_EMPTY_INPUT;
    }

    err = libp2p_multibase_base_from_prefix(in[0], &parsed_base);
    if (err != LIBP2P_MULTIBASE_OK)
    {
        return err;
    }

    if (base != NULL)
    {
        *base = parsed_base;
    }

    switch (parsed_base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        return libp2p_multibase_decode_base58btc(in, in_len, out, out_len, written);

    case LIBP2P_MULTIBASE_BASE64URL:
        return libp2p_multibase_decode_base64url(in, in_len, out, out_len, written);

    default:
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}

libp2p_multibase_err_t libp2p_multibase_encoded_size(
    libp2p_multibase_t base,
    size_t in_len,
    size_t *out_len)
{
    size_t payload_len = 0U;
    char prefix = '\0';
    libp2p_multibase_err_t err = libp2p_multibase_prefix_for_base(base, &prefix);

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (err != LIBP2P_MULTIBASE_OK)
    {
        return err;
    }

    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        payload_len = libp2p_multibase_base58_encoded_upper_bound(in_len);
        break;

    case LIBP2P_MULTIBASE_BASE64URL:
        payload_len = libp2p_multibase_base64_encoded_exact_size(in_len);
        break;

    default:
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }

    if (libp2p_multibase_add_overflow(1U, payload_len, &payload_len) != 0)
    {
        payload_len = SIZE_MAX;
    }

    if (out_len != NULL)
    {
        *out_len = payload_len;
    }

    (void)prefix;
    return LIBP2P_MULTIBASE_OK;
}

libp2p_multibase_err_t libp2p_multibase_max_decoded_size(
    libp2p_multibase_t base,
    size_t text_len,
    size_t *out_len)
{
    size_t max_len = 0U;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        max_len = text_len;
        break;

    case LIBP2P_MULTIBASE_BASE64URL:
        max_len = libp2p_multibase_base64_decoded_upper_bound(text_len);
        break;

    default:
        return LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    }

    if (out_len != NULL)
    {
        *out_len = max_len;
    }

    return LIBP2P_MULTIBASE_OK;
}
