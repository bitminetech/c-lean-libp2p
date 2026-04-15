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

static const char multibase_base58btc_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int multibase_add_overflow(size_t a, size_t b, size_t *out)
{
    int overflowed = 0;
    size_t result = SIZE_MAX;

    if ((SIZE_MAX - a) < b)
    {
        overflowed = 1;
    }
    else
    {
        result = a + b;
    }

    *out = result;
    return overflowed;
}

static int multibase_mul_overflow(size_t a, size_t b, size_t *out)
{
    int overflowed = 0;
    size_t result = SIZE_MAX;

    if ((a != 0U) && ((SIZE_MAX / a) < b))
    {
        overflowed = 1;
    }
    else
    {
        result = a * b;
    }

    *out = result;
    return overflowed;
}

static size_t multibase_base58_encoded_upper_bound(size_t in_len)
{
    size_t scaled = 0U;
    size_t result = 0U;

    if (in_len != 0U)
    {
        if (multibase_mul_overflow(in_len, 138U, &scaled) != 0)
        {
            result = SIZE_MAX;
        }
        else
        {
            result = (scaled / 100U) + 1U;
        }
    }

    return result;
}

static size_t multibase_base64_encoded_exact_size(size_t in_len)
{
    size_t full_groups = in_len / 3U;
    size_t total = 0U;
    size_t result = SIZE_MAX;
    const size_t remainder = in_len % 3U;

    if (multibase_mul_overflow(full_groups, 4U, &total) == 0)
    {
        switch (remainder)
        {
        case 0U:
            result = total;
            break;

        case 1U:
            if (multibase_add_overflow(total, 2U, &total) == 0)
            {
                result = total;
            }
            break;

        default:
            if (multibase_add_overflow(total, 3U, &total) == 0)
            {
                result = total;
            }
            break;
        }
    }

    return result;
}

static size_t multibase_base64_decoded_upper_bound(size_t text_len)
{
    size_t groups = 0U;
    size_t total = 0U;
    size_t result = SIZE_MAX;

    if (multibase_add_overflow(text_len, 3U, &groups) == 0)
    {
        groups /= 4U;

        if (multibase_mul_overflow(groups, 3U, &total) == 0)
        {
            result = total;
        }
    }

    return result;
}

static int multibase_base64_decoded_exact_size(size_t text_len, size_t *decoded_len)
{
    size_t total = 0U;
    size_t result = 0U;
    int size_is_valid = 1;
    const size_t remainder = text_len % 4U;

    if (remainder == 1U)
    {
        size_is_valid = 0;
    }
    else
    {
        const size_t full_groups = text_len / 4U;
        if (multibase_mul_overflow(full_groups, 3U, &total) != 0)
        {
            result = SIZE_MAX;
        }
        else
        {
            switch (remainder)
            {
            case 0U:
                result = total;
                break;

            case 2U:
                if (multibase_add_overflow(total, 1U, &total) != 0)
                {
                    result = SIZE_MAX;
                }
                else
                {
                    result = total;
                }
                break;

            default:
                if (multibase_add_overflow(total, 2U, &total) != 0)
                {
                    result = SIZE_MAX;
                }
                else
                {
                    result = total;
                }
                break;
            }
        }
    }

    *decoded_len = result;
    return size_is_valid;
}

static libp2p_multibase_err_t multibase_prefix_for_base(
    libp2p_multibase_t base,
    char *prefix)
{
    char resolved_prefix = '\0';
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;

    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        resolved_prefix = 'z';
        err = LIBP2P_MULTIBASE_OK;
        break;

    case LIBP2P_MULTIBASE_BASE64URL:
        resolved_prefix = 'u';
        err = LIBP2P_MULTIBASE_OK;
        break;

    default:
        break;
    }

    *prefix = resolved_prefix;
    return err;
}

static libp2p_multibase_err_t multibase_base_from_prefix(
    char prefix,
    libp2p_multibase_t *base)
{
    libp2p_multibase_t resolved_base = LIBP2P_MULTIBASE_BASE58BTC;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
    int base_was_resolved = 0;

    switch (prefix)
    {
    case 'z':
        resolved_base = LIBP2P_MULTIBASE_BASE58BTC;
        err = LIBP2P_MULTIBASE_OK;
        base_was_resolved = 1;
        break;

    case 'u':
        resolved_base = LIBP2P_MULTIBASE_BASE64URL;
        err = LIBP2P_MULTIBASE_OK;
        base_was_resolved = 1;
        break;

    case '\0':
    case '/':
    case '1':
    case 'Q':
        err = LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX;
        break;

    default:
        break;
    }

    if ((base != NULL) && (base_was_resolved != 0))
    {
        *base = resolved_base;
    }

    return err;
}

static int multibase_base58_value(char character, uint8_t *value)
{
    size_t index = 0U;
    int found = 0;
    uint8_t resolved_value = 0U;

    for (index = 0U; index < 58U; index++)
    {
        if (multibase_base58btc_alphabet[index] == character)
        {
            resolved_value = (uint8_t)index;
            found = 1;
            break;
        }
    }

    *value = resolved_value;
    return found;
}

static int multibase_base64url_value(char character, uint8_t *value)
{
    const unsigned int ascii_value = (unsigned int)(unsigned char)character;
    unsigned int resolved_value = 0U;
    int is_valid = 0;

    if ((character >= 'A') && (character <= 'Z'))
    {
        resolved_value = ascii_value - (unsigned int)'A';
        is_valid = 1;
    }
    else if ((character >= 'a') && (character <= 'z'))
    {
        resolved_value = 26U + (ascii_value - (unsigned int)'a');
        is_valid = 1;
    }
    else if ((character >= '0') && (character <= '9'))
    {
        resolved_value = 52U + (ascii_value - (unsigned int)'0');
        is_valid = 1;
    }
    else if (character == '-')
    {
        resolved_value = 62U;
        is_valid = 1;
    }
    else if (character == '_')
    {
        resolved_value = 63U;
        is_valid = 1;
    }
    else
    {
        /* Invalid base64url character. */
    }

    *value = (uint8_t)resolved_value;
    return is_valid;
}

static libp2p_multibase_err_t multibase_encode_base64url(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    static const char base64url_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t exact_payload_len = multibase_base64_encoded_exact_size(in_len);
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;
    size_t exact_total_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (multibase_add_overflow(1U, exact_payload_len, &exact_total_len) != 0)
    {
        exact_total_len = SIZE_MAX;
    }

    if (written != NULL)
    {
        *written = exact_total_len;
    }

    if (((in_len != 0U) && (in == NULL)) || (out == NULL) || (out_len < exact_total_len))
    {
        err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }
    else
    {
        size_t in_index = 0U;
        size_t out_index = 0U;

        out[out_index] = 'u';
        out_index++;

        while ((in_index + 3U) <= in_len)
        {
            const uint32_t chunk = ((uint32_t)in[in_index] << 16U) |
                                   ((uint32_t)in[in_index + 1U] << 8U) |
                                   (uint32_t)in[in_index + 2U];

            out[out_index] = base64url_alphabet[(chunk >> 18U) & 0x3fU];
            out[out_index + 1U] = base64url_alphabet[(chunk >> 12U) & 0x3fU];
            out[out_index + 2U] = base64url_alphabet[(chunk >> 6U) & 0x3fU];
            out[out_index + 3U] = base64url_alphabet[chunk & 0x3fU];

            in_index += 3U;
            out_index += 4U;
        }

        {
            const size_t remaining = in_len - in_index;

            if (remaining == 1U)
            {
                const uint8_t byte0 = in[in_index];

                out[out_index] = base64url_alphabet[byte0 >> 2U];
                out[out_index + 1U] = base64url_alphabet[(byte0 & 0x03U) << 4U];
            }
            else if (remaining == 2U)
            {
                const uint8_t byte0 = in[in_index];
                const uint8_t byte1 = in[in_index + 1U];

                out[out_index] = base64url_alphabet[byte0 >> 2U];
                out[out_index + 1U] =
                    base64url_alphabet[((byte0 & 0x03U) << 4U) | (byte1 >> 4U)];
                out[out_index + 2U] = base64url_alphabet[(byte1 & 0x0fU) << 2U];
            }
            else
            {
                /* No trailing bytes remain. */
            }
        }
    }

    return err;
}

static libp2p_multibase_err_t multibase_encode_base58btc(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    size_t zero_count = 0U;
    size_t significant_len = 0U;
    size_t required_bound = 0U;
    size_t scratch_offset = 0U;
    size_t digits_capacity = 0U;
    size_t used = 0U;
    size_t in_index = 0U;
    size_t out_index = 0U;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in_len != 0U) && (in == NULL))
    {
        err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
    }
    else
    {
        while ((zero_count < in_len) && (in[zero_count] == 0U))
        {
            zero_count++;
        }

        significant_len = in_len - zero_count;
        scratch_offset = 1U + zero_count;
        required_bound = scratch_offset;

        if (significant_len != 0U)
        {
            const size_t digits_bound = multibase_base58_encoded_upper_bound(significant_len);

            if (digits_bound == SIZE_MAX)
            {
                required_bound = SIZE_MAX;
            }
            else if (multibase_add_overflow(required_bound, digits_bound, &required_bound) != 0)
            {
                required_bound = SIZE_MAX;
            }
            else
            {
                /* required_bound already contains the exact upper bound. */
            }
        }
        else
        {
            /* Only the prefix and leading zero digits are required. */
        }

        if (written != NULL)
        {
            *written = required_bound;
        }

        if (significant_len == 0U)
        {
            if ((out == NULL) || (out_len < required_bound))
            {
                err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
            }
            else
            {
                out[0] = 'z';
                for (out_index = 0U; out_index < zero_count; out_index++)
                {
                    out[1U + out_index] = '1';
                }

                if (written != NULL)
                {
                    *written = required_bound;
                }
            }
        }
        else if ((out == NULL) || (out_len <= scratch_offset))
        {
            err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
        }
        else
        {
            digits_capacity = out_len - scratch_offset;
            for (out_index = 0U; out_index < digits_capacity; out_index++)
            {
                out[scratch_offset + out_index] = '\0';
            }

            in_index = zero_count;
            while ((in_index < in_len) && (err == LIBP2P_MULTIBASE_OK))
            {
                uint32_t carry = (uint32_t)in[in_index];
                size_t digit_index = 0U;

                while (((carry != 0U) || (digit_index < used)) &&
                       (err == LIBP2P_MULTIBASE_OK))
                {
                    if (digit_index >= digits_capacity)
                    {
                        err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
                    }
                    else
                    {
                        const size_t array_index = digits_capacity - 1U - digit_index;
                        const size_t scratch_index = scratch_offset + array_index;
                        uint32_t digit_value = 0U;

                        carry += ((uint32_t)(uint8_t)out[scratch_index]) << 8U;
                        digit_value = carry % 58U;
                        out[scratch_index] = (char)digit_value;
                        carry /= 58U;
                        digit_index++;
                    }
                }

                if (err == LIBP2P_MULTIBASE_OK)
                {
                    used = digit_index;
                }

                in_index++;
            }

            if (err == LIBP2P_MULTIBASE_OK)
            {
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
                        const uint8_t digit =
                            (uint8_t)out[scratch_offset + start_index + out_index];
                        out[scratch_offset + out_index] = multibase_base58btc_alphabet[digit];
                    }
                }

                if (written != NULL)
                {
                    *written = scratch_offset + used;
                }
            }
        }
    }

    return err;
}

static libp2p_multibase_err_t multibase_decode_base64url(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const size_t payload_len = in_len - 1U;
    const size_t remainder = payload_len % 4U;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;
    size_t exact_size = 0U;
    size_t in_index = 1U;
    size_t out_index = 0U;
    int size_is_valid = multibase_base64_decoded_exact_size(payload_len, &exact_size);
    int output_available = 0;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (size_is_valid == 0)
    {
        err = LIBP2P_MULTIBASE_ERR_INVALID_LENGTH;
    }
    else
    {
        if (written != NULL)
        {
            *written = exact_size;
        }

        if ((out != NULL) && (out_len >= exact_size))
        {
            output_available = 1;
        }

        while ((in_index + 4U) <= in_len)
        {
            uint8_t v0 = 0U;
            uint8_t v1 = 0U;
            uint8_t v2 = 0U;
            uint8_t v3 = 0U;
            uint32_t chunk = 0U;

            if ((multibase_base64url_value(in[in_index], &v0) == 0) ||
                (multibase_base64url_value(in[in_index + 1U], &v1) == 0) ||
                (multibase_base64url_value(in[in_index + 2U], &v2) == 0) ||
                (multibase_base64url_value(in[in_index + 3U], &v3) == 0))
            {
                err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
                break;
            }

            chunk =
                ((uint32_t)v0 << 18U) | ((uint32_t)v1 << 12U) | ((uint32_t)v2 << 6U) | (uint32_t)v3;

            if (output_available != 0)
            {
                out[out_index] = (uint8_t)(chunk >> 16U);
                out[out_index + 1U] = (uint8_t)(chunk >> 8U);
                out[out_index + 2U] = (uint8_t)chunk;
            }

            in_index += 4U;
            out_index += 3U;
        }

        if (err == LIBP2P_MULTIBASE_OK)
        {
            if (remainder == 2U)
            {
                uint8_t v0 = 0U;
                uint8_t v1 = 0U;

                if ((multibase_base64url_value(in[in_index], &v0) == 0) ||
                    (multibase_base64url_value(in[in_index + 1U], &v1) == 0))
                {
                    err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
                }
                else if ((v1 & 0x0fU) != 0U)
                {
                    err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
                }
                else if (output_available != 0)
                {
                    out[out_index] = (uint8_t)((v0 << 2U) | (v1 >> 4U));
                }
                else
                {
                    /* Output buffer is only required after validation succeeds. */
                }
            }
            else if (remainder == 3U)
            {
                uint8_t v0 = 0U;
                uint8_t v1 = 0U;
                uint8_t v2 = 0U;

                if ((multibase_base64url_value(in[in_index], &v0) == 0) ||
                    (multibase_base64url_value(in[in_index + 1U], &v1) == 0) ||
                    (multibase_base64url_value(in[in_index + 2U], &v2) == 0))
                {
                    err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
                }
                else if ((v2 & 0x03U) != 0U)
                {
                    err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
                }
                else if (output_available != 0)
                {
                    out[out_index] = (uint8_t)((v0 << 2U) | (v1 >> 4U));
                    out[out_index + 1U] = (uint8_t)((v1 << 4U) | (v2 >> 2U));
                }
                else
                {
                    /* Output buffer is only required after validation succeeds. */
                }
            }
            else
            {
                /* No trailing payload characters remain. */
            }
        }

        if ((err == LIBP2P_MULTIBASE_OK) && (output_available == 0))
        {
            err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
        }
    }

    return err;
}

static libp2p_multibase_err_t multibase_decode_base58btc(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const size_t payload_len = in_len - 1U;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;
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

        if (multibase_base58_value(in[text_index], &value) == 0)
        {
            err = LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER;
            break;
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

    if (err == LIBP2P_MULTIBASE_OK)
    {
        if (buffer_too_small != 0)
        {
            err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
        }
        else if ((zero_count + used) > out_len)
        {
            err = LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL;
        }
        else
        {
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
        }
    }

    return err;
}

libp2p_multibase_err_t libp2p_multibase_encode(
    libp2p_multibase_t base,
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;

    switch (base)
    {
    case LIBP2P_MULTIBASE_BASE58BTC:
        err = multibase_encode_base58btc(in, in_len, out, out_len, written);
        break;

    case LIBP2P_MULTIBASE_BASE64URL:
        err = multibase_encode_base64url(in, in_len, out, out_len, written);
        break;

    default:
        if (written != NULL)
        {
            *written = 0U;
        }
        break;
    }

    return err;
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
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_ERR_EMPTY_INPUT;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U))
    {
        err = LIBP2P_MULTIBASE_ERR_EMPTY_INPUT;
    }
    else
    {
        err = multibase_base_from_prefix(in[0], &parsed_base);
        if (err == LIBP2P_MULTIBASE_OK)
        {
            if (base != NULL)
            {
                *base = parsed_base;
            }

            switch (parsed_base)
            {
            case LIBP2P_MULTIBASE_BASE58BTC:
                err = multibase_decode_base58btc(in, in_len, out, out_len, written);
                break;

            case LIBP2P_MULTIBASE_BASE64URL:
                err = multibase_decode_base64url(in, in_len, out, out_len, written);
                break;

            default:
                err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
                break;
            }
        }
    }

    return err;
}

libp2p_multibase_err_t libp2p_multibase_encoded_size(
    libp2p_multibase_t base,
    size_t in_len,
    size_t *out_len)
{
    size_t payload_len = 0U;
    char prefix = '\0';
    libp2p_multibase_err_t err = multibase_prefix_for_base(base, &prefix);

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (err != LIBP2P_MULTIBASE_OK)
    {
        /* The requested base is unsupported. */
    }
    else
    {
        switch (base)
        {
        case LIBP2P_MULTIBASE_BASE58BTC:
            payload_len = multibase_base58_encoded_upper_bound(in_len);
            break;

        case LIBP2P_MULTIBASE_BASE64URL:
            payload_len = multibase_base64_encoded_exact_size(in_len);
            break;

        default:
            err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
            break;
        }

        if (err == LIBP2P_MULTIBASE_OK)
        {
            if (multibase_add_overflow(1U, payload_len, &payload_len) != 0)
            {
                payload_len = SIZE_MAX;
            }

            if (out_len != NULL)
            {
                *out_len = payload_len;
            }
        }
    }

    (void)prefix;
    return err;
}

libp2p_multibase_err_t libp2p_multibase_max_decoded_size(
    libp2p_multibase_t base,
    size_t text_len,
    size_t *out_len)
{
    size_t max_len = 0U;
    libp2p_multibase_err_t err = LIBP2P_MULTIBASE_OK;

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
        max_len = multibase_base64_decoded_upper_bound(text_len);
        break;

    default:
        err = LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE;
        break;
    }

    if ((err == LIBP2P_MULTIBASE_OK) && (out_len != NULL))
    {
        *out_len = max_len;
    }

    return err;
}
