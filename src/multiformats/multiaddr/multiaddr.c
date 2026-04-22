/**
 * @file multiaddr.c
 * @brief Multiaddr subset implementation for c-lean-libp2p.
 *
 * The peer-id helpers use fixed-size scratch buffers sized for the supported
 * subset: legacy base58btc peer IDs and CIDv1 `libp2p-key` peer IDs whose
 * multihash is either identity of a <=42-byte key or sha2-256.
 */

#include "multiformats/multiaddr/multiaddr.h"

#include <string.h>

#include "multiformats/multibase/multibase.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_MULTIADDR_CODE_LIBP2P_KEY   0x72ULL
#define LIBP2P_MULTIADDR_CID_VERSION_1     0x01ULL
#define LIBP2P_MULTIADDR_MAX_VARINT_VALUE  0x7FFFFFFFFFFFFFFFULL
#define LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES 128U
#define LIBP2P_MULTIADDR_MAX_PEER_ID_TEXT  192U

typedef struct
{
    uint64_t code;
    const char *name;
    libp2p_multiaddr_value_class_t value_class;
    size_t fixed_size;
} libp2p_multiaddr_protocol_entry_t;

static const libp2p_multiaddr_protocol_entry_t multiaddr_protocol_table[] =
    {{LIBP2P_MULTIADDR_CODE_IP4, "ip4", LIBP2P_MULTIADDR_VALUE_FIXED, 4U},
     {LIBP2P_MULTIADDR_CODE_IP6, "ip6", LIBP2P_MULTIADDR_VALUE_FIXED, 16U},
     {LIBP2P_MULTIADDR_CODE_UDP, "udp", LIBP2P_MULTIADDR_VALUE_FIXED, 2U},
     {LIBP2P_MULTIADDR_CODE_QUIC_V1, "quic-v1", LIBP2P_MULTIADDR_VALUE_NONE, 0U},
     {LIBP2P_MULTIADDR_CODE_P2P, "p2p", LIBP2P_MULTIADDR_VALUE_VARIABLE, 0U}};

static int multiaddr_add_overflow(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (((SIZE_MAX - a) < b))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a + b;
    }

    return result;
}

static size_t multiaddr_protocol_table_len(void)
{
    return sizeof(multiaddr_protocol_table) / sizeof(multiaddr_protocol_table[0]);
}

static int multiaddr_size_fits_varint_limit(size_t value_len)
{
    const size_t max_len = (size_t)LIBP2P_MULTIADDR_MAX_VARINT_VALUE;

    return (value_len <= max_len) ? 1 : 0;
}

static int multiaddr_char_sequence_matches(const char *left, const char *right, size_t len)
{
    int result = 1;

    if ((left == NULL) || (right == NULL))
    {
        result = 0;
    }
    else
    {
        size_t index = 0U;

        for (index = 0U; index < len; index++)
        {
            if (left[index] != right[index])
            {
                result = 0;
            }
        }
    }

    return result;
}

static int multiaddr_byte_sequence_matches(const uint8_t *left, const uint8_t *right, size_t len)
{
    int result = 1;

    if ((len != 0U) && ((left == NULL) || (right == NULL)))
    {
        result = 0;
    }
    else
    {
        size_t index = 0U;

        for (index = 0U; index < len; index++)
        {
            if (left[index] != right[index])
            {
                result = 0;
            }
        }
    }

    return result;
}

static const libp2p_multiaddr_protocol_entry_t *multiaddr_find_protocol_by_code(
    uint64_t code)
{
    size_t index = 0U;
    const libp2p_multiaddr_protocol_entry_t *result = NULL;

    for (index = 0U; index < multiaddr_protocol_table_len(); index++)
    {
        if (multiaddr_protocol_table[index].code == code)
        {
            result = &multiaddr_protocol_table[index];
            break;
        }
    }

    return result;
}

static const libp2p_multiaddr_protocol_entry_t *multiaddr_find_protocol_by_name(
    const char *name,
    size_t name_len)
{
    size_t index = 0U;
    const libp2p_multiaddr_protocol_entry_t *result = NULL;

    for (index = 0U; index < multiaddr_protocol_table_len(); index++)
    {
        const char *const entry_name = multiaddr_protocol_table[index].name;
        const size_t entry_name_len = strlen(entry_name);

        if ((entry_name_len == name_len) &&
            (multiaddr_char_sequence_matches(entry_name, name, name_len) != 0))
        {
            result = &multiaddr_protocol_table[index];
            break;
        }
    }

    return result;
}

static int multiaddr_is_ipfs_alias(const char *name, size_t name_len)
{
    static const char alias[] = "ipfs";
    int result = 0;

    if ((name_len == (sizeof(alias) - 1U)) &&
        (multiaddr_char_sequence_matches(name, alias, sizeof(alias) - 1U) != 0))
    {
        result = 1;
    }

    return result;
}

static libp2p_multiaddr_err_t multiaddr_map_varint_err(libp2p_uvarint_err_t err)
{
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_ERR_MALFORMED;

    switch (err)
    {
    case LIBP2P_UVARINT_ERR_TRUNCATED:
        result = LIBP2P_MULTIADDR_ERR_TRUNCATED;
        break;

    case LIBP2P_UVARINT_OK:
        result = LIBP2P_MULTIADDR_OK;
        break;

    case LIBP2P_UVARINT_ERR_BUF_TOO_SMALL:
    case LIBP2P_UVARINT_ERR_NON_MINIMAL:
    case LIBP2P_UVARINT_ERR_OVERFLOW:
    default:
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
        break;
    }

    return result;
}

static int multiaddr_parse_decimal(
    const char *text,
    size_t text_len,
    uint32_t max_value,
    uint32_t *value)
{
    uint32_t parsed = 0U;
    size_t index = 0U;
    int result = 1;

    if ((text == NULL) || (text_len == 0U) || (value == NULL))
    {
        result = 0;
    }

    for (index = 0U; (index < text_len) && (result != 0); index++)
    {
        const unsigned char character = (unsigned char)text[index];
        const unsigned char zero_char = (unsigned char)'0';
        const unsigned char nine_char = (unsigned char)'9';

        if ((character < zero_char) || (character > nine_char))
        {
            result = 0;
        }
        else
        {
            const uint32_t digit = ((uint32_t)character) - ((uint32_t)zero_char);

            if (parsed > ((max_value - digit) / 10U))
            {
                result = 0;
            }
            else
            {
                parsed = (parsed * 10U) + digit;
            }
        }
    }

    if (result != 0)
    {
        *value = parsed;
    }

    return result;
}

static int multiaddr_hex_value(char character, uint8_t *value)
{
    uint32_t numeric_value = 0U;
    int result = 1;

    if (value == NULL)
    {
        result = 0;
    }

    if ((character >= '0') && (character <= '9'))
    {
        numeric_value = ((uint32_t)(unsigned char)character) - ((uint32_t)'0');
    }
    else if ((character >= 'a') && (character <= 'f'))
    {
        numeric_value = 10U + (((uint32_t)(unsigned char)character) - ((uint32_t)'a'));
    }
    else if ((character >= 'A') && (character <= 'F'))
    {
        numeric_value = 10U + (((uint32_t)(unsigned char)character) - ((uint32_t)'A'));
    }
    else
    {
        result = 0;
    }

    if (value != NULL)
    {
        *value = (uint8_t)numeric_value;
    }

    return result;
}

static int multiaddr_parse_ipv4(const char *text, size_t text_len, uint8_t out[4])
{
    size_t part = 0U;
    size_t start = 0U;
    size_t pos = 0U;
    int result = 1;

    if ((text == NULL) || (out == NULL))
    {
        result = 0;
    }

    for (part = 0U; (part < 4U) && (result != 0); part++)
    {
        size_t part_len = 0U;
        uint32_t parsed_value = 0U;

        if (start >= text_len)
        {
            result = 0;
        }

        while ((pos < text_len) && (text[pos] != '.') && (result != 0))
        {
            pos++;
        }

        part_len = pos - start;
        if (multiaddr_parse_decimal(&text[start], part_len, 255U, &parsed_value) == 0)
        {
            result = 0;
        }
        else
        {
            out[part] = (uint8_t)parsed_value;

            if (part == 3U)
            {
                if (pos != text_len)
                {
                    result = 0;
                }
            }
            else if (pos >= text_len)
            {
                result = 0;
            }
            else
            {
                pos++;
                start = pos;
            }
        }
    }

    if (part != 4U)
    {
        result = 0;
    }

    return result;
}

static int multiaddr_parse_ipv6(const char *text, size_t text_len, uint8_t out[16])
{
    uint16_t groups[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    size_t group_count = 0U;
    size_t compress_index = SIZE_MAX;
    size_t pos = 0U;
    int result = 1;
    int parsing_complete = 0;

    if ((text == NULL) || (text_len == 0U) || (out == NULL))
    {
        result = 0;
    }

    if ((result != 0) && (text[0] == ':'))
    {
        if ((text_len < 2U) || (text[1] != ':'))
        {
            result = 0;
        }
        else
        {
            compress_index = 0U;
            pos = 2U;
            if (pos == text_len)
            {
                group_count = 0U;
                parsing_complete = 1;
            }
        }
    }

    while ((pos < text_len) && (result != 0) && (parsing_complete == 0))
    {
        size_t segment_start = pos;
        size_t segment_end = pos;
        uint16_t value = 0U;
        int ipv4_tail = 0;

        if (group_count >= 8U)
        {
            result = 0;
        }

        while ((segment_end < text_len) && (text[segment_end] != ':') && (result != 0) &&
               (ipv4_tail == 0))
        {
            if (text[segment_end] == '.')
            {
                uint8_t ipv4_bytes[4] = {0U, 0U, 0U, 0U};

                if (group_count > 6U)
                {
                    result = 0;
                }
                else if (multiaddr_parse_ipv4(
                             &text[segment_start],
                             text_len - segment_start,
                             ipv4_bytes) == 0)
                {
                    result = 0;
                }
                else
                {
                    groups[group_count] =
                        (uint16_t)(((uint16_t)ipv4_bytes[0] << 8U) | (uint16_t)ipv4_bytes[1]);
                    groups[group_count + 1U] =
                        (uint16_t)(((uint16_t)ipv4_bytes[2] << 8U) | (uint16_t)ipv4_bytes[3]);
                    group_count += 2U;
                    pos = text_len;
                    ipv4_tail = 1;
                    parsing_complete = 1;
                }
            }
            else
            {
                segment_end++;
            }
        }

        if ((result != 0) && (ipv4_tail == 0))
        {
            size_t digit_count = 0U;

            if (segment_end == segment_start)
            {
                result = 0;
            }

            while ((segment_start < segment_end) && (result != 0))
            {
                uint8_t hex_value = 0U;

                if (digit_count >= 4U)
                {
                    result = 0;
                }
                else if (multiaddr_hex_value(text[segment_start], &hex_value) == 0)
                {
                    result = 0;
                }
                else
                {
                    value = (uint16_t)((value << 4U) | (uint16_t)hex_value);
                    digit_count++;
                    segment_start++;
                }
            }

            if (result != 0)
            {
                groups[group_count] = value;
                group_count++;
                pos = segment_end;

                if (pos >= text_len)
                {
                    parsing_complete = 1;
                }
                else if (((pos + 1U) < text_len) && (text[pos + 1U] == ':'))
                {
                    if (compress_index != SIZE_MAX)
                    {
                        result = 0;
                    }
                    else
                    {
                        compress_index = group_count;
                        pos += 2U;
                        if (pos == text_len)
                        {
                            parsing_complete = 1;
                        }
                    }
                }
                else
                {
                    pos++;
                    if (pos == text_len)
                    {
                        result = 0;
                    }
                }
            }
        }
    }

    if ((result != 0) && (compress_index != SIZE_MAX))
    {
        const size_t zeros_to_insert = 8U - group_count;

        if (group_count > 8U)
        {
            result = 0;
        }
        else
        {
            size_t group_index = 0U;

            for (group_index = group_count; group_index > compress_index; group_index--)
            {
                groups[group_index + zeros_to_insert - 1U] = groups[group_index - 1U];
            }
            for (group_index = 0U; group_index < zeros_to_insert; group_index++)
            {
                groups[compress_index + group_index] = 0U;
            }
        }
    }
    else if ((result != 0) && (group_count != 8U))
    {
        result = 0;
    }
    else
    {
        /* All groups were present without compression. */
    }

    if (result != 0)
    {
        size_t group_index = 0U;

        for (group_index = 0U; group_index < 8U; group_index++)
        {
            out[group_index * 2U] = (uint8_t)(groups[group_index] >> 8U);
            out[(group_index * 2U) + 1U] = (uint8_t)(groups[group_index] & 0xffU);
        }
    }

    return result;
}

static void multiaddr_write_char(char *out, size_t out_len, size_t *pos, char value)
{
    if ((out != NULL) && (*pos < out_len))
    {
        out[*pos] = value;
    }

    *pos += 1U;
}

static void multiaddr_write_bytes(
    char *out,
    size_t out_len,
    size_t *pos,
    const char *bytes,
    size_t bytes_len)
{
    size_t index = 0U;

    for (index = 0U; index < bytes_len; index++)
    {
        multiaddr_write_char(out, out_len, pos, bytes[index]);
    }
}

static void multiaddr_write_decimal_u32(
    char *out,
    size_t out_len,
    size_t *pos,
    uint32_t value)
{
    char digits[10];
    size_t digit_count = 0U;
    const char decimal_digits[] = "0123456789";
    uint32_t remaining = value;

    do
    {
        const uint32_t digit = remaining % 10U;

        digits[digit_count] = decimal_digits[digit];
        remaining /= 10U;
        digit_count++;
    } while (remaining != 0U);

    while (digit_count != 0U)
    {
        digit_count--;
        multiaddr_write_char(out, out_len, pos, digits[digit_count]);
    }
}

static void multiaddr_write_hex_group(char *out, size_t out_len, size_t *pos, uint16_t value)
{
    char digits[4];
    size_t digit_count = 0U;
    const char hex_digits[] = "0123456789abcdef";
    uint16_t remaining = value;

    do
    {
        const uint8_t nibble = (uint8_t)(remaining & 0x0fU);

        digits[digit_count] = hex_digits[nibble];
        digit_count++;
        remaining >>= 4U;
    } while (remaining != 0U);

    while (digit_count != 0U)
    {
        digit_count--;
        multiaddr_write_char(out, out_len, pos, digits[digit_count]);
    }
}

static void multiaddr_write_ipv4(
    const uint8_t value[4],
    char *out,
    size_t out_len,
    size_t *pos)
{
    size_t index = 0U;

    for (index = 0U; index < 4U; index++)
    {
        if (index != 0U)
        {
            multiaddr_write_char(out, out_len, pos, '.');
        }
        multiaddr_write_decimal_u32(out, out_len, pos, (uint32_t)value[index]);
    }
}

static void multiaddr_write_ipv6(
    const uint8_t value[16],
    char *out,
    size_t out_len,
    size_t *pos)
{
    uint16_t groups[8];
    size_t index = 0U;
    size_t best_start = SIZE_MAX;
    size_t best_len = 0U;
    size_t current_start = 0U;
    size_t current_len = 0U;
    int need_separator = 0;

    for (index = 0U; index < 8U; index++)
    {
        groups[index] =
            (uint16_t)(((uint16_t)value[index * 2U] << 8U) | (uint16_t)value[(index * 2U) + 1U]);
    }

    for (index = 0U; index < 8U; index++)
    {
        if (groups[index] == 0U)
        {
            if (current_len == 0U)
            {
                current_start = index;
            }
            current_len++;
        }
        else
        {
            if (current_len > best_len)
            {
                best_start = current_start;
                best_len = current_len;
            }
            current_len = 0U;
        }
    }

    if (current_len > best_len)
    {
        best_start = current_start;
        best_len = current_len;
    }

    if (best_len < 2U)
    {
        best_start = SIZE_MAX;
        best_len = 0U;
    }

    index = 0U;
    while (index < 8U)
    {
        if ((best_len != 0U) && (index == best_start))
        {
            multiaddr_write_char(out, out_len, pos, ':');
            multiaddr_write_char(out, out_len, pos, ':');
            need_separator = 0;
            index += best_len;
            continue;
        }

        if (need_separator != 0)
        {
            multiaddr_write_char(out, out_len, pos, ':');
        }

        multiaddr_write_hex_group(out, out_len, pos, groups[index]);
        need_separator = 1;
        index++;
    }
}

static int multiaddr_validate_p2p_value(const uint8_t *value, size_t value_len)
{
    uint64_t code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t digest_len = 0U;
    size_t read = 0U;
    int result = 0;

    if (libp2p_multihash_decode(value, value_len, &code, &digest, &digest_len, &read) !=
        LIBP2P_MULTIHASH_OK)
    {
        result = 0;
    }
    else if (read == value_len)
    {
        result = 1;
    }
    else
    {
        /* The decoded payload did not consume the full component. */
    }

    (void)code;
    (void)digest;
    (void)digest_len;
    return result;
}

static int multiaddr_is_legacy_peer_id(const char *text, size_t text_len)
{
    int result = 0;

    if ((text_len >= 1U) && (text[0] == '1'))
    {
        result = 1;
    }
    else if ((text_len >= 2U) && (text[0] == 'Q') && (text[1] == 'm'))
    {
        result = 1;
    }
    else
    {
        /* The peer-id prefix is not one of the legacy forms. */
    }

    return result;
}

static int multiaddr_parse_legacy_peer_id(
    const char *text,
    size_t text_len,
    uint8_t *peer_id,
    size_t peer_id_capacity,
    size_t *peer_id_len)
{
    char prefixed[LIBP2P_MULTIADDR_MAX_PEER_ID_TEXT];
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
    size_t decoded_len = 0U;
    size_t multihash_read = 0U;
    int result = 1;

    if ((text == NULL) || (peer_id == NULL) || (peer_id_len == NULL) || (text_len >= sizeof(prefixed)))
    {
        result = 0;
    }

    if (result != 0)
    {
        size_t index = 0U;

        prefixed[0] = 'z';
        for (index = 0U; index < text_len; index++)
        {
            prefixed[index + 1U] = text[index];
        }
    }

    if ((result != 0) &&
        (libp2p_multibase_decode(
             prefixed,
             text_len + 1U,
             &base,
             peer_id,
             peer_id_capacity,
             &decoded_len) != LIBP2P_MULTIBASE_OK))
    {
        result = 0;
    }

    if ((result != 0) &&
        (libp2p_multihash_decode(peer_id, decoded_len, NULL, NULL, NULL, &multihash_read) !=
         LIBP2P_MULTIHASH_OK))
    {
        result = 0;
    }

    if ((result != 0) && (multihash_read != decoded_len))
    {
        result = 0;
    }

    if (result != 0)
    {
        *peer_id_len = decoded_len;
    }

    return result;
}

static int multiaddr_parse_cid_peer_id(
    const char *text,
    size_t text_len,
    uint8_t *peer_id,
    size_t peer_id_capacity,
    size_t *peer_id_len)
{
    uint8_t cid_bytes[LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES];
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
    size_t cid_len = 0U;
    uint64_t version = UINT64_C(0);
    uint64_t codec = UINT64_C(0);
    size_t version_read = 0U;
    size_t codec_read = 0U;
    size_t multihash_offset = 0U;
    size_t multihash_read = 0U;
    int result = 1;

    if ((text == NULL) || (peer_id == NULL) || (peer_id_len == NULL))
    {
        result = 0;
    }

    if ((result != 0) &&
        (libp2p_multibase_decode(text, text_len, &base, cid_bytes, sizeof(cid_bytes), &cid_len) !=
         LIBP2P_MULTIBASE_OK))
    {
        result = 0;
    }

    if ((result != 0) &&
        (libp2p_uvarint_decode(cid_bytes, cid_len, &version, &version_read) != LIBP2P_UVARINT_OK))
    {
        result = 0;
    }

    if ((result != 0) && (version != LIBP2P_MULTIADDR_CID_VERSION_1))
    {
        result = 0;
    }

    if ((result != 0) && (version_read >= cid_len))
    {
        result = 0;
    }

    if ((result != 0) &&
        (libp2p_uvarint_decode(
             &cid_bytes[version_read],
             cid_len - version_read,
             &codec,
             &codec_read) != LIBP2P_UVARINT_OK))
    {
        result = 0;
    }

    if ((result != 0) && (codec != LIBP2P_MULTIADDR_CODE_LIBP2P_KEY))
    {
        result = 0;
    }

    if (result != 0)
    {
        multihash_offset = version_read + codec_read;
        if (multihash_offset > cid_len)
        {
            result = 0;
        }
    }

    if ((result != 0) &&
        (libp2p_multihash_decode(
             &cid_bytes[multihash_offset],
             cid_len - multihash_offset,
             NULL,
             NULL,
             NULL,
             &multihash_read) != LIBP2P_MULTIHASH_OK))
    {
        result = 0;
    }

    if ((result != 0) && ((multihash_offset + multihash_read) != cid_len))
    {
        result = 0;
    }

    if ((result != 0) && (multihash_read > peer_id_capacity))
    {
        result = 0;
    }

    if (result != 0)
    {
        (void)memcpy(peer_id, &cid_bytes[multihash_offset], multihash_read);
        *peer_id_len = multihash_read;
    }

    return result;
}

static int multiaddr_parse_peer_id(
    const char *text,
    size_t text_len,
    uint8_t *peer_id,
    size_t peer_id_capacity,
    size_t *peer_id_len)
{
    int result = 0;

    if (multiaddr_is_legacy_peer_id(text, text_len) != 0)
    {
        result = multiaddr_parse_legacy_peer_id(
            text,
            text_len,
            peer_id,
            peer_id_capacity,
            peer_id_len);
    }
    else
    {
        result = multiaddr_parse_cid_peer_id(
            text,
            text_len,
            peer_id,
            peer_id_capacity,
            peer_id_len);
    }

    return result;
}

static int multiaddr_format_peer_id(
    const uint8_t *peer_id,
    size_t peer_id_len,
    char *text,
    size_t text_capacity,
    size_t *text_len)
{
    size_t encoded_len = 0U;
    int result = 1;

    if ((peer_id_len > LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES) || (text_capacity == 0U))
    {
        result = 0;
    }

    if ((result != 0) &&
        (libp2p_multibase_encode(
             LIBP2P_MULTIBASE_BASE58BTC,
             peer_id,
             peer_id_len,
             text,
             text_capacity,
             &encoded_len) != LIBP2P_MULTIBASE_OK))
    {
        result = 0;
    }

    if ((result != 0) && (encoded_len == 0U))
    {
        result = 0;
    }

    if (result != 0)
    {
        size_t index = 0U;

        for (index = 0U; index < (encoded_len - 1U); index++)
        {
            text[index] = text[index + 1U];
        }

        *text_len = encoded_len - 1U;
    }

    return result;
}

static libp2p_multiaddr_err_t multiaddr_read_text_segment(
    const char *in,
    size_t in_len,
    size_t *offset,
    const char **segment_text,
    size_t *segment_len)
{
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;

    if ((in == NULL) || (offset == NULL) || (segment_text == NULL) || (segment_len == NULL))
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else if ((*offset >= in_len) || (in[*offset] != '/'))
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else
    {
        const size_t start = *offset + 1U;

        *offset += 1U;
        while ((*offset < in_len) && (in[*offset] != '/'))
        {
            *offset += 1U;
        }

        *segment_text = &in[start];
        *segment_len = *offset - start;
    }

    return result;
}

static libp2p_multiaddr_err_t multiaddr_parse_text_component(
    uint64_t code,
    const char *value_text,
    size_t value_len,
    uint8_t fixed_value[16],
    uint8_t peer_id[LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES],
    const uint8_t **component_value,
    size_t *component_value_len)
{
    uint32_t parsed_number = 0U;
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;

    if ((value_text == NULL) || (fixed_value == NULL) || (peer_id == NULL) ||
        (component_value == NULL) || (component_value_len == NULL))
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else
    {
        *component_value = NULL;
        *component_value_len = 0U;

        switch (code)
        {
        case LIBP2P_MULTIADDR_CODE_IP4:
            if (multiaddr_parse_ipv4(value_text, value_len, fixed_value) != 0)
            {
                *component_value = fixed_value;
                *component_value_len = 4U;
                result = LIBP2P_MULTIADDR_OK;
            }
            break;

        case LIBP2P_MULTIADDR_CODE_IP6:
            if (multiaddr_parse_ipv6(value_text, value_len, fixed_value) != 0)
            {
                *component_value = fixed_value;
                *component_value_len = 16U;
                result = LIBP2P_MULTIADDR_OK;
            }
            break;

        case LIBP2P_MULTIADDR_CODE_UDP:
            if (multiaddr_parse_decimal(value_text, value_len, 65535U, &parsed_number) != 0)
            {
                fixed_value[0] = (uint8_t)(parsed_number >> 8U);
                fixed_value[1] = (uint8_t)(parsed_number & 0xffU);
                *component_value = fixed_value;
                *component_value_len = 2U;
                result = LIBP2P_MULTIADDR_OK;
            }
            break;

        case LIBP2P_MULTIADDR_CODE_P2P:
            if (multiaddr_parse_peer_id(
                    value_text,
                    value_len,
                    peer_id,
                    LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES,
                    component_value_len) != 0)
            {
                *component_value = peer_id;
                result = LIBP2P_MULTIADDR_OK;
            }
            break;

        default:
            result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
            break;
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_validate(const uint8_t *buf, size_t buf_len)
{
    libp2p_multiaddr_cursor_t cursor = {buf, buf_len, 0U};
    const uint64_t multiaddr_code_p2p_local = 0x01A5ULL;
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;
    int done = 0;

    while ((done == 0) && (result == LIBP2P_MULTIADDR_OK))
    {
        uint64_t code = UINT64_C(0);
        const uint8_t *value = NULL;
        size_t value_len = 0U;
        libp2p_multiaddr_err_t err =
            libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len);

        if (err == LIBP2P_MULTIADDR_ERR_END)
        {
            done = 1;
        }
        else if (err != LIBP2P_MULTIADDR_OK)
        {
            result = err;
        }
        else if ((code == multiaddr_code_p2p_local) &&
                 (multiaddr_validate_p2p_value(value, value_len) == 0))
        {
            result = LIBP2P_MULTIADDR_ERR_MALFORMED;
        }
        else
        {
            /* The component is valid. */
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_next_component(
    libp2p_multiaddr_cursor_t *cursor,
    uint64_t *code,
    const uint8_t **value,
    size_t *value_len)
{
    uint64_t parsed_code = UINT64_C(0);
    const uint8_t *parsed_value = NULL;
    size_t parsed_value_len = 0U;
    size_t code_read = 0U;
    const libp2p_multiaddr_protocol_entry_t *protocol = NULL;
    size_t offset = 0U;
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;

    if (code != NULL)
    {
        *code = UINT64_C(0);
    }
    if (value != NULL)
    {
        *value = NULL;
    }
    if (value_len != NULL)
    {
        *value_len = 0U;
    }

    if (cursor == NULL)
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else if ((cursor->buf == NULL) && (cursor->buf_len != 0U))
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else if (cursor->offset > cursor->buf_len)
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else if (cursor->offset == cursor->buf_len)
    {
        result = LIBP2P_MULTIADDR_ERR_END;
    }
    else
    {
        const libp2p_multiaddr_err_t err = multiaddr_map_varint_err(libp2p_uvarint_decode(
            &cursor->buf[cursor->offset],
            cursor->buf_len - cursor->offset,
            &parsed_code,
            &code_read));

        offset = cursor->offset;
        if (err != LIBP2P_MULTIADDR_OK)
        {
            result = err;
        }
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        offset += code_read;
        protocol = multiaddr_find_protocol_by_code(parsed_code);
        if (protocol == NULL)
        {
            result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
        }
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        switch (protocol->value_class)
        {
        case LIBP2P_MULTIADDR_VALUE_NONE:
            break;

        case LIBP2P_MULTIADDR_VALUE_FIXED:
            if ((cursor->buf_len - offset) < protocol->fixed_size)
            {
                result = LIBP2P_MULTIADDR_ERR_TRUNCATED;
            }
            else
            {
                parsed_value = &cursor->buf[offset];
                parsed_value_len = protocol->fixed_size;
                offset += protocol->fixed_size;
            }
            break;

        case LIBP2P_MULTIADDR_VALUE_VARIABLE:
        {
            uint64_t declared_len = UINT64_C(0);
            size_t length_read = 0U;
            libp2p_multiaddr_err_t err = multiaddr_map_varint_err(libp2p_uvarint_decode(
                &cursor->buf[offset],
                cursor->buf_len - offset,
                &declared_len,
                &length_read));

            if (err != LIBP2P_MULTIADDR_OK)
            {
                result = err;
            }
            else if (declared_len > (uint64_t)SIZE_MAX)
            {
                result = LIBP2P_MULTIADDR_ERR_MALFORMED;
            }
            else
            {
                offset += length_read;
                if ((cursor->buf_len - offset) < (size_t)declared_len)
                {
                    result = LIBP2P_MULTIADDR_ERR_TRUNCATED;
                }
                else
                {
                    parsed_value = &cursor->buf[offset];
                    parsed_value_len = (size_t)declared_len;
                    offset += (size_t)declared_len;
                }
            }
            break;
        }

        default:
            result = LIBP2P_MULTIADDR_ERR_MALFORMED;
            break;
        }
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        cursor->offset = offset;

        if (code != NULL)
        {
            *code = parsed_code;
        }
        if (value != NULL)
        {
            *value = parsed_value;
        }
        if (value_len != NULL)
        {
            *value_len = parsed_value_len;
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_append_component(
    uint64_t code,
    const uint8_t *value,
    size_t value_len,
    uint8_t *buf,
    size_t buf_len,
    size_t *pos)
{
    const libp2p_multiaddr_protocol_entry_t *protocol = NULL;
    size_t start = 0U;
    size_t total_size = 0U;
    uint8_t code_buf[LIBP2P_UVARINT_MAX_BYTES + 1U];
    uint8_t length_buf[LIBP2P_UVARINT_MAX_BYTES + 1U];
    size_t code_written = 0U;
    size_t length_written = 0U;
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;

    if (pos == NULL)
    {
        result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }
    else
    {
        start = *pos;
        protocol = multiaddr_find_protocol_by_code(code);
        if (protocol == NULL)
        {
            result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
        }
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        switch (protocol->value_class)
        {
        case LIBP2P_MULTIADDR_VALUE_NONE:
            if (value_len != 0U)
            {
                result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
            }
            break;

        case LIBP2P_MULTIADDR_VALUE_FIXED:
            if ((value == NULL) || (value_len != protocol->fixed_size))
            {
                result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
            }
            break;

        case LIBP2P_MULTIADDR_VALUE_VARIABLE:
            if (((value == NULL) && (value_len != 0U)) ||
                (multiaddr_size_fits_varint_limit(value_len) == 0) ||
                (multiaddr_validate_p2p_value(value, value_len) == 0))
            {
                result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
            }
            break;

        default:
            result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
            break;
        }
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        const size_t code_size = (size_t)libp2p_uvarint_size(code);

        total_size = code_size;

        if (protocol->value_class == LIBP2P_MULTIADDR_VALUE_VARIABLE)
        {
            const size_t length_size = (size_t)libp2p_uvarint_size((uint64_t)value_len);

            if (multiaddr_add_overflow(total_size, length_size, &total_size) != 0)
            {
                *pos = SIZE_MAX;
                result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
            }
        }

        if ((result == LIBP2P_MULTIADDR_OK) &&
            (multiaddr_add_overflow(total_size, value_len, &total_size) != 0))
        {
            *pos = SIZE_MAX;
            result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
        }
        if ((result == LIBP2P_MULTIADDR_OK) &&
            (multiaddr_add_overflow(start, total_size, &total_size) != 0))
        {
            *pos = SIZE_MAX;
            result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
        }

        if (result == LIBP2P_MULTIADDR_OK)
        {
            *pos = total_size;
        }
    }

    if ((result == LIBP2P_MULTIADDR_OK) &&
        (libp2p_uvarint_encode(code, code_buf, sizeof(code_buf), &code_written) !=
         LIBP2P_UVARINT_OK))
    {
        result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && ((buf == NULL) || (buf_len < total_size)))
    {
        result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        (void)memcpy(&buf[start], code_buf, code_written);
        start += code_written;

        if (protocol->value_class == LIBP2P_MULTIADDR_VALUE_VARIABLE)
        {
            if (libp2p_uvarint_encode(
                    (uint64_t)value_len,
                    length_buf,
                    sizeof(length_buf),
                    &length_written) != LIBP2P_UVARINT_OK)
            {
                result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
            }
            else
            {
                (void)memcpy(&buf[start], length_buf, length_written);
                start += length_written;
            }
        }

        if ((result == LIBP2P_MULTIADDR_OK) && (value_len != 0U))
        {
            (void)memcpy(&buf[start], value, value_len);
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_encapsulate(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t total = 0U;
    libp2p_multiaddr_err_t result = libp2p_multiaddr_validate(a, a_len);

    if (written != NULL)
    {
        *written = 0U;
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        result = libp2p_multiaddr_validate(b, b_len);
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        if (multiaddr_add_overflow(a_len, b_len, &total) != 0)
        {
            total = SIZE_MAX;
        }
    }

    if (written != NULL)
    {
        *written = total;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && ((out == NULL) || (out_len < total)))
    {
        result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        if (a_len != 0U)
        {
            (void)memcpy(out, a, a_len);
        }
        if (b_len != 0U)
        {
            (void)memcpy(&out[a_len], b, b_len);
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_decapsulate(
    const uint8_t *outer,
    size_t outer_len,
    const uint8_t *inner,
    size_t inner_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t match_offset = SIZE_MAX;
    size_t desired_written = 0U;
    libp2p_multiaddr_cursor_t cursor = {outer, outer_len, 0U};
    libp2p_multiaddr_err_t result = libp2p_multiaddr_validate(outer, outer_len);
    int done = 0;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (result == LIBP2P_MULTIADDR_OK)
    {
        result = libp2p_multiaddr_validate(inner, inner_len);
    }

    if ((result == LIBP2P_MULTIADDR_OK) && (inner_len == 0U))
    {
        desired_written = outer_len;
        if (written != NULL)
        {
            *written = outer_len;
        }
        if ((out == NULL) || (out_len < outer_len))
        {
            result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
        }
        else if (outer_len != 0U)
        {
            (void)memcpy(out, outer, outer_len);
        }
        else
        {
            /* Nothing to copy for an empty multiaddr. */
        }
    }

    while ((result == LIBP2P_MULTIADDR_OK) && (inner_len != 0U) && (done == 0))
    {
        uint64_t code = UINT64_C(0);
        const uint8_t *value = NULL;
        size_t value_len = 0U;
        const size_t component_start = cursor.offset;
        libp2p_multiaddr_err_t err =
            libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len);

        (void)code;
        (void)value;
        (void)value_len;

        if (err == LIBP2P_MULTIADDR_ERR_END)
        {
            done = 1;
        }
        else if (err != LIBP2P_MULTIADDR_OK)
        {
            result = err;
        }
        else if (((outer_len - component_start) >= inner_len) &&
                 (multiaddr_byte_sequence_matches(&outer[component_start], inner, inner_len) != 0))
        {
            match_offset = component_start;
        }
        else
        {
            /* This component is not the decapsulation target. */
        }
    }

    if ((result == LIBP2P_MULTIADDR_OK) && (inner_len != 0U) && (match_offset == SIZE_MAX))
    {
        result = LIBP2P_MULTIADDR_ERR_NOT_FOUND;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && (inner_len != 0U))
    {
        desired_written = match_offset;
    }

    if (written != NULL)
    {
        *written = desired_written;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && (inner_len != 0U) &&
        ((out == NULL) || (out_len < match_offset)))
    {
        result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && (inner_len != 0U) && (match_offset != 0U))
    {
        (void)memcpy(out, outer, match_offset);
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_protocol_info(
    uint64_t code,
    const char **name,
    libp2p_multiaddr_value_class_t *value_class,
    size_t *fixed_size)
{
    const libp2p_multiaddr_protocol_entry_t *protocol =
        multiaddr_find_protocol_by_code(code);
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;

    if (protocol == NULL)
    {
        result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
    }
    else
    {
        if (name != NULL)
        {
            *name = protocol->name;
        }
        if (value_class != NULL)
        {
            *value_class = protocol->value_class;
        }
        if (fixed_size != NULL)
        {
            *fixed_size = protocol->fixed_size;
        }
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_from_string(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t offset = 0U;
    size_t pos = 0U;
    libp2p_multiaddr_err_t result = LIBP2P_MULTIADDR_OK;
    libp2p_multiaddr_err_t parse_result = LIBP2P_MULTIADDR_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U) || (in[0] != '/'))
    {
        parse_result = LIBP2P_MULTIADDR_ERR_MALFORMED;
    }

    while ((offset < in_len) && (parse_result == LIBP2P_MULTIADDR_OK))
    {
        const char *protocol_text = NULL;
        size_t protocol_len = 0U;
        const libp2p_multiaddr_protocol_entry_t *protocol = NULL;
        libp2p_multiaddr_err_t err = LIBP2P_MULTIADDR_OK;

        err = multiaddr_read_text_segment(in, in_len, &offset, &protocol_text, &protocol_len);
        if ((err != LIBP2P_MULTIADDR_OK) || (protocol_len == 0U))
        {
            parse_result = (err != LIBP2P_MULTIADDR_OK) ? err : LIBP2P_MULTIADDR_ERR_MALFORMED;
        }
        else if (multiaddr_is_ipfs_alias(protocol_text, protocol_len) != 0)
        {
            protocol = multiaddr_find_protocol_by_code(LIBP2P_MULTIADDR_CODE_P2P);
        }
        else
        {
            protocol = multiaddr_find_protocol_by_name(protocol_text, protocol_len);
        }

        if ((parse_result == LIBP2P_MULTIADDR_OK) && (protocol == NULL))
        {
            parse_result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
        }

        if (parse_result == LIBP2P_MULTIADDR_OK)
        {
            const uint64_t code = protocol->code;

            switch (code)
            {
            case LIBP2P_MULTIADDR_CODE_QUIC_V1:
                err = libp2p_multiaddr_append_component(
                    code,
                    NULL,
                    0U,
                    (result == LIBP2P_MULTIADDR_OK) ? out : NULL,
                    (result == LIBP2P_MULTIADDR_OK) ? out_len : 0U,
                    &pos);
                break;

            case LIBP2P_MULTIADDR_CODE_IP4:
            case LIBP2P_MULTIADDR_CODE_IP6:
            case LIBP2P_MULTIADDR_CODE_UDP:
            case LIBP2P_MULTIADDR_CODE_P2P:
            {
                const char *value_text = NULL;
                size_t value_len = 0U;
                const uint8_t *component_value = NULL;
                size_t component_value_len = 0U;
                uint8_t fixed_value[16];
                uint8_t peer_id[LIBP2P_MULTIADDR_MAX_PEER_ID_BYTES];

                err = multiaddr_read_text_segment(in, in_len, &offset, &value_text, &value_len);
                if (err != LIBP2P_MULTIADDR_OK)
                {
                    parse_result = err;
                }
                else if (value_len == 0U)
                {
                    parse_result = LIBP2P_MULTIADDR_ERR_INVALID_VALUE;
                }
                else
                {
                    parse_result = multiaddr_parse_text_component(
                        code,
                        value_text,
                        value_len,
                        fixed_value,
                        peer_id,
                        &component_value,
                        &component_value_len);
                }

                if (parse_result == LIBP2P_MULTIADDR_OK)
                {
                    err = libp2p_multiaddr_append_component(
                        code,
                        component_value,
                        component_value_len,
                        (result == LIBP2P_MULTIADDR_OK) ? out : NULL,
                        (result == LIBP2P_MULTIADDR_OK) ? out_len : 0U,
                        &pos);
                }
                break;
            }

            default:
                parse_result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
                break;
            }
        }

        if (parse_result == LIBP2P_MULTIADDR_OK)
        {
            if (err == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL)
            {
                result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
            }
            else if (err != LIBP2P_MULTIADDR_OK)
            {
                parse_result = err;
            }
            else
            {
                /* The component was appended successfully. */
            }
        }
    }

    if (written != NULL)
    {
        *written = pos;
    }

    if (parse_result != LIBP2P_MULTIADDR_OK)
    {
        result = parse_result;
    }

    return result;
}

libp2p_multiaddr_err_t libp2p_multiaddr_to_string(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    libp2p_multiaddr_cursor_t cursor = {in, in_len, 0U};
    size_t pos = 0U;
    libp2p_multiaddr_err_t result = libp2p_multiaddr_validate(in, in_len);
    int done = 0;

    if (written != NULL)
    {
        *written = 0U;
    }

    while ((done == 0) && (result == LIBP2P_MULTIADDR_OK))
    {
        uint64_t code = UINT64_C(0);
        const uint8_t *value = NULL;
        size_t value_len = 0U;
        const char *name = NULL;
        char peer_id_text[LIBP2P_MULTIADDR_MAX_PEER_ID_TEXT];
        size_t peer_id_len = 0U;
        libp2p_multiaddr_err_t err =
            libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len);

        if (err == LIBP2P_MULTIADDR_ERR_END)
        {
            done = 1;
        }
        else if (err != LIBP2P_MULTIADDR_OK)
        {
            result = err;
        }
        else if (libp2p_multiaddr_protocol_info(code, &name, NULL, NULL) != LIBP2P_MULTIADDR_OK)
        {
            result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
        }
        else
        {
            multiaddr_write_char(out, out_len, &pos, '/');
            multiaddr_write_bytes(out, out_len, &pos, name, strlen(name));

            switch (code)
            {
            case LIBP2P_MULTIADDR_CODE_QUIC_V1:
                break;

            case LIBP2P_MULTIADDR_CODE_IP4:
                if ((value == NULL) || (value_len != 4U))
                {
                    result = LIBP2P_MULTIADDR_ERR_MALFORMED;
                }
                else
                {
                    multiaddr_write_char(out, out_len, &pos, '/');
                    multiaddr_write_ipv4(value, out, out_len, &pos);
                }
                break;

            case LIBP2P_MULTIADDR_CODE_IP6:
                if ((value == NULL) || (value_len != 16U))
                {
                    result = LIBP2P_MULTIADDR_ERR_MALFORMED;
                }
                else
                {
                    multiaddr_write_char(out, out_len, &pos, '/');
                    multiaddr_write_ipv6(value, out, out_len, &pos);
                }
                break;

            case LIBP2P_MULTIADDR_CODE_UDP:
                if ((value == NULL) || (value_len != 2U))
                {
                    result = LIBP2P_MULTIADDR_ERR_MALFORMED;
                }
                else
                {
                    multiaddr_write_char(out, out_len, &pos, '/');
                    multiaddr_write_decimal_u32(
                        out,
                        out_len,
                        &pos,
                        (uint32_t)(((uint32_t)value[0] << 8U) | (uint32_t)value[1]));
                }
                break;

            case LIBP2P_MULTIADDR_CODE_P2P:
                if (value == NULL)
                {
                    result = LIBP2P_MULTIADDR_ERR_MALFORMED;
                }
                else if (multiaddr_format_peer_id(
                             value,
                             value_len,
                             peer_id_text,
                             sizeof(peer_id_text),
                             &peer_id_len) == 0)
                {
                    result = LIBP2P_MULTIADDR_ERR_MALFORMED;
                }
                else
                {
                    multiaddr_write_char(out, out_len, &pos, '/');
                    multiaddr_write_bytes(out, out_len, &pos, peer_id_text, peer_id_len);
                }
                break;

            default:
                result = LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL;
                break;
            }
        }
    }

    if (written != NULL)
    {
        *written = pos;
    }

    if ((result == LIBP2P_MULTIADDR_OK) && ((out == NULL) || (out_len < pos)))
    {
        result = LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL;
    }

    return result;
}
