#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multibase/multibase.h"

#define LIBP2P_TEST_MULTIADDR_CODE_IP4     UINT64_C(0x04)
#define LIBP2P_TEST_MULTIADDR_CODE_TCP     UINT64_C(0x06)
#define LIBP2P_TEST_MULTIADDR_CODE_IP6     UINT64_C(0x29)
#define LIBP2P_TEST_MULTIADDR_CODE_UDP     UINT64_C(0x0111)
#define LIBP2P_TEST_MULTIADDR_CODE_P2P     UINT64_C(0x01A5)
#define LIBP2P_TEST_MULTIADDR_CODE_QUIC    UINT64_C(0x01CC)
#define LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1 UINT64_C(0x01CD)

static const char multiaddr_unit_legacy_peer_id[] =
    "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";

static int multiaddr_unit_hex_nibble(char character, uint8_t *value)
{
    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'a'));
        return 1;
    }
    if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'A'));
        return 1;
    }

    *value = 0U;
    return 0;
}

static int multiaddr_unit_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = strlen(text);
    size_t index = 0U;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if ((text_len % 2U) != 0U)
    {
        return 0;
    }
    if ((text_len / 2U) > out_capacity)
    {
        return 0;
    }

    for (index = 0U; index < text_len; index += 2U)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((multiaddr_unit_hex_nibble(text[index], &high) == 0) ||
            (multiaddr_unit_hex_nibble(text[index + 1U], &low) == 0))
        {
            return 0;
        }

        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    if (out_len != NULL)
    {
        *out_len = text_len / 2U;
    }

    return 1;
}

static int multiaddr_unit_load_peer_id(uint8_t *out, size_t out_len, size_t *written)
{
    static const char peer_id_hex[] =
        "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47";

    return multiaddr_unit_parse_hex(peer_id_hex, out, out_len, written);
}

static int multiaddr_unit_build_ip4_udp(
    uint16_t port,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const uint8_t ip4_value[4] = {127U, 0U, 0U, 1U};
    const uint8_t udp_value[2] = {(uint8_t)(port >> 8U), (uint8_t)(port & 0xffU)};
    size_t pos = 0U;
    libp2p_multiaddr_err_t err = LIBP2P_MULTIADDR_OK;

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_IP4,
        ip4_value,
        sizeof(ip4_value),
        out,
        out_len,
        &pos);
    if (err != LIBP2P_MULTIADDR_OK)
    {
        if (written != NULL)
        {
            *written = pos;
        }
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_UDP,
        udp_value,
        sizeof(udp_value),
        out,
        out_len,
        &pos);
    if (written != NULL)
    {
        *written = pos;
    }

    return (err == LIBP2P_MULTIADDR_OK) ? 1 : 0;
}

static int multiaddr_unit_build_quic_p2p(uint8_t *out, size_t out_len, size_t *written)
{
    uint8_t peer_id[64];
    size_t peer_id_len = 0U;
    size_t pos = 0U;
    libp2p_multiaddr_err_t err = LIBP2P_MULTIADDR_OK;

    if (multiaddr_unit_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len) == 0)
    {
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
        NULL,
        0U,
        out,
        out_len,
        &pos);
    if (err != LIBP2P_MULTIADDR_OK)
    {
        if (written != NULL)
        {
            *written = pos;
        }
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_P2P,
        peer_id,
        peer_id_len,
        out,
        out_len,
        &pos);
    if (written != NULL)
    {
        *written = pos;
    }

    return (err == LIBP2P_MULTIADDR_OK) ? 1 : 0;
}

static int multiaddr_unit_build_sample_address(uint8_t *out, size_t out_len, size_t *written)
{
    size_t pos = 0U;
    uint8_t peer_id[64];
    size_t peer_id_len = 0U;
    const uint8_t ip4_value[4] = {127U, 0U, 0U, 1U};
    const uint8_t udp_value[2] = {0x0fU, 0xa1U};
    libp2p_multiaddr_err_t err = LIBP2P_MULTIADDR_OK;

    if (multiaddr_unit_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len) == 0)
    {
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_IP4,
        ip4_value,
        sizeof(ip4_value),
        out,
        out_len,
        &pos);
    if (err != LIBP2P_MULTIADDR_OK)
    {
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_UDP,
        udp_value,
        sizeof(udp_value),
        out,
        out_len,
        &pos);
    if (err != LIBP2P_MULTIADDR_OK)
    {
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
        NULL,
        0U,
        out,
        out_len,
        &pos);
    if (err != LIBP2P_MULTIADDR_OK)
    {
        return 0;
    }

    err = libp2p_multiaddr_append_component(
        LIBP2P_TEST_MULTIADDR_CODE_P2P,
        peer_id,
        peer_id_len,
        out,
        out_len,
        &pos);
    if (written != NULL)
    {
        *written = pos;
    }

    return (err == LIBP2P_MULTIADDR_OK) ? 1 : 0;
}

static int multiaddr_unit_make_cid_peer_id_text(char *out, size_t out_len, size_t *written)
{
    uint8_t peer_id[64];
    size_t peer_id_len = 0U;
    uint8_t cid_bytes[66];
    size_t cid_len = 0U;

    if (multiaddr_unit_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len) == 0)
    {
        return 0;
    }

    cid_bytes[0] = 0x01U;
    cid_bytes[1] = 0x72U;
    (void)memcpy(cid_bytes + 2U, peer_id, peer_id_len);
    cid_len = peer_id_len + 2U;

    return libp2p_multibase_encode(
               LIBP2P_MULTIBASE_BASE58BTC,
               cid_bytes,
               cid_len,
               out,
               out_len,
               written) == LIBP2P_MULTIBASE_OK
               ? 1
               : 0;
}

static void multiaddr_unit_validate_empty(void)
{
    assert(libp2p_multiaddr_validate(NULL, 0U) == LIBP2P_MULTIADDR_OK);
}

static void multiaddr_unit_protocol_info(void)
{
    const char *name = NULL;
    libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
    size_t fixed_size = 0U;

    assert(
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            &name,
            &value_class,
            &fixed_size) == LIBP2P_MULTIADDR_OK);
    assert(strcmp(name, "ip4") == 0);
    assert(value_class == LIBP2P_MULTIADDR_VALUE_FIXED);
    assert(fixed_size == 4U);

    assert(
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
            &name,
            &value_class,
            &fixed_size) == LIBP2P_MULTIADDR_OK);
    assert(strcmp(name, "quic-v1") == 0);
    assert(value_class == LIBP2P_MULTIADDR_VALUE_NONE);
    assert(fixed_size == 0U);

    assert(
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            &name,
            &value_class,
            &fixed_size) == LIBP2P_MULTIADDR_OK);
    assert(strcmp(name, "p2p") == 0);
    assert(value_class == LIBP2P_MULTIADDR_VALUE_VARIABLE);
    assert(fixed_size == 0U);

    assert(
        libp2p_multiaddr_protocol_info(LIBP2P_TEST_MULTIADDR_CODE_TCP, NULL, NULL, NULL) ==
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
}

static void multiaddr_unit_next_component_iteration(void)
{
    uint8_t address[128];
    size_t address_len = 0U;
    uint8_t expected_peer_id[64];
    size_t expected_peer_id_len = 0U;
    libp2p_multiaddr_cursor_t cursor = {address, 0U, 0U};
    uint64_t code = UINT64_C(0);
    const uint8_t *value = NULL;
    size_t value_len = 0U;

    assert(multiaddr_unit_build_sample_address(address, sizeof(address), &address_len) != 0);
    assert(
        multiaddr_unit_load_peer_id(
            expected_peer_id,
            sizeof(expected_peer_id),
            &expected_peer_id_len) != 0);
    cursor.buf_len = address_len;

    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) == LIBP2P_MULTIADDR_OK);
    assert(code == LIBP2P_TEST_MULTIADDR_CODE_IP4);
    assert(value_len == 4U);
    assert(memcmp(value, ((const uint8_t[]){127U, 0U, 0U, 1U}), 4U) == 0);

    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) == LIBP2P_MULTIADDR_OK);
    assert(code == LIBP2P_TEST_MULTIADDR_CODE_UDP);
    assert(value_len == 2U);
    assert(memcmp(value, ((const uint8_t[]){0x0fU, 0xa1U}), 2U) == 0);

    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) == LIBP2P_MULTIADDR_OK);
    assert(code == LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1);
    assert(value_len == 0U);

    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) == LIBP2P_MULTIADDR_OK);
    assert(code == LIBP2P_TEST_MULTIADDR_CODE_P2P);
    assert(value_len == expected_peer_id_len);
    assert(memcmp(value, expected_peer_id, expected_peer_id_len) == 0);

    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_END);
    assert(cursor.offset == address_len);
}

static void multiaddr_unit_next_component_errors(void)
{
    libp2p_multiaddr_cursor_t cursor = {NULL, 0U, 0U};
    uint64_t code = UINT64_C(0);
    const uint8_t *value = NULL;
    size_t value_len = 0U;
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t non_minimal_code[] = {0x84U, 0x00U};
    const uint8_t single_byte[] = {0x04U};

    assert(
        libp2p_multiaddr_next_component(NULL, NULL, NULL, NULL) == LIBP2P_MULTIADDR_ERR_MALFORMED);

    cursor.buf = NULL;
    cursor.buf_len = 1U;
    cursor.offset = 0U;
    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);

    cursor.buf = single_byte;
    cursor.buf_len = sizeof(single_byte);
    cursor.offset = sizeof(single_byte) + 1U;
    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);

    cursor.buf = single_byte;
    cursor.buf_len = sizeof(single_byte);
    cursor.offset = sizeof(single_byte);
    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_END);

    cursor.buf = truncated_ip4;
    cursor.buf_len = sizeof(truncated_ip4);
    cursor.offset = 0U;
    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_TRUNCATED);

    cursor.buf = non_minimal_code;
    cursor.buf_len = sizeof(non_minimal_code);
    cursor.offset = 0U;
    assert(
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);
}

static void multiaddr_unit_append_component_measure_and_write(void)
{
    const uint8_t ip4_value[4] = {127U, 0U, 0U, 1U};
    uint8_t peer_id[64];
    size_t peer_id_len = 0U;
    uint8_t encoded_ip4[5];
    uint8_t encoded_p2p[64];
    size_t pos = 0U;

    assert(multiaddr_unit_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len) != 0);

    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            ip4_value,
            sizeof(ip4_value),
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(pos == 5U);

    pos = 0U;
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            ip4_value,
            sizeof(ip4_value),
            encoded_ip4,
            sizeof(encoded_ip4),
            &pos) == LIBP2P_MULTIADDR_OK);
    assert(pos == sizeof(encoded_ip4));
    assert(memcmp(encoded_ip4, ((const uint8_t[]){0x04U, 127U, 0U, 0U, 1U}), 5U) == 0);

    pos = 0U;
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            peer_id,
            peer_id_len,
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(pos == (peer_id_len + 3U));

    pos = 0U;
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            peer_id,
            peer_id_len,
            encoded_p2p,
            peer_id_len + 3U,
            &pos) == LIBP2P_MULTIADDR_OK);
    assert(pos == (peer_id_len + 3U));
    assert(encoded_p2p[0] == 0xA5U);
    assert(encoded_p2p[1] == 0x03U);
    assert((size_t)encoded_p2p[2] == peer_id_len);
}

static void multiaddr_unit_append_component_rejects_invalid(void)
{
    const uint8_t one_byte_value[1] = {0U};
    const uint8_t invalid_peer_id[] = {0x11U, 0x14U, 0U, 0U};
    size_t pos = 0U;

    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            NULL) == LIBP2P_MULTIADDR_ERR_MALFORMED);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_TCP,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            NULL,
            4U,
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            NULL,
            1U,
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            invalid_peer_id,
            sizeof(invalid_peer_id),
            NULL,
            0U,
            &pos) == LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
}

static void multiaddr_unit_validate_rejects_invalid(void)
{
    const uint8_t unsupported_tcp[] = {0x06U, 0x01U, 0xbbU};
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t truncated_p2p[] = {0xa5U, 0x03U, 0x22U, 0x12U};
    const uint8_t malformed_p2p[] = {0xa5U, 0x03U, 0x02U, 0x81U, 0x00U};

    assert(
        libp2p_multiaddr_validate(unsupported_tcp, sizeof(unsupported_tcp)) ==
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_validate(truncated_ip4, sizeof(truncated_ip4)) ==
        LIBP2P_MULTIADDR_ERR_TRUNCATED);
    assert(
        libp2p_multiaddr_validate(truncated_p2p, sizeof(truncated_p2p)) ==
        LIBP2P_MULTIADDR_ERR_TRUNCATED);
    assert(
        libp2p_multiaddr_validate(malformed_p2p, sizeof(malformed_p2p)) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);
}

static void multiaddr_unit_encapsulate(void)
{
    uint8_t prefix[32];
    uint8_t suffix[96];
    uint8_t combined[128];
    uint8_t expected[128];
    size_t prefix_len = 0U;
    size_t suffix_len = 0U;
    size_t combined_len = 0U;
    size_t expected_len = 0U;
    const uint8_t invalid_outer[] = {0x06U, 0x01U, 0xbbU};

    assert(multiaddr_unit_build_ip4_udp(4001U, prefix, sizeof(prefix), &prefix_len) != 0);
    assert(multiaddr_unit_build_quic_p2p(suffix, sizeof(suffix), &suffix_len) != 0);
    (void)memcpy(expected, prefix, prefix_len);
    (void)memcpy(expected + prefix_len, suffix, suffix_len);
    expected_len = prefix_len + suffix_len;

    assert(
        libp2p_multiaddr_encapsulate(
            prefix,
            prefix_len,
            suffix,
            suffix_len,
            NULL,
            0U,
            &combined_len) == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(combined_len == expected_len);

    assert(
        libp2p_multiaddr_encapsulate(
            prefix,
            prefix_len,
            suffix,
            suffix_len,
            combined,
            sizeof(combined),
            &combined_len) == LIBP2P_MULTIADDR_OK);
    assert(combined_len == expected_len);
    assert(memcmp(combined, expected, expected_len) == 0);

    assert(
        libp2p_multiaddr_encapsulate(
            invalid_outer,
            sizeof(invalid_outer),
            suffix,
            suffix_len,
            combined,
            sizeof(combined),
            &combined_len) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
}

static void multiaddr_unit_decapsulate(void)
{
    uint8_t outer[128];
    uint8_t inner[96];
    uint8_t output[64];
    uint8_t expected_prefix[32];
    uint8_t not_found[32];
    size_t outer_len = 0U;
    size_t inner_len = 0U;
    size_t expected_prefix_len = 0U;
    size_t not_found_len = 0U;
    size_t written = 0U;

    assert(multiaddr_unit_build_sample_address(outer, sizeof(outer), &outer_len) != 0);
    assert(multiaddr_unit_build_quic_p2p(inner, sizeof(inner), &inner_len) != 0);
    assert(
        multiaddr_unit_build_ip4_udp(
            4001U,
            expected_prefix,
            sizeof(expected_prefix),
            &expected_prefix_len) != 0);
    assert(multiaddr_unit_build_ip4_udp(4002U, not_found, sizeof(not_found), &not_found_len) != 0);

    assert(
        libp2p_multiaddr_decapsulate(outer, outer_len, inner, inner_len, NULL, 0U, &written) ==
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(written == expected_prefix_len);

    assert(
        libp2p_multiaddr_decapsulate(
            outer,
            outer_len,
            inner,
            inner_len,
            output,
            sizeof(output),
            &written) == LIBP2P_MULTIADDR_OK);
    assert(written == expected_prefix_len);
    assert(memcmp(output, expected_prefix, expected_prefix_len) == 0);

    assert(
        libp2p_multiaddr_decapsulate(outer, outer_len, NULL, 0U, NULL, 0U, &written) ==
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(written == outer_len);

    assert(
        libp2p_multiaddr_decapsulate(
            outer,
            outer_len,
            not_found,
            not_found_len,
            output,
            sizeof(output),
            &written) == LIBP2P_MULTIADDR_ERR_NOT_FOUND);
}

static void multiaddr_unit_from_and_to_string(void)
{
    static const char address_text[] =
        "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";
    uint8_t expected_bytes[128];
    uint8_t actual_bytes[128];
    size_t expected_len = 0U;
    size_t written = 0U;
    char roundtrip[128];

    assert(
        multiaddr_unit_build_sample_address(
            expected_bytes,
            sizeof(expected_bytes),
            &expected_len) != 0);

    assert(
        libp2p_multiaddr_from_string(address_text, sizeof(address_text) - 1U, NULL, 0U, &written) ==
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(written == expected_len);

    assert(
        libp2p_multiaddr_from_string(
            address_text,
            sizeof(address_text) - 1U,
            actual_bytes,
            sizeof(actual_bytes),
            &written) == LIBP2P_MULTIADDR_OK);
    assert(written == expected_len);
    assert(memcmp(actual_bytes, expected_bytes, expected_len) == 0);

    assert(
        libp2p_multiaddr_to_string(actual_bytes, written, NULL, 0U, &expected_len) ==
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL);
    assert(expected_len == (sizeof(address_text) - 1U));

    assert(
        libp2p_multiaddr_to_string(
            actual_bytes,
            written,
            roundtrip,
            sizeof(roundtrip),
            &expected_len) == LIBP2P_MULTIADDR_OK);
    assert(expected_len == (sizeof(address_text) - 1U));
    assert(memcmp(roundtrip, address_text, sizeof(address_text) - 1U) == 0);
}

static void multiaddr_unit_string_canonicalization(void)
{
    char cid_peer_id[128];
    size_t cid_peer_id_len = 0U;
    char alias_text[160];
    char cid_text[160];
    uint8_t alias_bytes[128];
    uint8_t cid_bytes[128];
    size_t alias_len = 0U;
    size_t cid_len = 0U;
    char canonical[160];
    size_t canonical_len = 0U;
    int written = 0;

    assert(
        multiaddr_unit_make_cid_peer_id_text(cid_peer_id, sizeof(cid_peer_id), &cid_peer_id_len) !=
        0);

    written = snprintf(canonical, sizeof(canonical), "/p2p/%s", multiaddr_unit_legacy_peer_id);
    assert(written >= 0);
    canonical_len = (size_t)written;
    assert(canonical_len < sizeof(canonical));

    written = snprintf(alias_text, sizeof(alias_text), "/ipfs/%s", multiaddr_unit_legacy_peer_id);
    assert(written >= 0);
    alias_len = (size_t)written;
    assert(alias_len < sizeof(alias_text));

    written = snprintf(cid_text, sizeof(cid_text), "/p2p/%s", cid_peer_id);
    assert(written >= 0);
    cid_len = (size_t)written;
    assert(cid_len < sizeof(cid_text));

    assert(
        libp2p_multiaddr_from_string(
            alias_text,
            alias_len,
            alias_bytes,
            sizeof(alias_bytes),
            &alias_len) == LIBP2P_MULTIADDR_OK);
    assert(
        libp2p_multiaddr_from_string(cid_text, cid_len, cid_bytes, sizeof(cid_bytes), &cid_len) ==
        LIBP2P_MULTIADDR_OK);
    assert(alias_len == cid_len);
    assert(memcmp(alias_bytes, cid_bytes, cid_len) == 0);

    assert(
        libp2p_multiaddr_to_string(
            alias_bytes,
            alias_len,
            canonical,
            sizeof(canonical),
            &canonical_len) == LIBP2P_MULTIADDR_OK);
    assert(
        memcmp(
            canonical,
            "/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk",
            sizeof("/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk") - 1U) == 0);
}

static void multiaddr_unit_from_string_invalid_inputs(void)
{
    uint8_t out[128];
    size_t written = 0U;

    assert(
        libp2p_multiaddr_from_string(NULL, 0U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);
    assert(
        libp2p_multiaddr_from_string("/", 1U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);
    assert(
        libp2p_multiaddr_from_string("//", 2U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_MALFORMED);
    assert(
        libp2p_multiaddr_from_string("/tcp/443", 8U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_from_string("/ip4/256.0.0.1", 14U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_from_string("/ip6/2001:::1", 13U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_from_string("/udp/65536", 10U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
    assert(
        libp2p_multiaddr_from_string("/p2p/not-a-peer-id", 18U, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE);
}

static void multiaddr_unit_to_string_errors(void)
{
    const uint8_t unsupported_tcp[] = {0x06U, 0x01U, 0xbbU};
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t malformed_p2p[] = {0xa5U, 0x03U, 0x02U, 0x81U, 0x00U};
    char out[128];
    size_t written = 0U;

    assert(
        libp2p_multiaddr_to_string(
            unsupported_tcp,
            sizeof(unsupported_tcp),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_to_string(
            truncated_ip4,
            sizeof(truncated_ip4),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIADDR_ERR_TRUNCATED);
    assert(
        libp2p_multiaddr_to_string(
            malformed_p2p,
            sizeof(malformed_p2p),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIADDR_ERR_MALFORMED);
}

static void multiaddr_unit_ipv6_roundtrip(void)
{
    static const char ipv6_input[] = "/ip6/2001:0db8:0:0:0:0:0:1/udp/0";
    static const char ipv6_canonical[] = "/ip6/2001:db8::1/udp/0";
    uint8_t address[64];
    char formatted[64];
    size_t address_len = 0U;
    size_t formatted_len = 0U;

    assert(
        libp2p_multiaddr_from_string(
            ipv6_input,
            sizeof(ipv6_input) - 1U,
            address,
            sizeof(address),
            &address_len) == LIBP2P_MULTIADDR_OK);
    assert(
        libp2p_multiaddr_to_string(
            address,
            address_len,
            formatted,
            sizeof(formatted),
            &formatted_len) == LIBP2P_MULTIADDR_OK);
    assert(formatted_len == (sizeof(ipv6_canonical) - 1U));
    assert(memcmp(formatted, ipv6_canonical, sizeof(ipv6_canonical) - 1U) == 0);
}

int main(void)
{
    multiaddr_unit_validate_empty();
    multiaddr_unit_protocol_info();
    multiaddr_unit_next_component_iteration();
    multiaddr_unit_next_component_errors();
    multiaddr_unit_append_component_measure_and_write();
    multiaddr_unit_append_component_rejects_invalid();
    multiaddr_unit_validate_rejects_invalid();
    multiaddr_unit_encapsulate();
    multiaddr_unit_decapsulate();
    multiaddr_unit_from_and_to_string();
    multiaddr_unit_string_canonicalization();
    multiaddr_unit_from_string_invalid_inputs();
    multiaddr_unit_to_string_errors();
    multiaddr_unit_ipv6_roundtrip();
    return 0;
}
