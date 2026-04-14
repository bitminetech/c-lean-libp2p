#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/multiformats_test_utils.h"
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

static int multiaddr_unit_load_peer_id(uint8_t *out, size_t out_len, size_t *written)
{
    static const char peer_id_hex[] =
        "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47";

    return libp2p_test_hex_to_bytes(peer_id_hex, out, out_len, written);
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

static int multiaddr_unit_validate_empty(libp2p_test_context_t *ctx)
{
    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(NULL, 0U),
        LIBP2P_MULTIADDR_OK,
        "validate empty address");
    return 1;
}

static int multiaddr_unit_protocol_info(libp2p_test_context_t *ctx)
{
    const char *name = NULL;
    libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
    size_t fixed_size = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            &name,
            &value_class,
            &fixed_size),
        LIBP2P_MULTIADDR_OK,
        "protocol_info ip4");
    LIBP2P_TEST_CHECK(ctx, strcmp(name, "ip4") == 0, "protocol_info ip4 name");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        value_class,
        LIBP2P_MULTIADDR_VALUE_FIXED,
        "protocol_info ip4 class");
    LIBP2P_TEST_CHECK_SIZE(ctx, fixed_size, 4U, "protocol_info ip4 size");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
            &name,
            &value_class,
            &fixed_size),
        LIBP2P_MULTIADDR_OK,
        "protocol_info quic-v1");
    LIBP2P_TEST_CHECK(ctx, strcmp(name, "quic-v1") == 0, "protocol_info quic-v1 name");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        value_class,
        LIBP2P_MULTIADDR_VALUE_NONE,
        "protocol_info quic-v1 class");
    LIBP2P_TEST_CHECK_SIZE(ctx, fixed_size, 0U, "protocol_info quic-v1 size");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_protocol_info(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            &name,
            &value_class,
            &fixed_size),
        LIBP2P_MULTIADDR_OK,
        "protocol_info p2p");
    LIBP2P_TEST_CHECK(ctx, strcmp(name, "p2p") == 0, "protocol_info p2p name");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        value_class,
        LIBP2P_MULTIADDR_VALUE_VARIABLE,
        "protocol_info p2p class");
    LIBP2P_TEST_CHECK_SIZE(ctx, fixed_size, 0U, "protocol_info p2p size");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_protocol_info(LIBP2P_TEST_MULTIADDR_CODE_TCP, NULL, NULL, NULL),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "protocol_info unsupported");

    return 1;
}

static int multiaddr_unit_next_component_iteration(libp2p_test_context_t *ctx)
{
    uint8_t address[128];
    size_t address_len = 0U;
    uint8_t expected_peer_id[64];
    size_t expected_peer_id_len = 0U;
    libp2p_multiaddr_cursor_t cursor = {address, 0U, 0U};
    uint64_t code = UINT64_C(0);
    const uint8_t *value = NULL;
    size_t value_len = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_sample_address(address, sizeof(address), &address_len) != 0,
        "build sample address");
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_load_peer_id(
            expected_peer_id,
            sizeof(expected_peer_id),
            &expected_peer_id_len) != 0,
        "load peer id");
    cursor.buf_len = address_len;

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_OK,
        "next_component ip4");
    LIBP2P_TEST_CHECK_U64(ctx, code, LIBP2P_TEST_MULTIADDR_CODE_IP4, "code ip4");
    LIBP2P_TEST_CHECK_SIZE(ctx, value_len, 4U, "ip4 value length");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        value,
        value_len,
        ((const uint8_t[]){127U, 0U, 0U, 1U}),
        4U,
        "ip4 value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_OK,
        "next_component udp");
    LIBP2P_TEST_CHECK_U64(ctx, code, LIBP2P_TEST_MULTIADDR_CODE_UDP, "code udp");
    LIBP2P_TEST_CHECK_SIZE(ctx, value_len, 2U, "udp value length");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        value,
        value_len,
        ((const uint8_t[]){0x0fU, 0xa1U}),
        2U,
        "udp value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_OK,
        "next_component quic-v1");
    LIBP2P_TEST_CHECK_U64(ctx, code, LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1, "code quic-v1");
    LIBP2P_TEST_CHECK_SIZE(ctx, value_len, 0U, "quic-v1 value length");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_OK,
        "next_component p2p");
    LIBP2P_TEST_CHECK_U64(ctx, code, LIBP2P_TEST_MULTIADDR_CODE_P2P, "code p2p");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        value,
        value_len,
        expected_peer_id,
        expected_peer_id_len,
        "p2p value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_END,
        "next_component end");
    LIBP2P_TEST_CHECK_SIZE(ctx, cursor.offset, address_len, "cursor consumed bytes");

    return 1;
}

static int multiaddr_unit_next_component_errors(libp2p_test_context_t *ctx)
{
    libp2p_multiaddr_cursor_t cursor = {NULL, 0U, 0U};
    uint64_t code = UINT64_C(0);
    const uint8_t *value = NULL;
    size_t value_len = 0U;
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t non_minimal_code[] = {0x84U, 0x00U};
    const uint8_t single_byte[] = {0x04U};

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(NULL, NULL, NULL, NULL),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "next_component null cursor");

    cursor.buf = NULL;
    cursor.buf_len = 1U;
    cursor.offset = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "next_component null buffer");

    cursor.buf = single_byte;
    cursor.buf_len = sizeof(single_byte);
    cursor.offset = sizeof(single_byte) + 1U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "next_component offset overflow");

    cursor.buf = single_byte;
    cursor.buf_len = sizeof(single_byte);
    cursor.offset = sizeof(single_byte);
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_END,
        "next_component end cursor");

    cursor.buf = truncated_ip4;
    cursor.buf_len = sizeof(truncated_ip4);
    cursor.offset = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_TRUNCATED,
        "next_component truncated ip4");

    cursor.buf = non_minimal_code;
    cursor.buf_len = sizeof(non_minimal_code);
    cursor.offset = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "next_component non-minimal code");

    return 1;
}

static int multiaddr_unit_append_component_measure_and_write(libp2p_test_context_t *ctx)
{
    const uint8_t ip4_value[4] = {127U, 0U, 0U, 1U};
    uint8_t peer_id[64];
    size_t peer_id_len = 0U;
    uint8_t encoded_ip4[5];
    uint8_t encoded_p2p[64];
    size_t pos = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len) != 0,
        "load peer id");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            ip4_value,
            sizeof(ip4_value),
            NULL,
            0U,
            &pos),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "append_component ip4 measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, pos, 5U, "append_component ip4 required");

    pos = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            ip4_value,
            sizeof(ip4_value),
            encoded_ip4,
            sizeof(encoded_ip4),
            &pos),
        LIBP2P_MULTIADDR_OK,
        "append_component ip4 write");
    LIBP2P_TEST_CHECK_SIZE(ctx, pos, sizeof(encoded_ip4), "append_component ip4 written");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        encoded_ip4,
        sizeof(encoded_ip4),
        ((const uint8_t[]){0x04U, 127U, 0U, 0U, 1U}),
        5U,
        "append_component ip4 bytes");

    pos = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            peer_id,
            peer_id_len,
            NULL,
            0U,
            &pos),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "append_component p2p measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, pos, peer_id_len + 3U, "append_component p2p required");

    pos = 0U;
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            peer_id,
            peer_id_len,
            encoded_p2p,
            peer_id_len + 3U,
            &pos),
        LIBP2P_MULTIADDR_OK,
        "append_component p2p write");
    LIBP2P_TEST_CHECK_SIZE(ctx, pos, peer_id_len + 3U, "append_component p2p written");
    LIBP2P_TEST_CHECK_U64(ctx, encoded_p2p[0], UINT64_C(0xA5), "append_component p2p byte0");
    LIBP2P_TEST_CHECK_U64(ctx, encoded_p2p[1], UINT64_C(0x03), "append_component p2p byte1");
    LIBP2P_TEST_CHECK_SIZE(ctx, encoded_p2p[2], peer_id_len, "append_component p2p length");

    return 1;
}

static int multiaddr_unit_append_component_rejects_invalid(libp2p_test_context_t *ctx)
{
    const uint8_t one_byte_value[1] = {0U};
    const uint8_t invalid_peer_id[] = {0x11U, 0x14U, 0U, 0U};
    size_t pos = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_IP4,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            NULL),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "append_component missing pos");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_TCP,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            &pos),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "append_component unsupported protocol");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_QUIC_V1,
            one_byte_value,
            sizeof(one_byte_value),
            NULL,
            0U,
            &pos),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "append_component quic-v1 unexpected value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(LIBP2P_TEST_MULTIADDR_CODE_IP4, NULL, 4U, NULL, 0U, &pos),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "append_component ip4 null value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(LIBP2P_TEST_MULTIADDR_CODE_P2P, NULL, 1U, NULL, 0U, &pos),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "append_component p2p null value");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_append_component(
            LIBP2P_TEST_MULTIADDR_CODE_P2P,
            invalid_peer_id,
            sizeof(invalid_peer_id),
            NULL,
            0U,
            &pos),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "append_component invalid peer id");

    return 1;
}

static int multiaddr_unit_validate_rejects_invalid(libp2p_test_context_t *ctx)
{
    const uint8_t unsupported_tcp[] = {0x06U, 0x01U, 0xbbU};
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t truncated_p2p[] = {0xa5U, 0x03U, 0x22U, 0x12U};
    const uint8_t malformed_p2p[] = {0xa5U, 0x03U, 0x02U, 0x81U, 0x00U};

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(unsupported_tcp, sizeof(unsupported_tcp)),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "validate unsupported tcp");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(truncated_ip4, sizeof(truncated_ip4)),
        LIBP2P_MULTIADDR_ERR_TRUNCATED,
        "validate truncated ip4");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(truncated_p2p, sizeof(truncated_p2p)),
        LIBP2P_MULTIADDR_ERR_TRUNCATED,
        "validate truncated p2p");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(malformed_p2p, sizeof(malformed_p2p)),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "validate malformed p2p");

    return 1;
}

static int multiaddr_unit_encapsulate(libp2p_test_context_t *ctx)
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

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_ip4_udp(4001U, prefix, sizeof(prefix), &prefix_len) != 0,
        "build prefix");
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_quic_p2p(suffix, sizeof(suffix), &suffix_len) != 0,
        "build suffix");
    (void)memcpy(expected, prefix, prefix_len);
    (void)memcpy(expected + prefix_len, suffix, suffix_len);
    expected_len = prefix_len + suffix_len;

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_encapsulate(
            prefix,
            prefix_len,
            suffix,
            suffix_len,
            NULL,
            0U,
            &combined_len),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "encapsulate measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, combined_len, expected_len, "encapsulate required");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_encapsulate(
            prefix,
            prefix_len,
            suffix,
            suffix_len,
            combined,
            sizeof(combined),
            &combined_len),
        LIBP2P_MULTIADDR_OK,
        "encapsulate write");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        combined,
        combined_len,
        expected,
        expected_len,
        "encapsulate bytes");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_encapsulate(
            invalid_outer,
            sizeof(invalid_outer),
            suffix,
            suffix_len,
            combined,
            sizeof(combined),
            &combined_len),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "encapsulate invalid outer");

    return 1;
}

static int multiaddr_unit_decapsulate(libp2p_test_context_t *ctx)
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

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_sample_address(outer, sizeof(outer), &outer_len) != 0,
        "build outer");
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_quic_p2p(inner, sizeof(inner), &inner_len) != 0,
        "build inner");
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_ip4_udp(
            4001U,
            expected_prefix,
            sizeof(expected_prefix),
            &expected_prefix_len) != 0,
        "build prefix");
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_ip4_udp(4002U, not_found, sizeof(not_found), &not_found_len) != 0,
        "build not_found");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_decapsulate(outer, outer_len, inner, inner_len, NULL, 0U, &written),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "decapsulate measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, written, expected_prefix_len, "decapsulate required");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_decapsulate(
            outer,
            outer_len,
            inner,
            inner_len,
            output,
            sizeof(output),
            &written),
        LIBP2P_MULTIADDR_OK,
        "decapsulate write");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        output,
        written,
        expected_prefix,
        expected_prefix_len,
        "decapsulate bytes");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_decapsulate(outer, outer_len, NULL, 0U, NULL, 0U, &written),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "decapsulate empty inner measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, written, outer_len, "decapsulate empty inner required");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_decapsulate(
            outer,
            outer_len,
            not_found,
            not_found_len,
            output,
            sizeof(output),
            &written),
        LIBP2P_MULTIADDR_ERR_NOT_FOUND,
        "decapsulate not found");

    return 1;
}

static int multiaddr_unit_from_and_to_string(libp2p_test_context_t *ctx)
{
    static const char address_text[] =
        "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";
    uint8_t expected_bytes[128];
    uint8_t actual_bytes[128];
    size_t expected_len = 0U;
    size_t written = 0U;
    char roundtrip[128];

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_build_sample_address(
            expected_bytes,
            sizeof(expected_bytes),
            &expected_len) != 0,
        "build expected bytes");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(address_text, sizeof(address_text) - 1U, NULL, 0U, &written),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "from_string measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, written, expected_len, "from_string required");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            address_text,
            sizeof(address_text) - 1U,
            actual_bytes,
            sizeof(actual_bytes),
            &written),
        LIBP2P_MULTIADDR_OK,
        "from_string write");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        actual_bytes,
        written,
        expected_bytes,
        expected_len,
        "from_string bytes");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(actual_bytes, written, NULL, 0U, &expected_len),
        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
        "to_string measure");
    LIBP2P_TEST_CHECK_SIZE(ctx, expected_len, sizeof(address_text) - 1U, "to_string required");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            actual_bytes,
            written,
            roundtrip,
            sizeof(roundtrip),
            &expected_len),
        LIBP2P_MULTIADDR_OK,
        "to_string write");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        roundtrip,
        expected_len,
        address_text,
        sizeof(address_text) - 1U,
        "roundtrip string");

    return 1;
}

static int multiaddr_unit_string_canonicalization(libp2p_test_context_t *ctx)
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

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_unit_make_cid_peer_id_text(cid_peer_id, sizeof(cid_peer_id), &cid_peer_id_len) !=
            0,
        "make cid peer id");

    canonical_len =
        (size_t)snprintf(canonical, sizeof(canonical), "/p2p/%s", multiaddr_unit_legacy_peer_id);
    LIBP2P_TEST_CHECK(ctx, canonical_len < sizeof(canonical), "format canonical string");

    alias_len =
        (size_t)snprintf(alias_text, sizeof(alias_text), "/ipfs/%s", multiaddr_unit_legacy_peer_id);
    LIBP2P_TEST_CHECK(ctx, alias_len < sizeof(alias_text), "format alias string");

    cid_len = (size_t)snprintf(cid_text, sizeof(cid_text), "/p2p/%s", cid_peer_id);
    LIBP2P_TEST_CHECK(ctx, cid_len < sizeof(cid_text), "format cid string");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            alias_text,
            alias_len,
            alias_bytes,
            sizeof(alias_bytes),
            &alias_len),
        LIBP2P_MULTIADDR_OK,
        "from_string ipfs alias");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(cid_text, cid_len, cid_bytes, sizeof(cid_bytes), &cid_len),
        LIBP2P_MULTIADDR_OK,
        "from_string cid peer id");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        alias_bytes,
        alias_len,
        cid_bytes,
        cid_len,
        "canonical peer bytes");

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            alias_bytes,
            alias_len,
            canonical,
            sizeof(canonical),
            &canonical_len),
        LIBP2P_MULTIADDR_OK,
        "to_string canonicalized alias");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        canonical,
        canonical_len,
        ((const char *)"/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"),
        sizeof("/p2p/QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk") - 1U,
        "canonical alias text");

    return 1;
}

static int multiaddr_unit_from_string_invalid_inputs(libp2p_test_context_t *ctx)
{
    uint8_t out[128];
    size_t written = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(NULL, 0U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "from_string null");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/", 1U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "from_string slash only");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("//", 2U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "from_string empty protocol");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/tcp/443", 8U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "from_string unsupported tcp");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/ip4/256.0.0.1", 14U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "from_string invalid ip4");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/ip6/2001:::1", 13U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "from_string invalid ip6");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/udp/65536", 10U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "from_string invalid udp");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string("/p2p/not-a-peer-id", 18U, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
        "from_string invalid peer id");

    return 1;
}

static int multiaddr_unit_to_string_errors(libp2p_test_context_t *ctx)
{
    const uint8_t unsupported_tcp[] = {0x06U, 0x01U, 0xbbU};
    const uint8_t truncated_ip4[] = {0x04U, 0x7fU, 0x00U, 0x00U};
    const uint8_t malformed_p2p[] = {0xa5U, 0x03U, 0x02U, 0x81U, 0x00U};
    char out[128];
    size_t written = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            unsupported_tcp,
            sizeof(unsupported_tcp),
            out,
            sizeof(out),
            &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "to_string unsupported protocol");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            truncated_ip4,
            sizeof(truncated_ip4),
            out,
            sizeof(out),
            &written),
        LIBP2P_MULTIADDR_ERR_TRUNCATED,
        "to_string truncated");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            malformed_p2p,
            sizeof(malformed_p2p),
            out,
            sizeof(out),
            &written),
        LIBP2P_MULTIADDR_ERR_MALFORMED,
        "to_string malformed");

    return 1;
}

static int multiaddr_unit_ipv6_roundtrip(libp2p_test_context_t *ctx)
{
    static const char ipv6_input[] = "/ip6/2001:0db8:0:0:0:0:0:1/udp/0";
    static const char ipv6_canonical[] = "/ip6/2001:db8::1/udp/0";
    uint8_t address[64];
    char formatted[64];
    size_t address_len = 0U;
    size_t formatted_len = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);

    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            ipv6_input,
            sizeof(ipv6_input) - 1U,
            address,
            sizeof(address),
            &address_len),
        LIBP2P_MULTIADDR_OK,
        "from_string ipv6");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            address,
            address_len,
            formatted,
            sizeof(formatted),
            &formatted_len),
        LIBP2P_MULTIADDR_OK,
        "to_string ipv6");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        formatted,
        formatted_len,
        ipv6_canonical,
        sizeof(ipv6_canonical) - 1U,
        "ipv6 canonical");

    return 1;
}

int main(void)
{
    libp2p_test_context_t ctx;

    libp2p_test_context_init(&ctx);

    if ((multiaddr_unit_validate_empty(&ctx) == 0) || (multiaddr_unit_protocol_info(&ctx) == 0) ||
        (multiaddr_unit_next_component_iteration(&ctx) == 0) ||
        (multiaddr_unit_next_component_errors(&ctx) == 0) ||
        (multiaddr_unit_append_component_measure_and_write(&ctx) == 0) ||
        (multiaddr_unit_append_component_rejects_invalid(&ctx) == 0) ||
        (multiaddr_unit_validate_rejects_invalid(&ctx) == 0) ||
        (multiaddr_unit_encapsulate(&ctx) == 0) || (multiaddr_unit_decapsulate(&ctx) == 0) ||
        (multiaddr_unit_from_and_to_string(&ctx) == 0) ||
        (multiaddr_unit_string_canonicalization(&ctx) == 0) ||
        (multiaddr_unit_from_string_invalid_inputs(&ctx) == 0) ||
        (multiaddr_unit_to_string_errors(&ctx) == 0) || (multiaddr_unit_ipv6_roundtrip(&ctx) == 0))
    {
        (void)fprintf(
            stderr,
            "multiaddr unit: %zu cases, %zu failures\n",
            ctx.cases_run,
            ctx.failures);
        return 1;
    }

    (void)printf("multiaddr unit: %zu cases\n", ctx.cases_run);
    return 0;
}
