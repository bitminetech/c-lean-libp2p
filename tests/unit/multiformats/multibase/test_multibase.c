#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"

static int multibase_unit_fail(const char *test_name, size_t line, const char *message)
{
    (void)fprintf(
        stderr,
        "multibase unit failure in %s at line %lu: %s\n",
        test_name,
        (unsigned long)line,
        message);
    return 1;
}

#define MULTIBASE_UNIT_CHECK(test_name, expr, message)                            \
    do                                                                            \
    {                                                                             \
        if (!(expr))                                                              \
        {                                                                         \
            return multibase_unit_fail((test_name), (size_t)__LINE__, (message)); \
        }                                                                         \
    } while (0)

static int multibase_unit_test_encode_supported_vectors(void)
{
    static const uint8_t multibase_unit_yes_mani[] =
        {0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[32];
    size_t written = 0U;

    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_OK,
        "base58btc encode should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        written == 15U,
        "base58btc encoded length mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        memcmp(out, "z7paNL19xttacUY", 15U) == 0,
        "base58btc encoded bytes mismatch");

    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_OK,
        "base64url encode should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        written == 15U,
        "base64url encoded length mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_supported_vectors",
        memcmp(out, "ueWVzIG1hbmkgIQ", 15U) == 0,
        "base64url encoded bytes mismatch");

    return 0;
}

static int multibase_unit_test_encode_empty_and_measure(void)
{
    static const uint8_t multibase_unit_two_zeros[] =
        {0x00U, 0x00U, 0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[32];
    size_t measured = 0U;
    size_t written = 0U;

    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(LIBP2P_MULTIBASE_BASE58BTC, NULL, 0U, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_OK,
        "empty base58btc encode should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        written == 1U,
        "empty base58btc encoded length mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        out[0] == 'z',
        "empty base58btc output mismatch");

    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(LIBP2P_MULTIBASE_BASE64URL, NULL, 0U, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_OK,
        "empty base64url encode should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        written == 1U,
        "empty base64url encoded length mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        out[0] == 'u',
        "empty base64url output mismatch");

    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            NULL,
            0U,
            &measured) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base64url measure should return buffer-too-small");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        measured == 17U,
        "base64url measured size mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            out,
            measured,
            &written) == LIBP2P_MULTIBASE_OK,
        "base64url encode after measure should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        written == 17U,
        "base64url written size mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        memcmp(out, "uAAB5ZXMgbWFuaSAh", 17U) == 0,
        "base64url encoded output mismatch");

    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            NULL,
            0U,
            &measured) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base58btc measure should return buffer-too-small");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        measured == 17U,
        "base58btc measured upper bound mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            out,
            measured,
            &written) == LIBP2P_MULTIBASE_OK,
        "base58btc encode after measure should succeed");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        written == 17U,
        "base58btc exact written size mismatch");
    MULTIBASE_UNIT_CHECK(
        "encode_empty_and_measure",
        memcmp(out, "z117paNL19xttacUY", 17U) == 0,
        "base58btc encoded output mismatch");

    return 0;
}

static int multibase_unit_test_encode_errors(void)
{
    static const uint8_t multibase_unit_yes_mani[] =
        {0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[15];
    size_t written = 123U;

    MULTIBASE_UNIT_CHECK(
        "encode_errors",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out) - 1U,
            &written) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base64url short buffer should fail");
    MULTIBASE_UNIT_CHECK(
        "encode_errors",
        written == 15U,
        "base64url short buffer should report required size");

    MULTIBASE_UNIT_CHECK(
        "encode_errors",
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            NULL,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base58btc NULL input should fail");
    MULTIBASE_UNIT_CHECK(
        "encode_errors",
        written == 0U,
        "base58btc NULL input should leave written at zero");

    MULTIBASE_UNIT_CHECK(
        "encode_errors",
        libp2p_multibase_encode(
            (libp2p_multibase_t)99,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE,
        "unsupported base should fail");
    MULTIBASE_UNIT_CHECK("encode_errors", written == 0U, "unsupported base should zero written");

    return 0;
}

static int multibase_unit_test_decode_supported_vectors(void)
{
    static const uint8_t multibase_unit_two_zeros[] =
        {0x00U, 0x00U, 0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    uint8_t out[32];
    libp2p_multibase_t base = (libp2p_multibase_t)99;
    size_t written = 0U;

    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_OK,
        "base58btc decode should succeed");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        base == LIBP2P_MULTIBASE_BASE58BTC,
        "base58btc decoded base mismatch");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        written == sizeof(multibase_unit_two_zeros),
        "base58btc decoded size mismatch");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        memcmp(out, multibase_unit_two_zeros, sizeof(multibase_unit_two_zeros)) == 0,
        "base58btc decoded bytes mismatch");

    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_OK,
        "base64url decode should succeed");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        base == LIBP2P_MULTIBASE_BASE64URL,
        "base64url decoded base mismatch");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        written == sizeof(multibase_unit_two_zeros),
        "base64url decoded size mismatch");
    MULTIBASE_UNIT_CHECK(
        "decode_supported_vectors",
        memcmp(out, multibase_unit_two_zeros, sizeof(multibase_unit_two_zeros)) == 0,
        "base64url decoded bytes mismatch");

    return 0;
}

static int multibase_unit_test_decode_measure_and_off_by_one(void)
{
    uint8_t out[32];
    libp2p_multibase_t base = (libp2p_multibase_t)99;
    size_t measured = 0U;
    size_t written = 0U;

    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, NULL, 0U, &measured) ==
            LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base64url decode measure should fail with buffer-too-small");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        measured == 12U,
        "base64url decode measure mismatch");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, out, measured - 1U, &written) ==
            LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base64url off-by-one buffer should fail");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        written == 12U,
        "base64url off-by-one should still report exact size");

    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, NULL, 0U, &measured) ==
            LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
        "base58btc decode measure should fail with buffer-too-small");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        measured == 16U,
        "base58btc decode measure should report payload upper bound");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, out, measured, &written) ==
            LIBP2P_MULTIBASE_OK,
        "base58btc decode after measure should succeed");
    MULTIBASE_UNIT_CHECK(
        "decode_measure_and_off_by_one",
        written == 12U,
        "base58btc exact decoded size mismatch");

    return 0;
}

static int multibase_unit_test_decode_errors(void)
{
    uint8_t out[8];
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
    size_t written = 99U;
    const char multibase_unit_nul_prefix[1] = {'\0'};

    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode(NULL, 0U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_EMPTY_INPUT,
        "NULL empty input should be rejected");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("", 0U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_EMPTY_INPUT,
        "zero-length input should be rejected");

    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode(multibase_unit_nul_prefix, 1U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX,
        "NUL prefix should be reserved");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("/abc", 4U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX,
        "slash prefix should be reserved");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("1abc", 4U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX,
        "legacy peer id prefix should be reserved");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("Qabc", 4U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX,
        "CIDv0 peer id prefix should be reserved");

    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("f00", 3U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE,
        "unsupported prefix should fail");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("z0", 2U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER,
        "invalid base58btc character should fail");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("uA", 2U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_INVALID_LENGTH,
        "invalid base64url length should fail");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("uA=", 3U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER,
        "invalid base64url character should fail");
    MULTIBASE_UNIT_CHECK(
        "decode_errors",
        libp2p_multibase_decode("uAB", 3U, &base, out, sizeof(out), &written) ==
            LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER,
        "non-canonical base64url trailing bits should fail");

    return 0;
}

static int multibase_unit_test_size_helpers(void)
{
    size_t size = 0U;

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_encoded_size(LIBP2P_MULTIBASE_BASE64URL, 10U, &size) ==
            LIBP2P_MULTIBASE_OK,
        "base64url encoded size should succeed");
    MULTIBASE_UNIT_CHECK("size_helpers", size == 15U, "base64url encoded size mismatch");

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_encoded_size(LIBP2P_MULTIBASE_BASE58BTC, 12U, &size) ==
            LIBP2P_MULTIBASE_OK,
        "base58btc encoded size should succeed");
    MULTIBASE_UNIT_CHECK("size_helpers", size == 18U, "base58btc encoded upper bound mismatch");

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_max_decoded_size(LIBP2P_MULTIBASE_BASE64URL, 16U, &size) ==
            LIBP2P_MULTIBASE_OK,
        "base64url max decoded size should succeed");
    MULTIBASE_UNIT_CHECK("size_helpers", size == 12U, "base64url max decoded size mismatch");

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_max_decoded_size(LIBP2P_MULTIBASE_BASE58BTC, 16U, &size) ==
            LIBP2P_MULTIBASE_OK,
        "base58btc max decoded size should succeed");
    MULTIBASE_UNIT_CHECK("size_helpers", size == 16U, "base58btc max decoded size mismatch");

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_encoded_size((libp2p_multibase_t)99, 1U, &size) ==
            LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE,
        "unsupported base encoded size should fail");
    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        size == 0U,
        "unsupported base encoded size should zero output");

    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        libp2p_multibase_max_decoded_size((libp2p_multibase_t)99, 1U, &size) ==
            LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE,
        "unsupported base max decoded size should fail");
    MULTIBASE_UNIT_CHECK(
        "size_helpers",
        size == 0U,
        "unsupported base max decoded size should zero output");

    return 0;
}

int main(void)
{
    int failures = 0;

    failures += multibase_unit_test_encode_supported_vectors();
    failures += multibase_unit_test_encode_empty_and_measure();
    failures += multibase_unit_test_encode_errors();
    failures += multibase_unit_test_decode_supported_vectors();
    failures += multibase_unit_test_decode_measure_and_off_by_one();
    failures += multibase_unit_test_decode_errors();
    failures += multibase_unit_test_size_helpers();

    if (failures == 0)
    {
        (void)printf("multibase unit: 7 tests passed\n");
    }

    return failures;
}
