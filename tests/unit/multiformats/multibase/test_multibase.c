#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"

static void multibase_unit_test_encode_supported_vectors(void)
{
    static const uint8_t multibase_unit_yes_mani[] =
        {0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[32];
    size_t written = 0U;

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_OK);
    assert(written == 15U);
    assert(memcmp(out, "z7paNL19xttacUY", 15U) == 0);

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_OK);
    assert(written == 15U);
    assert(memcmp(out, "ueWVzIG1hbmkgIQ", 15U) == 0);
}

static void multibase_unit_test_encode_empty_and_measure(void)
{
    static const uint8_t multibase_unit_two_zeros[] =
        {0x00U, 0x00U, 0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[32];
    size_t measured = 0U;
    size_t written = 0U;

    assert(
        libp2p_multibase_encode(LIBP2P_MULTIBASE_BASE58BTC, NULL, 0U, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_OK);
    assert(written == 1U);
    assert(out[0] == 'z');

    assert(
        libp2p_multibase_encode(LIBP2P_MULTIBASE_BASE64URL, NULL, 0U, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_OK);
    assert(written == 1U);
    assert(out[0] == 'u');

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            NULL,
            0U,
            &measured) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(measured == 17U);
    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            out,
            measured,
            &written) == LIBP2P_MULTIBASE_OK);
    assert(written == 17U);
    assert(memcmp(out, "uAAB5ZXMgbWFuaSAh", 17U) == 0);

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            NULL,
            0U,
            &measured) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(measured == 17U);
    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            multibase_unit_two_zeros,
            sizeof(multibase_unit_two_zeros),
            out,
            measured,
            &written) == LIBP2P_MULTIBASE_OK);
    assert(written == 17U);
    assert(memcmp(out, "z117paNL19xttacUY", 17U) == 0);
}

static void multibase_unit_test_encode_errors(void)
{
    static const uint8_t multibase_unit_yes_mani[] =
        {0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    char out[15];
    size_t written = 123U;

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out) - 1U,
            &written) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(written == 15U);

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            NULL,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(written == 0U);

    assert(
        libp2p_multibase_encode(
            (libp2p_multibase_t)99,
            multibase_unit_yes_mani,
            sizeof(multibase_unit_yes_mani),
            out,
            sizeof(out),
            &written) == LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE);
    assert(written == 0U);
}

static void multibase_unit_test_decode_supported_vectors(void)
{
    static const uint8_t multibase_unit_two_zeros[] =
        {0x00U, 0x00U, 0x79U, 0x65U, 0x73U, 0x20U, 0x6dU, 0x61U, 0x6eU, 0x69U, 0x20U, 0x21U};
    uint8_t out[32];
    libp2p_multibase_t base = (libp2p_multibase_t)99;
    size_t written = 0U;

    assert(
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_OK);
    assert(base == LIBP2P_MULTIBASE_BASE58BTC);
    assert(written == sizeof(multibase_unit_two_zeros));
    assert(memcmp(out, multibase_unit_two_zeros, sizeof(multibase_unit_two_zeros)) == 0);

    assert(
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_OK);
    assert(base == LIBP2P_MULTIBASE_BASE64URL);
    assert(written == sizeof(multibase_unit_two_zeros));
    assert(memcmp(out, multibase_unit_two_zeros, sizeof(multibase_unit_two_zeros)) == 0);
}

static void multibase_unit_test_decode_measure_and_off_by_one(void)
{
    uint8_t out[32];
    libp2p_multibase_t base = (libp2p_multibase_t)99;
    size_t measured = 0U;
    size_t written = 0U;

    assert(
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, NULL, 0U, &measured) ==
        LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(measured == 12U);
    assert(
        libp2p_multibase_decode("uAAB5ZXMgbWFuaSAh", 17U, &base, out, measured - 1U, &written) ==
        LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(written == 12U);

    assert(
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, NULL, 0U, &measured) ==
        LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL);
    assert(measured == 16U);
    assert(
        libp2p_multibase_decode("z117paNL19xttacUY", 17U, &base, out, measured, &written) ==
        LIBP2P_MULTIBASE_OK);
    assert(written == 12U);
}

static void multibase_unit_test_decode_errors(void)
{
    uint8_t out[8];
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
    size_t written = 99U;
    const char multibase_unit_nul_prefix[1] = {'\0'};

    assert(
        libp2p_multibase_decode(NULL, 0U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_EMPTY_INPUT);
    assert(
        libp2p_multibase_decode("", 0U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_EMPTY_INPUT);

    assert(
        libp2p_multibase_decode(multibase_unit_nul_prefix, 1U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX);
    assert(
        libp2p_multibase_decode("/abc", 4U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX);
    assert(
        libp2p_multibase_decode("1abc", 4U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX);
    assert(
        libp2p_multibase_decode("Qabc", 4U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX);

    assert(
        libp2p_multibase_decode("f00", 3U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE);
    assert(
        libp2p_multibase_decode("z0", 2U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER);
    assert(
        libp2p_multibase_decode("uA", 2U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_INVALID_LENGTH);
    assert(
        libp2p_multibase_decode("uA=", 3U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER);
    assert(
        libp2p_multibase_decode("uAB", 3U, &base, out, sizeof(out), &written) ==
        LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER);
}

static void multibase_unit_test_size_helpers(void)
{
    size_t size = 0U;

    assert(
        libp2p_multibase_encoded_size(LIBP2P_MULTIBASE_BASE64URL, 10U, &size) ==
        LIBP2P_MULTIBASE_OK);
    assert(size == 15U);

    assert(
        libp2p_multibase_encoded_size(LIBP2P_MULTIBASE_BASE58BTC, 12U, &size) ==
        LIBP2P_MULTIBASE_OK);
    assert(size == 18U);

    assert(
        libp2p_multibase_max_decoded_size(LIBP2P_MULTIBASE_BASE64URL, 16U, &size) ==
        LIBP2P_MULTIBASE_OK);
    assert(size == 12U);

    assert(
        libp2p_multibase_max_decoded_size(LIBP2P_MULTIBASE_BASE58BTC, 16U, &size) ==
        LIBP2P_MULTIBASE_OK);
    assert(size == 16U);

    assert(
        libp2p_multibase_encoded_size((libp2p_multibase_t)99, 1U, &size) ==
        LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE);
    assert(size == 0U);

    assert(
        libp2p_multibase_max_decoded_size((libp2p_multibase_t)99, 1U, &size) ==
        LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE);
    assert(size == 0U);
}

int main(void)
{
    multibase_unit_test_encode_supported_vectors();
    multibase_unit_test_encode_empty_and_measure();
    multibase_unit_test_encode_errors();
    multibase_unit_test_decode_supported_vectors();
    multibase_unit_test_decode_measure_and_off_by_one();
    multibase_unit_test_decode_errors();
    multibase_unit_test_size_helpers();
    return 0;
}
