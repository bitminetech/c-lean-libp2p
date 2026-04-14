#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

static void unsigned_varint_test_size_boundaries(void)
{
    assert(libp2p_uvarint_size(UINT64_C(0)) == 1);
    assert(libp2p_uvarint_size(UINT64_C(127)) == 1);
    assert(libp2p_uvarint_size(UINT64_C(128)) == 2);
    assert(libp2p_uvarint_size(UINT64_C(16384)) == 3);
    assert(libp2p_uvarint_size(UINT64_C(0x7FFFFFFFFFFFFFFF)) == 9);
    assert(libp2p_uvarint_size(UINT64_MAX) == 10);
}

static void unsigned_varint_test_encode_examples(void)
{
    static const struct
    {
        uint64_t value;
        uint8_t bytes[LIBP2P_UVARINT_MAX_BYTES];
        size_t length;
    } cases[] =
        {{UINT64_C(0x01), {0x01U}, 1U},
         {UINT64_C(0x7F), {0x7FU}, 1U},
         {UINT64_C(0x80), {0x80U, 0x01U}, 2U},
         {UINT64_C(0xFF), {0xFFU, 0x01U}, 2U},
         {UINT64_C(0x012C), {0xACU, 0x02U}, 2U},
         {UINT64_C(0x4000), {0x80U, 0x80U, 0x01U}, 3U}};
    size_t index = 0U;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); index++)
    {
        uint8_t encoded[LIBP2P_UVARINT_MAX_BYTES] = {0U};
        uint64_t decoded = UINT64_C(0);
        size_t written = 0U;
        size_t read = 0U;

        assert(
            libp2p_uvarint_encode(cases[index].value, encoded, sizeof(encoded), &written) ==
            LIBP2P_UVARINT_OK);
        assert(written == cases[index].length);
        assert(memcmp(encoded, cases[index].bytes, cases[index].length) == 0);

        assert(libp2p_uvarint_decode(encoded, written, &decoded, &read) == LIBP2P_UVARINT_OK);
        assert(decoded == cases[index].value);
        assert(read == cases[index].length);
    }
}

static void unsigned_varint_test_encode_measure_then_write(void)
{
    static const uint8_t expected[2] = {0xACU, 0x02U};
    uint8_t encoded[2] = {0U, 0U};
    size_t written = 0U;

    assert(
        libp2p_uvarint_encode(UINT64_C(300), NULL, 0U, &written) ==
        LIBP2P_UVARINT_ERR_BUF_TOO_SMALL);
    assert(written == 2U);

    written = 0U;
    assert(
        libp2p_uvarint_encode(UINT64_C(300), encoded, 1U, &written) ==
        LIBP2P_UVARINT_ERR_BUF_TOO_SMALL);
    assert(written == 2U);

    written = 0U;
    assert(
        libp2p_uvarint_encode(UINT64_C(300), encoded, sizeof(encoded), &written) ==
        LIBP2P_UVARINT_OK);
    assert(written == 2U);
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
}

static void unsigned_varint_test_encode_overflow(void)
{
    uint8_t encoded[10] = {0U};
    size_t written = 0U;

    assert(
        libp2p_uvarint_encode(UINT64_C(0x8000000000000000), encoded, sizeof(encoded), &written) ==
        LIBP2P_UVARINT_ERR_OVERFLOW);
    assert(written == 10U);
}

static void unsigned_varint_test_decode_maximum_value(void)
{
    uint8_t encoded[LIBP2P_UVARINT_MAX_BYTES] = {0U};
    uint64_t decoded = UINT64_C(0);
    size_t written = 0U;
    size_t read = 0U;

    assert(
        libp2p_uvarint_encode(UINT64_C(0x7FFFFFFFFFFFFFFF), encoded, sizeof(encoded), &written) ==
        LIBP2P_UVARINT_OK);
    assert(written == 9U);
    assert(libp2p_uvarint_decode(encoded, written, &decoded, &read) == LIBP2P_UVARINT_OK);
    assert(decoded == UINT64_C(0x7FFFFFFFFFFFFFFF));
    assert(read == 9U);
}

static void unsigned_varint_test_decode_truncated_inputs(void)
{
    uint64_t value = UINT64_C(123);
    size_t read = 17U;

    assert(libp2p_uvarint_decode(NULL, 0U, &value, &read) == LIBP2P_UVARINT_ERR_TRUNCATED);
    assert(value == UINT64_C(0));
    assert(read == 0U);

    value = UINT64_C(123);
    read = 17U;
    assert(libp2p_uvarint_decode(NULL, 1U, &value, &read) == LIBP2P_UVARINT_ERR_TRUNCATED);
    assert(value == UINT64_C(0));
    assert(read == 0U);

    value = UINT64_C(123);
    read = 17U;
    assert(
        libp2p_uvarint_decode((const uint8_t[]){0x80U}, 1U, &value, &read) ==
        LIBP2P_UVARINT_ERR_TRUNCATED);
    assert(value == UINT64_C(0));
    assert(read == 0U);
}

static void unsigned_varint_test_decode_non_minimal_and_overflow(void)
{
    uint64_t value = UINT64_C(99);
    size_t read = 11U;
    uint8_t overflow_bytes[LIBP2P_UVARINT_MAX_BYTES] =
        {0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U};

    assert(
        libp2p_uvarint_decode((const uint8_t[]){0x81U, 0x00U}, 2U, &value, &read) ==
        LIBP2P_UVARINT_ERR_NON_MINIMAL);
    assert(value == UINT64_C(0));
    assert(read == 0U);

    value = UINT64_C(99);
    read = 11U;
    assert(
        libp2p_uvarint_decode(overflow_bytes, sizeof(overflow_bytes), &value, &read) ==
        LIBP2P_UVARINT_ERR_OVERFLOW);
    assert(value == UINT64_C(0));
    assert(read == 0U);
}

int main(void)
{
    unsigned_varint_test_size_boundaries();
    unsigned_varint_test_encode_examples();
    unsigned_varint_test_encode_measure_then_write();
    unsigned_varint_test_encode_overflow();
    unsigned_varint_test_decode_maximum_value();
    unsigned_varint_test_decode_truncated_inputs();
    unsigned_varint_test_decode_non_minimal_and_overflow();
    return 0;
}
