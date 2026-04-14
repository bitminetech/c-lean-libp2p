#include <stddef.h>
#include <stdint.h>

#include "../../../common/multiformats_test_utils.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

static int unsigned_varint_test_size_boundaries(void)
{
    LIBP2P_TEST_ASSERT_EQ_INT(1, libp2p_uvarint_size(UINT64_C(0)));
    LIBP2P_TEST_ASSERT_EQ_INT(1, libp2p_uvarint_size(UINT64_C(127)));
    LIBP2P_TEST_ASSERT_EQ_INT(2, libp2p_uvarint_size(UINT64_C(128)));
    LIBP2P_TEST_ASSERT_EQ_INT(3, libp2p_uvarint_size(UINT64_C(16384)));
    LIBP2P_TEST_ASSERT_EQ_INT(9, libp2p_uvarint_size(UINT64_C(0x7FFFFFFFFFFFFFFF)));
    LIBP2P_TEST_ASSERT_EQ_INT(10, libp2p_uvarint_size(UINT64_MAX));
    return 0;
}

static int unsigned_varint_test_encode_examples(void)
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

        LIBP2P_TEST_ASSERT_EQ_INT(
            LIBP2P_UVARINT_OK,
            libp2p_uvarint_encode(cases[index].value, encoded, sizeof(encoded), &written));
        LIBP2P_TEST_ASSERT_EQ_SIZE(cases[index].length, written);
        LIBP2P_TEST_ASSERT_MEM_EQ(cases[index].bytes, encoded, cases[index].length);

        LIBP2P_TEST_ASSERT_EQ_INT(
            LIBP2P_UVARINT_OK,
            libp2p_uvarint_decode(encoded, written, &decoded, &read));
        LIBP2P_TEST_ASSERT_EQ_U64(cases[index].value, decoded);
        LIBP2P_TEST_ASSERT_EQ_SIZE(cases[index].length, read);
    }

    return 0;
}

static int unsigned_varint_test_encode_measure_then_write(void)
{
    static const uint8_t expected[2] = {0xACU, 0x02U};
    uint8_t encoded[2] = {0U, 0U};
    size_t written = 0U;

    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_BUF_TOO_SMALL,
        libp2p_uvarint_encode(UINT64_C(300), NULL, 0U, &written));
    LIBP2P_TEST_ASSERT_EQ_SIZE(2U, written);

    written = 0U;
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_BUF_TOO_SMALL,
        libp2p_uvarint_encode(UINT64_C(300), encoded, 1U, &written));
    LIBP2P_TEST_ASSERT_EQ_SIZE(2U, written);

    written = 0U;
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_OK,
        libp2p_uvarint_encode(UINT64_C(300), encoded, sizeof(encoded), &written));
    LIBP2P_TEST_ASSERT_EQ_SIZE(2U, written);
    LIBP2P_TEST_ASSERT_MEM_EQ(expected, encoded, 2U);
    return 0;
}

static int unsigned_varint_test_encode_overflow(void)
{
    uint8_t encoded[10] = {0U};
    size_t written = 0U;

    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_OVERFLOW,
        libp2p_uvarint_encode(UINT64_C(0x8000000000000000), encoded, sizeof(encoded), &written));
    LIBP2P_TEST_ASSERT_EQ_SIZE(10U, written);
    return 0;
}

static int unsigned_varint_test_decode_maximum_value(void)
{
    uint8_t encoded[LIBP2P_UVARINT_MAX_BYTES] = {0U};
    uint64_t decoded = UINT64_C(0);
    size_t written = 0U;
    size_t read = 0U;

    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_OK,
        libp2p_uvarint_encode(UINT64_C(0x7FFFFFFFFFFFFFFF), encoded, sizeof(encoded), &written));
    LIBP2P_TEST_ASSERT_EQ_SIZE(9U, written);
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_OK,
        libp2p_uvarint_decode(encoded, written, &decoded, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0x7FFFFFFFFFFFFFFF), decoded);
    LIBP2P_TEST_ASSERT_EQ_SIZE(9U, read);
    return 0;
}

static int unsigned_varint_test_decode_truncated_inputs(void)
{
    uint64_t value = UINT64_C(123);
    size_t read = 17U;

    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_TRUNCATED,
        libp2p_uvarint_decode(NULL, 0U, &value, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), value);
    LIBP2P_TEST_ASSERT_EQ_SIZE(0U, read);

    value = UINT64_C(123);
    read = 17U;
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_TRUNCATED,
        libp2p_uvarint_decode(NULL, 1U, &value, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), value);
    LIBP2P_TEST_ASSERT_EQ_SIZE(0U, read);

    value = UINT64_C(123);
    read = 17U;
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_TRUNCATED,
        libp2p_uvarint_decode((const uint8_t[]){0x80U}, 1U, &value, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), value);
    LIBP2P_TEST_ASSERT_EQ_SIZE(0U, read);
    return 0;
}

static int unsigned_varint_test_decode_non_minimal_and_overflow(void)
{
    uint64_t value = UINT64_C(99);
    size_t read = 11U;
    uint8_t overflow_bytes[LIBP2P_UVARINT_MAX_BYTES] =
        {0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U};

    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_NON_MINIMAL,
        libp2p_uvarint_decode((const uint8_t[]){0x81U, 0x00U}, 2U, &value, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), value);
    LIBP2P_TEST_ASSERT_EQ_SIZE(0U, read);

    value = UINT64_C(99);
    read = 11U;
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_OVERFLOW,
        libp2p_uvarint_decode(overflow_bytes, sizeof(overflow_bytes), &value, &read));
    LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), value);
    LIBP2P_TEST_ASSERT_EQ_SIZE(0U, read);
    return 0;
}

int main(void)
{
    size_t case_count = 0U;

    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "size_boundaries",
            unsigned_varint_test_size_boundaries,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "encode_examples",
            unsigned_varint_test_encode_examples,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "encode_measure_then_write",
            unsigned_varint_test_encode_measure_then_write,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "encode_overflow",
            unsigned_varint_test_encode_overflow,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "decode_maximum_value",
            unsigned_varint_test_decode_maximum_value,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "decode_truncated_inputs",
            unsigned_varint_test_decode_truncated_inputs,
            &case_count) != 0)
    {
        return 1;
    }
    if (libp2p_test_run_case(
            "unsigned_varint_unit",
            "decode_non_minimal_and_overflow",
            unsigned_varint_test_decode_non_minimal_and_overflow,
            &case_count) != 0)
    {
        return 1;
    }

    (void)fprintf(stderr, "unsigned_varint_unit: %zu cases passed\n", case_count);
    return 0;
}
