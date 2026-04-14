#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"

static int libp2p_multihash_unit_expect(int condition, const char *case_name, const char *message)
{
    if (condition == 0)
    {
        (void)fprintf(stderr, "%s: %s\n", case_name, message);
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_identity_empty_round_trip(void)
{
    static const char *const case_name = "identity_empty_round_trip";
    uint8_t encoded[2] = {0xffU, 0xffU};
    uint64_t code = UINT64_C(1);
    const uint8_t *digest = encoded;
    size_t digest_len = 99U;
    size_t read = 99U;
    size_t written = 99U;
    size_t size = 0U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, 0U, &size) == LIBP2P_MULTIHASH_OK,
            case_name,
            "size failed for empty identity") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(size == 2U, case_name, "unexpected size for empty identity") ==
        0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                NULL,
                0U,
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_OK,
            case_name,
            "encode failed for empty identity") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(written == sizeof(encoded), case_name, "wrong encode size") ==
        0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (encoded[0] == 0x00U) && (encoded[1] == 0x00U),
            case_name,
            "unexpected encoded bytes for empty identity") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
                LIBP2P_MULTIHASH_OK,
            case_name,
            "decode failed for empty identity") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (code == LIBP2P_MULTIHASH_CODE_IDENTITY) && (digest_len == 0U) &&
                (read == sizeof(encoded)) && (digest == (encoded + 2U)),
            case_name,
            "unexpected decode result for empty identity") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_measure_then_write_identity(void)
{
    static const char *const case_name = "measure_then_write_identity";
    const uint8_t digest[] = {0xaaU, 0xbbU, 0xccU};
    uint8_t encoded[5] = {0U, 0U, 0U, 0U, 0U};
    size_t written = 0U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                digest,
                sizeof(digest),
                NULL,
                0U,
                &written) == LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL,
            case_name,
            "measure call did not report buffer-too-small") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            written == sizeof(encoded),
            case_name,
            "wrong measured size") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                digest,
                sizeof(digest),
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_OK,
            case_name,
            "write call failed after measurement") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (written == sizeof(encoded)) && (encoded[0] == 0x00U) && (encoded[1] == 0x03U) &&
                (memcmp(encoded + 2U, digest, sizeof(digest)) == 0),
            case_name,
            "unexpected encoded identity bytes") == 0)
    {
        return 0;
    }

    return 1;
}

static void libp2p_multihash_unit_fill_sha2_digest(uint8_t digest[32])
{
    size_t index = 0U;

    for (index = 0U; index < 32U; index++)
    {
        digest[index] = (uint8_t)(index + 1U);
    }
}

static int libp2p_multihash_unit_test_sha2_256_round_trip(void)
{
    static const char *const case_name = "sha2_256_round_trip";
    uint8_t digest_bytes[32];
    uint8_t encoded[34];
    uint64_t code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t digest_len = 0U;
    size_t read = 0U;
    size_t written = 0U;
    size_t size = 0U;

    libp2p_multihash_unit_fill_sha2_digest(digest_bytes);

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_SHA2_256, sizeof(digest_bytes), &size) ==
                LIBP2P_MULTIHASH_OK,
            case_name,
            "size failed for sha2-256") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(size == sizeof(encoded), case_name, "wrong sha2-256 size") ==
        0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_SHA2_256,
                digest_bytes,
                sizeof(digest_bytes),
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_OK,
            case_name,
            "encode failed for sha2-256") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (written == sizeof(encoded)) && (encoded[0] == 0x12U) && (encoded[1] == 0x20U) &&
                (memcmp(encoded + 2U, digest_bytes, sizeof(digest_bytes)) == 0),
            case_name,
            "unexpected sha2-256 encoding") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
                LIBP2P_MULTIHASH_OK,
            case_name,
            "decode failed for sha2-256") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (code == LIBP2P_MULTIHASH_CODE_SHA2_256) && (digest == (encoded + 2U)) &&
                (digest_len == sizeof(digest_bytes)) && (read == sizeof(encoded)) &&
                (memcmp(digest, digest_bytes, sizeof(digest_bytes)) == 0),
            case_name,
            "unexpected sha2-256 decode result") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_encode_off_by_one_buffer(void)
{
    static const char *const case_name = "encode_off_by_one_buffer";
    const uint8_t digest[] = {0xffU};
    uint8_t encoded[2] = {0U, 0U};
    size_t written = 0U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                digest,
                sizeof(digest),
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL,
            case_name,
            "expected buffer-too-small for off-by-one buffer") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(written == 3U, case_name, "wrong required size reported") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_encode_unsupported_code(void)
{
    static const char *const case_name = "encode_unsupported_code";
    const uint8_t digest[20] = {0U};
    uint8_t encoded[32] = {0U};
    size_t written = 99U;
    size_t size = 99U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_size(UINT64_C(0x11), sizeof(digest), &size) ==
                LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE,
            case_name,
            "size did not reject unsupported code") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(size == 0U, case_name, "size output not cleared") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                UINT64_C(0x11),
                digest,
                sizeof(digest),
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE,
            case_name,
            "encode did not reject unsupported code") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(written == 0U, case_name, "written not reset on failure") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_digest_size_mismatch(void)
{
    static const char *const case_name = "digest_size_mismatch";
    uint8_t digest[31];
    uint8_t encoded[64] = {0U};
    size_t written = 99U;
    size_t size = 99U;

    (void)memset(digest, 0x5a, sizeof(digest));

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_SHA2_256, sizeof(digest), &size) ==
                LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH,
            case_name,
            "size did not reject invalid sha2-256 length") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(size == 0U, case_name, "size output not cleared") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_SHA2_256,
                digest,
                sizeof(digest),
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH,
            case_name,
            "encode did not reject invalid sha2-256 length") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(written == 0U, case_name, "written not reset on mismatch") ==
        0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_null_digest_with_nonzero_length(void)
{
    static const char *const case_name = "null_digest_with_nonzero_length";
    uint8_t encoded[8] = {0U};
    size_t written = 99U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                NULL,
                1U,
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH,
            case_name,
            "encode accepted NULL digest with non-zero length") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(written == 0U, case_name, "written not reset on failure") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_decode_unsupported_code(void)
{
    static const char *const case_name = "decode_unsupported_code";
    uint8_t encoded[22];
    uint64_t code = UINT64_C(7);
    const uint8_t *digest = encoded;
    size_t digest_len = 77U;
    size_t read = 77U;

    encoded[0] = 0x11U;
    encoded[1] = 0x14U;
    (void)memset(encoded + 2U, 0xa5, sizeof(encoded) - 2U);

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
                LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE,
            case_name,
            "decode accepted unsupported code") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (code == 0U) && (digest == NULL) && (digest_len == 0U) && (read == 0U),
            case_name,
            "decode outputs not reset on unsupported code") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_invalid_varint_non_minimal(void)
{
    static const char *const case_name = "invalid_varint_non_minimal";
    const uint8_t encoded[] = {0x81U, 0x00U, 0x00U};
    uint64_t code = UINT64_C(99);
    const uint8_t *digest = encoded;
    size_t digest_len = 99U;
    size_t read = 99U;
    size_t digest_offset = 99U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_read_header(
                encoded,
                sizeof(encoded),
                &code,
                &digest_len,
                &digest_offset) == LIBP2P_MULTIHASH_ERR_INVALID_VARINT,
            case_name,
            "read_header accepted non-minimal varint") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (code == 0U) && (digest_len == 0U) && (digest_offset == 0U),
            case_name,
            "read_header outputs not reset on invalid varint") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
                LIBP2P_MULTIHASH_ERR_INVALID_VARINT,
            case_name,
            "decode accepted non-minimal varint") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_invalid_varint_overflow(void)
{
    static const char *const case_name = "invalid_varint_overflow";
    const uint8_t encoded[] =
        {0x00U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U};
    size_t digest_len = 99U;
    size_t digest_offset = 99U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_read_header(
                encoded,
                sizeof(encoded),
                NULL,
                &digest_len,
                &digest_offset) == LIBP2P_MULTIHASH_ERR_INVALID_VARINT,
            case_name,
            "overflowing size varint was accepted") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (digest_len == 0U) && (digest_offset == 0U),
            case_name,
            "read_header outputs not reset after overflow") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_truncated_header(void)
{
    static const char *const case_name = "truncated_header";
    const uint8_t encoded[] = {0x00U};
    uint64_t code = UINT64_C(99);
    size_t digest_len = 99U;
    size_t digest_offset = 99U;
    size_t read = 99U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_read_header(
                encoded,
                sizeof(encoded),
                &code,
                &digest_len,
                &digest_offset) == LIBP2P_MULTIHASH_ERR_TRUNCATED,
            case_name,
            "read_header accepted truncated header") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), &code, NULL, &digest_len, &read) ==
                LIBP2P_MULTIHASH_ERR_TRUNCATED,
            case_name,
            "decode accepted truncated header") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_truncated_digest(void)
{
    static const char *const case_name = "truncated_digest";
    const uint8_t encoded[] = {0x00U, 0x03U, 0xaaU, 0xbbU};

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), NULL, NULL, NULL, NULL) ==
                LIBP2P_MULTIHASH_ERR_TRUNCATED,
            case_name,
            "decode accepted truncated digest") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_decode_digest_size_mismatch(void)
{
    static const char *const case_name = "decode_digest_size_mismatch";
    uint8_t encoded[33];

    encoded[0] = 0x12U;
    encoded[1] = 0x1fU;
    (void)memset(encoded + 2U, 0x11, sizeof(encoded) - 2U);

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_decode(encoded, sizeof(encoded), NULL, NULL, NULL, NULL) ==
                LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH,
            case_name,
            "decode accepted invalid sha2-256 digest length") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_read_header_success(void)
{
    static const char *const case_name = "read_header_success";
    const uint8_t encoded[] = {0x00U, 0x03U, 0xaaU, 0xbbU, 0xccU};
    uint64_t code = UINT64_C(0);
    size_t digest_len = 0U;
    size_t digest_offset = 0U;

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_read_header(
                encoded,
                sizeof(encoded),
                &code,
                &digest_len,
                &digest_offset) == LIBP2P_MULTIHASH_OK,
            case_name,
            "read_header failed for valid identity") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_unit_expect(
            (code == LIBP2P_MULTIHASH_CODE_IDENTITY) && (digest_len == 3U) && (digest_offset == 2U),
            case_name,
            "unexpected read_header result") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_unit_test_size_with_null_output(void)
{
    static const char *const case_name = "size_with_null_output";

    if (libp2p_multihash_unit_expect(
            libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, 0U, NULL) == LIBP2P_MULTIHASH_OK,
            case_name,
            "size failed with NULL out_len") == 0)
    {
        return 0;
    }

    return 1;
}

int main(void)
{
    int failed = 0;
    size_t total = 0U;

    total++;
    failed += 1 - libp2p_multihash_unit_test_identity_empty_round_trip();
    total++;
    failed += 1 - libp2p_multihash_unit_test_measure_then_write_identity();
    total++;
    failed += 1 - libp2p_multihash_unit_test_sha2_256_round_trip();
    total++;
    failed += 1 - libp2p_multihash_unit_test_encode_off_by_one_buffer();
    total++;
    failed += 1 - libp2p_multihash_unit_test_encode_unsupported_code();
    total++;
    failed += 1 - libp2p_multihash_unit_test_digest_size_mismatch();
    total++;
    failed += 1 - libp2p_multihash_unit_test_null_digest_with_nonzero_length();
    total++;
    failed += 1 - libp2p_multihash_unit_test_decode_unsupported_code();
    total++;
    failed += 1 - libp2p_multihash_unit_test_invalid_varint_non_minimal();
    total++;
    failed += 1 - libp2p_multihash_unit_test_invalid_varint_overflow();
    total++;
    failed += 1 - libp2p_multihash_unit_test_truncated_header();
    total++;
    failed += 1 - libp2p_multihash_unit_test_truncated_digest();
    total++;
    failed += 1 - libp2p_multihash_unit_test_decode_digest_size_mismatch();
    total++;
    failed += 1 - libp2p_multihash_unit_test_read_header_success();
    total++;
    failed += 1 - libp2p_multihash_unit_test_size_with_null_output();

    if (failed != 0)
    {
        (void)fprintf(stderr, "multihash unit: %d/%lu failed\n", failed, (unsigned long)total);
        return 1;
    }

    (void)printf("multihash unit: %lu cases passed\n", (unsigned long)total);
    return 0;
}
