#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"

static void multihash_unit_test_identity_empty_round_trip(void)
{
    uint8_t encoded[2] = {0xffU, 0xffU};
    uint64_t code = UINT64_C(1);
    const uint8_t *digest = encoded;
    size_t digest_len = 99U;
    size_t read = 99U;
    size_t written = 99U;
    size_t size = 0U;

    assert(libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, 0U, &size) == LIBP2P_MULTIHASH_OK);
    assert(size == 2U);

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            NULL,
            0U,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_OK);
    assert(written == sizeof(encoded));
    assert((encoded[0] == 0x00U) && (encoded[1] == 0x00U));

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
        LIBP2P_MULTIHASH_OK);
    assert(code == LIBP2P_MULTIHASH_CODE_IDENTITY);
    assert(digest_len == 0U);
    assert(read == sizeof(encoded));
    assert(digest == (encoded + 2U));
}

static void multihash_unit_test_measure_then_write_identity(void)
{
    const uint8_t digest[] = {0xaaU, 0xbbU, 0xccU};
    uint8_t encoded[5] = {0U, 0U, 0U, 0U, 0U};
    size_t written = 0U;

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            digest,
            sizeof(digest),
            NULL,
            0U,
            &written) == LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(encoded));

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            digest,
            sizeof(digest),
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_OK);
    assert(written == sizeof(encoded));
    assert((encoded[0] == 0x00U) && (encoded[1] == 0x03U));
    assert(memcmp(encoded + 2U, digest, sizeof(digest)) == 0);
}

static void multihash_unit_fill_sha2_digest(uint8_t digest[32])
{
    size_t index = 0U;

    for (index = 0U; index < 32U; index++)
    {
        digest[index] = (uint8_t)(index + 1U);
    }
}

static void multihash_unit_test_sha2_256_round_trip(void)
{
    uint8_t digest_bytes[32];
    uint8_t encoded[34];
    uint64_t code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t digest_len = 0U;
    size_t read = 0U;
    size_t written = 0U;
    size_t size = 0U;

    multihash_unit_fill_sha2_digest(digest_bytes);

    assert(
        libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_SHA2_256, sizeof(digest_bytes), &size) ==
        LIBP2P_MULTIHASH_OK);
    assert(size == sizeof(encoded));

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_SHA2_256,
            digest_bytes,
            sizeof(digest_bytes),
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_OK);
    assert(written == sizeof(encoded));
    assert((encoded[0] == 0x12U) && (encoded[1] == 0x20U));
    assert(memcmp(encoded + 2U, digest_bytes, sizeof(digest_bytes)) == 0);

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
        LIBP2P_MULTIHASH_OK);
    assert(code == LIBP2P_MULTIHASH_CODE_SHA2_256);
    assert(digest == (encoded + 2U));
    assert(digest_len == sizeof(digest_bytes));
    assert(read == sizeof(encoded));
    assert(memcmp(digest, digest_bytes, sizeof(digest_bytes)) == 0);
}

static void multihash_unit_test_encode_off_by_one_buffer(void)
{
    const uint8_t digest[] = {0xffU};
    uint8_t encoded[2] = {0U, 0U};
    size_t written = 0U;

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            digest,
            sizeof(digest),
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL);
    assert(written == 3U);
}

static void multihash_unit_test_encode_unsupported_code(void)
{
    const uint8_t digest[20] = {0U};
    uint8_t encoded[32] = {0U};
    size_t written = 99U;
    size_t size = 99U;

    assert(
        libp2p_multihash_size(UINT64_C(0x11), sizeof(digest), &size) ==
        LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE);
    assert(size == 0U);

    assert(
        libp2p_multihash_encode(
            UINT64_C(0x11),
            digest,
            sizeof(digest),
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE);
    assert(written == 0U);
}

static void multihash_unit_test_digest_size_mismatch(void)
{
    uint8_t digest[31];
    uint8_t encoded[64] = {0U};
    size_t written = 99U;
    size_t size = 99U;

    (void)memset(digest, 0x5a, sizeof(digest));

    assert(
        libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_SHA2_256, sizeof(digest), &size) ==
        LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH);
    assert(size == 0U);

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_SHA2_256,
            digest,
            sizeof(digest),
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH);
    assert(written == 0U);
}

static void multihash_unit_test_null_digest_with_nonzero_length(void)
{
    uint8_t encoded[8] = {0U};
    size_t written = 99U;

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            NULL,
            1U,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH);
    assert(written == 0U);
}

static void multihash_unit_test_decode_unsupported_code(void)
{
    uint8_t encoded[22];
    uint64_t code = UINT64_C(7);
    const uint8_t *digest = encoded;
    size_t digest_len = 77U;
    size_t read = 77U;

    encoded[0] = 0x11U;
    encoded[1] = 0x14U;
    (void)memset(encoded + 2U, 0xa5, sizeof(encoded) - 2U);

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
        LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE);
    assert(code == 0U);
    assert(digest == NULL);
    assert(digest_len == 0U);
    assert(read == 0U);
}

static void multihash_unit_test_invalid_varint_non_minimal(void)
{
    const uint8_t encoded[] = {0x81U, 0x00U, 0x00U};
    uint64_t code = UINT64_C(99);
    const uint8_t *digest = encoded;
    size_t digest_len = 99U;
    size_t read = 99U;
    size_t digest_offset = 99U;

    assert(
        libp2p_multihash_read_header(
            encoded,
            sizeof(encoded),
            &code,
            &digest_len,
            &digest_offset) == LIBP2P_MULTIHASH_ERR_INVALID_VARINT);
    assert(code == 0U);
    assert(digest_len == 0U);
    assert(digest_offset == 0U);

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), &code, &digest, &digest_len, &read) ==
        LIBP2P_MULTIHASH_ERR_INVALID_VARINT);
}

static void multihash_unit_test_invalid_varint_overflow(void)
{
    const uint8_t encoded[] =
        {0x00U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U};
    size_t digest_len = 99U;
    size_t digest_offset = 99U;

    assert(
        libp2p_multihash_read_header(encoded, sizeof(encoded), NULL, &digest_len, &digest_offset) ==
        LIBP2P_MULTIHASH_ERR_INVALID_VARINT);
    assert(digest_len == 0U);
    assert(digest_offset == 0U);
}

static void multihash_unit_test_truncated_header(void)
{
    const uint8_t encoded[] = {0x00U};
    uint64_t code = UINT64_C(99);
    size_t digest_len = 99U;
    size_t digest_offset = 99U;
    size_t read = 99U;

    assert(
        libp2p_multihash_read_header(
            encoded,
            sizeof(encoded),
            &code,
            &digest_len,
            &digest_offset) == LIBP2P_MULTIHASH_ERR_TRUNCATED);
    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), &code, NULL, &digest_len, &read) ==
        LIBP2P_MULTIHASH_ERR_TRUNCATED);
}

static void multihash_unit_test_truncated_digest(void)
{
    const uint8_t encoded[] = {0x00U, 0x03U, 0xaaU, 0xbbU};

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), NULL, NULL, NULL, NULL) ==
        LIBP2P_MULTIHASH_ERR_TRUNCATED);
}

static void multihash_unit_test_decode_digest_size_mismatch(void)
{
    uint8_t encoded[33];

    encoded[0] = 0x12U;
    encoded[1] = 0x1fU;
    (void)memset(encoded + 2U, 0x11, sizeof(encoded) - 2U);

    assert(
        libp2p_multihash_decode(encoded, sizeof(encoded), NULL, NULL, NULL, NULL) ==
        LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH);
}

static void multihash_unit_test_read_header_success(void)
{
    const uint8_t encoded[] = {0x00U, 0x03U, 0xaaU, 0xbbU, 0xccU};
    uint64_t code = UINT64_C(0);
    size_t digest_len = 0U;
    size_t digest_offset = 0U;

    assert(
        libp2p_multihash_read_header(
            encoded,
            sizeof(encoded),
            &code,
            &digest_len,
            &digest_offset) == LIBP2P_MULTIHASH_OK);
    assert(code == LIBP2P_MULTIHASH_CODE_IDENTITY);
    assert(digest_len == 3U);
    assert(digest_offset == 2U);
}

static void multihash_unit_test_size_with_null_output(void)
{
    assert(libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, 0U, NULL) == LIBP2P_MULTIHASH_OK);
}

int main(void)
{
    multihash_unit_test_identity_empty_round_trip();
    multihash_unit_test_measure_then_write_identity();
    multihash_unit_test_sha2_256_round_trip();
    multihash_unit_test_encode_off_by_one_buffer();
    multihash_unit_test_encode_unsupported_code();
    multihash_unit_test_digest_size_mismatch();
    multihash_unit_test_null_digest_with_nonzero_length();
    multihash_unit_test_decode_unsupported_code();
    multihash_unit_test_invalid_varint_non_minimal();
    multihash_unit_test_invalid_varint_overflow();
    multihash_unit_test_truncated_header();
    multihash_unit_test_truncated_digest();
    multihash_unit_test_decode_digest_size_mismatch();
    multihash_unit_test_read_header_success();
    multihash_unit_test_size_with_null_output();
    return 0;
}
