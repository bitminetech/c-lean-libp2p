/**
 * @file multihash.h
 * @brief Self-identifying cryptographic hash values.
 *
 * A multihash is a byte sequence of the form:
 *
 *   <varint hash-function code><varint digest size><digest bytes>
 *
 * Supported hash codes (subset for c-lean-libp2p):
 *   - identity (0x00) — raw bytes, used for libp2p peer IDs with keys <= 42 bytes
 *   - sha2-256 (0x12) — SHA-256
 *
 * @see https://github.com/multiformats/multihash
 */

#ifndef LIBP2P_MULTIHASH_H
#define LIBP2P_MULTIHASH_H

#include <stddef.h>
#include <stdint.h>

/** Identity multihash code. */
#define LIBP2P_MULTIHASH_CODE_IDENTITY 0x00U

/** sha2-256 multihash code. */
#define LIBP2P_MULTIHASH_CODE_SHA2_256 0x12U

/** Error codes returned by multihash operations. */
typedef enum
{
    LIBP2P_MULTIHASH_OK,
    LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL,
    LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE,
    LIBP2P_MULTIHASH_ERR_INVALID_VARINT,
    LIBP2P_MULTIHASH_ERR_TRUNCATED,
    LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH
} libp2p_multihash_err_t;

/**
 * Encode a hash code and digest into a multihash byte sequence.
 *
 * @param[in]  code        Multihash code (e.g., LIBP2P_MULTIHASH_CODE_SHA2_256).
 * @param[in]  digest      Digest bytes.
 * @param[in]  digest_len  Length of digest in bytes.
 * @param[out] out         Destination buffer.
 * @param[in]  out_len     Size of out in bytes.
 * @param[out] written     Bytes written, or required size on
 *                         LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIHASH_OK on success,
 *         LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE if code is not in the supported subset,
 *         LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH if digest_len is invalid for code.
 */
libp2p_multihash_err_t libp2p_multihash_encode(
    uint64_t code,
    const uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode a multihash byte sequence.
 *
 * @param[in]  in          Source buffer.
 * @param[in]  in_len      Size of in in bytes.
 * @param[out] code        Hash function code.
 * @param[out] digest      Pointer into in where the digest begins.
 * @param[out] digest_len  Digest size in bytes.
 * @param[out] read        Total bytes consumed (header + digest).
 * @return LIBP2P_MULTIHASH_OK on success,
 *         LIBP2P_MULTIHASH_ERR_INVALID_VARINT if code or size varint is malformed,
 *         LIBP2P_MULTIHASH_ERR_TRUNCATED if declared digest extends past in,
 *         LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE if code is not in the supported subset.
 */
libp2p_multihash_err_t libp2p_multihash_decode(
    const uint8_t *in,
    size_t in_len,
    uint64_t *code,
    const uint8_t **digest,
    size_t *digest_len,
    size_t *read);

/**
 * Parse only the hash code and digest size fields of a multihash.
 *
 * @param[in]  in             Source buffer.
 * @param[in]  in_len         Size of in in bytes.
 * @param[out] code           Hash function code.
 * @param[out] digest_len     Digest size in bytes.
 * @param[out] digest_offset  Byte offset into in where the digest begins.
 * @return LIBP2P_MULTIHASH_OK on success,
 *         LIBP2P_MULTIHASH_ERR_INVALID_VARINT if either varint is malformed,
 *         LIBP2P_MULTIHASH_ERR_TRUNCATED if in ends mid-header.
 */
libp2p_multihash_err_t libp2p_multihash_read_header(
    const uint8_t *in,
    size_t in_len,
    uint64_t *code,
    size_t *digest_len,
    size_t *digest_offset);

/**
 * Return the exact encoded size for a given hash code and digest length.
 *
 * @param[in]  code        Multihash code.
 * @param[in]  digest_len  Length of digest in bytes.
 * @param[out] out_len     Total encoded size in bytes.
 * @return LIBP2P_MULTIHASH_OK on success,
 *         LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE if code is not in the supported subset.
 */
libp2p_multihash_err_t libp2p_multihash_size(uint64_t code, size_t digest_len, size_t *out_len);

#endif /* LIBP2P_MULTIHASH_H */
