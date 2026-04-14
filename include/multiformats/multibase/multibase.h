/**
 * @file multibase.h
 * @brief Self-identifying base encodings.
 *
 * Encodes and decodes binary data as text with a prefix character identifying
 * the encoding base.
 *
 * Supported bases (subset for c-lean-libp2p):
 *   - base58btc  ('z') — Bitcoin base58, used for legacy peer IDs
 *   - base64url  ('u') — RFC4648 URL-safe base64, no padding
 *
 * @see https://github.com/multiformats/multibase
 */

#ifndef LIBP2P_MULTIBASE_H
#define LIBP2P_MULTIBASE_H

#include <stddef.h>
#include <stdint.h>

/** Supported multibase encodings. */
typedef enum
{
    LIBP2P_MULTIBASE_BASE58BTC,
    LIBP2P_MULTIBASE_BASE64URL
} libp2p_multibase_t;

/** Error codes returned by multibase operations. */
typedef enum
{
    LIBP2P_MULTIBASE_OK,
    LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL,
    LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE,
    LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX,
    LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER,
    LIBP2P_MULTIBASE_ERR_INVALID_LENGTH,
    LIBP2P_MULTIBASE_ERR_EMPTY_INPUT
} libp2p_multibase_err_t;

/**
 * Encode bytes as multibase text with the base prefix character.
 *
 * @param[in]  base     Encoding base.
 * @param[in]  in       Source bytes.
 * @param[in]  in_len   Length of in in bytes.
 * @param[out] out      Destination text buffer.
 * @param[in]  out_len  Size of out in characters.
 * @param[out] written  Characters written, or required size on
 *                      LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIBASE_OK on success.
 */
libp2p_multibase_err_t libp2p_multibase_encode(
    libp2p_multibase_t base,
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written);

/**
 * Decode multibase text into bytes, inferring the base from the prefix.
 *
 * Rejects reserved prefix code points (NUL, '/', '1', 'Q') with
 * LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX.
 *
 * @param[in]  in       Source text (includes prefix character).
 * @param[in]  in_len   Length of in in characters.
 * @param[out] base     Detected encoding base.
 * @param[out] out      Destination bytes buffer.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required upper bound on
 *                      LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIBASE_OK on success.
 */
libp2p_multibase_err_t libp2p_multibase_decode(
    const char *in,
    size_t in_len,
    libp2p_multibase_t *base,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Compute the exact buffer size needed to encode in_len bytes in a given base,
 * including the prefix character.
 *
 * @param[in]  base     Encoding base.
 * @param[in]  in_len   Number of input bytes.
 * @param[out] out_len  Required size of the encoded text in characters.
 * @return LIBP2P_MULTIBASE_OK on success,
 *         LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE if base is invalid.
 */
libp2p_multibase_err_t libp2p_multibase_encoded_size(
    libp2p_multibase_t base,
    size_t in_len,
    size_t *out_len);

/**
 * Compute an upper bound on the byte length produced by decoding text_len
 * characters (excluding the prefix) in a given base.
 *
 * @param[in]  base      Encoding base.
 * @param[in]  text_len  Number of encoded characters, excluding the prefix.
 * @param[out] out_len   Upper bound on decoded size in bytes.
 * @return LIBP2P_MULTIBASE_OK on success,
 *         LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE if base is invalid.
 */
libp2p_multibase_err_t libp2p_multibase_max_decoded_size(
    libp2p_multibase_t base,
    size_t text_len,
    size_t *out_len);

#endif /* LIBP2P_MULTIBASE_H */
