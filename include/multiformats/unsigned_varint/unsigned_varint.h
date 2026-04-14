/**
 * @file unsigned_varint.h
 * @brief Unsigned variable-length integer encoding (LEB128 variant).
 *
 * Implements the multiformats unsigned-varint spec:
 *   - Unsigned integers serialized 7 bits at a time, LSB first
 *   - MSB of each byte is a continuation flag
 *   - Minimally encoded (no leading zero bytes)
 *   - Maximum 9 bytes (63 bits)
 *
 * @see https://github.com/multiformats/unsigned-varint
 */

#ifndef LIBP2P_UNSIGNED_VARINT_H
#define LIBP2P_UNSIGNED_VARINT_H

#include <stddef.h>
#include <stdint.h>

/** Maximum number of bytes in an encoded unsigned varint. */
#define LIBP2P_UVARINT_MAX_BYTES 9U

/** Error codes returned by unsigned varint operations. */
typedef enum
{
    LIBP2P_UVARINT_OK,
    LIBP2P_UVARINT_ERR_BUF_TOO_SMALL,
    LIBP2P_UVARINT_ERR_OVERFLOW,
    LIBP2P_UVARINT_ERR_NON_MINIMAL,
    LIBP2P_UVARINT_ERR_TRUNCATED
} libp2p_uvarint_err_t;

/**
 * Encode a uint64 value as an unsigned varint.
 *
 * @param[in]  value    Value to encode.
 * @param[out] buf      Destination buffer.
 * @param[in]  buf_len  Size of destination buffer in bytes.
 * @param[out] written  Number of bytes written to buf.
 * @return LIBP2P_UVARINT_OK on success,
 *         LIBP2P_UVARINT_ERR_BUF_TOO_SMALL if buf_len is insufficient.
 */
libp2p_uvarint_err_t libp2p_uvarint_encode(
    uint64_t value,
    uint8_t *buf,
    size_t buf_len,
    size_t *written);

/**
 * Decode an unsigned varint from a byte buffer.
 *
 * @param[in]  buf      Source buffer.
 * @param[in]  buf_len  Size of source buffer in bytes.
 * @param[out] value    Decoded value.
 * @param[out] read     Number of bytes consumed from buf.
 * @return LIBP2P_UVARINT_OK on success,
 *         LIBP2P_UVARINT_ERR_TRUNCATED if continuation bit set on last byte,
 *         LIBP2P_UVARINT_ERR_OVERFLOW if encoding exceeds 9 bytes / 63 bits,
 *         LIBP2P_UVARINT_ERR_NON_MINIMAL if encoding has trailing zero bytes.
 */
libp2p_uvarint_err_t libp2p_uvarint_decode(
    const uint8_t *buf,
    size_t buf_len,
    uint64_t *value,
    size_t *read);

/**
 * Return the number of bytes needed to encode a value.
 *
 * @param[in] value  Value to measure.
 * @return Encoded size in bytes (1--9).
 */
uint8_t libp2p_uvarint_size(uint64_t value);

#endif /* LIBP2P_UNSIGNED_VARINT_H */
