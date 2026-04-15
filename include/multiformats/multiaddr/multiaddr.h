/**
 * @file multiaddr.h
 * @brief Composable network addresses.
 *
 * A binary multiaddr is a sequence of components where each component is:
 *
 *   <varint protocol-code><value bytes>
 *
 * Variable-size values are length-prefixed with a uvarint. Human-readable
 * multiaddrs use the form (/<protoName>/<value>)+.
 *
 * Supported protocols (subset for c-lean-libp2p):
 *   - /ip4     (fixed 4-byte IPv4 address)
 *   - /ip6     (fixed 16-byte IPv6 address)
 *   - /udp     (fixed 2-byte big-endian port)
 *   - /quic-v1 (no value)
 *   - /p2p     (length-prefixed multihash peer ID)
 *
 * @see https://github.com/multiformats/multiaddr
 */

#ifndef LIBP2P_MULTIADDR_H
#define LIBP2P_MULTIADDR_H

#include <stddef.h>
#include <stdint.h>

/** Multiaddr protocol codes (supported subset). */
#define LIBP2P_MULTIADDR_CODE_IP4     UINT64_C(0x04)
#define LIBP2P_MULTIADDR_CODE_IP6     UINT64_C(0x29)
#define LIBP2P_MULTIADDR_CODE_UDP     UINT64_C(0x0111)
#define LIBP2P_MULTIADDR_CODE_P2P     UINT64_C(0x01a5)
#define LIBP2P_MULTIADDR_CODE_QUIC_V1 UINT64_C(0x01cd)

/** Value-size class for a multiaddr protocol. */
typedef enum
{
    LIBP2P_MULTIADDR_VALUE_NONE,    /**< Zero-length value (e.g., /quic-v1). */
    LIBP2P_MULTIADDR_VALUE_FIXED,   /**< Fixed-size value (e.g., /ip4, /udp). */
    LIBP2P_MULTIADDR_VALUE_VARIABLE /**< uvarint-length-prefixed value (e.g., /p2p). */
} libp2p_multiaddr_value_class_t;

/** Error codes returned by multiaddr operations. */
typedef enum
{
    LIBP2P_MULTIADDR_OK,
    LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL,
    LIBP2P_MULTIADDR_ERR_MALFORMED,
    LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
    LIBP2P_MULTIADDR_ERR_INVALID_VALUE,
    LIBP2P_MULTIADDR_ERR_TRUNCATED,
    LIBP2P_MULTIADDR_ERR_NOT_FOUND,
    LIBP2P_MULTIADDR_ERR_END
} libp2p_multiaddr_err_t;

/** Cursor for iterating components of a binary multiaddr. */
typedef struct
{
    const uint8_t *buf;
    size_t buf_len;
    size_t offset;
} libp2p_multiaddr_cursor_t;

/**
 * Verify that a binary multiaddr is well-formed.
 *
 * Checks component boundaries, length prefixes, known protocol codes, and
 * legal value sizes for each protocol.
 *
 * @param[in] buf      Binary multiaddr buffer.
 * @param[in] buf_len  Size of buf in bytes.
 * @return LIBP2P_MULTIADDR_OK if well-formed,
 *         LIBP2P_MULTIADDR_ERR_MALFORMED on structural errors,
 *         LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL for unknown protocol codes,
 *         LIBP2P_MULTIADDR_ERR_TRUNCATED if buf ends mid-component.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_validate(const uint8_t *buf, size_t buf_len);

/**
 * Advance a cursor to the next protocol component.
 *
 * Callers initialize the cursor as
 *   { .buf = bytes, .buf_len = len, .offset = 0 }.
 * Returns LIBP2P_MULTIADDR_ERR_END when no more components remain.
 *
 * @param[in,out] cursor     Iteration cursor.
 * @param[out]    code       Protocol code of the yielded component.
 * @param[out]    value      Pointer into cursor->buf where the value begins.
 * @param[out]    value_len  Length of the value in bytes.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_END if cursor has reached the buffer end,
 *         LIBP2P_MULTIADDR_ERR_MALFORMED or ERR_TRUNCATED on structural errors.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_next_component(
    libp2p_multiaddr_cursor_t *cursor,
    uint64_t *code,
    const uint8_t **value,
    size_t *value_len);

/**
 * Append one protocol component to a binary multiaddr buffer.
 *
 * The protocol's value-size class determines whether value is length-prefixed.
 *
 * @param[in]     code       Protocol code.
 * @param[in]     value      Value bytes (may be NULL when value_len is 0).
 * @param[in]     value_len  Length of value in bytes.
 * @param[in,out] buf        Destination buffer.
 * @param[in]     buf_len    Total capacity of buf.
 * @param[in,out] pos        On entry, current write position. On success,
 *                           updated to the new position. On
 *                           LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL, set to the
 *                           position that would be reached after a
 *                           successful write.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL if code is unknown,
 *         LIBP2P_MULTIADDR_ERR_INVALID_VALUE if value_len is illegal for code.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_append_component(
    uint64_t code,
    const uint8_t *value,
    size_t value_len,
    uint8_t *buf,
    size_t buf_len,
    size_t *pos);

/**
 * Append one binary multiaddr onto another.
 *
 * @param[in]  a        First multiaddr bytes.
 * @param[in]  a_len    Length of a in bytes.
 * @param[in]  b        Second multiaddr bytes.
 * @param[in]  b_len    Length of b in bytes.
 * @param[out] out      Destination buffer.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIADDR_OK on success.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_encapsulate(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Remove the suffix starting at the last occurrence of an inner multiaddr.
 *
 * The match is component-boundary aligned. If inner does not occur in outer
 * on a component boundary, returns LIBP2P_MULTIADDR_ERR_NOT_FOUND.
 *
 * @param[in]  outer      Outer multiaddr bytes.
 * @param[in]  outer_len  Length of outer in bytes.
 * @param[in]  inner      Inner multiaddr bytes to strip.
 * @param[in]  inner_len  Length of inner in bytes.
 * @param[out] out        Destination buffer.
 * @param[in]  out_len    Size of out in bytes.
 * @param[out] written    Bytes written, or required size on
 *                        LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_NOT_FOUND if inner is not a boundary-aligned
 *         suffix of outer.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_decapsulate(
    const uint8_t *outer,
    size_t outer_len,
    const uint8_t *inner,
    size_t inner_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Look up name and value-size class for a multiaddr protocol code.
 *
 * @param[in]  code         Protocol code.
 * @param[out] name         Pointer to a static NUL-terminated protocol name.
 * @param[out] value_class  Value-size class (none, fixed, or variable).
 * @param[out] fixed_size   For LIBP2P_MULTIADDR_VALUE_FIXED, the exact value
 *                          size in bytes. Set to 0 otherwise.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL if code is unknown.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_protocol_info(
    uint64_t code,
    const char **name,
    libp2p_multiaddr_value_class_t *value_class,
    size_t *fixed_size);

/**
 * Parse a human-readable multiaddr string into its binary representation.
 *
 * Canonicalizes the legacy `/ipfs/...` alias to `/p2p/...`.
 *
 * @param[in]  in       Source text (not required to be NUL-terminated).
 * @param[in]  in_len   Length of in in characters.
 * @param[out] out      Destination buffer.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_MALFORMED on syntax errors,
 *         LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL on unknown protocol names,
 *         LIBP2P_MULTIADDR_ERR_INVALID_VALUE on malformed values.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_from_string(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Format a binary multiaddr into its human-readable string form.
 *
 * Output is NOT NUL-terminated.
 *
 * @param[in]  in       Binary multiaddr bytes.
 * @param[in]  in_len   Length of in in bytes.
 * @param[out] out      Destination text buffer.
 * @param[in]  out_len  Size of out in characters.
 * @param[out] written  Characters written, or required size on
 *                      LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_MULTIADDR_OK on success,
 *         LIBP2P_MULTIADDR_ERR_MALFORMED or ERR_TRUNCATED on invalid input,
 *         LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL on unknown protocol codes.
 */
libp2p_multiaddr_err_t libp2p_multiaddr_to_string(
    const uint8_t *in,
    size_t in_len,
    char *out,
    size_t out_len,
    size_t *written);

#endif /* LIBP2P_MULTIADDR_H */
