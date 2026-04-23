/**
 * @file peer_id.h
 * @brief secp256k1 key handling and peer ID operations.
 *
 * This c-lean-libp2p subset is secp256k1-only. It owns the secp256k1 key
 * lifecycle needed by peer IDs:
 *   - deterministic libp2p PublicKey / PrivateKey protobuf encoding
 *   - public-key derivation from a caller-supplied 32-byte secret
 *   - message signing and signature verification
 *   - secret buffer zeroization for caller-managed sensitive bytes
 *   - peer ID derivation, text parsing/formatting, and public-key extraction
 *
 * No other key types are modeled here. Ed25519, RSA, ECDSA, generic key-type
 * enums, and key generation are intentionally out of scope for this header.
 * Callers supply secp256k1 private key material as raw 32-byte secret bytes.
 *
 * The peer-id spec requires secp256k1 signatures to hash the message with
 * SHA-256, sign the 32-byte digest with the standard Bitcoin EC signature
 * algorithm, and encode the signature using standard Bitcoin DER encoding.
 * This header therefore exposes both:
 *   - raw secp256k1 ECDSA over 32-byte message hashes
 *   - spec-level message signing / verification that performs the SHA-256 step
 *
 * Peer IDs are derived from the deterministically encoded secp256k1 PublicKey
 * protobuf. Keys that encode to at most 42 bytes use the identity multihash;
 * longer encodings use sha2-256.
 *
 * @see https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
 */

#ifndef LIBP2P_PEER_ID_H
#define LIBP2P_PEER_ID_H

#include <stddef.h>
#include <stdint.h>

/** Raw secp256k1 private key size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES 32U

/** Compressed secp256k1 public key size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES 33U

/** Uncompressed secp256k1 public key size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES 65U

/** Exact encoded secp256k1 PrivateKey protobuf size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_MESSAGE_BYTES 36U

/** Maximum encoded secp256k1 PublicKey protobuf size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES 69U

/** SHA-256 digest size in bytes. */
#define LIBP2P_PEER_ID_SHA2_256_BYTES 32U

/** Maximum DER-encoded secp256k1 signature size in bytes. */
#define LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES 72U

/** Maximum encoded PublicKey size that may be inlined in an identity peer ID. */
#define LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES 42U

/** Maximum binary peer ID size in bytes for the secp256k1 subset. */
#define LIBP2P_PEER_ID_MAX_BYTES 39U

/** Error codes returned by peer_id operations. */
typedef enum
{
    LIBP2P_PEER_ID_OK,
    LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL,
    LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY,
    LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY,
    LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING,
    LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH,
    LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE,
    LIBP2P_PEER_ID_ERR_INVALID_PEER_ID,
    LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING,
    LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY
} libp2p_peer_id_err_t;

/**
 * Overwrite a caller-supplied byte buffer with zeros.
 *
 * This helper is intended for secrets held in caller-managed buffers, such as
 * private keys, derived secrets, and intermediate hashes. The implementation
 * uses volatile byte stores so the compiler cannot remove the writes as dead
 * stores.
 *
 * Passing a NULL buffer with len equal to 0 is a no-op.
 *
 * @param[in,out] buf  Buffer to overwrite with zeros.
 * @param[in]     len  Number of bytes to clear.
 */
static inline void libp2p_peer_id_zeroize(uint8_t *buf, size_t len)
{
    if (buf != NULL)
    {
        volatile uint8_t *data = buf;

        for (size_t index = 0U; index < len; index++)
        {
            data[index] = 0U;
        }
    }
}

/**
 * Return the exact encoded size of a secp256k1 PublicKey protobuf message.
 *
 * Accepts compressed or uncompressed standard Bitcoin EC public key encodings.
 *
 * @param[in]  public_key_len  Raw public key length in bytes.
 * @param[out] out_len         Exact encoded PublicKey protobuf size in bytes.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if public_key_len is not a
 *         supported secp256k1 public key length.
 */
libp2p_peer_id_err_t libp2p_peer_id_public_key_encoded_size(
    size_t public_key_len,
    size_t *out_len);

/**
 * Encode raw secp256k1 public key bytes as a deterministic libp2p PublicKey
 * protobuf message.
 *
 * @param[in]  public_key      Raw secp256k1 public key bytes.
 * @param[in]  public_key_len  Raw public key length in bytes.
 * @param[out] out             Destination buffer.
 * @param[in]  out_len         Size of out in bytes.
 * @param[out] written         Bytes written, or required size on
 *                             LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if the public key encoding is
 *         outside the secp256k1 subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_public_key_encode(
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode a deterministic libp2p PublicKey protobuf message into raw secp256k1
 * public key bytes.
 *
 * @param[in]  in       Encoded PublicKey protobuf bytes.
 * @param[in]  in_len   Length of in in bytes.
 * @param[out] out      Destination buffer for raw public key bytes.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING on malformed protobuf bytes,
 *         LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING if the key type is not the
 *         secp256k1 subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_public_key_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Encode a raw 32-byte secp256k1 private key as a deterministic libp2p
 * PrivateKey protobuf message.
 *
 * No key generation is performed; callers supply the secret bytes.
 *
 * @param[in]  private_key      Raw 32-byte secp256k1 secret.
 * @param[in]  private_key_len  Length of private_key in bytes.
 * @param[out] out              Destination buffer.
 * @param[in]  out_len          Size of out in bytes.
 * @param[out] written          Bytes written, or required size on
 *                              LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY if the secret length is
 *         invalid for the secp256k1 subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_private_key_encode(
    const uint8_t *private_key,
    size_t private_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode a deterministic libp2p PrivateKey protobuf message into raw 32-byte
 * secp256k1 private key bytes.
 *
 * @param[in]  in       Encoded PrivateKey protobuf bytes.
 * @param[in]  in_len   Length of in in bytes.
 * @param[out] out      Destination buffer for raw private key bytes.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING on malformed protobuf bytes,
 *         LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING if the key type is not the
 *         secp256k1 subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_private_key_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Derive a secp256k1 public key from a raw 32-byte private key.
 *
 * @param[in]  private_key      Raw 32-byte secp256k1 secret.
 * @param[in]  private_key_len  Length of private_key in bytes.
 * @param[in]  compressed       Non-zero for compressed public key output,
 *                              zero for uncompressed output.
 * @param[out] out              Destination buffer for raw public key bytes.
 * @param[in]  out_len          Size of out in bytes.
 * @param[out] written          Bytes written, or required size on
 *                              LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY if the secret is invalid for
 *         secp256k1.
 */
libp2p_peer_id_err_t libp2p_peer_id_public_key_from_private_key(
    const uint8_t *private_key,
    size_t private_key_len,
    int compressed,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Sign a 32-byte message hash with a secp256k1 private key.
 *
 * The signature is returned in standard Bitcoin DER encoding.
 *
 * @param[in]  private_key       Raw 32-byte secp256k1 secret.
 * @param[in]  private_key_len   Length of private_key in bytes.
 * @param[in]  message_hash      32-byte message hash.
 * @param[in]  message_hash_len  Length of message_hash in bytes.
 * @param[out] out               Destination buffer for the DER-encoded
 *                               signature.
 * @param[in]  out_len           Size of out in bytes.
 * @param[out] written           Bytes written, or required size on
 *                               LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY if the secret is invalid,
 *         LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH if message_hash_len is not
 *         32.
 */
libp2p_peer_id_err_t libp2p_peer_id_sign_hash(
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *message_hash,
    size_t message_hash_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Verify a DER-encoded secp256k1 signature over a 32-byte message hash.
 *
 * @param[in] public_key        Raw secp256k1 public key bytes.
 * @param[in] public_key_len    Length of public_key in bytes.
 * @param[in] message_hash      32-byte message hash.
 * @param[in] message_hash_len  Length of message_hash in bytes.
 * @param[in] signature         DER-encoded signature bytes.
 * @param[in] signature_len     Length of signature in bytes.
 * @return LIBP2P_PEER_ID_OK on successful verification,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if the public key encoding is
 *         invalid,
 *         LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH if message_hash_len is not
 *         32,
 *         LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE if the signature is malformed or
 *         does not verify.
 */
libp2p_peer_id_err_t libp2p_peer_id_verify_hash(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message_hash,
    size_t message_hash_len,
    const uint8_t *signature,
    size_t signature_len);

/**
 * Sign a message using the secp256k1 procedure required by the peer-id spec.
 *
 * The message is first hashed with SHA-256. The resulting 32-byte digest is
 * then signed using secp256k1 ECDSA and encoded using standard Bitcoin DER
 * encoding.
 *
 * @param[in]  private_key       Raw 32-byte secp256k1 secret.
 * @param[in]  private_key_len   Length of private_key in bytes.
 * @param[in]  message           Message bytes to hash and sign.
 * @param[in]  message_len       Length of message in bytes.
 * @param[out] out               Destination buffer for the DER-encoded
 *                               signature.
 * @param[in]  out_len           Size of out in bytes.
 * @param[out] written           Bytes written, or required size on
 *                               LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY if the secret is invalid.
 */
libp2p_peer_id_err_t libp2p_peer_id_sign_message(
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Verify a secp256k1 signature using the message-signing procedure required by
 * the peer-id spec.
 *
 * The message is hashed with SHA-256 before signature verification.
 *
 * @param[in] public_key      Raw secp256k1 public key bytes.
 * @param[in] public_key_len  Length of public_key in bytes.
 * @param[in] message         Message bytes to hash and verify.
 * @param[in] message_len     Length of message in bytes.
 * @param[in] signature       DER-encoded signature bytes.
 * @param[in] signature_len   Length of signature in bytes.
 * @return LIBP2P_PEER_ID_OK on successful verification,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if the public key encoding is
 *         invalid,
 *         LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE if the signature is malformed or
 *         does not verify.
 */
libp2p_peer_id_err_t libp2p_peer_id_verify_message(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len);

/**
 * Return the exact binary peer ID size for a secp256k1 public key length.
 *
 * The length determines whether the peer ID will use the identity multihash or
 * sha2-256 after deterministic libp2p PublicKey protobuf encoding.
 *
 * @param[in]  public_key_len  Raw public key length in bytes.
 * @param[out] out_len         Exact peer ID size in bytes.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if public_key_len is not a
 *         supported secp256k1 public key length.
 */
libp2p_peer_id_err_t libp2p_peer_id_size_from_secp256k1_public_key(
    size_t public_key_len,
    size_t *out_len);

/**
 * Derive a binary peer ID from a secp256k1 public key.
 *
 * Accepts compressed or uncompressed standard Bitcoin EC public key encodings.
 * When out is NULL or too small, returns
 * LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL and stores the exact required size in
 * written.
 *
 * @param[in]  public_key      Raw secp256k1 public key bytes.
 * @param[in]  public_key_len  Raw public key length in bytes.
 * @param[out] out             Destination buffer for the binary peer ID.
 * @param[in]  out_len         Size of out in bytes.
 * @param[out] written         Bytes written, or required size on
 *                             LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY if the public key encoding is
 *         outside the secp256k1 subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_from_secp256k1_public_key(
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Parse peer ID text into its binary multihash representation.
 *
 * Accepts the legacy raw base58btc multihash form and the CIDv1 `libp2p-key`
 * form when its multibase encoding is supported by the c-lean-libp2p
 * multibase subset.
 *
 * @param[in]  in       Source text (not required to be NUL-terminated).
 * @param[in]  in_len   Length of in in characters.
 * @param[out] out      Destination buffer for the binary peer ID.
 * @param[in]  out_len  Size of out in bytes.
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PEER_ID on malformed text or malformed
 *         decoded peer ID bytes,
 *         LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING if the text uses a CID or
 *         multibase form outside the supported subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_from_string(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Format a binary peer ID as legacy base58btc text.
 *
 * Output is not NUL-terminated. This secp256k1 subset deliberately omits a
 * separate CID text formatter and uses the legacy display form.
 *
 * @param[in]  peer_id       Binary peer ID bytes.
 * @param[in]  peer_id_len   Length of peer_id in bytes.
 * @param[out] out           Destination text buffer.
 * @param[in]  out_len       Size of out in characters.
 * @param[out] written       Characters written, or required size on
 *                           LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PEER_ID if peer_id is malformed,
 *         LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING if peer_id is outside the
 *         supported multihash subset.
 */
libp2p_peer_id_err_t libp2p_peer_id_to_string(
    const uint8_t *peer_id,
    size_t peer_id_len,
    char *out,
    size_t out_len,
    size_t *written);

/**
 * Recover the secp256k1 public key bytes from an identity-backed peer ID.
 *
 * This succeeds only when the peer ID inlines the deterministic secp256k1
 * PublicKey protobuf through the identity multihash. Peer IDs backed by
 * sha2-256 cannot be reversed and return
 * LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY.
 *
 * @param[in]  peer_id       Binary peer ID bytes.
 * @param[in]  peer_id_len   Length of peer_id in bytes.
 * @param[out] out           Destination buffer for raw secp256k1 public key
 *                           bytes.
 * @param[in]  out_len       Size of out in bytes.
 * @param[out] written       Bytes written, or required size on
 *                           LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL.
 * @return LIBP2P_PEER_ID_OK on success,
 *         LIBP2P_PEER_ID_ERR_INVALID_PEER_ID if peer_id is malformed,
 *         LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY if peer_id does not inline
 *         the public key.
 */
libp2p_peer_id_err_t libp2p_peer_id_extract_secp256k1_public_key(
    const uint8_t *peer_id,
    size_t peer_id_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

#endif /* LIBP2P_PEER_ID_H */
