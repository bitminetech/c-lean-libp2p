/**
 * @file quic_identity.h
 * @brief libp2p TLS identity binding for the mandatory QUIC transport.
 *
 * libp2p QUIC uses TLS 1.3 with ALPN "libp2p". The peer's libp2p identity is
 * authenticated by a certificate extension that carries the host public key and
 * a signature over the TLS certificate public key. This header owns that
 * libp2p-specific contract; AWS-LC remains an implementation detail.
 *
 * This version of the libp2p TLS handshake does not use SNI. Clients must not
 * send SNI, and servers must ignore SNI if a peer sends it anyway.
 */

#ifndef LIBP2P_QUIC_IDENTITY_H
#define LIBP2P_QUIC_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"
#include "transport/quic/quic_types.h"

/** libp2p TLS certificate extension OID, in dotted decimal notation. */
#define LIBP2P_QUIC_TLS_PUBLIC_KEY_EXTENSION_OID "1.3.6.1.4.1.53594.1.1"

/** Domain-separation prefix signed by the libp2p host key. */
#define LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX "libp2p-tls-handshake:"

/** Length of LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX, excluding trailing NUL. */
#define LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN 21U

/** Initial certificate and extension size limits for bounded callers. */
#define LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES     4096U
#define LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES 2048U
#define LIBP2P_QUIC_SIGNED_PUBLIC_KEY_MAX_BYTES   512U

/** Supported libp2p host-key subset for c-lean-libp2p. */
typedef enum
{
    LIBP2P_QUIC_HOST_KEY_SECP256K1
} libp2p_quic_host_key_type_t;

/** TLS certificate key algorithm generated for the QUIC leaf certificate. */
typedef enum
{
    LIBP2P_QUIC_CERT_KEY_ECDSA_P256
} libp2p_quic_certificate_key_type_t;

/**
 * libp2p host identity key used to create or validate local QUIC certificates.
 *
 * The host key is the long-lived libp2p peer identity key. The public key uses
 * the deterministic libp2p PublicKey protobuf encoding from peer_id.h. The
 * private key is the raw secp256k1 secret bytes accepted by peer_id.h.
 *
 * Certificate generation needs this structure to sign the TLS certificate
 * public key. Endpoint initialization does not; callers should not keep the
 * host private key in endpoint configuration after certificate generation.
 */
typedef struct
{
    libp2p_quic_host_key_type_t type;
    const uint8_t *private_key;
    size_t private_key_len;
    const uint8_t *public_key_message;
    size_t public_key_message_len;
} libp2p_quic_host_key_t;

/**
 * Local libp2p identity used by the QUIC TLS backend.
 *
 * The certificate and certificate private key are the TLS leaf certificate
 * material presented during the QUIC handshake. The certificate must contain
 * the libp2p public-key extension. The optional peer_id field lets callers pin
 * the expected local peer ID without retaining the host private key.
 *
 * All pointers remain caller-owned and must stay valid until the endpoint is
 * deinitialized or the identity is replaced.
 */
typedef struct
{
    const uint8_t *certificate_der;
    size_t certificate_der_len;
    const uint8_t *certificate_private_key_der;
    size_t certificate_private_key_der_len;
    const uint8_t *peer_id;
    size_t peer_id_len;
} libp2p_quic_local_identity_t;

/** Certificate generation parameters for self-signed libp2p QUIC certificates. */
typedef struct
{
    libp2p_quic_certificate_key_type_t certificate_key_type;
    uint64_t not_before_unix_seconds;
    uint64_t not_after_unix_seconds;
    libp2p_quic_random_fn_t random_fn;
    void *random_user_data;
} libp2p_quic_certificate_config_t;

/** Authenticated peer identity extracted from a libp2p QUIC certificate. */
typedef struct
{
    libp2p_quic_host_key_type_t host_key_type;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
    uint8_t host_public_key_message[LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES];
    size_t host_public_key_message_len;
    uint64_t not_before_unix_seconds;
    uint64_t not_after_unix_seconds;
} libp2p_quic_peer_identity_t;

/** Verification result details for a peer certificate chain. */
typedef struct
{
    uint8_t self_signature_valid;
    uint8_t libp2p_extension_present;
    uint8_t libp2p_extension_critical;
    uint8_t unknown_critical_extension_present;
    uint8_t subject_unique_id_present;
    uint8_t issuer_unique_id_present;
} libp2p_quic_certificate_report_t;

/**
 * Validate that host key fields are internally consistent.
 */
libp2p_quic_err_t libp2p_quic_host_key_validate(const libp2p_quic_host_key_t *host_key);

/**
 * Derive a peer ID from a host public key.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_host_key_peer_id(
    const libp2p_quic_host_key_t *host_key,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Validate that local identity fields are internally consistent.
 */
libp2p_quic_err_t libp2p_quic_local_identity_validate(const libp2p_quic_local_identity_t *identity);

/**
 * Derive the local peer ID from a local certificate's libp2p extension.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_local_identity_peer_id(
    const libp2p_quic_local_identity_t *identity,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Generate a self-signed TLS certificate and matching private key for QUIC.
 *
 * The certificate embeds the libp2p signed public-key extension derived from the
 * host key. The generated certificate key is a TLS certificate key, not the
 * libp2p host key.
 *
 * @param[out] cert_written  Bytes written, or required cert size on
 *                           LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 * @param[out] key_written   Bytes written, or required key size on
 *                           LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_identity_write_certificate_der(
    const libp2p_quic_host_key_t *host_key,
    const libp2p_quic_certificate_config_t *config,
    uint8_t *cert_out,
    size_t cert_out_len,
    size_t *cert_written,
    uint8_t *key_out,
    size_t key_out_len,
    size_t *key_written);

/**
 * Return the exact signing payload size for a certificate SubjectPublicKeyInfo.
 */
libp2p_quic_err_t libp2p_quic_identity_signing_payload_size(
    size_t certificate_public_key_spki_der_len,
    size_t *out_len);

/**
 * Write the payload signed by the libp2p host key.
 *
 * Output is:
 *   "libp2p-tls-handshake:" || certificate_public_key_spki_der
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_identity_write_signing_payload(
    const uint8_t *certificate_public_key_spki_der,
    size_t certificate_public_key_spki_der_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Verify a peer TLS leaf certificate and extract its authenticated peer ID.
 *
 * If expected_peer_id is non-NULL, the derived peer ID must match it exactly.
 * current_unix_seconds is used for certificate validity checks.
 */
libp2p_quic_err_t libp2p_quic_identity_verify_peer_certificate(
    const uint8_t *certificate_der,
    size_t certificate_der_len,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t current_unix_seconds,
    libp2p_quic_peer_identity_t *out);

/**
 * Verify a peer TLS certificate chain and extract its authenticated peer ID.
 *
 * The libp2p TLS spec requires exactly one self-signed certificate. This
 * function returns LIBP2P_QUIC_ERR_CERTIFICATE_CHAIN if certificate_count is not
 * exactly 1. It rejects invalid self-signatures, missing libp2p public-key
 * extensions, unknown critical extensions, and certificates that are not valid
 * at current_unix_seconds. c-lean-libp2p also rejects deprecated
 * subjectUniqueId and issuerUniqueId fields.
 *
 * When report is non-NULL, it is filled before returning.
 */
libp2p_quic_err_t libp2p_quic_identity_verify_peer_certificate_chain(
    const libp2p_quic_const_buffer_t *certificates_der,
    size_t certificate_count,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t current_unix_seconds,
    libp2p_quic_peer_identity_t *out,
    libp2p_quic_certificate_report_t *report);

/**
 * Encode the libp2p SignedKey extension payload as ASN.1 DER.
 *
 * This helper is exposed so tests and certificate builders can verify the
 * exact bytes that are embedded in the TLS certificate.
 */
libp2p_quic_err_t libp2p_quic_identity_encode_signed_key_der(
    const uint8_t *host_public_key_message,
    size_t host_public_key_message_len,
    const uint8_t *signature,
    size_t signature_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode the libp2p SignedKey extension payload from ASN.1 DER.
 *
 * @param[out] public_key_written  Bytes written, or required public-key size on
 *                                 LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 * @param[out] signature_written   Bytes written, or required signature size on
 *                                 LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_identity_decode_signed_key_der(
    const uint8_t *signed_key_der,
    size_t signed_key_der_len,
    uint8_t *public_key_out,
    size_t public_key_out_len,
    size_t *public_key_written,
    uint8_t *signature_out,
    size_t signature_out_len,
    size_t *signature_written);

#endif /* LIBP2P_QUIC_IDENTITY_H */
