/**
 * @file peer_record.h
 * @brief libp2p signed envelopes and peer routing records.
 *
 * This module implements the signed-envelope wire format from RFC 0002 and
 * the peer routing record payload from RFC 0003 for the c-lean-libp2p
 * secp256k1-only key subset. All decoded byte views borrow from caller-owned
 * input buffers. Encoding follows the project measure-then-write contract.
 */

#ifndef LIBP2P_PEER_RECORD_H
#define LIBP2P_PEER_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"
#include "peer_id/peer_id.h"

#define LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN           "libp2p-routing-state"
#define LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN_LEN       20U
#define LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE     "/libp2p/routing-state-record"
#define LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN 28U

#ifndef LIBP2P_PEER_RECORD_MAX_MULTIADDRS
#define LIBP2P_PEER_RECORD_MAX_MULTIADDRS 8U
#endif

#ifndef LIBP2P_PEER_RECORD_MAX_MULTIADDR_BYTES
#define LIBP2P_PEER_RECORD_MAX_MULTIADDR_BYTES 256U
#endif

#ifndef LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES
#define LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES 1536U
#endif

#ifndef LIBP2P_PEER_RECORD_MAX_SIGNING_BYTES
#define LIBP2P_PEER_RECORD_MAX_SIGNING_BYTES 1792U
#endif

#ifndef LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES
#define LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES 2048U
#endif

typedef enum
{
    LIBP2P_PEER_RECORD_OK = 0,
    LIBP2P_PEER_RECORD_ERR_INVALID_ARG,
    LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL,
    LIBP2P_PEER_RECORD_ERR_MALFORMED,
    LIBP2P_PEER_RECORD_ERR_TRUNCATED,
    LIBP2P_PEER_RECORD_ERR_LIMIT,
    LIBP2P_PEER_RECORD_ERR_UNSUPPORTED,
    LIBP2P_PEER_RECORD_ERR_SIGNATURE,
    LIBP2P_PEER_RECORD_ERR_PEER_ID_MISMATCH
} libp2p_peer_record_err_t;

typedef struct
{
    const uint8_t *data;
    size_t len;
} libp2p_peer_record_bytes_t;

typedef struct
{
    libp2p_peer_record_bytes_t public_key;
    libp2p_peer_record_bytes_t payload_type;
    libp2p_peer_record_bytes_t payload;
    libp2p_peer_record_bytes_t signature;
    uint8_t signer_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t signer_peer_id_len;
} libp2p_peer_record_envelope_t;

typedef struct
{
    libp2p_peer_record_bytes_t peer_id;
    uint64_t seqno;
    libp2p_peer_record_bytes_t multiaddrs[LIBP2P_PEER_RECORD_MAX_MULTIADDRS];
    size_t multiaddr_count;
} libp2p_peer_record_t;

libp2p_peer_record_err_t libp2p_peer_record_payload_size(
    const libp2p_peer_record_t *record,
    size_t *out_len);

libp2p_peer_record_err_t libp2p_peer_record_payload_encode(
    const libp2p_peer_record_t *record,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_peer_record_err_t libp2p_peer_record_payload_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_t *out_record);

libp2p_peer_record_err_t libp2p_peer_record_envelope_size(
    const libp2p_peer_record_envelope_t *envelope,
    size_t *out_len);

libp2p_peer_record_err_t libp2p_peer_record_envelope_encode(
    const libp2p_peer_record_envelope_t *envelope,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_peer_record_err_t libp2p_peer_record_envelope_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope);

libp2p_peer_record_err_t libp2p_peer_record_envelope_signing_size(
    libp2p_peer_record_bytes_t domain,
    libp2p_peer_record_bytes_t payload_type,
    libp2p_peer_record_bytes_t payload,
    size_t *out_len);

libp2p_peer_record_err_t libp2p_peer_record_envelope_signing_encode(
    libp2p_peer_record_bytes_t domain,
    libp2p_peer_record_bytes_t payload_type,
    libp2p_peer_record_bytes_t payload,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_peer_record_err_t libp2p_peer_record_envelope_verify(
    libp2p_peer_record_bytes_t domain,
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope);

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_size(
    const libp2p_host_identity_t *identity,
    uint64_t seqno,
    const libp2p_peer_record_bytes_t *multiaddrs,
    size_t multiaddr_count,
    size_t *out_len);

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_encode(
    const libp2p_host_identity_t *identity,
    uint64_t seqno,
    const libp2p_peer_record_bytes_t *multiaddrs,
    size_t multiaddr_count,
    uint8_t *out,
    size_t out_len,
    size_t *written);

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope,
    libp2p_peer_record_t *out_record);

#endif /* LIBP2P_PEER_RECORD_H */
