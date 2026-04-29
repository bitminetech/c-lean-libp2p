#include <string.h>

#include "peer_record_internal.h"

static libp2p_peer_record_bytes_t peer_record_domain(void)
{
    return peer_record_const_bytes(
        LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN,
        LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN_LEN);
}

static libp2p_peer_record_bytes_t peer_record_payload_type(void)
{
    return peer_record_const_bytes(
        LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE,
        LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN);
}

static libp2p_peer_record_err_t peer_record_validate_identity(
    const libp2p_host_identity_t *identity)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (identity == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (
        (identity->peer_id == NULL) || (identity->peer_id_len == 0U) ||
        (identity->peer_id_len > LIBP2P_PEER_ID_MAX_BYTES) ||
        (identity->public_key_message == NULL) || (identity->public_key_message_len == 0U) ||
        (identity->public_key_message_len >
         LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES) ||
        (identity->sign_fn == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_OK;
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_make_view(
    const libp2p_host_identity_t *identity,
    uint64_t seqno,
    const libp2p_peer_record_bytes_t *multiaddrs,
    size_t multiaddr_count,
    libp2p_peer_record_t *out_record)
{
    libp2p_peer_record_err_t result = peer_record_validate_identity(identity);

    if ((result == LIBP2P_PEER_RECORD_OK) && (out_record == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    if ((result == LIBP2P_PEER_RECORD_OK) &&
        ((multiaddr_count > LIBP2P_PEER_RECORD_MAX_MULTIADDRS) ||
         ((multiaddr_count != 0U) && (multiaddrs == NULL))))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        size_t index = 0U;

        (void)memset(out_record, 0, sizeof(*out_record));
        out_record->peer_id.data = identity->peer_id;
        out_record->peer_id.len = identity->peer_id_len;
        out_record->seqno = seqno;
        for (index = 0U; index < multiaddr_count; index++)
        {
            out_record->multiaddrs[index] = multiaddrs[index];
        }
        out_record->multiaddr_count = multiaddr_count;
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_sign_envelope(
    const libp2p_host_identity_t *identity,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t signing[LIBP2P_PEER_RECORD_MAX_SIGNING_BYTES];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    libp2p_peer_record_envelope_t envelope;
    size_t signing_len = 0U;
    size_t signature_len = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    (void)memset(&envelope, 0, sizeof(envelope));
    if ((identity == NULL) || (payload == NULL) || (payload_len == 0U) || (written == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_peer_record_envelope_signing_encode(
            peer_record_domain(),
            peer_record_payload_type(),
            peer_record_const_bytes((const char *)payload, payload_len),
            signing,
            sizeof(signing),
            &signing_len);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_host_err(identity->sign_fn(
            identity->user_data,
            signing,
            signing_len,
            signature,
            sizeof(signature),
            &signature_len));
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        envelope.public_key.data = identity->public_key_message;
        envelope.public_key.len = identity->public_key_message_len;
        envelope.payload_type = peer_record_payload_type();
        envelope.payload.data = payload;
        envelope.payload.len = payload_len;
        envelope.signature.data = signature;
        envelope.signature.len = signature_len;
        result = libp2p_peer_record_envelope_encode(&envelope, out, out_len, written);
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_encode(
    const libp2p_host_identity_t *identity,
    uint64_t seqno,
    const libp2p_peer_record_bytes_t *multiaddrs,
    size_t multiaddr_count,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_record_t record;
    uint8_t payload[LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES];
    size_t payload_len = 0U;
    libp2p_peer_record_err_t result =
        peer_record_make_view(identity, seqno, multiaddrs, multiaddr_count, &record);

    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = libp2p_peer_record_payload_encode(&record, payload, sizeof(payload), &payload_len);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_sign_envelope(identity, payload, payload_len, out, out_len, written);
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_size(
    const libp2p_host_identity_t *identity,
    uint64_t seqno,
    const libp2p_peer_record_bytes_t *multiaddrs,
    size_t multiaddr_count,
    size_t *out_len)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result = libp2p_peer_record_signed_envelope_encode(
            identity,
            seqno,
            multiaddrs,
            multiaddr_count,
            NULL,
            0U,
            out_len);
        if (result == LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL)
        {
            result = LIBP2P_PEER_RECORD_OK;
        }
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_payload_type_matches(
    libp2p_peer_record_bytes_t payload_type)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    const libp2p_peer_record_bytes_t expected = peer_record_payload_type();

    if ((payload_type.len != expected.len) ||
        (memcmp(payload_type.data, expected.data, expected.len) != 0))
    {
        result = LIBP2P_PEER_RECORD_ERR_UNSUPPORTED;
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_signed_envelope_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope,
    libp2p_peer_record_t *out_record)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((out_envelope == NULL) || (out_record == NULL))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_peer_record_envelope_verify(peer_record_domain(), in, in_len, out_envelope);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_payload_type_matches(out_envelope->payload_type);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = libp2p_peer_record_payload_decode(
            out_envelope->payload.data,
            out_envelope->payload.len,
            out_record);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if ((out_record->peer_id.len != out_envelope->signer_peer_id_len) ||
            (memcmp(
                 out_record->peer_id.data,
                 out_envelope->signer_peer_id,
                 out_record->peer_id.len) != 0))
        {
            result = LIBP2P_PEER_RECORD_ERR_PEER_ID_MISMATCH;
        }
    }

    return result;
}
