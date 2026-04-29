#include <string.h>

#include "peer_record_internal.h"

static libp2p_peer_record_err_t peer_record_validate_envelope(
    const libp2p_peer_record_envelope_t *envelope)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (envelope == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else if (
        (peer_record_bytes_present(envelope->public_key) == 0) ||
        (peer_record_bytes_present(envelope->payload_type) == 0) ||
        (peer_record_bytes_present(envelope->payload) == 0) ||
        (peer_record_bytes_present(envelope->signature) == 0) ||
        (envelope->public_key.len > LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES) ||
        (envelope->payload_type.len > LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN) ||
        (envelope->payload.len > LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES) ||
        (envelope->signature.len > LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        result = LIBP2P_PEER_RECORD_OK;
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_size(
    const libp2p_peer_record_envelope_t *envelope,
    size_t *out_len)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    size_t total = 0U;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
        result = peer_record_validate_envelope(envelope);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_len_field_size(
            PEER_RECORD_FIELD_ENVELOPE_PUBLIC_KEY,
            envelope->public_key.len,
            &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_len_field_size(
            PEER_RECORD_FIELD_ENVELOPE_PAYLOAD_TYPE,
            envelope->payload_type.len,
            &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_len_field_size(
            PEER_RECORD_FIELD_ENVELOPE_PAYLOAD,
            envelope->payload.len,
            &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_len_field_size(
            PEER_RECORD_FIELD_ENVELOPE_SIGNATURE,
            envelope->signature.len,
            &total);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (total > LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            *out_len = total;
        }
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_encode(
    const libp2p_peer_record_envelope_t *envelope,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (written == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *written = 0U;
        result = libp2p_peer_record_envelope_size(envelope, &required);
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *written = required;
            if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
            }
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_ENVELOPE_PUBLIC_KEY,
            envelope->public_key.data,
            envelope->public_key.len,
            out,
            out_len,
            &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_ENVELOPE_PAYLOAD_TYPE,
            envelope->payload_type.data,
            envelope->payload_type.len,
            out,
            out_len,
            &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_ENVELOPE_PAYLOAD,
            envelope->payload.data,
            envelope->payload.len,
            out,
            out_len,
            &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_len_field(
            PEER_RECORD_FIELD_ENVELOPE_SIGNATURE,
            envelope->signature.data,
            envelope->signature.len,
            out,
            out_len,
            &pos);
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_decode(
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope)
{
    size_t pos = 0U;
    uint8_t seen_public_key = 0U;
    uint8_t seen_payload_type = 0U;
    uint8_t seen_payload = 0U;
    uint8_t seen_signature = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if ((in == NULL) || (in_len == 0U) || (out_envelope == NULL) ||
        (in_len > LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES))
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
    }
    while ((result == LIBP2P_PEER_RECORD_OK) && (pos < in_len))
    {
        uint32_t field = 0U;
        uint32_t wire_type = 0U;

        result = peer_record_read_key(in, in_len, &pos, &field, &wire_type);
        if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_ENVELOPE_PUBLIC_KEY))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_public_key != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &out_envelope->public_key);
                seen_public_key = 1U;
            }
        }
        else if (
            (result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_ENVELOPE_PAYLOAD_TYPE))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_payload_type != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &out_envelope->payload_type);
                seen_payload_type = 1U;
            }
        }
        else if ((result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_ENVELOPE_PAYLOAD))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_payload != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &out_envelope->payload);
                seen_payload = 1U;
            }
        }
        else if (
            (result == LIBP2P_PEER_RECORD_OK) && (field == PEER_RECORD_FIELD_ENVELOPE_SIGNATURE))
        {
            if ((wire_type != PEER_RECORD_WIRE_LEN) || (seen_signature != 0U))
            {
                result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
            }
            else
            {
                result = peer_record_read_len_span(in, in_len, &pos, &out_envelope->signature);
                seen_signature = 1U;
            }
        }
        else if (result == LIBP2P_PEER_RECORD_OK)
        {
            result = peer_record_skip_value(in, in_len, &pos, wire_type);
        }
        else
        {
            /* Preserve the first decode error. */
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if ((seen_public_key == 0U) || (seen_payload_type == 0U) || (seen_payload == 0U) ||
            (seen_signature == 0U) || (peer_record_bytes_present(out_envelope->public_key) == 0) ||
            (peer_record_bytes_present(out_envelope->payload_type) == 0) ||
            (peer_record_bytes_present(out_envelope->payload) == 0) ||
            (peer_record_bytes_present(out_envelope->signature) == 0))
        {
            result = LIBP2P_PEER_RECORD_ERR_MALFORMED;
        }
        else if (
            (out_envelope->public_key.len >
             LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES) ||
            (out_envelope->payload_type.len > LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN) ||
            (out_envelope->payload.len > LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES) ||
            (out_envelope->signature.len > LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES))
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            result = LIBP2P_PEER_RECORD_OK;
        }
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_signing_size(
    libp2p_peer_record_bytes_t domain,
    libp2p_peer_record_bytes_t payload_type,
    libp2p_peer_record_bytes_t payload,
    size_t *out_len)
{
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;
    size_t total = 0U;
    size_t next = 0U;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *out_len = 0U;
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if ((peer_record_bytes_present(domain) == 0) ||
            (peer_record_bytes_present(payload_type) == 0) ||
            (peer_record_bytes_present(payload) == 0))
        {
            result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (peer_record_size_add(
                (size_t)libp2p_uvarint_size((uint64_t)domain.len),
                domain.len,
                &total) != 0)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (peer_record_size_add(
                total,
                (size_t)libp2p_uvarint_size((uint64_t)payload_type.len) + payload_type.len,
                &next) != 0)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            total = next;
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (peer_record_size_add(
                total,
                (size_t)libp2p_uvarint_size((uint64_t)payload.len) + payload.len,
                &next) != 0)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            total = next;
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (total > LIBP2P_PEER_RECORD_MAX_SIGNING_BYTES)
        {
            result = LIBP2P_PEER_RECORD_ERR_LIMIT;
        }
        else
        {
            *out_len = total;
        }
    }

    return result;
}

static libp2p_peer_record_err_t peer_record_write_signing_part(
    libp2p_peer_record_bytes_t bytes,
    uint8_t *out,
    size_t out_len,
    size_t *pos)
{
    libp2p_peer_record_err_t result =
        peer_record_write_uvarint((uint64_t)bytes.len, out, out_len, pos);

    if (result == LIBP2P_PEER_RECORD_OK)
    {
        if (bytes.len > (out_len - *pos))
        {
            result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
        }
        else
        {
            (void)memcpy(&out[*pos], bytes.data, bytes.len);
            *pos += bytes.len;
        }
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_signing_encode(
    libp2p_peer_record_bytes_t domain,
    libp2p_peer_record_bytes_t payload_type,
    libp2p_peer_record_bytes_t payload,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t pos = 0U;
    libp2p_peer_record_err_t result = LIBP2P_PEER_RECORD_OK;

    if (written == NULL)
    {
        result = LIBP2P_PEER_RECORD_ERR_INVALID_ARG;
    }
    else
    {
        *written = 0U;
        result = libp2p_peer_record_envelope_signing_size(domain, payload_type, payload, &required);
        if (result == LIBP2P_PEER_RECORD_OK)
        {
            *written = required;
            if ((out == NULL) || (out_len < required))
            {
                result = LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL;
            }
        }
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_signing_part(domain, out, out_len, &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_signing_part(payload_type, out, out_len, &pos);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = peer_record_write_signing_part(payload, out, out_len, &pos);
    }

    return result;
}

libp2p_peer_record_err_t libp2p_peer_record_envelope_verify(
    libp2p_peer_record_bytes_t domain,
    const uint8_t *in,
    size_t in_len,
    libp2p_peer_record_envelope_t *out_envelope)
{
    uint8_t raw_public_key[LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    uint8_t signing[LIBP2P_PEER_RECORD_MAX_SIGNING_BYTES];
    size_t raw_public_key_len = 0U;
    size_t signing_len = 0U;
    libp2p_peer_id_err_t peer_err;
    libp2p_peer_record_err_t result = libp2p_peer_record_envelope_decode(in, in_len, out_envelope);

    if (result == LIBP2P_PEER_RECORD_OK)
    {
        peer_err = libp2p_peer_id_public_key_decode(
            out_envelope->public_key.data,
            out_envelope->public_key.len,
            raw_public_key,
            sizeof(raw_public_key),
            &raw_public_key_len);
        result = peer_record_peer_id_err(peer_err);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        peer_err = libp2p_peer_id_from_secp256k1_public_key(
            raw_public_key,
            raw_public_key_len,
            out_envelope->signer_peer_id,
            sizeof(out_envelope->signer_peer_id),
            &out_envelope->signer_peer_id_len);
        result = peer_record_peer_id_err(peer_err);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        result = libp2p_peer_record_envelope_signing_encode(
            domain,
            out_envelope->payload_type,
            out_envelope->payload,
            signing,
            sizeof(signing),
            &signing_len);
    }
    if (result == LIBP2P_PEER_RECORD_OK)
    {
        peer_err = libp2p_peer_id_verify_message(
            raw_public_key,
            raw_public_key_len,
            signing,
            signing_len,
            out_envelope->signature.data,
            out_envelope->signature.len);
        result = peer_record_peer_id_err(peer_err);
    }

    return result;
}
