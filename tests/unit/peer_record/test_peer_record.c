#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "peer_record/peer_record.h"

static int peer_record_unit_hex_nibble(char character, uint8_t *value)
{
    int result = 1;

    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
    }
    else if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'a'));
    }
    else if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'A'));
    }
    else
    {
        *value = 0U;
        result = 0;
    }

    return result;
}

static int peer_record_unit_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = 0U;
    size_t index = 0U;
    int result = 1;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }
    if ((text == NULL) || (out == NULL) || (out_len == NULL))
    {
        result = 0;
    }
    while ((result != 0) && (text[text_len] != '\0'))
    {
        text_len++;
    }
    if ((result != 0) && (((text_len % 2U) != 0U) || ((text_len / 2U) > out_capacity)))
    {
        result = 0;
    }
    for (index = 0U; (index < (text_len / 2U)) && (result != 0); index++)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((peer_record_unit_hex_nibble(text[index * 2U], &high) == 0) ||
            (peer_record_unit_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
        {
            result = 0;
        }
        else
        {
            out[index] = (uint8_t)((high << 4U) | low);
        }
    }
    if (result != 0)
    {
        *out_len = text_len / 2U;
    }

    return result;
}

static void peer_record_unit_identity(
    libp2p_host_secp256k1_identity_t *storage,
    libp2p_host_identity_t *identity)
{
    static const char private_key_hex[] =
        "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    static uint8_t private_key[32];
    static int loaded = 0;
    size_t private_key_len = 0U;

    if (loaded == 0)
    {
        assert(
            peer_record_unit_parse_hex(
                private_key_hex,
                private_key,
                sizeof(private_key),
                &private_key_len) != 0);
        loaded = 1;
    }
    else
    {
        private_key_len = sizeof(private_key);
    }
    assert(
        libp2p_host_secp256k1_identity_init(storage, private_key, private_key_len, identity) ==
        LIBP2P_HOST_OK);
}

static void peer_record_unit_payload_round_trip(void)
{
    static const uint8_t addr[] =
        {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
    libp2p_host_secp256k1_identity_t storage;
    libp2p_host_identity_t identity;
    libp2p_peer_record_t record;
    libp2p_peer_record_t decoded;
    uint8_t payload[LIBP2P_PEER_RECORD_MAX_PAYLOAD_BYTES];
    size_t required = 0U;
    size_t written = 0U;

    peer_record_unit_identity(&storage, &identity);
    (void)memset(&record, 0, sizeof(record));
    record.peer_id.data = identity.peer_id;
    record.peer_id.len = identity.peer_id_len;
    record.seqno = 42U;
    record.multiaddrs[0].data = addr;
    record.multiaddrs[0].len = sizeof(addr);
    record.multiaddr_count = 1U;

    assert(libp2p_peer_record_payload_size(&record, &required) == LIBP2P_PEER_RECORD_OK);
    assert(
        libp2p_peer_record_payload_encode(&record, NULL, 0U, &written) ==
        LIBP2P_PEER_RECORD_ERR_BUF_TOO_SMALL);
    assert(written == required);
    assert(
        libp2p_peer_record_payload_encode(&record, payload, sizeof(payload), &written) ==
        LIBP2P_PEER_RECORD_OK);
    assert(written == required);
    assert(libp2p_peer_record_payload_decode(payload, written, &decoded) == LIBP2P_PEER_RECORD_OK);
    assert(decoded.seqno == 42U);
    assert(decoded.multiaddr_count == 1U);
    assert(decoded.peer_id.len == identity.peer_id_len);
    assert(memcmp(decoded.peer_id.data, identity.peer_id, decoded.peer_id.len) == 0);
    assert(decoded.multiaddrs[0].len == sizeof(addr));
    assert(memcmp(decoded.multiaddrs[0].data, addr, sizeof(addr)) == 0);
}

static void peer_record_unit_signed_envelope_round_trip(void)
{
    static const uint8_t addr[] =
        {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
    libp2p_host_secp256k1_identity_t storage;
    libp2p_host_identity_t identity;
    libp2p_peer_record_bytes_t addrs[1];
    libp2p_peer_record_envelope_t envelope;
    libp2p_peer_record_t record;
    uint8_t encoded[LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES];
    uint8_t tampered[LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES];
    size_t required = 0U;
    size_t written = 0U;

    peer_record_unit_identity(&storage, &identity);
    addrs[0].data = addr;
    addrs[0].len = sizeof(addr);

    assert(
        libp2p_peer_record_signed_envelope_size(&identity, 77U, addrs, 1U, &required) ==
        LIBP2P_PEER_RECORD_OK);
    assert(required != 0U);
    assert(
        libp2p_peer_record_signed_envelope_encode(
            &identity,
            77U,
            addrs,
            1U,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_PEER_RECORD_OK);
    assert(written == required);
    assert(
        libp2p_peer_record_signed_envelope_decode(encoded, written, &envelope, &record) ==
        LIBP2P_PEER_RECORD_OK);
    assert(record.seqno == 77U);
    assert(record.multiaddr_count == 1U);
    assert(envelope.signer_peer_id_len == identity.peer_id_len);
    assert(memcmp(envelope.signer_peer_id, identity.peer_id, envelope.signer_peer_id_len) == 0);

    (void)memcpy(tampered, encoded, written);
    tampered[written - 1U] ^= 1U;
    assert(
        libp2p_peer_record_signed_envelope_decode(tampered, written, &envelope, &record) ==
        LIBP2P_PEER_RECORD_ERR_SIGNATURE);
}

int main(void)
{
    peer_record_unit_payload_round_trip();
    peer_record_unit_signed_envelope_round_trip();
    return 0;
}
