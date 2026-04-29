#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "peer_record/peer_record.h"

static int peer_record_spec_hex_nibble(char character, uint8_t *value)
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

static int peer_record_spec_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = 0U;
    size_t index = 0U;
    int result = 1;

    *out_len = 0U;
    if ((text == NULL) || (out == NULL))
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

        if ((peer_record_spec_hex_nibble(text[index * 2U], &high) == 0) ||
            (peer_record_spec_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
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

static void peer_record_spec_identity(
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
            peer_record_spec_parse_hex(
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

static void peer_record_spec_test_constants(void)
{
    assert(strlen(LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN) == LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN_LEN);
    assert(strcmp(LIBP2P_PEER_RECORD_ENVELOPE_DOMAIN, "libp2p-routing-state") == 0);
    assert(
        strlen(LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE) ==
        LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN);
    assert(strcmp(LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE, "/libp2p/routing-state-record") == 0);
}

static void peer_record_spec_test_payload_vector(void)
{
    static const uint8_t addr[] =
        {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
    static const uint8_t expected[] = {0x0AU, 0x27U, 0x00U, 0x25U, 0x08U, 0x02U, 0x12U, 0x21U,
                                       0x03U, 0x77U, 0x77U, 0xE9U, 0x94U, 0xE4U, 0x52U, 0xC2U,
                                       0x16U, 0x04U, 0xF9U, 0x1DU, 0xE0U, 0x93U, 0xCEU, 0x41U,
                                       0x5FU, 0x54U, 0x32U, 0xF7U, 0x01U, 0xDDU, 0x8CU, 0xD1U,
                                       0xA7U, 0xA6U, 0xFEU, 0xA0U, 0xE6U, 0x30U, 0xBFU, 0xCAU,
                                       0x99U, 0x10U, 0x07U, 0x1AU, 0x0DU, 0x0AU, 0x0BU, 0x04U,
                                       0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U,
                                       0xCDU, 0x03U};
    libp2p_host_secp256k1_identity_t storage;
    libp2p_host_identity_t identity;
    libp2p_peer_record_t record;
    uint8_t encoded[128];
    size_t written = 0U;

    peer_record_spec_identity(&storage, &identity);
    (void)memset(&record, 0, sizeof(record));
    record.peer_id.data = identity.peer_id;
    record.peer_id.len = identity.peer_id_len;
    record.seqno = 7U;
    record.multiaddrs[0].data = addr;
    record.multiaddrs[0].len = sizeof(addr);
    record.multiaddr_count = 1U;

    assert(
        libp2p_peer_record_payload_encode(&record, encoded, sizeof(encoded), &written) ==
        LIBP2P_PEER_RECORD_OK);
    assert(written == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
}

static void peer_record_spec_test_signed_record_round_trip(void)
{
    static const uint8_t addr[] =
        {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
    libp2p_host_secp256k1_identity_t storage;
    libp2p_host_identity_t identity;
    libp2p_peer_record_bytes_t addrs[1];
    libp2p_peer_record_envelope_t envelope;
    libp2p_peer_record_t record;
    uint8_t signed_record[LIBP2P_PEER_RECORD_MAX_ENVELOPE_BYTES];
    size_t signed_record_len = 0U;

    peer_record_spec_identity(&storage, &identity);
    addrs[0].data = addr;
    addrs[0].len = sizeof(addr);

    assert(
        libp2p_peer_record_signed_envelope_encode(
            &identity,
            1570215229U,
            addrs,
            1U,
            signed_record,
            sizeof(signed_record),
            &signed_record_len) == LIBP2P_PEER_RECORD_OK);
    assert(
        libp2p_peer_record_signed_envelope_decode(
            signed_record,
            signed_record_len,
            &envelope,
            &record) == LIBP2P_PEER_RECORD_OK);
    assert(record.seqno == 1570215229U);
    assert(record.multiaddr_count == 1U);
    assert(envelope.payload_type.len == LIBP2P_PEER_RECORD_ENVELOPE_PAYLOAD_TYPE_LEN);
}

int main(void)
{
    peer_record_spec_test_constants();
    peer_record_spec_test_payload_vector();
    peer_record_spec_test_signed_record_round_trip();
    return 0;
}
