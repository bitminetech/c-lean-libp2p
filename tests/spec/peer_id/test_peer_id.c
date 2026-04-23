#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"

/* Vectors from docs/libp2p-specs/peer-ids/peer-ids.md lines 200-201. */
static const char peer_id_spec_private_key_hex[] =
    "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
static const char peer_id_spec_public_key_hex[] =
    "037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
static const char peer_id_spec_private_key_message_hex[] =
    "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
static const char peer_id_spec_public_key_message_hex[] =
    "08021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
/* Derived from the peer-id rules in lines 207-222 using the public-key vector above. */
static const char peer_id_spec_identity_peer_id_hex[] =
    "002508021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";

/* Text examples from docs/libp2p-specs/peer-ids/peer-ids.md lines 266-269. */
static const char peer_id_spec_sha2_cid_text[] =
    "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe";
static const char peer_id_spec_sha2_legacy_text[] =
    "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
static const char peer_id_spec_ed25519_legacy_text[] =
    "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

static int peer_id_spec_hex_nibble(char character, uint8_t *value)
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

static int peer_id_spec_parse_hex(
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

        if ((peer_id_spec_hex_nibble(text[index * 2U], &high) == 0) ||
            (peer_id_spec_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
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

static void peer_id_spec_test_key_vectors(void)
{
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t encoded_private[36];
    uint8_t encoded_public[37];
    size_t private_key_len = 0U;
    size_t public_key_len = 0U;
    size_t encoded_private_len = 0U;
    size_t encoded_public_len = 0U;

    assert(peer_id_spec_parse_hex(peer_id_spec_private_key_hex, private_key, sizeof(private_key), &private_key_len) != 0);
    assert(peer_id_spec_parse_hex(peer_id_spec_public_key_hex, public_key, sizeof(public_key), &public_key_len) != 0);
    assert(peer_id_spec_parse_hex(peer_id_spec_private_key_message_hex, encoded_private, sizeof(encoded_private), &encoded_private_len) != 0);
    assert(peer_id_spec_parse_hex(peer_id_spec_public_key_message_hex, encoded_public, sizeof(encoded_public), &encoded_public_len) != 0);

    assert(
        libp2p_peer_id_private_key_encode(
            private_key,
            private_key_len,
            encoded_private,
            sizeof(encoded_private),
            &encoded_private_len) == LIBP2P_PEER_ID_OK);
    assert(encoded_private_len == sizeof(encoded_private));

    assert(
        libp2p_peer_id_public_key_encode(
            public_key,
            public_key_len,
            encoded_public,
            sizeof(encoded_public),
            &encoded_public_len) == LIBP2P_PEER_ID_OK);
    assert(encoded_public_len == sizeof(encoded_public));

    assert(
        libp2p_peer_id_public_key_from_private_key(
            private_key,
            private_key_len,
            1,
            public_key,
            sizeof(public_key),
            &public_key_len) == LIBP2P_PEER_ID_OK);
    assert(public_key_len == 33U);
}

static void peer_id_spec_test_identity_peer_id_vector(void)
{
    uint8_t public_key[33];
    uint8_t expected_peer_id[39];
    uint8_t peer_id[39];
    size_t public_key_len = 0U;
    size_t expected_len = 0U;
    size_t written = 0U;

    assert(peer_id_spec_parse_hex(peer_id_spec_public_key_hex, public_key, sizeof(public_key), &public_key_len) != 0);
    assert(peer_id_spec_parse_hex(peer_id_spec_identity_peer_id_hex, expected_peer_id, sizeof(expected_peer_id), &expected_len) != 0);

    assert(
        libp2p_peer_id_from_secp256k1_public_key(
            public_key,
            public_key_len,
            peer_id,
            sizeof(peer_id),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == expected_len);
    assert(memcmp(peer_id, expected_peer_id, expected_len) == 0);
}

static void peer_id_spec_test_text_examples(void)
{
    uint8_t decoded_a[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t decoded_b[LIBP2P_PEER_ID_MAX_BYTES];
    char formatted[96];
    char prefixed[96];
    size_t written_a = 0U;
    size_t written_b = 0U;
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;

    assert(
        libp2p_peer_id_from_string(
            peer_id_spec_sha2_legacy_text,
            strlen(peer_id_spec_sha2_legacy_text),
            decoded_a,
            sizeof(decoded_a),
            &written_a) == LIBP2P_PEER_ID_OK);
    assert(
        libp2p_peer_id_to_string(
            decoded_a,
            written_a,
            formatted,
            sizeof(formatted),
            &written_b) == LIBP2P_PEER_ID_OK);
    assert(written_b == strlen(peer_id_spec_sha2_legacy_text));
    assert(memcmp(formatted, peer_id_spec_sha2_legacy_text, written_b) == 0);

    prefixed[0] = 'z';
    (void)memcpy(&prefixed[1], peer_id_spec_sha2_legacy_text, strlen(peer_id_spec_sha2_legacy_text));
    assert(
        libp2p_multibase_decode(
            prefixed,
            strlen(peer_id_spec_sha2_legacy_text) + 1U,
            &base,
            decoded_b,
            sizeof(decoded_b),
            &written_b) == LIBP2P_MULTIBASE_OK);
    assert(written_a == written_b);
    assert(memcmp(decoded_a, decoded_b, written_a) == 0);

    assert(
        libp2p_peer_id_from_string(
            peer_id_spec_sha2_cid_text,
            strlen(peer_id_spec_sha2_cid_text),
            decoded_a,
            sizeof(decoded_a),
            &written_a) == LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING);

    assert(
        libp2p_peer_id_from_string(
            peer_id_spec_ed25519_legacy_text,
            strlen(peer_id_spec_ed25519_legacy_text),
            decoded_a,
            sizeof(decoded_a),
            &written_a) == LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING);
}

int main(void)
{
    peer_id_spec_test_key_vectors();
    peer_id_spec_test_identity_peer_id_vector();
    peer_id_spec_test_text_examples();
    return 0;
}
