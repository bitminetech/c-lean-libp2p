#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"

#define LIBP2P_PEER_ID_UNIT_TEXT_MAX_BYTES 96U

static int peer_id_unit_hex_nibble(char character, uint8_t *value)
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

static int peer_id_unit_parse_hex(
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

    if ((result != 0) && ((text_len % 2U) != 0U))
    {
        result = 0;
    }

    if ((result != 0) && ((text_len / 2U) > out_capacity))
    {
        result = 0;
    }

    for (index = 0U; (index < (text_len / 2U)) && (result != 0); index++)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((peer_id_unit_hex_nibble(text[index * 2U], &high) == 0) ||
            (peer_id_unit_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
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

static void peer_id_unit_load_spec_private_key(uint8_t private_key[32])
{
    static const char private_key_hex[] =
        "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    size_t written = 0U;

    assert(peer_id_unit_parse_hex(private_key_hex, private_key, 32U, &written) != 0);
    assert(written == 32U);
}

static void peer_id_unit_load_spec_public_key(uint8_t public_key[33])
{
    static const char public_key_hex[] =
        "037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
    size_t written = 0U;

    assert(peer_id_unit_parse_hex(public_key_hex, public_key, 33U, &written) != 0);
    assert(written == 33U);
}

static void peer_id_unit_load_spec_private_key_message(uint8_t encoded[36])
{
    static const char private_key_message_hex[] =
        "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    size_t written = 0U;

    assert(peer_id_unit_parse_hex(private_key_message_hex, encoded, 36U, &written) != 0);
    assert(written == 36U);
}

static void peer_id_unit_load_spec_public_key_message(uint8_t encoded[37])
{
    static const char public_key_message_hex[] =
        "08021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
    size_t written = 0U;

    assert(peer_id_unit_parse_hex(public_key_message_hex, encoded, 37U, &written) != 0);
    assert(written == 37U);
}

static void peer_id_unit_test_zeroize(void)
{
    uint8_t bytes[8] = {0xa1U, 0xb2U, 0xc3U, 0xd4U, 0xe5U, 0xf6U, 0x12U, 0x34U};
    size_t index = 0U;

    libp2p_peer_id_zeroize(bytes, sizeof(bytes));

    for (index = 0U; index < sizeof(bytes); index++)
    {
        assert(bytes[index] == 0U);
    }
}

static void peer_id_unit_test_key_encode_decode_vectors(void)
{
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t private_key_message[36];
    uint8_t public_key_message[37];
    uint8_t decoded_private_key[32];
    uint8_t decoded_public_key[65];
    size_t written = 0U;

    peer_id_unit_load_spec_private_key(private_key);
    peer_id_unit_load_spec_public_key(public_key);
    peer_id_unit_load_spec_private_key_message(private_key_message);
    peer_id_unit_load_spec_public_key_message(public_key_message);

    assert(libp2p_peer_id_public_key_encoded_size(sizeof(public_key), &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(public_key_message));

    assert(
        libp2p_peer_id_public_key_encode(
            public_key,
            sizeof(public_key),
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(public_key_message));
    assert(
        libp2p_peer_id_public_key_encode(
            public_key,
            sizeof(public_key),
            public_key_message,
            sizeof(public_key_message),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(public_key_message));

    assert(
        libp2p_peer_id_public_key_decode(
            public_key_message,
            sizeof(public_key_message),
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(public_key));
    assert(
        libp2p_peer_id_public_key_decode(
            public_key_message,
            sizeof(public_key_message),
            decoded_public_key,
            sizeof(decoded_public_key),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(public_key));
    assert(memcmp(decoded_public_key, public_key, sizeof(public_key)) == 0);

    assert(
        libp2p_peer_id_private_key_encode(
            private_key,
            sizeof(private_key),
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(private_key_message));
    assert(
        libp2p_peer_id_private_key_encode(
            private_key,
            sizeof(private_key),
            private_key_message,
            sizeof(private_key_message),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(private_key_message));

    assert(
        libp2p_peer_id_private_key_decode(
            private_key_message,
            sizeof(private_key_message),
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(private_key));
    assert(
        libp2p_peer_id_private_key_decode(
            private_key_message,
            sizeof(private_key_message),
            decoded_private_key,
            sizeof(decoded_private_key),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(private_key));
    assert(memcmp(decoded_private_key, private_key, sizeof(private_key)) == 0);
}

static void peer_id_unit_test_public_key_derivation_and_peer_id(void)
{
    uint8_t private_key[32];
    uint8_t expected_public_key[33];
    uint8_t derived_public_key[65];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t extracted_public_key[65];
    size_t written = 0U;
    size_t peer_id_len = 0U;

    peer_id_unit_load_spec_private_key(private_key);
    peer_id_unit_load_spec_public_key(expected_public_key);

    assert(
        libp2p_peer_id_public_key_from_private_key(
            private_key,
            sizeof(private_key),
            1,
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(expected_public_key));
    assert(
        libp2p_peer_id_public_key_from_private_key(
            private_key,
            sizeof(private_key),
            1,
            derived_public_key,
            sizeof(derived_public_key),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(expected_public_key));
    assert(memcmp(derived_public_key, expected_public_key, sizeof(expected_public_key)) == 0);

    assert(
        libp2p_peer_id_size_from_secp256k1_public_key(sizeof(expected_public_key), &peer_id_len) ==
        LIBP2P_PEER_ID_OK);
    assert(peer_id_len == 39U);

    assert(
        libp2p_peer_id_from_secp256k1_public_key(
            expected_public_key,
            sizeof(expected_public_key),
            peer_id,
            sizeof(peer_id),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == peer_id_len);
    assert((peer_id[0] == 0x00U) && (peer_id[1] == 0x25U));

    assert(
        libp2p_peer_id_extract_secp256k1_public_key(
            peer_id,
            peer_id_len,
            NULL,
            0U,
            &written) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(expected_public_key));
    assert(
        libp2p_peer_id_extract_secp256k1_public_key(
            peer_id,
            peer_id_len,
            extracted_public_key,
            sizeof(extracted_public_key),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == sizeof(expected_public_key));
    assert(memcmp(extracted_public_key, expected_public_key, sizeof(expected_public_key)) == 0);
}

static void peer_id_unit_test_sha256_peer_id_extract_fails(void)
{
    uint8_t private_key[32];
    uint8_t public_key[65];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t written = 0U;
    size_t peer_id_len = 0U;

    peer_id_unit_load_spec_private_key(private_key);

    assert(
        libp2p_peer_id_public_key_from_private_key(
            private_key,
            sizeof(private_key),
            0,
            public_key,
            sizeof(public_key),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES);

    assert(
        libp2p_peer_id_size_from_secp256k1_public_key(
            LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES,
            &peer_id_len) == LIBP2P_PEER_ID_OK);
    assert(peer_id_len == 34U);

    assert(
        libp2p_peer_id_from_secp256k1_public_key(
            public_key,
            written,
            peer_id,
            sizeof(peer_id),
            &written) == LIBP2P_PEER_ID_OK);
    assert(written == peer_id_len);

    assert(
        libp2p_peer_id_extract_secp256k1_public_key(
            peer_id,
            peer_id_len,
            public_key,
            sizeof(public_key),
            &written) == LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY);
}

static void peer_id_unit_test_sign_and_verify(void)
{
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t hash[32];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    uint8_t message[] = {'l', 'i', 'b', 'p', '2', 'p', '-', 'p', 'e', 'e', 'r', '-', 'i', 'd'};
    size_t signature_len = 0U;

    peer_id_unit_load_spec_private_key(private_key);
    peer_id_unit_load_spec_public_key(public_key);

    (void)memset(hash, 0x5a, sizeof(hash));

    assert(
        libp2p_peer_id_sign_hash(
            private_key,
            sizeof(private_key),
            hash,
            sizeof(hash),
            NULL,
            0U,
            &signature_len) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(signature_len > 0U);
    assert(signature_len <= sizeof(signature));
    assert(
        libp2p_peer_id_sign_hash(
            private_key,
            sizeof(private_key),
            hash,
            sizeof(hash),
            signature,
            sizeof(signature),
            &signature_len) == LIBP2P_PEER_ID_OK);
    assert(signature_len > 0U);
    assert(signature_len <= sizeof(signature));

    assert(
        libp2p_peer_id_verify_hash(
            public_key,
            sizeof(public_key),
            hash,
            sizeof(hash),
            signature,
            signature_len) == LIBP2P_PEER_ID_OK);

    hash[0] ^= 0x01U;
    assert(
        libp2p_peer_id_verify_hash(
            public_key,
            sizeof(public_key),
            hash,
            sizeof(hash),
            signature,
            signature_len) == LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE);
    hash[0] ^= 0x01U;

    assert(
        libp2p_peer_id_sign_message(
            private_key,
            sizeof(private_key),
            message,
            sizeof(message),
            signature,
            sizeof(signature),
            &signature_len) == LIBP2P_PEER_ID_OK);
    assert(
        libp2p_peer_id_verify_message(
            public_key,
            sizeof(public_key),
            message,
            sizeof(message),
            signature,
            signature_len) == LIBP2P_PEER_ID_OK);

    message[0] = (uint8_t)'L';
    assert(
        libp2p_peer_id_verify_message(
            public_key,
            sizeof(public_key),
            message,
            sizeof(message),
            signature,
            signature_len) == LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE);
}

static void peer_id_unit_test_text_round_trip(void)
{
    uint8_t public_key[33];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t parsed_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t cid_bytes[LIBP2P_PEER_ID_MAX_BYTES + 4U];
    char text[LIBP2P_PEER_ID_UNIT_TEXT_MAX_BYTES];
    char cid_text[LIBP2P_PEER_ID_UNIT_TEXT_MAX_BYTES];
    size_t peer_id_len = 0U;
    size_t text_len = 0U;
    size_t cid_len = 0U;
    size_t version_written = 0U;
    size_t codec_written = 0U;
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE64URL;

    peer_id_unit_load_spec_public_key(public_key);

    assert(
        libp2p_peer_id_from_secp256k1_public_key(
            public_key,
            sizeof(public_key),
            peer_id,
            sizeof(peer_id),
            &peer_id_len) == LIBP2P_PEER_ID_OK);

    assert(
        libp2p_peer_id_to_string(
            peer_id,
            peer_id_len,
            NULL,
            0U,
            &text_len) == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL);
    assert(text_len > 0U);
    assert(
        libp2p_peer_id_to_string(
            peer_id,
            peer_id_len,
            text,
            sizeof(text),
            &text_len) == LIBP2P_PEER_ID_OK);
    assert(
        libp2p_peer_id_from_string(
            text,
            text_len,
            parsed_peer_id,
            sizeof(parsed_peer_id),
            &cid_len) == LIBP2P_PEER_ID_OK);
    assert(cid_len == peer_id_len);
    assert(memcmp(parsed_peer_id, peer_id, peer_id_len) == 0);

    assert(
        libp2p_uvarint_encode(
            UINT64_C(1),
            cid_bytes,
            sizeof(cid_bytes),
            &version_written) == LIBP2P_UVARINT_OK);
    assert(
        libp2p_uvarint_encode(
            UINT64_C(0x72),
            &cid_bytes[version_written],
            sizeof(cid_bytes) - version_written,
            &codec_written) == LIBP2P_UVARINT_OK);
    (void)memcpy(&cid_bytes[version_written + codec_written], peer_id, peer_id_len);

    assert(
        libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE64URL,
            cid_bytes,
            version_written + codec_written + peer_id_len,
            cid_text,
            sizeof(cid_text),
            &cid_len) == LIBP2P_MULTIBASE_OK);
    assert(base == LIBP2P_MULTIBASE_BASE64URL);

    assert(
        libp2p_peer_id_from_string(
            cid_text,
            cid_len,
            parsed_peer_id,
            sizeof(parsed_peer_id),
            &text_len) == LIBP2P_PEER_ID_OK);
    assert(text_len == peer_id_len);
    assert(memcmp(parsed_peer_id, peer_id, peer_id_len) == 0);
}

static void peer_id_unit_test_invalid_inputs(void)
{
    uint8_t invalid_private_key[32] = {0U};
    uint8_t invalid_public_key[33] = {0U};
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    uint8_t hash[32];
    uint8_t wrong_type_message[37];
    size_t written = 0U;

    peer_id_unit_load_spec_private_key(private_key);
    peer_id_unit_load_spec_public_key(public_key);
    peer_id_unit_load_spec_public_key_message(wrong_type_message);

    wrong_type_message[1] = 0x01U;
    invalid_public_key[0] = 0x04U;

    assert(
        libp2p_peer_id_private_key_encode(
            invalid_private_key,
            sizeof(invalid_private_key),
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY);

    assert(
        libp2p_peer_id_public_key_encode(
            invalid_public_key,
            sizeof(invalid_public_key),
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY);

    assert(
        libp2p_peer_id_public_key_decode(
            wrong_type_message,
            sizeof(wrong_type_message),
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING);

    (void)memset(hash, 0x11, sizeof(hash));
    assert(
        libp2p_peer_id_sign_hash(
            private_key,
            sizeof(private_key),
            hash,
            sizeof(hash) - 1U,
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH);

    assert(
        libp2p_peer_id_verify_hash(
            public_key,
            sizeof(public_key),
            hash,
            sizeof(hash),
            signature,
            1U) == LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE);

    assert(
        libp2p_peer_id_from_string(
            "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe",
            sizeof("bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe") - 1U,
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING);

    assert(
        libp2p_peer_id_from_string(
            "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA",
            sizeof("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA") - 1U,
            signature,
            sizeof(signature),
            &written) == LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING);
}

int main(void)
{
    peer_id_unit_test_zeroize();
    peer_id_unit_test_key_encode_decode_vectors();
    peer_id_unit_test_public_key_derivation_and_peer_id();
    peer_id_unit_test_sha256_peer_id_extract_fails();
    peer_id_unit_test_sign_and_verify();
    peer_id_unit_test_text_round_trip();
    peer_id_unit_test_invalid_inputs();
    return 0;
}
