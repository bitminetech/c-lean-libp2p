#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "transport/quic/quic_identity.h"

static int quic_identity_hex_nibble(char character, uint8_t *value)
{
    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'a'));
        return 1;
    }
    if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'A'));
        return 1;
    }

    *value = 0U;
    return 0;
}

static void quic_identity_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = strlen(text);
    size_t index = 0U;

    assert((text_len % 2U) == 0U);
    assert((text_len / 2U) <= out_capacity);

    for (index = 0U; index < text_len; index += 2U)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        assert(quic_identity_hex_nibble(text[index], &high) != 0);
        assert(quic_identity_hex_nibble(text[index + 1U], &low) != 0);
        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
}

static void quic_identity_load_private_key(uint8_t private_key[32])
{
    static const char private_key_hex[] =
        "53DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB";
    size_t written = 0U;

    quic_identity_parse_hex(private_key_hex, private_key, 32U, &written);
    assert(written == 32U);
}

static void quic_identity_load_public_key_message(uint8_t public_key_message[37])
{
    static const char public_key_message_hex[] =
        "08021221037777E994E452C21604F91DE093CE415F5432F701DD8CD1A7A6FEA0E630BFCA99";
    size_t written = 0U;

    quic_identity_parse_hex(public_key_message_hex, public_key_message, 37U, &written);
    assert(written == 37U);
}

static libp2p_quic_err_t quic_identity_test_random(uint8_t *out, size_t out_len, void *user_data)
{
    size_t index = 0U;
    uint8_t *state = (uint8_t *)user_data;

    assert(out != NULL);
    assert(state != NULL);

    for (index = 0U; index < out_len; index++)
    {
        out[index] = *state;
        *state = (uint8_t)(*state + 17U);
    }

    return LIBP2P_QUIC_OK;
}

static void quic_identity_load_host_key(
    uint8_t private_key[32],
    uint8_t public_key_message[37],
    libp2p_quic_host_key_t *host_key)
{
    quic_identity_load_private_key(private_key);
    quic_identity_load_public_key_message(public_key_message);

    host_key->type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
    host_key->private_key = private_key;
    host_key->private_key_len = 32U;
    host_key->public_key_message = public_key_message;
    host_key->public_key_message_len = 37U;
}

static void quic_identity_test_host_key_peer_id(void)
{
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t written = 0U;
    libp2p_quic_host_key_t host_key;

    quic_identity_load_host_key(private_key, public_key_message, &host_key);

    assert(libp2p_quic_host_key_validate(&host_key) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_host_key_peer_id(&host_key, NULL, 0U, &written) ==
        LIBP2P_QUIC_ERR_BUF_TOO_SMALL);
    assert(written == 39U);
    assert(
        libp2p_quic_host_key_peer_id(&host_key, peer_id, sizeof(peer_id), &written) ==
        LIBP2P_QUIC_OK);
    assert(written == 39U);
}

static void quic_identity_test_signing_payload(void)
{
    static const uint8_t spki[] = {0x30U, 0x03U, 0x02U, 0x01U, 0x05U};
    uint8_t out[64];
    size_t written = 0U;

    assert(libp2p_quic_identity_signing_payload_size(sizeof(spki), &written) == LIBP2P_QUIC_OK);
    assert(written == (LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN + sizeof(spki)));
    assert(
        libp2p_quic_identity_write_signing_payload(spki, sizeof(spki), out, 8U, &written) ==
        LIBP2P_QUIC_ERR_BUF_TOO_SMALL);
    assert(
        libp2p_quic_identity_write_signing_payload(
            spki,
            sizeof(spki),
            out,
            sizeof(out),
            &written) == LIBP2P_QUIC_OK);
    assert(memcmp(out, LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX, 21U) == 0);
    assert(memcmp(&out[21], spki, sizeof(spki)) == 0);
}

static void quic_identity_test_signed_key_der_roundtrip(void)
{
    uint8_t public_key_message[37];
    const uint8_t signature[3] = {0xaaU, 0xbbU, 0xccU};
    uint8_t der[64];
    uint8_t decoded_public_key[64];
    uint8_t decoded_signature[8];
    size_t der_len = 0U;
    size_t public_key_len = 0U;
    size_t signature_len = 0U;

    quic_identity_load_public_key_message(public_key_message);

    assert(
        libp2p_quic_identity_encode_signed_key_der(
            public_key_message,
            sizeof(public_key_message),
            signature,
            sizeof(signature),
            der,
            sizeof(der),
            &der_len) == LIBP2P_QUIC_OK);
    assert(der_len == 46U);
    assert(der[0] == 0x30U);
    assert(der[1] == 0x2cU);
    assert(der[2] == 0x04U);
    assert(der[3] == 0x25U);
    assert(der[41] == 0x04U);
    assert(der[42] == 0x03U);

    assert(
        libp2p_quic_identity_decode_signed_key_der(
            der,
            der_len,
            decoded_public_key,
            sizeof(decoded_public_key),
            &public_key_len,
            decoded_signature,
            sizeof(decoded_signature),
            &signature_len) == LIBP2P_QUIC_OK);
    assert(public_key_len == sizeof(public_key_message));
    assert(signature_len == sizeof(signature));
    assert(memcmp(decoded_public_key, public_key_message, sizeof(public_key_message)) == 0);
    assert(memcmp(decoded_signature, signature, sizeof(signature)) == 0);
}

static void quic_identity_test_signed_key_long_form(void)
{
    uint8_t public_key_message[37];
    uint8_t signature[130];
    uint8_t der[192];
    uint8_t decoded_public_key[64];
    uint8_t decoded_signature[140];
    size_t der_len = 0U;
    size_t public_key_len = 0U;
    size_t signature_len = 0U;
    size_t index = 0U;

    quic_identity_load_public_key_message(public_key_message);
    for (index = 0U; index < sizeof(signature); index++)
    {
        signature[index] = (uint8_t)index;
    }

    assert(
        libp2p_quic_identity_encode_signed_key_der(
            public_key_message,
            sizeof(public_key_message),
            signature,
            sizeof(signature),
            der,
            sizeof(der),
            &der_len) == LIBP2P_QUIC_OK);
    assert(der[0] == 0x30U);
    assert(der[1] == 0x81U);
    assert(der[2] == 0xacU);

    assert(
        libp2p_quic_identity_decode_signed_key_der(
            der,
            der_len,
            decoded_public_key,
            sizeof(decoded_public_key),
            &public_key_len,
            decoded_signature,
            sizeof(decoded_signature),
            &signature_len) == LIBP2P_QUIC_OK);
    assert(public_key_len == sizeof(public_key_message));
    assert(signature_len == sizeof(signature));
    assert(memcmp(decoded_signature, signature, sizeof(signature)) == 0);
}

static void quic_identity_test_rejects_bad_der(void)
{
    const uint8_t non_minimal[] = {0x30U, 0x81U, 0x7fU};
    const uint8_t trailing[] = {0x30U, 0x00U, 0x00U};
    uint8_t public_key[8];
    uint8_t signature[8];
    size_t public_key_len = 0U;
    size_t signature_len = 0U;

    assert(
        libp2p_quic_identity_decode_signed_key_der(
            non_minimal,
            sizeof(non_minimal),
            public_key,
            sizeof(public_key),
            &public_key_len,
            signature,
            sizeof(signature),
            &signature_len) == LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION);
    assert(
        libp2p_quic_identity_decode_signed_key_der(
            trailing,
            sizeof(trailing),
            public_key,
            sizeof(public_key),
            &public_key_len,
            signature,
            sizeof(signature),
            &signature_len) == LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION);
}

static void quic_identity_test_certificate_roundtrip(void)
{
    uint8_t private_key[32];
    uint8_t public_key_message[37];
    uint8_t cert[LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES];
    uint8_t cert_key[LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t derived_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t random_state = 9U;
    size_t cert_len = 0U;
    size_t key_len = 0U;
    size_t peer_id_len = 0U;
    size_t derived_peer_id_len = 0U;
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t config;
    libp2p_quic_peer_identity_t peer;
    libp2p_quic_certificate_report_t report;
    libp2p_quic_const_buffer_t chain[1];
    libp2p_quic_local_identity_t identity;

    quic_identity_load_host_key(private_key, public_key_message, &host_key);

    config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
    config.not_before_unix_seconds = UINT64_C(1700000000);
    config.not_after_unix_seconds = UINT64_C(1800000000);
    config.random_fn = quic_identity_test_random;
    config.random_user_data = &random_state;

    assert(
        libp2p_quic_identity_write_certificate_der(
            &host_key,
            &config,
            NULL,
            0U,
            &cert_len,
            NULL,
            0U,
            &key_len) == LIBP2P_QUIC_ERR_BUF_TOO_SMALL);
    assert(cert_len > 0U);
    assert(key_len > 0U);
    assert(cert_len <= sizeof(cert));
    assert(key_len <= sizeof(cert_key));

    random_state = 9U;
    assert(
        libp2p_quic_identity_write_certificate_der(
            &host_key,
            &config,
            cert,
            sizeof(cert),
            &cert_len,
            cert_key,
            sizeof(cert_key),
            &key_len) == LIBP2P_QUIC_OK);

    assert(
        libp2p_quic_host_key_peer_id(&host_key, peer_id, sizeof(peer_id), &peer_id_len) ==
        LIBP2P_QUIC_OK);

    chain[0].data = cert;
    chain[0].len = cert_len;
    assert(
        libp2p_quic_identity_verify_peer_certificate_chain(
            chain,
            1U,
            peer_id,
            peer_id_len,
            UINT64_C(1750000000),
            &peer,
            &report) == LIBP2P_QUIC_OK);
    assert(report.self_signature_valid == 1U);
    assert(report.libp2p_extension_present == 1U);
    assert(report.unknown_critical_extension_present == 0U);
    assert(peer.peer_id_len == peer_id_len);
    assert(memcmp(peer.peer_id, peer_id, peer_id_len) == 0);
    assert(peer.host_public_key_message_len == sizeof(public_key_message));
    assert(
        memcmp(peer.host_public_key_message, public_key_message, sizeof(public_key_message)) == 0);
    assert(peer.not_before_unix_seconds == config.not_before_unix_seconds);
    assert(peer.not_after_unix_seconds == config.not_after_unix_seconds);

    assert(
        libp2p_quic_identity_verify_peer_certificate(
            cert,
            cert_len,
            peer_id,
            peer_id_len - 1U,
            UINT64_C(1750000000),
            NULL) == LIBP2P_QUIC_ERR_PEER_ID_MISMATCH);
    assert(
        libp2p_quic_identity_verify_peer_certificate(
            cert,
            cert_len,
            peer_id,
            peer_id_len,
            UINT64_C(1800000001),
            NULL) == LIBP2P_QUIC_ERR_CERTIFICATE_TIME);

    identity.certificate_der = cert;
    identity.certificate_der_len = cert_len;
    identity.certificate_private_key_der = cert_key;
    identity.certificate_private_key_der_len = key_len;
    identity.peer_id = NULL;
    identity.peer_id_len = 0U;

    assert(libp2p_quic_local_identity_validate(&identity) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_local_identity_peer_id(
            &identity,
            derived_peer_id,
            sizeof(derived_peer_id),
            &derived_peer_id_len) == LIBP2P_QUIC_OK);
    assert(derived_peer_id_len == peer_id_len);
    assert(memcmp(derived_peer_id, peer_id, peer_id_len) == 0);
}

int main(void)
{
    quic_identity_test_host_key_peer_id();
    quic_identity_test_signing_payload();
    quic_identity_test_signed_key_der_roundtrip();
    quic_identity_test_signed_key_long_form();
    quic_identity_test_rejects_bad_der();
    quic_identity_test_certificate_roundtrip();

    return 0;
}
