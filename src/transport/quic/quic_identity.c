/**
 * @file quic_identity.c
 * @brief libp2p QUIC TLS identity helpers.
 */

#include "transport/quic/quic_identity.h"

#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/x509.h>
#include <string.h>

#define QUIC_IDENTITY_DER_SEQUENCE      0x30U
#define QUIC_IDENTITY_DER_OCTET_STRING  0x04U
#define QUIC_IDENTITY_DER_LONG_FORM_BIT 0x80U

#define QUIC_IDENTITY_CERT_SPKI_MAX_BYTES 256U
#define QUIC_IDENTITY_SIGNING_PAYLOAD_BYTES \
    (LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN + QUIC_IDENTITY_CERT_SPKI_MAX_BYTES)
#define QUIC_IDENTITY_CERT_RANDOM_SERIAL_LEN 8U

static libp2p_quic_err_t quic_identity_peer_id_err(libp2p_peer_id_err_t err)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_CERTIFICATE;

    switch (err)
    {
    case LIBP2P_PEER_ID_OK:
        result = LIBP2P_QUIC_OK;
        break;
    case LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL:
        result = LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
        break;
    case LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY:
    case LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY:
    case LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING:
    case LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING:
    case LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY:
    case LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH:
    case LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE:
    case LIBP2P_PEER_ID_ERR_INVALID_PEER_ID:
    default:
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
        break;
    }

    return result;
}

static int quic_identity_add_overflow(size_t a, size_t b, size_t *out)
{
    if ((SIZE_MAX - a) < b)
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a + b;
    return 0;
}

static size_t quic_identity_der_length_size(size_t len)
{
    size_t size = 1U;

    if (len >= 128U)
    {
        size_t value = len;

        size = 1U;
        do
        {
            size++;
            value >>= 8U;
        } while (value != 0U);
    }

    return size;
}

static libp2p_quic_err_t quic_identity_der_tlv_size(size_t value_len, size_t *out_len)
{
    size_t total = 0U;

    if (out_len == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (quic_identity_add_overflow(1U, quic_identity_der_length_size(value_len), &total) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }
    if (quic_identity_add_overflow(total, value_len, &total) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    *out_len = total;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_der_write_length(
    size_t len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = quic_identity_der_length_size(len);

    if (written != NULL)
    {
        *written = required;
    }
    if (out_len < required)
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    if (len < 128U)
    {
        out[0] = (uint8_t)len;
    }
    else
    {
        const size_t len_bytes = required - 1U;

        out[0] = (uint8_t)(QUIC_IDENTITY_DER_LONG_FORM_BIT | (uint8_t)len_bytes);
        for (size_t index = 0U; index < len_bytes; index++)
        {
            const size_t shift = (len_bytes - 1U - index) * 8U;
            out[index + 1U] = (uint8_t)(len >> shift);
        }
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_der_write_tlv(
    uint8_t tag,
    const uint8_t *value,
    size_t value_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t len_written = 0U;
    size_t required = 0U;
    libp2p_quic_err_t result = quic_identity_der_tlv_size(value_len, &required);

    if (written != NULL)
    {
        *written = required;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (((value == NULL) && (value_len != 0U)) || (out == NULL))
    {
        return (out == NULL) ? LIBP2P_QUIC_ERR_BUF_TOO_SMALL : LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (out_len < required)
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    out[0] = tag;
    result = quic_identity_der_write_length(value_len, &out[1], out_len - 1U, &len_written);
    if (result == LIBP2P_QUIC_OK)
    {
        (void)memcpy(&out[1U + len_written], value, value_len);
    }

    return result;
}

static libp2p_quic_err_t quic_identity_der_read_length(
    const uint8_t *in,
    size_t in_len,
    size_t *value_len,
    size_t *consumed)
{
    size_t len_bytes = 0U;
    size_t index = 0U;
    size_t parsed = 0U;

    if ((in == NULL) || (value_len == NULL) || (consumed == NULL) || (in_len == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if ((in[0] & QUIC_IDENTITY_DER_LONG_FORM_BIT) == 0U)
    {
        *value_len = (size_t)in[0];
        *consumed = 1U;
        return LIBP2P_QUIC_OK;
    }

    len_bytes = (size_t)(in[0] & 0x7fU);
    if ((len_bytes == 0U) || (len_bytes > sizeof(size_t)) || ((1U + len_bytes) > in_len))
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }
    if (in[1] == 0U)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }

    for (index = 0U; index < len_bytes; index++)
    {
        parsed = (parsed << 8U) | ((size_t)in[1U + index]);
    }
    if (parsed < 128U)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }

    *value_len = parsed;
    *consumed = 1U + len_bytes;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_der_read_tlv(
    const uint8_t *in,
    size_t in_len,
    uint8_t expected_tag,
    const uint8_t **value,
    size_t *value_len,
    size_t *consumed)
{
    size_t len_consumed = 0U;
    size_t total = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((in == NULL) || (value == NULL) || (value_len == NULL) || (consumed == NULL) ||
        (in_len < 2U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (in[0] != expected_tag)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }

    result = quic_identity_der_read_length(&in[1], in_len - 1U, value_len, &len_consumed);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (quic_identity_add_overflow(1U + len_consumed, *value_len, &total) != 0)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }
    if (total > in_len)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;
    }

    *value = &in[1U + len_consumed];
    *consumed = total;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_public_key_message_to_raw(
    const uint8_t *public_key_message,
    size_t public_key_message_len,
    uint8_t raw_public_key[LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES],
    size_t *raw_public_key_len)
{
    libp2p_peer_id_err_t err = LIBP2P_PEER_ID_OK;

    err = libp2p_peer_id_public_key_decode(
        public_key_message,
        public_key_message_len,
        raw_public_key,
        LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES,
        raw_public_key_len);

    return quic_identity_peer_id_err(err);
}

static libp2p_quic_err_t quic_identity_copy_measure(
    const uint8_t *src,
    size_t src_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    if (written == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *written = src_len;
    if ((out == NULL) || (out_len < src_len))
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    if (src_len != 0U)
    {
        (void)memcpy(out, src, src_len);
    }

    return LIBP2P_QUIC_OK;
}

static void quic_identity_zero_peer_identity(libp2p_quic_peer_identity_t *out)
{
    if (out != NULL)
    {
        (void)memset(out, 0, sizeof(*out));
    }
}

static uint64_t quic_identity_load_u64_be(const uint8_t bytes[8])
{
    size_t index = 0U;
    uint64_t value = 0U;

    for (index = 0U; index < 8U; index++)
    {
        value = (value << 8U) | (uint64_t)bytes[index];
    }

    return value;
}

static libp2p_quic_err_t quic_identity_random_serial(
    const libp2p_quic_certificate_config_t *config,
    uint64_t *out_serial)
{
    uint8_t serial_bytes[QUIC_IDENTITY_CERT_RANDOM_SERIAL_LEN];
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((config == NULL) || (config->random_fn == NULL) || (out_serial == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = config->random_fn(serial_bytes, sizeof(serial_bytes), config->random_user_data);
    if (result != LIBP2P_QUIC_OK)
    {
        (void)memset(serial_bytes, 0, sizeof(serial_bytes));
        return result;
    }

    *out_serial = quic_identity_load_u64_be(serial_bytes);
    if (*out_serial == 0U)
    {
        *out_serial = 1U;
    }
    (void)memset(serial_bytes, 0, sizeof(serial_bytes));

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_pkey_spki_der(
    const EVP_PKEY *pkey,
    uint8_t out[QUIC_IDENTITY_CERT_SPKI_MAX_BYTES],
    size_t *out_len)
{
    uint8_t *cursor = out;
    int len = 0;

    if ((pkey == NULL) || (out == NULL) || (out_len == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE;
    }
    if ((size_t)len > QUIC_IDENTITY_CERT_SPKI_MAX_BYTES)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    if (i2d_PUBKEY(pkey, &cursor) != len)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE;
    }

    *out_len = (size_t)len;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_write_pkey_signing_payload(
    const EVP_PKEY *pkey,
    uint8_t payload[QUIC_IDENTITY_SIGNING_PAYLOAD_BYTES],
    size_t *payload_len)
{
    uint8_t spki[QUIC_IDENTITY_CERT_SPKI_MAX_BYTES];
    size_t spki_len = 0U;
    size_t written = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((pkey == NULL) || (payload == NULL) || (payload_len == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_identity_pkey_spki_der(pkey, spki, &spki_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    result = libp2p_quic_identity_write_signing_payload(
        spki,
        spki_len,
        payload,
        QUIC_IDENTITY_SIGNING_PAYLOAD_BYTES,
        &written);
    if (result == LIBP2P_QUIC_OK)
    {
        *payload_len = written;
    }

    (void)memset(spki, 0, sizeof(spki));
    return result;
}

static libp2p_quic_err_t quic_identity_generate_certificate_key(EVP_PKEY **out_key)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;

    if (out_key == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    pkey = EVP_PKEY_new();
    if ((ec_key == NULL) || (pkey == NULL) || (EC_KEY_generate_key(ec_key) != 1) ||
        (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1))
    {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        *out_key = NULL;
        return LIBP2P_QUIC_ERR_TLS;
    }

    ec_key = NULL;
    *out_key = pkey;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_config_validate(
    const libp2p_quic_certificate_config_t *config)
{
    if (config == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (config->certificate_key_type != LIBP2P_QUIC_CERT_KEY_ECDSA_P256)
    {
        return LIBP2P_QUIC_ERR_UNSUPPORTED;
    }
    if ((config->random_fn == NULL) ||
        (config->not_before_unix_seconds >= config->not_after_unix_seconds))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((config->not_before_unix_seconds > (uint64_t)INT64_MAX) ||
        (config->not_after_unix_seconds > (uint64_t)INT64_MAX))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_identity_add_libp2p_extension(
    X509 *cert,
    const uint8_t *signed_key_der,
    size_t signed_key_der_len)
{
    ASN1_OBJECT *oid = NULL;
    ASN1_OCTET_STRING *value = NULL;
    X509_EXTENSION *extension = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_TLS;

    if ((cert == NULL) || (signed_key_der == NULL) || (signed_key_der_len == 0U) ||
        (signed_key_der_len > INT_MAX))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    oid = OBJ_txt2obj(LIBP2P_QUIC_TLS_PUBLIC_KEY_EXTENSION_OID, 1);
    value = ASN1_OCTET_STRING_new();
    if ((oid == NULL) || (value == NULL) ||
        (ASN1_OCTET_STRING_set(value, signed_key_der, (int)signed_key_der_len) != 1))
    {
        goto cleanup;
    }

    extension = X509_EXTENSION_create_by_OBJ(NULL, oid, 0, value);
    if ((extension == NULL) || (X509_add_ext(cert, extension, -1) != 1))
    {
        goto cleanup;
    }

    result = LIBP2P_QUIC_OK;

cleanup:
    X509_EXTENSION_free(extension);
    ASN1_OCTET_STRING_free(value);
    ASN1_OBJECT_free(oid);
    return result;
}

static libp2p_quic_err_t quic_identity_set_certificate_fields(
    X509 *cert,
    EVP_PKEY *certificate_key,
    const libp2p_quic_certificate_config_t *config,
    uint64_t serial)
{
    X509_NAME *name = NULL;
    ASN1_TIME *not_before = NULL;
    ASN1_TIME *not_after = NULL;
    static const uint8_t organization[] = {'l', 'i', 'b', 'p', '2', 'p', '.', 'i', 'o'};
    static const uint8_t common_name[] =
        {'c', '-', 'l', 'e', 'a', 'n', '-', 'l', 'i', 'b', 'p', '2', 'p', ' ', 'Q', 'U', 'I', 'C'};
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_TLS;

    if ((cert == NULL) || (certificate_key == NULL) || (config == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    name = X509_NAME_new();
    not_before = ASN1_TIME_set_posix(NULL, (int64_t)config->not_before_unix_seconds);
    not_after = ASN1_TIME_set_posix(NULL, (int64_t)config->not_after_unix_seconds);
    if ((name == NULL) || (not_before == NULL) || (not_after == NULL))
    {
        goto cleanup;
    }

    if ((X509_NAME_add_entry_by_txt(
             name,
             "O",
             MBSTRING_ASC,
             organization,
             (ossl_ssize_t)sizeof(organization),
             -1,
             0) != 1) ||
        (X509_NAME_add_entry_by_txt(
             name,
             "CN",
             MBSTRING_ASC,
             common_name,
             (ossl_ssize_t)sizeof(common_name),
             -1,
             0) != 1))
    {
        goto cleanup;
    }

    if ((X509_set_version(cert, X509_VERSION_3) != 1) ||
        (ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), serial) != 1) ||
        (X509_set1_notBefore(cert, not_before) != 1) ||
        (X509_set1_notAfter(cert, not_after) != 1) || (X509_set_subject_name(cert, name) != 1) ||
        (X509_set_issuer_name(cert, name) != 1) || (X509_set_pubkey(cert, certificate_key) != 1))
    {
        goto cleanup;
    }

    result = LIBP2P_QUIC_OK;

cleanup:
    ASN1_TIME_free(not_after);
    ASN1_TIME_free(not_before);
    X509_NAME_free(name);
    return result;
}

static libp2p_quic_err_t quic_identity_signed_key_for_certificate(
    const libp2p_quic_host_key_t *host_key,
    const EVP_PKEY *certificate_key,
    uint8_t signed_key_der[LIBP2P_QUIC_SIGNED_PUBLIC_KEY_MAX_BYTES],
    size_t *signed_key_der_len)
{
    uint8_t payload[QUIC_IDENTITY_SIGNING_PAYLOAD_BYTES];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    size_t payload_len = 0U;
    size_t signature_len = 0U;
    libp2p_peer_id_err_t peer_err = LIBP2P_PEER_ID_OK;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((host_key == NULL) || (certificate_key == NULL) || (signed_key_der == NULL) ||
        (signed_key_der_len == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_identity_write_pkey_signing_payload(certificate_key, payload, &payload_len);
    if (result != LIBP2P_QUIC_OK)
    {
        goto cleanup;
    }

    peer_err = libp2p_peer_id_sign_message(
        host_key->private_key,
        host_key->private_key_len,
        payload,
        payload_len,
        signature,
        sizeof(signature),
        &signature_len);
    result = quic_identity_peer_id_err(peer_err);
    if (result != LIBP2P_QUIC_OK)
    {
        goto cleanup;
    }

    result = libp2p_quic_identity_encode_signed_key_der(
        host_key->public_key_message,
        host_key->public_key_message_len,
        signature,
        signature_len,
        signed_key_der,
        LIBP2P_QUIC_SIGNED_PUBLIC_KEY_MAX_BYTES,
        signed_key_der_len);

cleanup:
    (void)memset(payload, 0, sizeof(payload));
    (void)memset(signature, 0, sizeof(signature));
    return result;
}

static libp2p_quic_err_t quic_identity_write_der_outputs(
    X509 *cert,
    const EVP_PKEY *key,
    uint8_t *cert_out,
    size_t cert_out_len,
    size_t *cert_written,
    uint8_t *key_out,
    size_t key_out_len,
    size_t *key_written)
{
    uint8_t *cert_cursor = cert_out;
    uint8_t *key_cursor = key_out;
    int cert_len = 0;
    int key_len = 0;

    if ((cert == NULL) || (key == NULL) || (cert_written == NULL) || (key_written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    cert_len = i2d_X509(cert, NULL);
    key_len = i2d_PrivateKey(key, NULL);
    if ((cert_len <= 0) || (key_len <= 0))
    {
        return LIBP2P_QUIC_ERR_TLS;
    }
    if (((size_t)cert_len > LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES) ||
        ((size_t)key_len > LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    *cert_written = (size_t)cert_len;
    *key_written = (size_t)key_len;
    if ((cert_out == NULL) || (cert_out_len < (size_t)cert_len) || (key_out == NULL) ||
        (key_out_len < (size_t)key_len))
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    if ((i2d_X509(cert, &cert_cursor) != cert_len) || (i2d_PrivateKey(key, &key_cursor) != key_len))
    {
        return LIBP2P_QUIC_ERR_TLS;
    }

    return LIBP2P_QUIC_OK;
}

static int quic_identity_cert_time_status(
    const X509 *cert,
    uint64_t current_unix_seconds,
    uint64_t *out_not_before,
    uint64_t *out_not_after)
{
    int64_t not_before = 0;
    int64_t not_after = 0;

    if ((cert == NULL) || (ASN1_TIME_to_posix(X509_get0_notBefore(cert), &not_before) != 1) ||
        (ASN1_TIME_to_posix(X509_get0_notAfter(cert), &not_after) != 1) || (not_before < 0) ||
        (not_after < 0) || (not_before > not_after))
    {
        return -1;
    }

    if (out_not_before != NULL)
    {
        *out_not_before = (uint64_t)not_before;
    }
    if (out_not_after != NULL)
    {
        *out_not_after = (uint64_t)not_after;
    }

    return (((uint64_t)not_before <= current_unix_seconds) &&
            (current_unix_seconds <= (uint64_t)not_after))
               ? 1
               : 0;
}

static libp2p_quic_err_t quic_identity_extract_extension(
    X509 *cert,
    const uint8_t **out_signed_key_der,
    size_t *out_signed_key_der_len,
    libp2p_quic_certificate_report_t *report)
{
    ASN1_OBJECT *libp2p_oid = NULL;
    const uint8_t *extension_data = NULL;
    size_t extension_data_len = 0U;
    int extension_count = 0;
    int index = 0;
    int found_count = 0;
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION;

    if ((cert == NULL) || (out_signed_key_der == NULL) || (out_signed_key_der_len == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    libp2p_oid = OBJ_txt2obj(LIBP2P_QUIC_TLS_PUBLIC_KEY_EXTENSION_OID, 1);
    if (libp2p_oid == NULL)
    {
        return LIBP2P_QUIC_ERR_TLS;
    }

    extension_count = X509_get_ext_count(cert);
    if (extension_count < 0)
    {
        goto cleanup;
    }

    if ((X509_get_extension_flags(cert) & EXFLAG_INVALID) != 0U)
    {
        goto cleanup;
    }

    for (index = 0; index < extension_count; index++)
    {
        X509_EXTENSION *extension = X509_get_ext(cert, index);
        ASN1_OBJECT *object = NULL;
        ASN1_OCTET_STRING *data = NULL;
        const int is_critical = (extension != NULL) ? X509_EXTENSION_get_critical(extension) : 0;

        if (extension == NULL)
        {
            goto cleanup;
        }

        object = X509_EXTENSION_get_object(extension);
        if (OBJ_cmp(object, libp2p_oid) == 0)
        {
            data = X509_EXTENSION_get_data(extension);
            found_count++;
            if (report != NULL)
            {
                report->libp2p_extension_present = 1U;
                report->libp2p_extension_critical = (uint8_t)(is_critical != 0);
            }
            if ((data == NULL) || (ASN1_STRING_length(data) <= 0))
            {
                goto cleanup;
            }
            extension_data = ASN1_STRING_get0_data(data);
            extension_data_len = (size_t)ASN1_STRING_length(data);
        }
        else if (is_critical != 0)
        {
            if (report != NULL)
            {
                report->unknown_critical_extension_present = 1U;
            }
            goto cleanup;
        }
        else
        {
            /* Non-critical extension with an OID this layer does not need. */
        }
    }

    if ((found_count != 1) || (extension_data == NULL) || (extension_data_len == 0U))
    {
        goto cleanup;
    }

    *out_signed_key_der = extension_data;
    *out_signed_key_der_len = extension_data_len;
    result = LIBP2P_QUIC_OK;

cleanup:
    ASN1_OBJECT_free(libp2p_oid);
    return result;
}

static libp2p_quic_err_t quic_identity_verify_signed_key(
    const EVP_PKEY *certificate_key,
    const uint8_t *signed_key_der,
    size_t signed_key_der_len,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t not_before_unix_seconds,
    uint64_t not_after_unix_seconds,
    libp2p_quic_peer_identity_t *out)
{
    uint8_t public_key_message[LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    uint8_t raw_public_key[LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    uint8_t payload[QUIC_IDENTITY_SIGNING_PAYLOAD_BYTES];
    size_t public_key_message_len = 0U;
    size_t signature_len = 0U;
    size_t raw_public_key_len = 0U;
    size_t peer_id_len = 0U;
    size_t payload_len = 0U;
    libp2p_peer_id_err_t peer_err = LIBP2P_PEER_ID_OK;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((certificate_key == NULL) || (signed_key_der == NULL) || (signed_key_der_len == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = libp2p_quic_identity_decode_signed_key_der(
        signed_key_der,
        signed_key_der_len,
        public_key_message,
        sizeof(public_key_message),
        &public_key_message_len,
        signature,
        sizeof(signature),
        &signature_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    result = quic_identity_public_key_message_to_raw(
        public_key_message,
        public_key_message_len,
        raw_public_key,
        &raw_public_key_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    result = quic_identity_write_pkey_signing_payload(certificate_key, payload, &payload_len);
    if (result != LIBP2P_QUIC_OK)
    {
        goto cleanup;
    }

    peer_err = libp2p_peer_id_verify_message(
        raw_public_key,
        raw_public_key_len,
        payload,
        payload_len,
        signature,
        signature_len);
    if (peer_err != LIBP2P_PEER_ID_OK)
    {
        result = LIBP2P_QUIC_ERR_CERTIFICATE_SIGNATURE;
        goto cleanup;
    }

    peer_err = libp2p_peer_id_from_secp256k1_public_key(
        raw_public_key,
        raw_public_key_len,
        peer_id,
        sizeof(peer_id),
        &peer_id_len);
    if (peer_err != LIBP2P_PEER_ID_OK)
    {
        result = quic_identity_peer_id_err(peer_err);
        goto cleanup;
    }

    if (expected_peer_id_len != 0U)
    {
        if ((expected_peer_id == NULL) || (expected_peer_id_len != peer_id_len) ||
            (memcmp(expected_peer_id, peer_id, peer_id_len) != 0))
        {
            result = LIBP2P_QUIC_ERR_PEER_ID_MISMATCH;
            goto cleanup;
        }
    }

    if (out != NULL)
    {
        quic_identity_zero_peer_identity(out);
        out->host_key_type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
        (void)memcpy(out->peer_id, peer_id, peer_id_len);
        out->peer_id_len = peer_id_len;
        (void)memcpy(out->host_public_key_message, public_key_message, public_key_message_len);
        out->host_public_key_message_len = public_key_message_len;
        out->not_before_unix_seconds = not_before_unix_seconds;
        out->not_after_unix_seconds = not_after_unix_seconds;
    }

cleanup:
    (void)memset(public_key_message, 0, sizeof(public_key_message));
    (void)memset(signature, 0, sizeof(signature));
    (void)memset(raw_public_key, 0, sizeof(raw_public_key));
    (void)memset(peer_id, 0, sizeof(peer_id));
    (void)memset(payload, 0, sizeof(payload));
    return result;
}

static libp2p_quic_err_t quic_identity_verify_peer_certificate_internal(
    const uint8_t *certificate_der,
    size_t certificate_der_len,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t current_unix_seconds,
    int check_time,
    libp2p_quic_peer_identity_t *out,
    libp2p_quic_certificate_report_t *report)
{
    const uint8_t *cursor = certificate_der;
    X509 *cert = NULL;
    EVP_PKEY *public_key = NULL;
    const uint8_t *signed_key_der = NULL;
    size_t signed_key_der_len = 0U;
    uint64_t not_before = 0U;
    uint64_t not_after = 0U;
    const ASN1_BIT_STRING *issuer_uid = NULL;
    const ASN1_BIT_STRING *subject_uid = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (report != NULL)
    {
        (void)memset(report, 0, sizeof(*report));
    }
    quic_identity_zero_peer_identity(out);

    if ((certificate_der == NULL) || (certificate_der_len == 0U) ||
        (certificate_der_len > LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES) ||
        (certificate_der_len > (size_t)LONG_MAX))
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE;
    }
    if ((expected_peer_id == NULL) && (expected_peer_id_len != 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    cert = d2i_X509(NULL, &cursor, (long)certificate_der_len);
    if ((cert == NULL) || (cursor != &certificate_der[certificate_der_len]))
    {
        result = LIBP2P_QUIC_ERR_CERTIFICATE;
        goto cleanup;
    }

    X509_get0_uids(cert, &issuer_uid, &subject_uid);
    if (report != NULL)
    {
        report->issuer_unique_id_present = (uint8_t)(issuer_uid != NULL);
        report->subject_unique_id_present = (uint8_t)(subject_uid != NULL);
    }
    if ((issuer_uid != NULL) || (subject_uid != NULL))
    {
        result = LIBP2P_QUIC_ERR_CERTIFICATE;
        goto cleanup;
    }

    public_key = X509_get_pubkey(cert);
    if ((public_key == NULL) ||
        (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) != 0) ||
        (X509_verify(cert, public_key) != 1))
    {
        result = LIBP2P_QUIC_ERR_CERTIFICATE_SIGNATURE;
        goto cleanup;
    }
    if (report != NULL)
    {
        report->self_signature_valid = 1U;
    }

    {
        const int time_status =
            quic_identity_cert_time_status(cert, current_unix_seconds, &not_before, &not_after);

        if ((time_status < 0) || ((check_time != 0) && (time_status == 0)))
        {
            result = LIBP2P_QUIC_ERR_CERTIFICATE_TIME;
            goto cleanup;
        }
    }

    result = quic_identity_extract_extension(cert, &signed_key_der, &signed_key_der_len, report);
    if (result != LIBP2P_QUIC_OK)
    {
        goto cleanup;
    }

    result = quic_identity_verify_signed_key(
        public_key,
        signed_key_der,
        signed_key_der_len,
        expected_peer_id,
        expected_peer_id_len,
        not_before,
        not_after,
        out);

cleanup:
    EVP_PKEY_free(public_key);
    X509_free(cert);
    return result;
}

libp2p_quic_err_t libp2p_quic_host_key_validate(const libp2p_quic_host_key_t *host_key)
{
    uint8_t raw_public_key[LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    uint8_t signature[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
    static const uint8_t validation_message[] = {'c', '-', 'l', 'e', 'a', 'n', '-', 'l', 'i',
                                                 'b', 'p', '2', 'p', '-', 'q', 'u', 'i', 'c',
                                                 '-', 'h', 'o', 's', 't', '-', 'k', 'e', 'y'};
    size_t raw_public_key_len = 0U;
    size_t signature_len = 0U;
    libp2p_peer_id_err_t peer_err = LIBP2P_PEER_ID_OK;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (host_key == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (host_key->type != LIBP2P_QUIC_HOST_KEY_SECP256K1)
    {
        return LIBP2P_QUIC_ERR_UNSUPPORTED;
    }
    if ((host_key->private_key == NULL) ||
        (host_key->private_key_len != LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((host_key->public_key_message == NULL) || (host_key->public_key_message_len == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_identity_public_key_message_to_raw(
        host_key->public_key_message,
        host_key->public_key_message_len,
        raw_public_key,
        &raw_public_key_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    peer_err = libp2p_peer_id_sign_message(
        host_key->private_key,
        host_key->private_key_len,
        validation_message,
        sizeof(validation_message),
        signature,
        sizeof(signature),
        &signature_len);
    if (peer_err != LIBP2P_PEER_ID_OK)
    {
        return quic_identity_peer_id_err(peer_err);
    }

    peer_err = libp2p_peer_id_verify_message(
        raw_public_key,
        raw_public_key_len,
        validation_message,
        sizeof(validation_message),
        signature,
        signature_len);

    return quic_identity_peer_id_err(peer_err);
}

libp2p_quic_err_t libp2p_quic_host_key_peer_id(
    const libp2p_quic_host_key_t *host_key,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t raw_public_key[LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    size_t raw_public_key_len = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((host_key == NULL) || (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_identity_public_key_message_to_raw(
        host_key->public_key_message,
        host_key->public_key_message_len,
        raw_public_key,
        &raw_public_key_len);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    return quic_identity_peer_id_err(libp2p_peer_id_from_secp256k1_public_key(
        raw_public_key,
        raw_public_key_len,
        out,
        out_len,
        written));
}

libp2p_quic_err_t libp2p_quic_local_identity_validate(const libp2p_quic_local_identity_t *identity)
{
    if (identity == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((identity->certificate_der == NULL) || (identity->certificate_der_len == 0U) ||
        (identity->certificate_der_len > LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES))
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE;
    }
    if ((identity->certificate_private_key_der == NULL) ||
        (identity->certificate_private_key_der_len == 0U) ||
        (identity->certificate_private_key_der_len > LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES))
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE;
    }
    if (identity->peer_id_len != 0U)
    {
        char text[1];
        size_t written = 0U;

        if ((identity->peer_id == NULL) || (identity->peer_id_len > LIBP2P_PEER_ID_MAX_BYTES))
        {
            return LIBP2P_QUIC_ERR_INVALID_ARG;
        }
        if (libp2p_peer_id_to_string(
                identity->peer_id,
                identity->peer_id_len,
                text,
                0U,
                &written) != LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL)
        {
            return LIBP2P_QUIC_ERR_INVALID_ARG;
        }
    }

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_local_identity_peer_id(
    const libp2p_quic_local_identity_t *identity,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_peer_identity_t parsed;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((identity == NULL) || (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((identity->peer_id != NULL) && (identity->peer_id_len != 0U))
    {
        return quic_identity_copy_measure(
            identity->peer_id,
            identity->peer_id_len,
            out,
            out_len,
            written);
    }

    result = quic_identity_verify_peer_certificate_internal(
        identity->certificate_der,
        identity->certificate_der_len,
        NULL,
        0U,
        0U,
        0,
        &parsed,
        NULL);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    return quic_identity_copy_measure(parsed.peer_id, parsed.peer_id_len, out, out_len, written);
}

libp2p_quic_err_t libp2p_quic_identity_write_certificate_der(
    const libp2p_quic_host_key_t *host_key,
    const libp2p_quic_certificate_config_t *config,
    uint8_t *cert_out,
    size_t cert_out_len,
    size_t *cert_written,
    uint8_t *key_out,
    size_t key_out_len,
    size_t *key_written)
{
    EVP_PKEY *certificate_key = NULL;
    X509 *cert = NULL;
    uint8_t signed_key_der[LIBP2P_QUIC_SIGNED_PUBLIC_KEY_MAX_BYTES];
    size_t signed_key_der_len = 0U;
    uint64_t serial = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((cert_written == NULL) || (key_written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    *cert_written = 0U;
    *key_written = 0U;

    result = libp2p_quic_host_key_validate(host_key);
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_config_validate(config);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_random_serial(config, &serial);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_generate_certificate_key(&certificate_key);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        cert = X509_new();
        result = (cert != NULL) ? LIBP2P_QUIC_OK : LIBP2P_QUIC_ERR_TLS;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_set_certificate_fields(cert, certificate_key, config, serial);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_signed_key_for_certificate(
            host_key,
            certificate_key,
            signed_key_der,
            &signed_key_der_len);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_add_libp2p_extension(cert, signed_key_der, signed_key_der_len);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = (X509_sign(cert, certificate_key, EVP_sha256()) > 0) ? LIBP2P_QUIC_OK
                                                                      : LIBP2P_QUIC_ERR_TLS;
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_write_der_outputs(
            cert,
            certificate_key,
            cert_out,
            cert_out_len,
            cert_written,
            key_out,
            key_out_len,
            key_written);
    }

    (void)memset(signed_key_der, 0, sizeof(signed_key_der));
    X509_free(cert);
    EVP_PKEY_free(certificate_key);
    return result;
}

libp2p_quic_err_t libp2p_quic_identity_signing_payload_size(
    size_t certificate_public_key_spki_der_len,
    size_t *out_len)
{
    if (out_len == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (quic_identity_add_overflow(
            LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN,
            certificate_public_key_spki_der_len,
            out_len) != 0)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_identity_write_signing_payload(
    const uint8_t *certificate_public_key_spki_der,
    size_t certificate_public_key_spki_der_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    size_t prefix_index = 0U;
    libp2p_quic_err_t result =
        libp2p_quic_identity_signing_payload_size(certificate_public_key_spki_der_len, &required);

    if (written != NULL)
    {
        *written = required;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (((certificate_public_key_spki_der == NULL) &&
         (certificate_public_key_spki_der_len != 0U)) ||
        (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((out == NULL) || (out_len < required))
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    for (prefix_index = 0U; prefix_index < LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN;
         prefix_index++)
    {
        out[prefix_index] = (uint8_t)LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX[prefix_index];
    }
    (void)memcpy(
        &out[LIBP2P_QUIC_TLS_HANDSHAKE_SIGNING_PREFIX_LEN],
        certificate_public_key_spki_der,
        certificate_public_key_spki_der_len);

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_identity_verify_peer_certificate(
    const uint8_t *certificate_der,
    size_t certificate_der_len,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t current_unix_seconds,
    libp2p_quic_peer_identity_t *out)
{
    return quic_identity_verify_peer_certificate_internal(
        certificate_der,
        certificate_der_len,
        expected_peer_id,
        expected_peer_id_len,
        current_unix_seconds,
        1,
        out,
        NULL);
}

libp2p_quic_err_t libp2p_quic_identity_verify_peer_certificate_chain(
    const libp2p_quic_const_buffer_t *certificates_der,
    size_t certificate_count,
    const uint8_t *expected_peer_id,
    size_t expected_peer_id_len,
    uint64_t current_unix_seconds,
    libp2p_quic_peer_identity_t *out,
    libp2p_quic_certificate_report_t *report)
{
    if (report != NULL)
    {
        (void)memset(report, 0, sizeof(*report));
    }
    if (certificate_count != 1U)
    {
        return LIBP2P_QUIC_ERR_CERTIFICATE_CHAIN;
    }
    if (certificates_der == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return quic_identity_verify_peer_certificate_internal(
        certificates_der[0].data,
        certificates_der[0].len,
        expected_peer_id,
        expected_peer_id_len,
        current_unix_seconds,
        1,
        out,
        report);
}

libp2p_quic_err_t libp2p_quic_identity_encode_signed_key_der(
    const uint8_t *host_public_key_message,
    size_t host_public_key_message_len,
    const uint8_t *signature,
    size_t signature_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t content[LIBP2P_QUIC_SIGNED_PUBLIC_KEY_MAX_BYTES];
    size_t public_key_tlv_len = 0U;
    size_t signature_tlv_len = 0U;
    size_t content_len = 0U;
    size_t tlv_written = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (written != NULL)
    {
        *written = 0U;
    }
    if (((host_public_key_message == NULL) && (host_public_key_message_len != 0U)) ||
        ((signature == NULL) && (signature_len != 0U)) || (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = quic_identity_der_tlv_size(host_public_key_message_len, &public_key_tlv_len);
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_der_tlv_size(signature_len, &signature_tlv_len);
    }
    if ((result == LIBP2P_QUIC_OK) &&
        (quic_identity_add_overflow(public_key_tlv_len, signature_tlv_len, &content_len) != 0))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    if ((result == LIBP2P_QUIC_OK) && (content_len > sizeof(content)))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    result = quic_identity_der_write_tlv(
        QUIC_IDENTITY_DER_OCTET_STRING,
        host_public_key_message,
        host_public_key_message_len,
        content,
        sizeof(content),
        &tlv_written);
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_der_write_tlv(
            QUIC_IDENTITY_DER_OCTET_STRING,
            signature,
            signature_len,
            &content[tlv_written],
            sizeof(content) - tlv_written,
            &signature_tlv_len);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_der_write_tlv(
            QUIC_IDENTITY_DER_SEQUENCE,
            content,
            content_len,
            out,
            out_len,
            written);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_identity_decode_signed_key_der(
    const uint8_t *signed_key_der,
    size_t signed_key_der_len,
    uint8_t *public_key_out,
    size_t public_key_out_len,
    size_t *public_key_written,
    uint8_t *signature_out,
    size_t signature_out_len,
    size_t *signature_written)
{
    const uint8_t *sequence = NULL;
    const uint8_t *public_key = NULL;
    const uint8_t *signature = NULL;
    size_t sequence_len = 0U;
    size_t sequence_consumed = 0U;
    size_t public_key_len = 0U;
    size_t public_key_consumed = 0U;
    size_t signature_len = 0U;
    size_t signature_consumed = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((public_key_written == NULL) || (signature_written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    *public_key_written = 0U;
    *signature_written = 0U;

    result = quic_identity_der_read_tlv(
        signed_key_der,
        signed_key_der_len,
        QUIC_IDENTITY_DER_SEQUENCE,
        &sequence,
        &sequence_len,
        &sequence_consumed);
    if ((result != LIBP2P_QUIC_OK) || (sequence_consumed != signed_key_der_len))
    {
        return (result == LIBP2P_QUIC_OK) ? LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION : result;
    }

    result = quic_identity_der_read_tlv(
        sequence,
        sequence_len,
        QUIC_IDENTITY_DER_OCTET_STRING,
        &public_key,
        &public_key_len,
        &public_key_consumed);
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_identity_der_read_tlv(
            &sequence[public_key_consumed],
            sequence_len - public_key_consumed,
            QUIC_IDENTITY_DER_OCTET_STRING,
            &signature,
            &signature_len,
            &signature_consumed);
    }
    if ((result != LIBP2P_QUIC_OK) || ((public_key_consumed + signature_consumed) != sequence_len))
    {
        return (result == LIBP2P_QUIC_OK) ? LIBP2P_QUIC_ERR_CERTIFICATE_EXTENSION : result;
    }

    *public_key_written = public_key_len;
    *signature_written = signature_len;
    if ((public_key_out == NULL) || (public_key_out_len < public_key_len) ||
        (signature_out == NULL) || (signature_out_len < signature_len))
    {
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    (void)memcpy(public_key_out, public_key, public_key_len);
    (void)memcpy(signature_out, signature, signature_len);
    return LIBP2P_QUIC_OK;
}
