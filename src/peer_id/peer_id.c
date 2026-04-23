/**
 * @file peer_id.c
 * @brief secp256k1 key handling and peer ID operations.
 *
 * This implementation depends on the vendored libsecp256k1 internal SHA-256
 * implementation via src/hash.h and src/hash_impl.h. Those are not part of the
 * library's public API, so the include path is wired explicitly in CMake and
 * may need maintenance if the submodule layout changes.
 */

#include "peer_id/peer_id.h"

#include <string.h>

#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#include "secp256k1.h"
#include "secp256k1_preallocated.h"

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "hash.h"
#include "hash_impl.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#define LIBP2P_PEER_ID_PROTOBUF_KEY_TYPE_TAG            0x08U
#define LIBP2P_PEER_ID_PROTOBUF_KEY_DATA_TAG            0x12U
#define LIBP2P_PEER_ID_SECP256K1_KEY_TYPE               0x02U
#define LIBP2P_PEER_ID_CID_VERSION_1                    0x01U
#define LIBP2P_PEER_ID_CID_CODEC_LIBP2P_KEY             0x72U
#define LIBP2P_PEER_ID_TEXT_MAX_BYTES                   96U
#define LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_BYTES  4096U
#define LIBP2P_PEER_ID_SECP_CONTEXT_NONE                1U
#define LIBP2P_PEER_ID_SECP_EC_UNCOMPRESSED             2U
#define LIBP2P_PEER_ID_SECP_EC_COMPRESSED               258U
#define LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_WORDS  512U

static int peer_id_public_key_length_is_supported(size_t public_key_len)
{
    return ((public_key_len == LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES) ||
            (public_key_len == LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES))
               ? 1
               : 0;
}

static libp2p_peer_id_err_t peer_id_multibase_err_to_peer_id(libp2p_multibase_err_t err)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;

    switch (err)
    {
    case LIBP2P_MULTIBASE_OK:
        result = LIBP2P_PEER_ID_OK;
        break;

    case LIBP2P_MULTIBASE_ERR_BUF_TOO_SMALL:
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
        break;

    case LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE:
    case LIBP2P_MULTIBASE_ERR_RESERVED_PREFIX:
        result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
        break;

    case LIBP2P_MULTIBASE_ERR_INVALID_CHARACTER:
    case LIBP2P_MULTIBASE_ERR_INVALID_LENGTH:
    case LIBP2P_MULTIBASE_ERR_EMPTY_INPUT:
    default:
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
        break;
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_multihash_err_to_peer_id(libp2p_multihash_err_t err)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;

    switch (err)
    {
    case LIBP2P_MULTIHASH_OK:
        result = LIBP2P_PEER_ID_OK;
        break;

    case LIBP2P_MULTIHASH_ERR_BUF_TOO_SMALL:
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
        break;

    case LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE:
        result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
        break;

    case LIBP2P_MULTIHASH_ERR_INVALID_VARINT:
    case LIBP2P_MULTIHASH_ERR_TRUNCATED:
    case LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH:
    default:
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
        break;
    }

    return result;
}

static void peer_id_sha256(const uint8_t *message, size_t message_len, uint8_t hash[32])
{
    secp256k1_sha256 sha;

    secp256k1_sha256_initialize(&sha);
    if ((message != NULL) && (message_len != 0U))
    {
        secp256k1_sha256_write(&sha, message, message_len);
    }
    secp256k1_sha256_finalize(&sha, hash);
    secp256k1_sha256_clear(&sha);
}

static libp2p_peer_id_err_t peer_id_create_context(
    void *context_storage,
    secp256k1_context **context_out)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    const size_t required =
        secp256k1_context_preallocated_size(LIBP2P_PEER_ID_SECP_CONTEXT_NONE);

    if ((context_storage == NULL) || (context_out == NULL))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }
    else
    {
        *context_out = NULL;
    }

    if ((result == LIBP2P_PEER_ID_OK) &&
        (required > LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        *context_out = secp256k1_context_preallocated_create(
            context_storage,
            LIBP2P_PEER_ID_SECP_CONTEXT_NONE);
        if (*context_out == NULL)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_key_message_size(size_t key_len, size_t *out_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }
    else
    {
        const size_t type_size = (size_t)libp2p_uvarint_size((uint64_t)LIBP2P_PEER_ID_SECP256K1_KEY_TYPE);
        const size_t length_size = (size_t)libp2p_uvarint_size((uint64_t)key_len);

        *out_len = 2U + type_size + length_size + key_len;
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_validate_private_key(
    const uint8_t *private_key,
    size_t private_key_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if ((private_key == NULL) || (private_key_len != LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY;
    }
    else
    {
        uint64_t context_storage[LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_WORDS];
        secp256k1_context *context = NULL;

        result = peer_id_create_context(context_storage, &context);
        if ((result == LIBP2P_PEER_ID_OK) && (secp256k1_ec_seckey_verify(context, private_key) == 0))
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY;
        }

        if (context != NULL)
        {
            secp256k1_context_preallocated_destroy(context);
        }
        secp256k1_memclear_explicit(context_storage, sizeof(context_storage));
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_parse_public_key(
    const uint8_t *public_key,
    size_t public_key_len,
    secp256k1_pubkey *parsed_pubkey)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if ((public_key == NULL) || (parsed_pubkey == NULL) ||
        (peer_id_public_key_length_is_supported(public_key_len) == 0))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
    }
    else
    {
        secp256k1_selftest();
        if (secp256k1_ec_pubkey_parse(
                secp256k1_context_static,
                parsed_pubkey,
                public_key,
                public_key_len) == 0)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_serialize_public_key(
    const secp256k1_pubkey *public_key,
    int compressed,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t required =
        (compressed != 0) ? LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES
                          : LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (public_key == NULL)
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
    }
    else
    {
        if (written != NULL)
        {
            *written = required;
        }

        if ((out == NULL) || (out_len < required))
        {
            result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
        }
        else
        {
            size_t output_len = required;
            unsigned int flags = LIBP2P_PEER_ID_SECP_EC_UNCOMPRESSED;

            if (compressed != 0)
            {
                flags = LIBP2P_PEER_ID_SECP_EC_COMPRESSED;
            }

            secp256k1_selftest();
            if (secp256k1_ec_pubkey_serialize(
                    secp256k1_context_static,
                    out,
                    &output_len,
                    public_key,
                    flags) == 0)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
            }
            else if (output_len != required)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
            }
            else
            {
                if (written != NULL)
                {
                    *written = output_len;
                }
            }
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_encode_key_message(
    const uint8_t *key_bytes,
    size_t key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t required = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = peer_id_key_message_size(key_len, &required);
    if (written != NULL)
    {
        *written = required;
    }

    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < required)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        uint8_t length_buf[LIBP2P_UVARINT_MAX_BYTES];
        size_t length_written = 0U;

        out[0] = LIBP2P_PEER_ID_PROTOBUF_KEY_TYPE_TAG;
        out[1] = LIBP2P_PEER_ID_SECP256K1_KEY_TYPE;
        out[2] = LIBP2P_PEER_ID_PROTOBUF_KEY_DATA_TAG;

        if (libp2p_uvarint_encode(
                (uint64_t)key_len,
                length_buf,
                sizeof(length_buf),
                &length_written) != LIBP2P_UVARINT_OK)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
        }
        else
        {
            size_t index = 0U;
            size_t data_offset = 3U + length_written;

            for (index = 0U; index < length_written; index++)
            {
                out[3U + index] = length_buf[index];
            }
            for (index = 0U; index < key_len; index++)
            {
                out[data_offset + index] = key_bytes[index];
            }

            if (written != NULL)
            {
                *written = required;
            }
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_decode_key_message(
    const uint8_t *in,
    size_t in_len,
    size_t *data_offset,
    size_t *data_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t offset = 0U;
    uint64_t parsed_type = UINT64_C(0);
    size_t type_read = 0U;
    uint64_t parsed_length_u64 = UINT64_C(0);
    size_t length_read = 0U;

    if ((in == NULL) || (data_offset == NULL) || (data_len == NULL))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }
    else if ((in_len < 4U) || (in[0] != LIBP2P_PEER_ID_PROTOBUF_KEY_TYPE_TAG))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }
    else if (libp2p_uvarint_decode(
                 &in[1],
                 in_len - 1U,
                 &parsed_type,
                 &type_read) != LIBP2P_UVARINT_OK)
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }
    else
    {
        offset = 1U + type_read;

        if ((offset >= in_len) || (in[offset] != LIBP2P_PEER_ID_PROTOBUF_KEY_DATA_TAG))
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
        }
        else if (parsed_type != (uint64_t)LIBP2P_PEER_ID_SECP256K1_KEY_TYPE)
        {
            result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
        }
        else if (libp2p_uvarint_decode(
                     &in[offset + 1U],
                     in_len - offset - 1U,
                     &parsed_length_u64,
                     &length_read) != LIBP2P_UVARINT_OK)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
        }
        else
        {
            /* The key message header is structurally valid. */
        }
    }

    if ((result == LIBP2P_PEER_ID_OK) && (parsed_length_u64 > (uint64_t)SIZE_MAX))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        size_t start = offset + 1U + length_read;
        size_t payload_len = (size_t)parsed_length_u64;

        if ((start > in_len) || ((in_len - start) != payload_len))
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
        }
        else
        {
            *data_offset = start;
            *data_len = payload_len;
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_validate_binary_peer_id(
    const uint8_t *peer_id,
    size_t peer_id_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    uint64_t code = UINT64_C(0);
    size_t digest_len = 0U;
    size_t digest_offset = 0U;
    libp2p_multihash_err_t multihash_err = LIBP2P_MULTIHASH_OK;

    multihash_err =
        libp2p_multihash_read_header(peer_id, peer_id_len, &code, &digest_len, &digest_offset);
    result = peer_id_multihash_err_to_peer_id(multihash_err);

    if ((result == LIBP2P_PEER_ID_OK) && ((digest_offset + digest_len) != peer_id_len))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        switch (code)
        {
        case LIBP2P_MULTIHASH_CODE_IDENTITY:
        {
            size_t key_offset = 0U;
            size_t key_len = 0U;

            if (digest_len > LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
            }
            else
            {
                result = peer_id_decode_key_message(
                    &peer_id[digest_offset],
                    digest_len,
                    &key_offset,
                    &key_len);
            }

            if (result == LIBP2P_PEER_ID_OK)
            {
                secp256k1_pubkey parsed_pubkey;

                result = peer_id_parse_public_key(
                    &peer_id[digest_offset + key_offset],
                    key_len,
                    &parsed_pubkey);
            }
            break;
        }

        case LIBP2P_MULTIHASH_CODE_SHA2_256:
            if (digest_len != LIBP2P_PEER_ID_SHA2_256_BYTES)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
            }
            break;

        default:
            result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
            break;
        }
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_decode_legacy_text(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    char prefixed[LIBP2P_PEER_ID_TEXT_MAX_BYTES + 1U];
    size_t prefixed_len = 0U;
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U) || (in_len > LIBP2P_PEER_ID_TEXT_MAX_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }
    else
    {
        prefixed[0] = 'z';
        for (size_t index = 0U; index < in_len; index++)
        {
            prefixed[index + 1U] = in[index];
        }
        prefixed_len = in_len + 1U;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        libp2p_multibase_err_t multibase_err = libp2p_multibase_decode(
            prefixed,
            prefixed_len,
            &base,
            out,
            out_len,
            written);

        result = peer_id_multibase_err_to_peer_id(multibase_err);
    }

    return result;
}

static libp2p_peer_id_err_t peer_id_decode_cid_text(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    uint8_t decoded[LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES + 8U];
    size_t decoded_len = 0U;
    libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
    uint64_t version = UINT64_C(0);
    uint64_t codec = UINT64_C(0);
    size_t version_read = 0U;
    size_t codec_read = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }
    else
    {
        libp2p_multibase_err_t multibase_err = libp2p_multibase_decode(
            in,
            in_len,
            &base,
            decoded,
            sizeof(decoded),
            &decoded_len);

        result = peer_id_multibase_err_to_peer_id(multibase_err);
    }

    if ((result == LIBP2P_PEER_ID_OK) &&
        (libp2p_uvarint_decode(decoded, decoded_len, &version, &version_read) != LIBP2P_UVARINT_OK))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }

    if ((result == LIBP2P_PEER_ID_OK) &&
        (version != (uint64_t)LIBP2P_PEER_ID_CID_VERSION_1))
    {
        result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
    }

    if ((result == LIBP2P_PEER_ID_OK) && (version_read > decoded_len))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }
    else if ((result == LIBP2P_PEER_ID_OK) &&
             (libp2p_uvarint_decode(
                  &decoded[version_read],
                  decoded_len - version_read,
                  &codec,
                  &codec_read) != LIBP2P_UVARINT_OK))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }
    else
    {
        /* The CID multicodec varint decoded successfully. */
    }

    if ((result == LIBP2P_PEER_ID_OK) &&
        (codec != (uint64_t)LIBP2P_PEER_ID_CID_CODEC_LIBP2P_KEY))
    {
        result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
    }
    else
    {
        /* The CID codec is in the supported subset. */
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        size_t peer_id_offset = version_read + codec_read;
        size_t peer_id_len = decoded_len - peer_id_offset;

        result = peer_id_validate_binary_peer_id(&decoded[peer_id_offset], peer_id_len);
        if (result == LIBP2P_PEER_ID_OK)
        {
            if (written != NULL)
            {
                *written = peer_id_len;
            }

            if ((out == NULL) || (out_len < peer_id_len))
            {
                result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
            }
            else
            {
                size_t index = 0U;

                for (index = 0U; index < peer_id_len; index++)
                {
                    out[index] = decoded[peer_id_offset + index];
                }
            }
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_public_key_encoded_size(
    size_t public_key_len,
    size_t *out_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if (peer_id_public_key_length_is_supported(public_key_len) == 0)
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
    }
    else
    {
        result = peer_id_key_message_size(public_key_len, out_len);
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_public_key_encode(
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    secp256k1_pubkey parsed_pubkey;

    result = peer_id_parse_public_key(public_key, public_key_len, &parsed_pubkey);
    if (result == LIBP2P_PEER_ID_OK)
    {
        result = peer_id_encode_key_message(public_key, public_key_len, out, out_len, written);
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_public_key_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t offset = 0U;
    size_t key_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = peer_id_decode_key_message(in, in_len, &offset, &key_len);
    if ((result == LIBP2P_PEER_ID_OK) && (written != NULL))
    {
        *written = key_len;
    }

    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < key_len)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        secp256k1_pubkey parsed_pubkey;

        result = peer_id_parse_public_key(&in[offset], key_len, &parsed_pubkey);
        if (result == LIBP2P_PEER_ID_OK)
        {
            size_t index = 0U;

            for (index = 0U; index < key_len; index++)
            {
                out[index] = in[offset + index];
            }
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_private_key_encode(
    const uint8_t *private_key,
    size_t private_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = peer_id_validate_private_key(private_key, private_key_len);
    if ((result == LIBP2P_PEER_ID_OK) && (written != NULL))
    {
        *written = LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_MESSAGE_BYTES;
    }

    if ((result == LIBP2P_PEER_ID_OK) &&
        ((out == NULL) || (out_len < LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_MESSAGE_BYTES)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        result = peer_id_encode_key_message(private_key, private_key_len, out, out_len, written);
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_private_key_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t offset = 0U;
    size_t key_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = peer_id_decode_key_message(in, in_len, &offset, &key_len);
    if ((result == LIBP2P_PEER_ID_OK) &&
        (key_len != LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_KEY_ENCODING;
    }

    if ((result == LIBP2P_PEER_ID_OK) && (written != NULL))
    {
        *written = key_len;
    }

    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < key_len)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        result = peer_id_validate_private_key(&in[offset], key_len);
        if (result == LIBP2P_PEER_ID_OK)
        {
            size_t index = 0U;

            for (index = 0U; index < key_len; index++)
            {
                out[index] = in[offset + index];
            }
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_public_key_from_private_key(
    const uint8_t *private_key,
    size_t private_key_len,
    int compressed,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t required =
        (compressed != 0) ? LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES
                          : LIBP2P_PEER_ID_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_BYTES;

    if (written != NULL)
    {
        *written = required;
    }

    result = peer_id_validate_private_key(private_key, private_key_len);
    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < required)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        uint64_t context_storage[LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_WORDS];
        secp256k1_context *context = NULL;

        result = peer_id_create_context(context_storage, &context);
        if (result == LIBP2P_PEER_ID_OK)
        {
            secp256k1_pubkey public_key;

            if (secp256k1_ec_pubkey_create(context, &public_key, private_key) == 0)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY;
            }
            else
            {
                result = peer_id_serialize_public_key(
                    &public_key,
                    compressed,
                    out,
                    out_len,
                    written);
            }
        }

        if (context != NULL)
        {
            secp256k1_context_preallocated_destroy(context);
        }
        secp256k1_memclear_explicit(context_storage, sizeof(context_storage));
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_sign_hash(
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *message_hash,
    size_t message_hash_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((message_hash == NULL) || (message_hash_len != LIBP2P_PEER_ID_SHA2_256_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH;
    }
    else
    {
        result = peer_id_validate_private_key(private_key, private_key_len);
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        uint64_t context_storage[LIBP2P_PEER_ID_SECP256K1_CONTEXT_STORAGE_WORDS];
        secp256k1_context *context = NULL;

        result = peer_id_create_context(context_storage, &context);
        if (result == LIBP2P_PEER_ID_OK)
        {
            secp256k1_ecdsa_signature signature;
            uint8_t signature_bytes[LIBP2P_PEER_ID_SECP256K1_SIGNATURE_MAX_BYTES];
            size_t signature_len = sizeof(signature_bytes);

            if (secp256k1_ecdsa_sign(context, &signature, message_hash, private_key, NULL, NULL) == 0)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY;
            }
            else if (secp256k1_ecdsa_signature_serialize_der(
                         context,
                         signature_bytes,
                         &signature_len,
                         &signature) == 0)
            {
                result = LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE;
            }
            else
            {
                if (written != NULL)
                {
                    *written = signature_len;
                }

                if ((out == NULL) || (out_len < signature_len))
                {
                    result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
                }
                else
                {
                    size_t index = 0U;

                    for (index = 0U; index < signature_len; index++)
                    {
                        out[index] = signature_bytes[index];
                    }
                }
            }

            libp2p_peer_id_zeroize(signature_bytes, sizeof(signature_bytes));
        }

        if (context != NULL)
        {
            secp256k1_context_preallocated_destroy(context);
        }
        secp256k1_memclear_explicit(context_storage, sizeof(context_storage));
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_verify_hash(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message_hash,
    size_t message_hash_len,
    const uint8_t *signature,
    size_t signature_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    secp256k1_pubkey parsed_pubkey;

    if ((message_hash == NULL) || (message_hash_len != LIBP2P_PEER_ID_SHA2_256_BYTES))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_MESSAGE_HASH;
    }
    else if ((signature == NULL) || (signature_len == 0U))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE;
    }
    else
    {
        result = peer_id_parse_public_key(public_key, public_key_len, &parsed_pubkey);
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        secp256k1_ecdsa_signature parsed_signature;

        secp256k1_selftest();
        if (secp256k1_ecdsa_signature_parse_der(
                secp256k1_context_static,
                &parsed_signature,
                signature,
                signature_len) == 0)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE;
        }
        else if (secp256k1_ecdsa_verify(
                     secp256k1_context_static,
                     &parsed_signature,
                     message_hash,
                     &parsed_pubkey) == 0)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_SIGNATURE;
        }
        else
        {
            /* The signature verified successfully. */
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_sign_message(
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t hash[LIBP2P_PEER_ID_SHA2_256_BYTES];
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    peer_id_sha256(message, message_len, hash);
    result = libp2p_peer_id_sign_hash(
        private_key,
        private_key_len,
        hash,
        sizeof(hash),
        out,
        out_len,
        written);
    libp2p_peer_id_zeroize(hash, sizeof(hash));

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_verify_message(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len)
{
    uint8_t hash[LIBP2P_PEER_ID_SHA2_256_BYTES];
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;

    peer_id_sha256(message, message_len, hash);
    result = libp2p_peer_id_verify_hash(
        public_key,
        public_key_len,
        hash,
        sizeof(hash),
        signature,
        signature_len);
    libp2p_peer_id_zeroize(hash, sizeof(hash));

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_size_from_secp256k1_public_key(
    size_t public_key_len,
    size_t *out_len)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    size_t encoded_key_len = 0U;

    if (out_len == NULL)
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PUBLIC_KEY;
    }
    else
    {
        *out_len = 0U;
        result = libp2p_peer_id_public_key_encoded_size(public_key_len, &encoded_key_len);
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        if (encoded_key_len <= LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES)
        {
            result = peer_id_multihash_err_to_peer_id(libp2p_multihash_size(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                encoded_key_len,
                out_len));
        }
        else
        {
            result = peer_id_multihash_err_to_peer_id(libp2p_multihash_size(
                LIBP2P_MULTIHASH_CODE_SHA2_256,
                LIBP2P_PEER_ID_SHA2_256_BYTES,
                out_len));
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_from_secp256k1_public_key(
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    uint8_t encoded_key[LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES];
    size_t encoded_key_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = libp2p_peer_id_public_key_encode(
        public_key,
        public_key_len,
        encoded_key,
        sizeof(encoded_key),
        &encoded_key_len);

    if (result == LIBP2P_PEER_ID_OK)
    {
        if (encoded_key_len <= LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES)
        {
            result = peer_id_multihash_err_to_peer_id(libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                encoded_key,
                encoded_key_len,
                out,
                out_len,
                written));
        }
        else
        {
            uint8_t hash[LIBP2P_PEER_ID_SHA2_256_BYTES];

            peer_id_sha256(encoded_key, encoded_key_len, hash);
            result = peer_id_multihash_err_to_peer_id(libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_SHA2_256,
                hash,
                sizeof(hash),
                out,
                out_len,
                written));
            libp2p_peer_id_zeroize(hash, sizeof(hash));
        }
    }

    libp2p_peer_id_zeroize(encoded_key, sizeof(encoded_key));
    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_from_string(
    const char *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    uint8_t decoded[LIBP2P_PEER_ID_MAX_BYTES];
    size_t decoded_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((in == NULL) || (in_len == 0U))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }
    else if (((in[0] == '1')) ||
             ((in_len >= 2U) && (in[0] == 'Q') && (in[1] == 'm')))
    {
        result = peer_id_decode_legacy_text(in, in_len, decoded, sizeof(decoded), &decoded_len);
    }
    else
    {
        result = peer_id_decode_cid_text(in, in_len, decoded, sizeof(decoded), &decoded_len);
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        result = peer_id_validate_binary_peer_id(decoded, decoded_len);
    }

    if ((result == LIBP2P_PEER_ID_OK) && (written != NULL))
    {
        *written = decoded_len;
    }

    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < decoded_len)))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        size_t index = 0U;

        for (index = 0U; index < decoded_len; index++)
        {
            out[index] = decoded[index];
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_to_string(
    const uint8_t *peer_id,
    size_t peer_id_len,
    char *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    char encoded[LIBP2P_PEER_ID_TEXT_MAX_BYTES];
    size_t encoded_len = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    result = peer_id_validate_binary_peer_id(peer_id, peer_id_len);
    if (result == LIBP2P_PEER_ID_OK)
    {
        libp2p_multibase_err_t multibase_err = libp2p_multibase_encode(
            LIBP2P_MULTIBASE_BASE58BTC,
            peer_id,
            peer_id_len,
            encoded,
            sizeof(encoded),
            &encoded_len);

        result = peer_id_multibase_err_to_peer_id(multibase_err);
    }

    if ((result == LIBP2P_PEER_ID_OK) && (encoded_len == 0U))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }

    if ((result == LIBP2P_PEER_ID_OK) && (written != NULL))
    {
        *written = encoded_len - 1U;
    }

    if ((result == LIBP2P_PEER_ID_OK) && ((out == NULL) || (out_len < (encoded_len - 1U))))
    {
        result = LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL;
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        for (size_t index = 1U; index < encoded_len; index++)
        {
            out[index - 1U] = encoded[index];
        }
    }

    return result;
}

libp2p_peer_id_err_t libp2p_peer_id_extract_secp256k1_public_key(
    const uint8_t *peer_id,
    size_t peer_id_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_peer_id_err_t result = LIBP2P_PEER_ID_OK;
    uint64_t code = UINT64_C(0);
    size_t digest_len = 0U;
    size_t digest_offset = 0U;
    libp2p_multihash_err_t multihash_err = LIBP2P_MULTIHASH_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    multihash_err =
        libp2p_multihash_read_header(peer_id, peer_id_len, &code, &digest_len, &digest_offset);
    result = peer_id_multihash_err_to_peer_id(multihash_err);

    if ((result == LIBP2P_PEER_ID_OK) && ((digest_offset + digest_len) != peer_id_len))
    {
        result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
    }

    if ((result == LIBP2P_PEER_ID_OK) && (code == LIBP2P_MULTIHASH_CODE_SHA2_256))
    {
        result = LIBP2P_PEER_ID_ERR_NO_INLINE_PUBLIC_KEY;
    }
    else if ((result == LIBP2P_PEER_ID_OK) && (code != LIBP2P_MULTIHASH_CODE_IDENTITY))
    {
        result = LIBP2P_PEER_ID_ERR_UNSUPPORTED_ENCODING;
    }
    else
    {
        /* The peer ID uses the supported identity multihash. */
    }

    if (result == LIBP2P_PEER_ID_OK)
    {
        if (digest_len > LIBP2P_PEER_ID_INLINE_KEY_MAX_BYTES)
        {
            result = LIBP2P_PEER_ID_ERR_INVALID_PEER_ID;
        }
        else
        {
            result = libp2p_peer_id_public_key_decode(
                &peer_id[digest_offset],
                digest_len,
                out,
                out_len,
                written);
        }
    }

    return result;
}
