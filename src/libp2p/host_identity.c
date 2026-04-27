#include <string.h>

#include "host_internal.h"
#include "libp2p/libp2p_host_secp256k1_identity.h"

libp2p_host_err_t host_map_peer_err(int peer_err)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (peer_err == (int)LIBP2P_PEER_ID_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (peer_err == (int)LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (peer_err == (int)LIBP2P_PEER_ID_ERR_INVALID_PRIVATE_KEY)
    {
        result = LIBP2P_HOST_ERR_IDENTITY;
    }
    else
    {
        result = LIBP2P_HOST_ERR_IDENTITY;
    }

    return result;
}

libp2p_host_err_t libp2p_host_peer_id(
    const libp2p_host_t *host,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (written != NULL)
    {
        *written = 0U;
    }
    if (result == LIBP2P_HOST_OK)
    {
        if (written == NULL)
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if ((out == NULL) || (out_len < host->config.identity.peer_id_len))
        {
            *written = host->config.identity.peer_id_len;
            result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
        }
        else
        {
            (void)memcpy(out, host->config.identity.peer_id, host->config.identity.peer_id_len);
            *written = host->config.identity.peer_id_len;
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_sign(
    libp2p_host_t *host,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out_sig,
    size_t out_sig_len,
    size_t *written)
{
    libp2p_host_err_t result = host_validate_any(host);

    if (result == LIBP2P_HOST_OK)
    {
        if (((message == NULL) && (message_len != 0U)) || (written == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else
        {
            result = host->config.identity.sign_fn(
                host->config.identity.user_data,
                message,
                message_len,
                out_sig,
                out_sig_len,
                written);
        }
    }

    return result;
}

static libp2p_host_secp256k1_identity_t *host_identity_from_user_data(void *user_data)
{
    libp2p_host_secp256k1_identity_t *identity = NULL;

    (void)memcpy((void *)&identity, (const void *)&user_data, sizeof identity);

    return identity;
}

static libp2p_host_err_t host_secp256k1_sign(
    void *user_data,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out_sig,
    size_t out_sig_len,
    size_t *written)
{
    const libp2p_host_secp256k1_identity_t *identity = host_identity_from_user_data(user_data);
    libp2p_peer_id_err_t err;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if ((identity == NULL) || (((message == NULL) && (message_len != 0U))) || (written == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        err = libp2p_peer_id_sign_message(
            identity->private_key,
            identity->private_key_len,
            message,
            message_len,
            out_sig,
            out_sig_len,
            written);
        result = host_map_peer_err((int)err);
    }

    return result;
}

libp2p_host_err_t libp2p_host_secp256k1_identity_init(
    libp2p_host_secp256k1_identity_t *identity,
    const uint8_t *private_key,
    size_t private_key_len,
    libp2p_host_identity_t *out)
{
    uint8_t public_key[LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES];
    size_t public_key_len = 0U;
    libp2p_peer_id_err_t peer_err;
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (out != NULL)
    {
        (void)memset(out, 0, sizeof(*out));
    }
    if ((identity == NULL) || (private_key == NULL) ||
        (private_key_len != LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES) || (out == NULL))
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        (void)memset(identity, 0, sizeof(*identity));
        peer_err = libp2p_peer_id_public_key_from_private_key(
            private_key,
            private_key_len,
            1,
            public_key,
            sizeof(public_key),
            &public_key_len);
        result = host_map_peer_err((int)peer_err);
    }
    if (result == LIBP2P_HOST_OK)
    {
        peer_err = libp2p_peer_id_public_key_encode(
            public_key,
            public_key_len,
            identity->public_key_message,
            sizeof(identity->public_key_message),
            &identity->public_key_message_len);
        result = host_map_peer_err((int)peer_err);
    }
    if (result == LIBP2P_HOST_OK)
    {
        peer_err = libp2p_peer_id_from_secp256k1_public_key(
            public_key,
            public_key_len,
            identity->peer_id,
            sizeof(identity->peer_id),
            &identity->peer_id_len);
        result = host_map_peer_err((int)peer_err);
    }
    if (result == LIBP2P_HOST_OK)
    {
        identity->private_key = private_key;
        identity->private_key_len = private_key_len;
        out->peer_id = identity->peer_id;
        out->peer_id_len = identity->peer_id_len;
        out->public_key_message = identity->public_key_message;
        out->public_key_message_len = identity->public_key_message_len;
        out->sign_fn = host_secp256k1_sign;
        out->user_data = identity;
    }

    return result;
}
