/**
 * @file quic_backend_ngtcp2_tls.c
 * @brief ngtcp2 + AWS-LC backend for libp2p QUIC v1.
 */

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/evp.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

/* Character constants remain valid static initializers for MSVC's C compiler. */
static const uint8_t quic_backend_libp2p_alpn[sizeof(LIBP2P_QUIC_ALPN)] =
    {(uint8_t)LIBP2P_QUIC_ALPN_LEN,
     (uint8_t)'l',
     (uint8_t)'i',
     (uint8_t)'b',
     (uint8_t)'p',
     (uint8_t)'2',
     (uint8_t)'p'};

static int quic_backend_alpn_select_cb(
    SSL *ssl,
    const uint8_t **out,
    uint8_t *out_len,
    const uint8_t *in,
    unsigned in_len,
    void *arg)
{
    uint8_t *selected = NULL;
    uint8_t selected_len = 0U;
    int result = 0;

    (void)ssl;
    (void)arg;

    result = SSL_select_next_proto(
        &selected,
        &selected_len,
        quic_backend_libp2p_alpn,
        (unsigned)sizeof(quic_backend_libp2p_alpn),
        in,
        in_len);
    if (result != OPENSSL_NPN_NEGOTIATED)
    {
        result = SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    else
    {
        *out = selected;
        *out_len = selected_len;
        result = SSL_TLSEXT_ERR_OK;
    }

    return result;
}

static ngtcp2_conn *quic_backend_crypto_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    const libp2p_quic_conn_t *conn = NULL;
    ngtcp2_conn *result = NULL;

    if ((conn_ref != NULL) && (conn_ref->user_data != NULL))
    {
        conn = quic_backend_conn_from_memory(conn_ref->user_data);
        result = conn->ngconn;
    }

    return result;
}

static enum ssl_verify_result_t quic_backend_ssl_verify_cb(SSL *ssl, uint8_t *out_alert)
{
    ngtcp2_crypto_conn_ref *conn_ref = NULL;
    libp2p_quic_conn_t *conn = NULL;
    libp2p_quic_endpoint_t *endpoint = NULL;
    const STACK_OF(CRYPTO_BUFFER) *chain = NULL;
    CRYPTO_BUFFER *leaf = NULL;
    libp2p_quic_const_buffer_t certificate;
    uint64_t now = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    enum ssl_verify_result_t verify_result = ssl_verify_invalid;

    if (out_alert != NULL)
    {
        *out_alert = SSL_AD_CERTIFICATE_UNKNOWN;
    }

    conn_ref = SSL_get_app_data(ssl);
    if ((conn_ref == NULL) || (conn_ref->user_data == NULL))
    {
        if (out_alert != NULL)
        {
            *out_alert = SSL_AD_INTERNAL_ERROR;
        }
        result = LIBP2P_QUIC_ERR_INTERNAL;
    }
    else
    {
        conn = quic_backend_conn_from_memory(conn_ref->user_data);
        endpoint = conn->endpoint;

        chain = SSL_get0_peer_certificates(ssl);
        if ((chain == NULL) || (sk_CRYPTO_BUFFER_num(chain) != 1U))
        {
            if (out_alert != NULL)
            {
                *out_alert = SSL_AD_BAD_CERTIFICATE;
            }
            result = LIBP2P_QUIC_ERR_CERTIFICATE_CHAIN;
        }
    }

    if ((result == LIBP2P_QUIC_OK) &&
        (endpoint->config.unix_time_fn(&now, endpoint->config.unix_time_user_data) !=
         LIBP2P_QUIC_OK))
    {
        if (out_alert != NULL)
        {
            *out_alert = SSL_AD_INTERNAL_ERROR;
        }
        result = LIBP2P_QUIC_ERR_INTERNAL;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        leaf = sk_CRYPTO_BUFFER_value(chain, 0U);
        certificate.data = CRYPTO_BUFFER_data(leaf);
        certificate.len = CRYPTO_BUFFER_len(leaf);

        result = libp2p_quic_identity_verify_peer_certificate_chain(
            &certificate,
            1U,
            (conn->expected_peer_id_len != 0U) ? conn->expected_peer_id : NULL,
            conn->expected_peer_id_len,
            now,
            &conn->peer_identity,
            NULL);
        if (result != LIBP2P_QUIC_OK)
        {
            if (out_alert != NULL)
            {
                *out_alert = (result == LIBP2P_QUIC_ERR_CERTIFICATE_TIME)
                                 ? SSL_AD_CERTIFICATE_EXPIRED
                                 : SSL_AD_BAD_CERTIFICATE;
                quic_backend_debug_format(
                    conn,
                    "tls peer certificate rejected err=%d alert=%d len=%zu",
                    (int)result,
                    (int)*out_alert,
                    0U);
            }
        }
        else
        {
            quic_backend_debug_text(conn, "tls peer certificate accepted");
            conn->has_peer_identity = 1U;
            verify_result = ssl_verify_ok;
        }
    }

    return verify_result;
}

static libp2p_quic_err_t quic_backend_ssl_ctx_load_identity(
    SSL_CTX *ctx,
    const libp2p_quic_local_identity_t *identity)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((ctx == NULL) || (identity == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (
        (SSL_CTX_use_certificate_ASN1(
             ctx,
             identity->certificate_der_len,
             identity->certificate_der) != 1) ||
        (SSL_CTX_use_PrivateKey_ASN1(
             EVP_PKEY_EC,
             ctx,
             identity->certificate_private_key_der,
             identity->certificate_private_key_der_len) != 1) ||
        (SSL_CTX_check_private_key(ctx) != 1))
    {
        result = LIBP2P_QUIC_ERR_TLS;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

static libp2p_quic_conn_t *quic_backend_ssl_conn(SSL *ssl)
{
    ngtcp2_crypto_conn_ref *conn_ref = NULL;
    libp2p_quic_conn_t *result = NULL;

    if (ssl != NULL)
    {
        conn_ref = SSL_get_app_data(ssl);
        if ((conn_ref != NULL) && (conn_ref->user_data != NULL))
        {
            result = quic_backend_conn_from_memory(conn_ref->user_data);
        }
    }

    return result;
}

static void quic_backend_ssl_info_cb(const SSL *ssl, int type, int value)
{
    libp2p_quic_conn_t *conn = quic_backend_ssl_conn((SSL *)ssl);

    if ((type & SSL_CB_HANDSHAKE_START) != 0)
    {
        quic_backend_debug_text(conn, "tls handshake start");
    }
    if ((type & SSL_CB_HANDSHAKE_DONE) != 0)
    {
        quic_backend_debug_text(conn, "tls handshake done");
    }
    if ((type & SSL_CB_READ_ALERT) != 0)
    {
        quic_backend_debug_format(
            conn,
            "tls read alert level=%d alert=%d len=%zu",
            value >> 8,
            value & 0xFF,
            0U);
    }
    if ((type & SSL_CB_WRITE_ALERT) != 0)
    {
        quic_backend_debug_format(
            conn,
            "tls write alert level=%d alert=%d len=%zu",
            value >> 8,
            value & 0xFF,
            0U);
    }
}

static void quic_backend_ssl_msg_cb(
    int is_write,
    int version,
    int content_type,
    const void *buf,
    size_t len,
    SSL *ssl,
    void *arg)
{
    libp2p_quic_conn_t *conn = quic_backend_ssl_conn(ssl);

    (void)arg;
    quic_backend_debug_format(
        conn,
        "tls message write=%d content_type=%d len=%zu",
        is_write,
        content_type,
        len);
    quic_backend_debug_format(conn, "tls message version=%d state=%d len=%zu", version, 0, len);
    if ((buf != NULL) && (len != 0U))
    {
        quic_backend_debug_bytes(
            conn,
            LIBP2P_QUIC_DEBUG_EVENT_TLS_MESSAGE,
            (const uint8_t *)buf,
            len);
    }
}

QUIC_BACKEND_INTERNAL SSL_CTX *quic_backend_ssl_ctx_new(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_role_t role)
{
    SSL_CTX *ctx = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    int verify_mode = SSL_VERIFY_PEER;
    const SSL_METHOD *method = TLS_client_method();

    if (role == LIBP2P_QUIC_ROLE_SERVER)
    {
        method = TLS_server_method();
    }
    ctx = SSL_CTX_new(method);

    if (ctx != NULL)
    {
        if (role == LIBP2P_QUIC_ROLE_SERVER)
        {
            if (ngtcp2_crypto_boringssl_configure_server_context(ctx) != 0)
            {
                result = LIBP2P_QUIC_ERR_TLS;
            }
            verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            SSL_CTX_set_alpn_select_cb(ctx, quic_backend_alpn_select_cb, NULL);
        }
        else if (ngtcp2_crypto_boringssl_configure_client_context(ctx) != 0)
        {
            result = LIBP2P_QUIC_ERR_TLS;
        }
        else
        {
            result = LIBP2P_QUIC_OK;
        }
    }
    else
    {
        result = LIBP2P_QUIC_ERR_TLS;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_backend_ssl_ctx_load_identity(ctx, &endpoint->config.identity);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        SSL_CTX_set_custom_verify(ctx, verify_mode, quic_backend_ssl_verify_cb);
        SSL_CTX_set_verify_depth(ctx, 0);
        if (endpoint->config.debug_fn != NULL)
        {
            SSL_CTX_set_info_callback(ctx, quic_backend_ssl_info_cb);
            SSL_CTX_set_msg_callback(ctx, quic_backend_ssl_msg_cb);
        }
    }
    else if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    else
    {
        ctx = NULL;
    }

    return ctx;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_ssl_new_for_conn(libp2p_quic_conn_t *conn)
{
    SSL_CTX *ctx = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (conn->role == LIBP2P_QUIC_ROLE_SERVER)
    {
        ctx = conn->endpoint->server_ctx;
    }
    else
    {
        ctx = conn->endpoint->client_ctx;
    }
    conn->ssl = SSL_new(ctx);
    if (conn->ssl == NULL)
    {
        result = LIBP2P_QUIC_ERR_TLS;
    }
    else
    {
        conn->conn_ref.get_conn = quic_backend_crypto_get_conn;
        conn->conn_ref.user_data = conn;
        SSL_set_app_data(conn->ssl, &conn->conn_ref);

        if (conn->role == LIBP2P_QUIC_ROLE_SERVER)
        {
            SSL_set_accept_state(conn->ssl);
        }
        else
        {
            SSL_set_connect_state(conn->ssl);
            if (SSL_set_alpn_protos(
                    conn->ssl,
                    quic_backend_libp2p_alpn,
                    sizeof(quic_backend_libp2p_alpn)) != 0)
            {
                result = LIBP2P_QUIC_ERR_TLS;
            }
        }
    }

    return result;
}
