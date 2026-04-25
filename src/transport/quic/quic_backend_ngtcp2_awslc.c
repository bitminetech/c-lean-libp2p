/**
 * @file quic_backend_ngtcp2_awslc.c
 * @brief ngtcp2 + AWS-LC backend for libp2p QUIC v1.
 */

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <limits.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/evp.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "transport/quic/quic_backend.h"

#define QUIC_BACKEND_ENDPOINT_MAGIC UINT32_C(0x71455031)
#define QUIC_BACKEND_CONN_MAGIC     UINT32_C(0x71434e31)
#define QUIC_BACKEND_STREAM_MAGIC   UINT32_C(0x71535431)

#define QUIC_BACKEND_CONN_ID_BYTES          8U
#define QUIC_BACKEND_MAX_CONN_IDS_PER_CONN  8U
#define QUIC_BACKEND_EVENTS_PER_CONNECTION  8U
#define QUIC_BACKEND_EXTRA_EVENTS           16U
#define QUIC_BACKEND_ACTIVE_CID_LIMIT       8U
#define QUIC_BACKEND_STREAM_SEND_MULTIPLIER 2U

typedef struct quic_backend_stream_vec quic_backend_stream_vec_t;

struct libp2p_quic_stream
{
    uint32_t magic;
    libp2p_quic_conn_t *conn;
    int64_t stream_id;
    libp2p_quic_stream_state_t state;
    uint8_t incoming;
    uint8_t accepted;
    uint8_t remote_fin;
    uint8_t remote_fin_delivered;
    uint8_t local_fin_queued;
    uint8_t local_fin_sent;
    uint8_t reset;
    uint8_t *rx_data;
    size_t rx_len;
    size_t rx_read_offset;
    size_t rx_cap;
    uint64_t rx_next_offset;
    uint8_t *tx_data;
    size_t tx_len;
    size_t tx_sent_len;
    size_t tx_cap;
};

struct quic_backend_stream_vec
{
    libp2p_quic_stream_t **items;
    size_t len;
    size_t cap;
};

struct libp2p_quic_conn
{
    uint32_t magic;
    libp2p_quic_endpoint_t *endpoint;
    libp2p_quic_role_t role;
    libp2p_quic_conn_state_t state;
    ngtcp2_conn *ngconn;
    SSL *ssl;
    ngtcp2_crypto_conn_ref conn_ref;
    libp2p_quic_addr_t local_addr;
    libp2p_quic_addr_t remote_addr;
    void *user_data;
    libp2p_quic_peer_identity_t peer_identity;
    uint8_t has_peer_identity;
    uint8_t expected_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t expected_peer_id_len;
    ngtcp2_cid cids[QUIC_BACKEND_MAX_CONN_IDS_PER_CONN];
    size_t cid_count;
    quic_backend_stream_vec_t streams;
    uint8_t close_requested;
    uint8_t close_sent;
    ngtcp2_ccerr close_error;
    libp2p_quic_err_t callback_error;
};

struct libp2p_quic_endpoint
{
    uint32_t magic;
    libp2p_quic_endpoint_config_t config;
    libp2p_quic_allocator_t allocator;
    ngtcp2_mem ngtcp2_mem;
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    libp2p_quic_addr_t local_addr;
    uint8_t bound;
    uint8_t closed;
    libp2p_quic_conn_t **connections;
    size_t connection_count;
    size_t incoming_connection_count;
    size_t outgoing_connection_count;
    libp2p_quic_event_t *events;
    size_t event_cap;
    size_t event_head;
    size_t event_len;
};

static void *quic_backend_default_malloc(size_t size, void *user_data)
{
    (void)user_data;
    return malloc(size);
}

static void *quic_backend_default_calloc(size_t nmemb, size_t size, void *user_data)
{
    (void)user_data;
    return calloc(nmemb, size);
}

static void *quic_backend_default_realloc(void *ptr, size_t size, void *user_data)
{
    (void)user_data;
    return realloc(ptr, size);
}

static void quic_backend_default_free(void *ptr, void *user_data)
{
    (void)user_data;
    free(ptr);
}

static int quic_backend_size_mul_overflow(size_t a, size_t b, size_t *out)
{
    if ((a != 0U) && (b > (SIZE_MAX / a)))
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a * b;
    return 0;
}

static int quic_backend_size_add_overflow(size_t a, size_t b, size_t *out)
{
    if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        return 1;
    }

    *out = a + b;
    return 0;
}

static libp2p_quic_err_t quic_backend_allocator_normalize(
    const libp2p_quic_allocator_t *in,
    libp2p_quic_allocator_t *out)
{
    if (out == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if ((in == NULL) || ((in->malloc_fn == NULL) && (in->calloc_fn == NULL) &&
                         (in->realloc_fn == NULL) && (in->free_fn == NULL)))
    {
        out->malloc_fn = quic_backend_default_malloc;
        out->calloc_fn = quic_backend_default_calloc;
        out->realloc_fn = quic_backend_default_realloc;
        out->free_fn = quic_backend_default_free;
        out->user_data = NULL;
        return LIBP2P_QUIC_OK;
    }

    if ((in->malloc_fn == NULL) || (in->calloc_fn == NULL) || (in->realloc_fn == NULL) ||
        (in->free_fn == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out = *in;
    return LIBP2P_QUIC_OK;
}

static void *quic_backend_malloc(libp2p_quic_endpoint_t *endpoint, size_t size)
{
    return endpoint->allocator.malloc_fn(size, endpoint->allocator.user_data);
}

static void *quic_backend_calloc(libp2p_quic_endpoint_t *endpoint, size_t nmemb, size_t size)
{
    return endpoint->allocator.calloc_fn(nmemb, size, endpoint->allocator.user_data);
}

static void *quic_backend_realloc(libp2p_quic_endpoint_t *endpoint, void *ptr, size_t size)
{
    return endpoint->allocator.realloc_fn(ptr, size, endpoint->allocator.user_data);
}

static void quic_backend_free(libp2p_quic_endpoint_t *endpoint, void *ptr)
{
    if ((endpoint != NULL) && (ptr != NULL))
    {
        endpoint->allocator.free_fn(ptr, endpoint->allocator.user_data);
    }
}

static void *quic_backend_ngtcp2_malloc(size_t size, void *user_data)
{
    return quic_backend_malloc((libp2p_quic_endpoint_t *)user_data, size);
}

static void *quic_backend_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data)
{
    return quic_backend_calloc((libp2p_quic_endpoint_t *)user_data, nmemb, size);
}

static void *quic_backend_ngtcp2_realloc(void *ptr, size_t size, void *user_data)
{
    return quic_backend_realloc((libp2p_quic_endpoint_t *)user_data, ptr, size);
}

static void quic_backend_ngtcp2_free(void *ptr, void *user_data)
{
    quic_backend_free((libp2p_quic_endpoint_t *)user_data, ptr);
}

static libp2p_quic_err_t quic_backend_validate_endpoint(const libp2p_quic_endpoint_t *endpoint)
{
    if ((endpoint == NULL) || (endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return endpoint->closed != 0U ? LIBP2P_QUIC_ERR_CLOSED : LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_validate_conn(const libp2p_quic_conn_t *conn)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (conn->endpoint == NULL) ||
        (conn->endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return (conn->state == LIBP2P_QUIC_CONN_CLOSED || conn->state == LIBP2P_QUIC_CONN_DRAINED)
               ? LIBP2P_QUIC_ERR_CLOSED
               : LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_validate_stream(const libp2p_quic_stream_t *stream)
{
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) ||
        (stream->conn == NULL) || (stream->conn->magic != QUIC_BACKEND_CONN_MAGIC))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    return (stream->state == LIBP2P_QUIC_STREAM_CLOSED || stream->state == LIBP2P_QUIC_STREAM_RESET)
               ? LIBP2P_QUIC_ERR_CLOSED
               : LIBP2P_QUIC_OK;
}

static ngtcp2_tstamp quic_backend_time_to_ngtcp2(libp2p_quic_time_us_t now_us)
{
    if (now_us > (UINT64_MAX / (uint64_t)NGTCP2_MICROSECONDS))
    {
        return UINT64_MAX;
    }

    return now_us * (uint64_t)NGTCP2_MICROSECONDS;
}

static libp2p_quic_time_us_t quic_backend_time_from_ngtcp2(ngtcp2_tstamp ts)
{
    return (libp2p_quic_time_us_t)(ts / (uint64_t)NGTCP2_MICROSECONDS);
}

static ngtcp2_duration quic_backend_duration_to_ngtcp2(libp2p_quic_time_us_t duration_us)
{
    return quic_backend_time_to_ngtcp2(duration_us);
}

static uint8_t quic_backend_ecn_to_ngtcp2(libp2p_quic_ecn_t ecn)
{
    switch (ecn)
    {
    case LIBP2P_QUIC_ECN_ECT0:
        return NGTCP2_ECN_ECT_0;
    case LIBP2P_QUIC_ECN_ECT1:
        return NGTCP2_ECN_ECT_1;
    case LIBP2P_QUIC_ECN_CE:
        return NGTCP2_ECN_CE;
    case LIBP2P_QUIC_ECN_NOT_ECT:
    default:
        return NGTCP2_ECN_NOT_ECT;
    }
}

static libp2p_quic_ecn_t quic_backend_ecn_from_ngtcp2(uint8_t ecn)
{
    switch (ecn & NGTCP2_ECN_MASK)
    {
    case NGTCP2_ECN_ECT_0:
        return LIBP2P_QUIC_ECN_ECT0;
    case NGTCP2_ECN_ECT_1:
        return LIBP2P_QUIC_ECN_ECT1;
    case NGTCP2_ECN_CE:
        return LIBP2P_QUIC_ECN_CE;
    case NGTCP2_ECN_NOT_ECT:
    default:
        return LIBP2P_QUIC_ECN_NOT_ECT;
    }
}

static libp2p_quic_err_t quic_backend_event_push(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_type_t type,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code,
    uint64_t transport_error_code)
{
    size_t pos = 0U;
    libp2p_quic_event_t event;

    if ((endpoint == NULL) || (endpoint->events == NULL) || (endpoint->event_cap == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (endpoint->event_len == endpoint->event_cap)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    event.type = type;
    event.conn = conn;
    event.stream = stream;
    event.app_error_code = app_error_code;
    event.transport_error_code = transport_error_code;

    pos = (endpoint->event_head + endpoint->event_len) % endpoint->event_cap;
    endpoint->events[pos] = event;
    endpoint->event_len++;

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_addr_to_sockaddr(
    const libp2p_quic_addr_t *addr,
    ngtcp2_sockaddr_union *out,
    ngtcp2_socklen *out_len)
{
    if ((addr == NULL) || (out == NULL) || (out_len == NULL) ||
        (libp2p_quic_addr_validate(addr) != LIBP2P_QUIC_OK))
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }

    (void)memset(out, 0, sizeof(*out));
    if (addr->family == LIBP2P_QUIC_ADDR_IP4)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        (void)memcpy(&sin->sin_addr, addr->ip, 4U);
        *out_len = (ngtcp2_socklen)sizeof(*sin);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        (void)memcpy(&sin6->sin6_addr, addr->ip, 16U);
        *out_len = (ngtcp2_socklen)sizeof(*sin6);
    }

    return LIBP2P_QUIC_OK;
}

static void quic_backend_path_from_addrs(
    const libp2p_quic_addr_t *local_addr,
    const libp2p_quic_addr_t *remote_addr,
    ngtcp2_path_storage *path)
{
    ngtcp2_sockaddr_union local;
    ngtcp2_sockaddr_union remote;
    ngtcp2_socklen local_len = 0;
    ngtcp2_socklen remote_len = 0;

    (void)quic_backend_addr_to_sockaddr(local_addr, &local, &local_len);
    (void)quic_backend_addr_to_sockaddr(remote_addr, &remote, &remote_len);
    ngtcp2_path_storage_init(
        path,
        (const ngtcp2_sockaddr *)&local,
        local_len,
        (const ngtcp2_sockaddr *)&remote,
        remote_len,
        NULL);
}

static libp2p_quic_err_t quic_backend_copy_measure(
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

static libp2p_quic_err_t quic_backend_ngtcp2_err(int rv)
{
    switch (rv)
    {
    case 0:
        return LIBP2P_QUIC_OK;
    case NGTCP2_ERR_NOMEM:
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    case NGTCP2_ERR_NOBUF:
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    case NGTCP2_ERR_STREAM_ID_BLOCKED:
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    case NGTCP2_ERR_STREAM_NOT_FOUND:
        return LIBP2P_QUIC_ERR_NOT_FOUND;
    case NGTCP2_ERR_STREAM_SHUT_WR:
    case NGTCP2_ERR_CLOSING:
    case NGTCP2_ERR_DRAINING:
    case NGTCP2_ERR_IDLE_CLOSE:
        return LIBP2P_QUIC_ERR_CLOSED;
    case NGTCP2_ERR_CRYPTO:
        return LIBP2P_QUIC_ERR_TLS;
    case NGTCP2_ERR_VERSION_NEGOTIATION:
    case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
        return LIBP2P_QUIC_ERR_VERSION;
    case NGTCP2_ERR_INVALID_ARGUMENT:
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    case NGTCP2_ERR_INVALID_STATE:
        return LIBP2P_QUIC_ERR_STATE;
    case NGTCP2_ERR_CALLBACK_FAILURE:
        return LIBP2P_QUIC_ERR_BACKEND;
    default:
        return LIBP2P_QUIC_ERR_BACKEND;
    }
}

static int quic_backend_alpn_select_cb(
    SSL *ssl,
    const uint8_t **out,
    uint8_t *out_len,
    const uint8_t *in,
    unsigned in_len,
    void *arg)
{
    static const uint8_t libp2p_alpn[] =
        {(uint8_t)LIBP2P_QUIC_ALPN_LEN, 'l', 'i', 'b', 'p', '2', 'p'};
    uint8_t *selected = NULL;
    uint8_t selected_len = 0U;
    int result = 0;

    (void)ssl;
    (void)arg;

    result = SSL_select_next_proto(
        &selected,
        &selected_len,
        libp2p_alpn,
        sizeof(libp2p_alpn),
        in,
        in_len);
    if (result != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *out = selected;
    *out_len = selected_len;
    return SSL_TLSEXT_ERR_OK;
}

static ngtcp2_conn *quic_backend_crypto_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    const libp2p_quic_conn_t *conn = NULL;

    if ((conn_ref == NULL) || (conn_ref->user_data == NULL))
    {
        return NULL;
    }

    conn = (libp2p_quic_conn_t *)conn_ref->user_data;
    return conn->ngconn;
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

    if (out_alert != NULL)
    {
        *out_alert = SSL_AD_CERTIFICATE_UNKNOWN;
    }

    conn_ref = (ngtcp2_crypto_conn_ref *)SSL_get_app_data(ssl);
    if ((conn_ref == NULL) || (conn_ref->user_data == NULL))
    {
        if (out_alert != NULL)
        {
            *out_alert = SSL_AD_INTERNAL_ERROR;
        }
        return ssl_verify_invalid;
    }

    conn = (libp2p_quic_conn_t *)conn_ref->user_data;
    endpoint = conn->endpoint;

    chain = SSL_get0_peer_certificates(ssl);
    if ((chain == NULL) || (sk_CRYPTO_BUFFER_num(chain) != 1U))
    {
        if (out_alert != NULL)
        {
            *out_alert = SSL_AD_BAD_CERTIFICATE;
        }
        return ssl_verify_invalid;
    }

    if (endpoint->config.unix_time_fn(&now, endpoint->config.unix_time_user_data) != LIBP2P_QUIC_OK)
    {
        if (out_alert != NULL)
        {
            *out_alert = SSL_AD_INTERNAL_ERROR;
        }
        return ssl_verify_invalid;
    }

    leaf = sk_CRYPTO_BUFFER_value(chain, 0U);
    certificate.data = CRYPTO_BUFFER_data(leaf);
    certificate.len = CRYPTO_BUFFER_len(leaf);

    result = libp2p_quic_identity_verify_peer_certificate_chain(
        &certificate,
        1U,
        conn->expected_peer_id_len != 0U ? conn->expected_peer_id : NULL,
        conn->expected_peer_id_len,
        now,
        &conn->peer_identity,
        NULL);
    if (result != LIBP2P_QUIC_OK)
    {
        if (out_alert != NULL)
        {
            *out_alert = (result == LIBP2P_QUIC_ERR_CERTIFICATE_TIME) ? SSL_AD_CERTIFICATE_EXPIRED
                                                                      : SSL_AD_BAD_CERTIFICATE;
        }
        return ssl_verify_invalid;
    }

    conn->has_peer_identity = 1U;
    return ssl_verify_ok;
}

static libp2p_quic_err_t quic_backend_ssl_ctx_load_identity(
    SSL_CTX *ctx,
    const libp2p_quic_local_identity_t *identity)
{
    if ((ctx == NULL) || (identity == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if ((SSL_CTX_use_certificate_ASN1(
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
        return LIBP2P_QUIC_ERR_TLS;
    }

    return LIBP2P_QUIC_OK;
}

static SSL_CTX *quic_backend_ssl_ctx_new(libp2p_quic_endpoint_t *endpoint, libp2p_quic_role_t role)
{
    SSL_CTX *ctx = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    int verify_mode = SSL_VERIFY_PEER;

    ctx = SSL_CTX_new(role == LIBP2P_QUIC_ROLE_SERVER ? TLS_server_method() : TLS_client_method());
    if (ctx == NULL)
    {
        return NULL;
    }

    if (role == LIBP2P_QUIC_ROLE_SERVER)
    {
        if (ngtcp2_crypto_boringssl_configure_server_context(ctx) != 0)
        {
            SSL_CTX_free(ctx);
            return NULL;
        }
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_alpn_select_cb(ctx, quic_backend_alpn_select_cb, NULL);
    }
    else
    {
        if (ngtcp2_crypto_boringssl_configure_client_context(ctx) != 0)
        {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    result = quic_backend_ssl_ctx_load_identity(ctx, &endpoint->config.identity);
    if (result != LIBP2P_QUIC_OK)
    {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_custom_verify(ctx, verify_mode, quic_backend_ssl_verify_cb);
    SSL_CTX_set_verify_depth(ctx, 0);

    return ctx;
}

static libp2p_quic_err_t quic_backend_ssl_new_for_conn(libp2p_quic_conn_t *conn)
{
    static const uint8_t libp2p_alpn[] =
        {(uint8_t)LIBP2P_QUIC_ALPN_LEN, 'l', 'i', 'b', 'p', '2', 'p'};
    SSL_CTX *ctx = NULL;

    ctx = (conn->role == LIBP2P_QUIC_ROLE_SERVER) ? conn->endpoint->server_ctx
                                                  : conn->endpoint->client_ctx;
    conn->ssl = SSL_new(ctx);
    if (conn->ssl == NULL)
    {
        return LIBP2P_QUIC_ERR_TLS;
    }

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
        if (SSL_set_alpn_protos(conn->ssl, libp2p_alpn, sizeof(libp2p_alpn)) != 0)
        {
            return LIBP2P_QUIC_ERR_TLS;
        }
    }

    return LIBP2P_QUIC_OK;
}

static void quic_backend_ngtcp2_rand_cb(
    uint8_t *dest,
    size_t destlen,
    const ngtcp2_rand_ctx *rand_ctx)
{
    libp2p_quic_conn_t *conn = NULL;

    if ((dest == NULL) || (rand_ctx == NULL) || (rand_ctx->native_handle == NULL))
    {
        return;
    }

    conn = (libp2p_quic_conn_t *)rand_ctx->native_handle;
    if (conn->endpoint->config.random_fn(dest, destlen, conn->endpoint->config.random_user_data) !=
        LIBP2P_QUIC_OK)
    {
        (void)memset(dest, 0, destlen);
        conn->callback_error = LIBP2P_QUIC_ERR_INTERNAL;
    }
}

static int quic_backend_get_path_challenge_data_cb(
    ngtcp2_conn *ngconn,
    ngtcp2_path_challenge_data *data,
    void *user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;

    (void)ngconn;
    if ((conn == NULL) || (data == NULL) ||
        (conn->endpoint->config
             .random_fn(data->data, sizeof(data->data), conn->endpoint->config.random_user_data) !=
         LIBP2P_QUIC_OK))
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int quic_backend_conn_add_cid(libp2p_quic_conn_t *conn, const ngtcp2_cid *cid)
{
    size_t index = 0U;

    if ((conn == NULL) || (cid == NULL) || (cid->datalen == 0U) ||
        (cid->datalen > NGTCP2_MAX_CIDLEN))
    {
        return -1;
    }

    for (index = 0U; index < conn->cid_count; index++)
    {
        if (ngtcp2_cid_eq(&conn->cids[index], cid) != 0)
        {
            return 0;
        }
    }
    if (conn->cid_count == QUIC_BACKEND_MAX_CONN_IDS_PER_CONN)
    {
        return -1;
    }

    conn->cids[conn->cid_count] = *cid;
    conn->cid_count++;
    return 0;
}

static int quic_backend_get_new_connection_id_cb(
    ngtcp2_conn *ngconn,
    ngtcp2_cid *cid,
    ngtcp2_stateless_reset_token *token,
    size_t cidlen,
    void *user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;

    (void)ngconn;
    if ((conn == NULL) || (cid == NULL) || (token == NULL) || (cidlen == 0U) ||
        (cidlen > NGTCP2_MAX_CIDLEN))
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if ((conn->endpoint->config
             .random_fn(cid->data, cidlen, conn->endpoint->config.random_user_data) !=
         LIBP2P_QUIC_OK) ||
        (conn->endpoint->config.random_fn(
             token->data,
             sizeof(token->data),
             conn->endpoint->config.random_user_data) != LIBP2P_QUIC_OK))
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;
    return quic_backend_conn_add_cid(conn, cid) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static libp2p_quic_stream_t *quic_backend_conn_find_stream(
    const libp2p_quic_conn_t *conn,
    int64_t stream_id)
{
    size_t index = 0U;

    if (conn == NULL)
    {
        return NULL;
    }

    for (index = 0U; index < conn->streams.len; index++)
    {
        if ((conn->streams.items[index] != NULL) &&
            (conn->streams.items[index]->stream_id == stream_id))
        {
            return conn->streams.items[index];
        }
    }

    return NULL;
}

static libp2p_quic_err_t quic_backend_stream_vec_push(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream)
{
    if ((conn == NULL) || (stream == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (conn->streams.len == conn->streams.cap)
    {
        const size_t new_cap = conn->streams.cap == 0U ? 8U : conn->streams.cap * 2U;
        size_t new_bytes = 0U;
        libp2p_quic_stream_t **new_items = NULL;

        if ((new_cap < conn->streams.cap) ||
            // NOLINTNEXTLINE(bugprone-sizeof-expression)
            (quic_backend_size_mul_overflow(new_cap, sizeof(*conn->streams.items), &new_bytes) !=
             0))
        {
            return LIBP2P_QUIC_ERR_LIMIT;
        }

        new_items = (libp2p_quic_stream_t **)
            quic_backend_realloc(conn->endpoint, (void *)conn->streams.items, new_bytes);
        if (new_items == NULL)
        {
            return LIBP2P_QUIC_ERR_NO_MEMORY;
        }

        conn->streams.items = new_items;
        conn->streams.cap = new_cap;
    }

    conn->streams.items[conn->streams.len] = stream;
    conn->streams.len++;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_stream_t *quic_backend_stream_new(
    libp2p_quic_conn_t *conn,
    int64_t stream_id,
    int incoming)
{
    libp2p_quic_stream_t *stream = NULL;

    stream = (libp2p_quic_stream_t *)quic_backend_calloc(conn->endpoint, 1U, sizeof(*stream));
    if (stream == NULL)
    {
        return NULL;
    }

    stream->magic = QUIC_BACKEND_STREAM_MAGIC;
    stream->conn = conn;
    stream->stream_id = stream_id;
    stream->state = LIBP2P_QUIC_STREAM_OPEN;
    stream->incoming = (uint8_t)(incoming != 0);

    if (quic_backend_stream_vec_push(conn, stream) != LIBP2P_QUIC_OK)
    {
        quic_backend_free(conn->endpoint, stream);
        return NULL;
    }

    return stream;
}

static void quic_backend_stream_free(libp2p_quic_stream_t *stream)
{
    libp2p_quic_endpoint_t *endpoint = NULL;

    if (stream == NULL)
    {
        return;
    }

    endpoint = stream->conn != NULL ? stream->conn->endpoint : NULL;
    quic_backend_free(endpoint, stream->rx_data);
    quic_backend_free(endpoint, stream->tx_data);
    stream->magic = 0U;
    quic_backend_free(endpoint, stream);
}

static int quic_backend_stream_open_cb(ngtcp2_conn *ngconn, int64_t stream_id, void *user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;
    libp2p_quic_stream_t *stream = NULL;

    (void)ngconn;
    if (conn == NULL)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    stream = quic_backend_conn_find_stream(conn, stream_id);
    if (stream == NULL)
    {
        stream = quic_backend_stream_new(conn, stream_id, 1);
        if (stream == NULL)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return quic_backend_event_push(
               conn->endpoint,
               LIBP2P_QUIC_EVENT_STREAM_INCOMING,
               conn,
               stream,
               0U,
               0U) == LIBP2P_QUIC_OK
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

static libp2p_quic_err_t quic_backend_stream_rx_append(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t datalen)
{
    size_t available_tail = 0U;
    size_t required = 0U;
    uint8_t *new_data = NULL;

    if ((stream == NULL) || ((data == NULL) && (datalen != 0U)))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (datalen == 0U)
    {
        return LIBP2P_QUIC_OK;
    }

    available_tail = stream->rx_cap - stream->rx_len;
    if (available_tail < datalen)
    {
        if (quic_backend_size_add_overflow(stream->rx_len, datalen, &required) != 0)
        {
            return LIBP2P_QUIC_ERR_LIMIT;
        }

        if (required < (stream->rx_cap * 2U))
        {
            required = stream->rx_cap * 2U;
        }
        if (required < 1024U)
        {
            required = 1024U;
        }

        new_data =
            (uint8_t *)quic_backend_realloc(stream->conn->endpoint, stream->rx_data, required);
        if (new_data == NULL)
        {
            return LIBP2P_QUIC_ERR_NO_MEMORY;
        }
        stream->rx_data = new_data;
        stream->rx_cap = required;
    }

    (void)memcpy(&stream->rx_data[stream->rx_len], data, datalen);
    stream->rx_len += datalen;
    return LIBP2P_QUIC_OK;
}

static int quic_backend_recv_stream_data_cb(
    ngtcp2_conn *ngconn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t *data,
    size_t datalen,
    void *user_data,
    void *stream_user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;
    libp2p_quic_stream_t *stream = (libp2p_quic_stream_t *)stream_user_data;

    (void)ngconn;
    if (conn == NULL)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (stream == NULL)
    {
        stream = quic_backend_conn_find_stream(conn, stream_id);
        if (stream == NULL)
        {
            stream = quic_backend_stream_new(conn, stream_id, 1);
            if (stream == NULL)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        if (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (offset != stream->rx_next_offset)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (quic_backend_stream_rx_append(stream, data, datalen) != LIBP2P_QUIC_OK)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    stream->rx_next_offset += (uint64_t)datalen;
    if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0U)
    {
        stream->remote_fin = 1U;
        stream->state = stream->local_fin_sent != 0U ? LIBP2P_QUIC_STREAM_CLOSED
                                                     : LIBP2P_QUIC_STREAM_HALF_CLOSED_REMOTE;
    }

    return quic_backend_event_push(
               conn->endpoint,
               LIBP2P_QUIC_EVENT_STREAM_READABLE,
               conn,
               stream,
               0U,
               0U) == LIBP2P_QUIC_OK
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int quic_backend_stream_close_cb(
    ngtcp2_conn *ngconn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;
    libp2p_quic_stream_t *stream = (libp2p_quic_stream_t *)stream_user_data;

    (void)ngconn;
    if (conn == NULL)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (stream == NULL)
    {
        stream = quic_backend_conn_find_stream(conn, stream_id);
        if (stream == NULL)
        {
            stream = quic_backend_stream_new(conn, stream_id, 1);
            if (stream == NULL)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if (quic_backend_event_push(
                    conn->endpoint,
                    LIBP2P_QUIC_EVENT_STREAM_INCOMING,
                    conn,
                    stream,
                    0U,
                    0U) != LIBP2P_QUIC_OK)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    if (stream != NULL)
    {
        stream->state = ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0U)
                            ? LIBP2P_QUIC_STREAM_RESET
                            : LIBP2P_QUIC_STREAM_CLOSED;
        stream->reset = (uint8_t)((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0U);
    }

    return quic_backend_event_push(
               conn->endpoint,
               LIBP2P_QUIC_EVENT_STREAM_CLOSED,
               conn,
               stream,
               ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0U) ? app_error_code : 0U,
               0U) == LIBP2P_QUIC_OK
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int quic_backend_stream_reset_cb(
    ngtcp2_conn *ngconn,
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;
    libp2p_quic_stream_t *stream = (libp2p_quic_stream_t *)stream_user_data;

    (void)ngconn;
    (void)final_size;
    if (conn == NULL)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (stream == NULL)
    {
        stream = quic_backend_conn_find_stream(conn, stream_id);
        if (stream == NULL)
        {
            stream = quic_backend_stream_new(conn, stream_id, 1);
            if (stream == NULL)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if (quic_backend_event_push(
                    conn->endpoint,
                    LIBP2P_QUIC_EVENT_STREAM_INCOMING,
                    conn,
                    stream,
                    0U,
                    0U) != LIBP2P_QUIC_OK)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    if (stream != NULL)
    {
        stream->state = LIBP2P_QUIC_STREAM_RESET;
        stream->reset = 1U;
    }

    return quic_backend_event_push(
               conn->endpoint,
               LIBP2P_QUIC_EVENT_STREAM_CLOSED,
               conn,
               stream,
               app_error_code,
               0U) == LIBP2P_QUIC_OK
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int quic_backend_handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data)
{
    libp2p_quic_conn_t *conn = (libp2p_quic_conn_t *)user_data;

    (void)ngconn;
    if (conn == NULL)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    conn->state = LIBP2P_QUIC_CONN_ESTABLISHED;
    return quic_backend_event_push(
               conn->endpoint,
               LIBP2P_QUIC_EVENT_CONN_ESTABLISHED,
               conn,
               NULL,
               0U,
               0U) == LIBP2P_QUIC_OK
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int quic_backend_extend_max_streams_cb(
    ngtcp2_conn *ngconn,
    uint64_t max_streams,
    void *user_data)
{
    (void)ngconn;
    (void)max_streams;
    (void)user_data;
    return 0;
}

static const ngtcp2_callbacks quic_backend_callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = quic_backend_handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = quic_backend_recv_stream_data_cb,
    .stream_open = quic_backend_stream_open_cb,
    .stream_close = quic_backend_stream_close_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .extend_max_local_streams_bidi = quic_backend_extend_max_streams_cb,
    .extend_max_local_streams_uni = quic_backend_extend_max_streams_cb,
    .rand = quic_backend_ngtcp2_rand_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .stream_reset = quic_backend_stream_reset_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .get_new_connection_id2 = quic_backend_get_new_connection_id_cb,
    .get_path_challenge_data2 = quic_backend_get_path_challenge_data_cb,
};

static void quic_backend_settings_init(
    const libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_conn_t *conn,
    ngtcp2_settings *settings)
{
    ngtcp2_settings_default(settings);
    settings->initial_ts = 0U;
    settings->max_tx_udp_payload_size = endpoint->config.max_datagram_payload_bytes;
    settings->handshake_timeout =
        quic_backend_duration_to_ngtcp2(endpoint->config.handshake_timeout_us);
    settings->max_window = endpoint->config.initial_conn_window_bytes;
    settings->max_stream_window = endpoint->config.initial_stream_window_bytes;
    settings->no_pmtud = 1U;
    settings->rand_ctx.native_handle = (void *)conn;
}

static void quic_backend_transport_params_init(
    const libp2p_quic_endpoint_t *endpoint,
    ngtcp2_transport_params *params)
{
    ngtcp2_transport_params_default(params);
    params->initial_max_stream_data_bidi_local = endpoint->config.initial_stream_window_bytes;
    params->initial_max_stream_data_bidi_remote = endpoint->config.initial_stream_window_bytes;
    params->initial_max_stream_data_uni = 0U;
    params->initial_max_data = endpoint->config.initial_conn_window_bytes;
    params->initial_max_streams_bidi = endpoint->config.max_bidi_streams;
    params->initial_max_streams_uni = endpoint->config.max_uni_streams;
    params->max_idle_timeout = quic_backend_duration_to_ngtcp2(endpoint->config.idle_timeout_us);
    params->max_udp_payload_size = endpoint->config.max_datagram_payload_bytes;
    params->active_connection_id_limit = QUIC_BACKEND_ACTIVE_CID_LIMIT;
    params->max_datagram_frame_size = 0U;
    params->disable_active_migration = 1U;
}

static libp2p_quic_err_t quic_backend_random_cid(libp2p_quic_endpoint_t *endpoint, ngtcp2_cid *cid)
{
    if ((endpoint == NULL) || (cid == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    cid->datalen = QUIC_BACKEND_CONN_ID_BYTES;
    return endpoint->config.random_fn(cid->data, cid->datalen, endpoint->config.random_user_data);
}

static void quic_backend_conn_free(libp2p_quic_conn_t *conn)
{
    libp2p_quic_endpoint_t *endpoint = NULL;
    size_t index = 0U;

    if (conn == NULL)
    {
        return;
    }

    endpoint = conn->endpoint;
    for (index = 0U; index < conn->streams.len; index++)
    {
        quic_backend_stream_free(conn->streams.items[index]);
    }
    quic_backend_free(endpoint, (void *)conn->streams.items);
    ngtcp2_conn_del(conn->ngconn);
    SSL_free(conn->ssl);
    conn->magic = 0U;
    quic_backend_free(endpoint, conn);
}

static libp2p_quic_err_t quic_backend_conn_add_to_endpoint(libp2p_quic_conn_t *conn)
{
    libp2p_quic_endpoint_t *endpoint = conn->endpoint;

    if (endpoint->connection_count == endpoint->config.max_connections)
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }
    if ((conn->role == LIBP2P_QUIC_ROLE_CLIENT) &&
        (endpoint->outgoing_connection_count == endpoint->config.max_outgoing_connections))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }
    if ((conn->role == LIBP2P_QUIC_ROLE_SERVER) &&
        (endpoint->incoming_connection_count == endpoint->config.max_incoming_connections))
    {
        return LIBP2P_QUIC_ERR_LIMIT;
    }

    endpoint->connections[endpoint->connection_count] = conn;
    endpoint->connection_count++;
    if (conn->role == LIBP2P_QUIC_ROLE_CLIENT)
    {
        endpoint->outgoing_connection_count++;
    }
    else
    {
        endpoint->incoming_connection_count++;
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_client_new(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *dial_config,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_conn_t *conn = NULL;
    ngtcp2_path_storage path;
    ngtcp2_cid dcid;
    ngtcp2_cid scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv = 0;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    conn = (libp2p_quic_conn_t *)quic_backend_calloc(endpoint, 1U, sizeof(*conn));
    if (conn == NULL)
    {
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    }

    conn->magic = QUIC_BACKEND_CONN_MAGIC;
    conn->endpoint = endpoint;
    conn->role = LIBP2P_QUIC_ROLE_CLIENT;
    conn->state = LIBP2P_QUIC_CONN_HANDSHAKING;
    conn->local_addr = endpoint->local_addr;
    conn->remote_addr = dial_config->remote_addr;
    conn->user_data = dial_config->user_data;
    conn->expected_peer_id_len = dial_config->remote_addr.peer_id_len;
    (void)memcpy(
        conn->expected_peer_id,
        dial_config->remote_addr.peer_id,
        conn->expected_peer_id_len);
    ngtcp2_ccerr_default(&conn->close_error);

    result = quic_backend_ssl_new_for_conn(conn);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }

    result = quic_backend_random_cid(endpoint, &dcid);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = quic_backend_random_cid(endpoint, &scid);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    if (quic_backend_conn_add_cid(conn, &scid) != 0)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
        goto fail;
    }

    quic_backend_path_from_addrs(&conn->local_addr, &conn->remote_addr, &path);
    quic_backend_settings_init(endpoint, conn, &settings);
    quic_backend_transport_params_init(endpoint, &params);

    rv = ngtcp2_conn_client_new(
        &conn->ngconn,
        &dcid,
        &scid,
        &path.path,
        NGTCP2_PROTO_VER_V1,
        &quic_backend_callbacks,
        &settings,
        &params,
        &endpoint->ngtcp2_mem,
        conn);
    if (rv != 0)
    {
        result = quic_backend_ngtcp2_err(rv);
        goto fail;
    }

    ngtcp2_conn_set_tls_native_handle(conn->ngconn, conn->ssl);

    result = quic_backend_conn_add_to_endpoint(conn);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }

    (void)
        quic_backend_event_push(endpoint, LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY, conn, NULL, 0U, 0U);
    *out_conn = conn;
    return LIBP2P_QUIC_OK;

fail:
    quic_backend_conn_free(conn);
    return result;
}

static libp2p_quic_err_t quic_backend_conn_server_new(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    const ngtcp2_pkt_hd *hd,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_conn_t *conn = NULL;
    ngtcp2_path_storage path;
    ngtcp2_cid scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv = 0;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    conn = (libp2p_quic_conn_t *)quic_backend_calloc(endpoint, 1U, sizeof(*conn));
    if (conn == NULL)
    {
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    }

    conn->magic = QUIC_BACKEND_CONN_MAGIC;
    conn->endpoint = endpoint;
    conn->role = LIBP2P_QUIC_ROLE_SERVER;
    conn->state = LIBP2P_QUIC_CONN_HANDSHAKING;
    conn->local_addr = datagram->local_addr;
    conn->remote_addr = datagram->remote_addr;
    ngtcp2_ccerr_default(&conn->close_error);

    result = quic_backend_ssl_new_for_conn(conn);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    result = quic_backend_random_cid(endpoint, &scid);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }
    if (quic_backend_conn_add_cid(conn, &scid) != 0)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
        goto fail;
    }

    quic_backend_path_from_addrs(&conn->local_addr, &conn->remote_addr, &path);
    quic_backend_settings_init(endpoint, conn, &settings);
    quic_backend_transport_params_init(endpoint, &params);
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1U;

    rv = ngtcp2_conn_server_new(
        &conn->ngconn,
        &hd->scid,
        &scid,
        &path.path,
        hd->version,
        &quic_backend_callbacks,
        &settings,
        &params,
        &endpoint->ngtcp2_mem,
        conn);
    if (rv != 0)
    {
        result = quic_backend_ngtcp2_err(rv);
        goto fail;
    }

    ngtcp2_conn_set_tls_native_handle(conn->ngconn, conn->ssl);

    result = quic_backend_conn_add_to_endpoint(conn);
    if (result != LIBP2P_QUIC_OK)
    {
        goto fail;
    }

    (void)quic_backend_event_push(endpoint, LIBP2P_QUIC_EVENT_CONN_INCOMING, conn, NULL, 0U, 0U);
    *out_conn = conn;
    return LIBP2P_QUIC_OK;

fail:
    quic_backend_conn_free(conn);
    return result;
}

static libp2p_quic_conn_t *quic_backend_find_conn_by_packet(
    const libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram)
{
    ngtcp2_version_cid version_cid;
    size_t conn_index = 0U;
    size_t cid_index = 0U;

    for (conn_index = 0U; conn_index < endpoint->connection_count; conn_index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[conn_index];

        if (conn == NULL)
        {
            continue;
        }
        for (cid_index = 0U; cid_index < conn->cid_count; cid_index++)
        {
            (void)memset(&version_cid, 0, sizeof(version_cid));
            if ((ngtcp2_pkt_decode_version_cid(
                     &version_cid,
                     datagram->data,
                     datagram->data_len,
                     conn->cids[cid_index].datalen) == 0) &&
                (version_cid.dcidlen == conn->cids[cid_index].datalen) &&
                (memcmp(version_cid.dcid, conn->cids[cid_index].data, version_cid.dcidlen) == 0))
            {
                return conn;
            }
        }
    }

    for (conn_index = 0U; conn_index < endpoint->connection_count; conn_index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[conn_index];

        if ((conn != NULL) &&
            (libp2p_quic_addr_equal(&conn->local_addr, &datagram->local_addr, 0) != 0) &&
            (libp2p_quic_addr_equal(&conn->remote_addr, &datagram->remote_addr, 0) != 0))
        {
            return conn;
        }
    }

    return NULL;
}

static libp2p_quic_err_t quic_backend_handle_conn_error(libp2p_quic_conn_t *conn, int rv)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (rv == 0)
    {
        return LIBP2P_QUIC_OK;
    }

    result = quic_backend_ngtcp2_err(rv);
    if ((rv == NGTCP2_ERR_CLOSING) || (rv == NGTCP2_ERR_DRAINING) || (rv == NGTCP2_ERR_IDLE_CLOSE))
    {
        const ngtcp2_ccerr *ccerr = ngtcp2_conn_get_ccerr2(conn->ngconn);
        uint64_t app_error_code = 0U;
        uint64_t transport_error_code = 0U;

        if (ccerr != NULL)
        {
            if (ccerr->type == NGTCP2_CCERR_TYPE_APPLICATION)
            {
                app_error_code = ccerr->error_code;
            }
            else if (ccerr->type == NGTCP2_CCERR_TYPE_TRANSPORT)
            {
                transport_error_code = ccerr->error_code;
            }
        }

        conn->state = LIBP2P_QUIC_CONN_CLOSED;
        (void)quic_backend_event_push(
            conn->endpoint,
            LIBP2P_QUIC_EVENT_CONN_CLOSED,
            conn,
            NULL,
            app_error_code,
            transport_error_code);
        return LIBP2P_QUIC_OK;
    }

    if (rv == NGTCP2_ERR_CRYPTO)
    {
        ngtcp2_ccerr_set_tls_alert(
            &conn->close_error,
            ngtcp2_conn_get_tls_alert2(conn->ngconn),
            NULL,
            0U);
    }
    else
    {
        ngtcp2_ccerr_set_liberr(&conn->close_error, rv, NULL, 0U);
    }
    conn->close_requested = 1U;
    conn->state = LIBP2P_QUIC_CONN_CLOSING;
    (void)quic_backend_event_push(
        conn->endpoint,
        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
        conn,
        NULL,
        0U,
        0U);

    return result;
}

static libp2p_quic_stream_t *quic_backend_conn_next_tx_stream(libp2p_quic_conn_t *conn)
{
    size_t index = 0U;

    for (index = 0U; index < conn->streams.len; index++)
    {
        libp2p_quic_stream_t *stream = conn->streams.items[index];

        if ((stream != NULL) && (stream->state != LIBP2P_QUIC_STREAM_CLOSED) &&
            (stream->state != LIBP2P_QUIC_STREAM_RESET) &&
            ((stream->tx_sent_len < stream->tx_len) ||
             ((stream->local_fin_queued != 0U) && (stream->local_fin_sent == 0U))))
        {
            return stream;
        }
    }

    return NULL;
}

static libp2p_quic_err_t quic_backend_write_conn_datagram(
    libp2p_quic_conn_t *conn,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    ngtcp2_path_storage path;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite = 0;
    ngtcp2_ssize ndatalen = -1;
    ngtcp2_tstamp ts = quic_backend_time_to_ngtcp2(now_us);
    libp2p_quic_stream_t *stream = NULL;
    ngtcp2_vec vec;
    const ngtcp2_vec *vec_ptr = NULL;
    size_t vec_count = 0U;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    int64_t stream_id = -1;

    if (conn->close_requested != 0U)
    {
        ngtcp2_path_storage_zero(&path);
        (void)memset(&pi, 0, sizeof(pi));
        nwrite = ngtcp2_conn_write_connection_close(
            conn->ngconn,
            &path.path,
            &pi,
            datagram->data,
            datagram->data_cap,
            &conn->close_error,
            ts);
        if (nwrite > 0)
        {
            conn->close_sent = 1U;
            conn->state = LIBP2P_QUIC_CONN_CLOSING;
            datagram->local_addr = conn->local_addr;
            datagram->remote_addr = conn->remote_addr;
            datagram->data_len = (size_t)nwrite;
            datagram->ecn = quic_backend_ecn_from_ngtcp2(pi.ecn);
            return LIBP2P_QUIC_OK;
        }

        return nwrite == 0 ? LIBP2P_QUIC_ERR_WOULD_BLOCK : quic_backend_ngtcp2_err((int)nwrite);
    }

    stream = quic_backend_conn_next_tx_stream(conn);
    if (stream != NULL)
    {
        const size_t remaining = stream->tx_len - stream->tx_sent_len;
        stream_id = stream->stream_id;
        if (remaining != 0U)
        {
            vec.base = &stream->tx_data[stream->tx_sent_len];
            vec.len = remaining;
            vec_ptr = &vec;
            vec_count = 1U;
        }
        if ((stream->local_fin_queued != 0U) && (stream->local_fin_sent == 0U))
        {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
    }

    ngtcp2_path_storage_zero(&path);
    (void)memset(&pi, 0, sizeof(pi));
    nwrite = ngtcp2_conn_writev_stream(
        conn->ngconn,
        &path.path,
        &pi,
        datagram->data,
        datagram->data_cap,
        &ndatalen,
        flags,
        stream_id,
        vec_ptr,
        vec_count,
        ts);
    if (nwrite > 0)
    {
        ngtcp2_conn_update_pkt_tx_time(conn->ngconn, ts);
        datagram->local_addr = conn->local_addr;
        datagram->remote_addr = conn->remote_addr;
        datagram->data_len = (size_t)nwrite;
        datagram->ecn = quic_backend_ecn_from_ngtcp2(pi.ecn);

        if ((stream != NULL) && (ndatalen >= 0))
        {
            stream->tx_sent_len += (size_t)ndatalen;
            if (((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) != 0U) &&
                (stream->tx_sent_len == stream->tx_len))
            {
                stream->local_fin_sent = 1U;
                stream->state = stream->remote_fin != 0U ? LIBP2P_QUIC_STREAM_CLOSED
                                                         : LIBP2P_QUIC_STREAM_HALF_CLOSED_LOCAL;
            }
        }
        return LIBP2P_QUIC_OK;
    }
    if (nwrite == 0)
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }
    if ((nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) || (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) ||
        (nwrite == NGTCP2_ERR_STREAM_NOT_FOUND))
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    return quic_backend_handle_conn_error(conn, (int)nwrite);
}

static libp2p_quic_err_t quic_backend_config_validate(const libp2p_quic_endpoint_config_t *config)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (config == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (((config->role & LIBP2P_QUIC_ROLE_CLIENT_SERVER) == 0U) ||
        ((config->role & ~LIBP2P_QUIC_ROLE_CLIENT_SERVER) != 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((config->random_fn == NULL) || (config->unix_time_fn == NULL) ||
        (config->max_connections == 0U) ||
        (config->max_incoming_connections > config->max_connections) ||
        (config->max_outgoing_connections > config->max_connections) ||
        (config->max_bidi_streams == 0U) ||
        (config->max_datagram_payload_bytes < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES) ||
        (config->max_datagram_payload_bytes > NGTCP2_MAX_TX_UDP_PAYLOAD_SIZE) ||
        (config->initial_conn_window_bytes == 0U) || (config->initial_stream_window_bytes == 0U) ||
        (config->idle_timeout_us == 0U) || (config->handshake_timeout_us == 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    result = libp2p_quic_local_identity_validate(&config->identity);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    return quic_backend_allocator_normalize(&config->allocator, &(libp2p_quic_allocator_t){0});
}

static libp2p_quic_err_t quic_backend_endpoint_storage_size(
    const libp2p_quic_endpoint_config_t *config,
    size_t *out_len)
{
    if ((config == NULL) || (out_len == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_len = sizeof(libp2p_quic_endpoint_t);
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_storage_align(size_t *out_align)
{
    if (out_align == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_align = alignof(libp2p_quic_endpoint_t);
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_init(
    void *storage,
    size_t storage_len,
    const libp2p_quic_endpoint_config_t *config,
    libp2p_quic_endpoint_t **out_endpoint)
{
    libp2p_quic_endpoint_t *endpoint = (libp2p_quic_endpoint_t *)storage;
    libp2p_quic_allocator_t allocator;
    size_t events_per_conn = 0U;
    size_t event_cap = 0U;
    size_t pointer_bytes = 0U;
    size_t event_bytes = 0U;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out_endpoint == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    *out_endpoint = NULL;

    result = quic_backend_config_validate(config);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = quic_backend_allocator_normalize(&config->allocator, &allocator);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((storage == NULL) || (storage_len < sizeof(*endpoint)) ||
        (((uintptr_t)storage % alignof(libp2p_quic_endpoint_t)) != 0U))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
    endpoint->magic = QUIC_BACKEND_ENDPOINT_MAGIC;
    endpoint->config = *config;
    endpoint->allocator = allocator;
    endpoint->ngtcp2_mem.user_data = endpoint;
    endpoint->ngtcp2_mem.malloc = quic_backend_ngtcp2_malloc;
    endpoint->ngtcp2_mem.free = quic_backend_ngtcp2_free;
    endpoint->ngtcp2_mem.calloc = quic_backend_ngtcp2_calloc;
    endpoint->ngtcp2_mem.realloc = quic_backend_ngtcp2_realloc;

    if (quic_backend_size_mul_overflow(
            config->max_connections,
            // NOLINTNEXTLINE(bugprone-sizeof-expression)
            sizeof(*endpoint->connections),
            &pointer_bytes) != 0)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
        goto fail;
    }
    if ((quic_backend_size_mul_overflow(
             config->max_connections,
             QUIC_BACKEND_EVENTS_PER_CONNECTION,
             &events_per_conn) != 0) ||
        (quic_backend_size_add_overflow(events_per_conn, QUIC_BACKEND_EXTRA_EVENTS, &event_cap) !=
         0) ||
        (quic_backend_size_mul_overflow(event_cap, sizeof(*endpoint->events), &event_bytes) != 0))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
        goto fail;
    }

    endpoint->connections = (libp2p_quic_conn_t **)
        // NOLINTNEXTLINE(bugprone-sizeof-expression)
        quic_backend_calloc(endpoint, config->max_connections, sizeof(*endpoint->connections));
    endpoint->events =
        (libp2p_quic_event_t *)quic_backend_calloc(endpoint, event_cap, sizeof(*endpoint->events));
    endpoint->event_cap = event_cap;
    if ((endpoint->connections == NULL) || (endpoint->events == NULL))
    {
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
        goto fail;
    }
    (void)pointer_bytes;
    (void)event_bytes;

    if ((config->role & LIBP2P_QUIC_ROLE_CLIENT) != 0U)
    {
        endpoint->client_ctx = quic_backend_ssl_ctx_new(endpoint, LIBP2P_QUIC_ROLE_CLIENT);
        if (endpoint->client_ctx == NULL)
        {
            result = LIBP2P_QUIC_ERR_TLS;
            goto fail;
        }
    }
    if ((config->role & LIBP2P_QUIC_ROLE_SERVER) != 0U)
    {
        endpoint->server_ctx = quic_backend_ssl_ctx_new(endpoint, LIBP2P_QUIC_ROLE_SERVER);
        if (endpoint->server_ctx == NULL)
        {
            result = LIBP2P_QUIC_ERR_TLS;
            goto fail;
        }
    }

    *out_endpoint = endpoint;
    return LIBP2P_QUIC_OK;

fail:
    SSL_CTX_free(endpoint->client_ctx);
    SSL_CTX_free(endpoint->server_ctx);
    quic_backend_free(endpoint, (void *)endpoint->connections);
    quic_backend_free(endpoint, endpoint->events);
    endpoint->magic = 0U;
    return result;
}

static void quic_backend_endpoint_deinit(libp2p_quic_endpoint_t *endpoint)
{
    size_t index = 0U;

    if ((endpoint == NULL) || (endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC))
    {
        return;
    }

    for (index = 0U; index < endpoint->connection_count; index++)
    {
        quic_backend_conn_free(endpoint->connections[index]);
    }
    SSL_CTX_free(endpoint->client_ctx);
    SSL_CTX_free(endpoint->server_ctx);
    quic_backend_free(endpoint, (void *)endpoint->connections);
    quic_backend_free(endpoint, endpoint->events);
    endpoint->magic = 0U;
}

static libp2p_quic_err_t quic_backend_endpoint_bind(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_addr_t *local_addr)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    result = libp2p_quic_addr_validate(local_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (endpoint->connection_count != 0U)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    endpoint->local_addr = *local_addr;
    endpoint->local_addr.has_peer_id = 0U;
    endpoint->local_addr.peer_id_len = 0U;
    endpoint->bound = 1U;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_dial(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *config,
    libp2p_quic_conn_t **out_conn)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((config == NULL) || (out_conn == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((endpoint->config.role & LIBP2P_QUIC_ROLE_CLIENT) == 0U)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }
    if (endpoint->bound == 0U)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }
    result = libp2p_quic_addr_validate(&config->remote_addr);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((config->remote_addr.has_peer_id == 0U) || (config->remote_addr.peer_id_len == 0U))
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }

    return quic_backend_conn_client_new(endpoint, config, out_conn);
}

static libp2p_quic_err_t quic_backend_endpoint_recv_datagram(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    libp2p_quic_conn_t *conn = NULL;
    ngtcp2_path_storage path;
    ngtcp2_pkt_info pi;
    ngtcp2_pkt_hd hd;
    int rv = 0;
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((datagram == NULL) || (datagram->data == NULL) || (datagram->data_len == 0U) ||
        (libp2p_quic_addr_validate(&datagram->local_addr) != LIBP2P_QUIC_OK) ||
        (libp2p_quic_addr_validate(&datagram->remote_addr) != LIBP2P_QUIC_OK))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    conn = quic_backend_find_conn_by_packet(endpoint, datagram);
    if (conn == NULL)
    {
        if ((endpoint->config.role & LIBP2P_QUIC_ROLE_SERVER) == 0U)
        {
            return LIBP2P_QUIC_OK;
        }

        (void)memset(&hd, 0, sizeof(hd));
        rv = ngtcp2_accept(&hd, datagram->data, datagram->data_len);
        if ((rv != 0) || (hd.version != NGTCP2_PROTO_VER_V1))
        {
            return LIBP2P_QUIC_OK;
        }

        result = quic_backend_conn_server_new(endpoint, datagram, &hd, &conn);
        if (result != LIBP2P_QUIC_OK)
        {
            return result;
        }
    }

    quic_backend_path_from_addrs(&datagram->local_addr, &datagram->remote_addr, &path);
    (void)memset(&pi, 0, sizeof(pi));
    pi.ecn = quic_backend_ecn_to_ngtcp2(datagram->ecn);

    rv = ngtcp2_conn_read_pkt(
        conn->ngconn,
        &path.path,
        &pi,
        datagram->data,
        datagram->data_len,
        quic_backend_time_to_ngtcp2(now_us));
    if (rv != 0)
    {
        return quic_backend_handle_conn_error(conn, rv);
    }

    (void)
        quic_backend_event_push(endpoint, LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY, conn, NULL, 0U, 0U);
    return conn->callback_error != LIBP2P_QUIC_OK ? conn->callback_error : LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_next_datagram(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    size_t index = 0U;
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((datagram == NULL) || (datagram->data == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    datagram->data_len = 0U;
    if (datagram->data_cap < LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES)
    {
        datagram->data_len = LIBP2P_QUIC_MIN_INITIAL_DATAGRAM_BYTES;
        return LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
    }

    for (index = 0U; index < endpoint->connection_count; index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[index];

        if ((conn == NULL) || (conn->state == LIBP2P_QUIC_CONN_CLOSED) ||
            (conn->state == LIBP2P_QUIC_CONN_DRAINED))
        {
            continue;
        }

        result = quic_backend_write_conn_datagram(conn, datagram, now_us);
        if (result == LIBP2P_QUIC_OK)
        {
            return LIBP2P_QUIC_OK;
        }
        if (result != LIBP2P_QUIC_ERR_WOULD_BLOCK)
        {
            return result;
        }
    }

    return LIBP2P_QUIC_ERR_WOULD_BLOCK;
}

static libp2p_quic_err_t quic_backend_endpoint_poll(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t now_us)
{
    size_t index = 0U;
    ngtcp2_tstamp now = quic_backend_time_to_ngtcp2(now_us);
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    for (index = 0U; index < endpoint->connection_count; index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[index];
        ngtcp2_tstamp expiry = 0U;

        if ((conn == NULL) || (conn->state == LIBP2P_QUIC_CONN_CLOSED) ||
            (conn->state == LIBP2P_QUIC_CONN_DRAINED))
        {
            continue;
        }

        expiry = ngtcp2_conn_get_expiry2(conn->ngconn);
        if ((expiry != UINT64_MAX) && (expiry <= now))
        {
            const int rv = ngtcp2_conn_handle_expiry(conn->ngconn, now);
            if (rv != 0)
            {
                result = quic_backend_handle_conn_error(conn, rv);
                if (result != LIBP2P_QUIC_OK)
                {
                    return result;
                }
            }
            (void)quic_backend_event_push(
                endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                conn,
                NULL,
                0U,
                0U);
        }
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_next_deadline(
    const libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t *out_deadline_us)
{
    size_t index = 0U;
    ngtcp2_tstamp best = UINT64_MAX;

    if ((endpoint == NULL) || (endpoint->magic != QUIC_BACKEND_ENDPOINT_MAGIC) ||
        (out_deadline_us == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    for (index = 0U; index < endpoint->connection_count; index++)
    {
        const libp2p_quic_conn_t *conn = endpoint->connections[index];
        ngtcp2_tstamp expiry = UINT64_MAX;

        if ((conn == NULL) || (conn->state == LIBP2P_QUIC_CONN_CLOSED) ||
            (conn->state == LIBP2P_QUIC_CONN_DRAINED))
        {
            continue;
        }
        expiry = ngtcp2_conn_get_expiry2(conn->ngconn);
        if (expiry < best)
        {
            best = expiry;
        }
    }

    if (best == UINT64_MAX)
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    *out_deadline_us = quic_backend_time_from_ngtcp2(best);
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_next_event(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_t *out_event)
{
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_event == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (endpoint->event_len == 0U)
    {
        (void)memset(out_event, 0, sizeof(*out_event));
        out_event->type = LIBP2P_QUIC_EVENT_NONE;
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    *out_event = endpoint->events[endpoint->event_head];
    endpoint->event_head = (endpoint->event_head + 1U) % endpoint->event_cap;
    endpoint->event_len--;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_endpoint_close(
    libp2p_quic_endpoint_t *endpoint,
    uint64_t app_error_code)
{
    size_t index = 0U;
    libp2p_quic_err_t result = quic_backend_validate_endpoint(endpoint);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    for (index = 0U; index < endpoint->connection_count; index++)
    {
        if (endpoint->connections[index] != NULL)
        {
            ngtcp2_ccerr_set_application_error(
                &endpoint->connections[index]->close_error,
                app_error_code,
                NULL,
                0U);
            endpoint->connections[index]->close_requested = 1U;
            endpoint->connections[index]->state = LIBP2P_QUIC_CONN_CLOSING;
        }
    }
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_state(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_conn_state_t *out_state)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out_state == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_state = conn->state;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (conn->has_peer_identity == 0U)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    return quic_backend_copy_measure(
        conn->peer_identity.peer_id,
        conn->peer_identity.peer_id_len,
        out,
        out_len,
        written);
}

static libp2p_quic_err_t quic_backend_conn_peer_identity(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_peer_identity_t *out)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (conn->has_peer_identity == 0U)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    *out = conn->peer_identity;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_local_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out = conn->local_addr;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_remote_addr(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_addr_t *out)
{
    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out = conn->remote_addr;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_close(libp2p_quic_conn_t *conn, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    ngtcp2_ccerr_set_application_error(&conn->close_error, app_error_code, NULL, 0U);
    conn->close_requested = 1U;
    conn->state = LIBP2P_QUIC_CONN_CLOSING;
    return quic_backend_event_push(
        conn->endpoint,
        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
        conn,
        NULL,
        0U,
        0U);
}

static libp2p_quic_err_t quic_backend_conn_open_bidi_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    int64_t stream_id = -1;
    libp2p_quic_stream_t *stream = NULL;
    int rv = 0;
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (out_stream != NULL)
    {
        *out_stream = NULL;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_stream == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (conn->state != LIBP2P_QUIC_CONN_ESTABLISHED)
    {
        return LIBP2P_QUIC_ERR_STATE;
    }

    stream = quic_backend_stream_new(conn, -1, 0);
    if (stream == NULL)
    {
        return LIBP2P_QUIC_ERR_NO_MEMORY;
    }

    rv = ngtcp2_conn_open_bidi_stream(conn->ngconn, &stream_id, stream);
    if (rv != 0)
    {
        quic_backend_stream_free(stream);
        conn->streams.len--;
        return quic_backend_ngtcp2_err(rv);
    }

    stream->stream_id = stream_id;
    *out_stream = stream;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_conn_accept_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    size_t index = 0U;
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (out_stream != NULL)
    {
        *out_stream = NULL;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if (out_stream == NULL)
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    for (index = 0U; index < conn->streams.len; index++)
    {
        libp2p_quic_stream_t *stream = conn->streams.items[index];

        if ((stream != NULL) && (stream->incoming != 0U) && (stream->accepted == 0U))
        {
            stream->accepted = 1U;
            *out_stream = stream;
            return LIBP2P_QUIC_OK;
        }
    }

    return LIBP2P_QUIC_ERR_WOULD_BLOCK;
}

static libp2p_quic_err_t quic_backend_stream_id(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_id_t *out_id)
{
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_id == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_id = (libp2p_quic_stream_id_t)stream->stream_id;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_stream_state(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_state_t *out_state)
{
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_state == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_state = stream->state;
    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_stream_read(
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    size_t available = 0U;
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (read_len != NULL)
    {
        *read_len = 0U;
    }
    if (fin != NULL)
    {
        *fin = 0;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((read_len == NULL) || (fin == NULL) || ((out == NULL) && (out_len != 0U)))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    available = stream->rx_len - stream->rx_read_offset;
    if (available != 0U)
    {
        const size_t copied = available < out_len ? available : out_len;
        if (copied != 0U)
        {
            (void)memcpy(out, &stream->rx_data[stream->rx_read_offset], copied);
            stream->rx_read_offset += copied;
            *read_len = copied;
            (void)ngtcp2_conn_extend_max_stream_offset(
                stream->conn->ngconn,
                stream->stream_id,
                copied);
            ngtcp2_conn_extend_max_offset(stream->conn->ngconn, copied);
        }
        if (stream->rx_read_offset == stream->rx_len)
        {
            stream->rx_read_offset = 0U;
            stream->rx_len = 0U;
        }
    }

    if ((stream->remote_fin != 0U) && (stream->rx_len == 0U) &&
        (stream->remote_fin_delivered == 0U))
    {
        *fin = 1;
        stream->remote_fin_delivered = 1U;
    }

    if ((*read_len == 0U) && (*fin == 0))
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    return LIBP2P_QUIC_OK;
}

static libp2p_quic_err_t quic_backend_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    size_t limit = 0U;
    size_t required = 0U;
    uint8_t *new_data = NULL;
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (accepted != NULL)
    {
        *accepted = 0U;
    }
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }
    if ((accepted == NULL) || ((data == NULL) && (data_len != 0U)))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if (stream->local_fin_queued != 0U)
    {
        return LIBP2P_QUIC_ERR_CLOSED;
    }

    limit = stream->conn->endpoint->config.initial_stream_window_bytes *
            QUIC_BACKEND_STREAM_SEND_MULTIPLIER;
    if ((quic_backend_size_add_overflow(stream->tx_len, data_len, &required) != 0) ||
        (required > limit))
    {
        return LIBP2P_QUIC_ERR_WOULD_BLOCK;
    }

    if (required > stream->tx_cap)
    {
        size_t new_cap = stream->tx_cap == 0U ? 1024U : stream->tx_cap * 2U;

        while (new_cap < required)
        {
            if (new_cap > (SIZE_MAX / 2U))
            {
                return LIBP2P_QUIC_ERR_LIMIT;
            }
            new_cap *= 2U;
        }
        new_data =
            (uint8_t *)quic_backend_realloc(stream->conn->endpoint, stream->tx_data, new_cap);
        if (new_data == NULL)
        {
            return LIBP2P_QUIC_ERR_NO_MEMORY;
        }
        stream->tx_data = new_data;
        stream->tx_cap = new_cap;
    }

    if (data_len != 0U)
    {
        (void)memcpy(&stream->tx_data[stream->tx_len], data, data_len);
        stream->tx_len += data_len;
        *accepted = data_len;
    }
    if (fin != 0)
    {
        stream->local_fin_queued = 1U;
    }

    return quic_backend_event_push(
        stream->conn->endpoint,
        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
        stream->conn,
        stream,
        0U,
        0U);
}

static libp2p_quic_err_t quic_backend_stream_finish(libp2p_quic_stream_t *stream)
{
    size_t accepted = 0U;

    return quic_backend_stream_write(stream, NULL, 0U, 1, &accepted);
}

static libp2p_quic_err_t quic_backend_stream_reset(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    int rv = 0;
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    rv = ngtcp2_conn_shutdown_stream_write(
        stream->conn->ngconn,
        0U,
        stream->stream_id,
        app_error_code);
    if (rv != 0)
    {
        return quic_backend_ngtcp2_err(rv);
    }
    stream->state = LIBP2P_QUIC_STREAM_RESET;
    stream->reset = 1U;
    return quic_backend_event_push(
        stream->conn->endpoint,
        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
        stream->conn,
        stream,
        app_error_code,
        0U);
}

static libp2p_quic_err_t quic_backend_stream_stop_sending(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    int rv = 0;
    libp2p_quic_err_t result = quic_backend_validate_stream(stream);

    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    rv = ngtcp2_conn_shutdown_stream_read(
        stream->conn->ngconn,
        0U,
        stream->stream_id,
        app_error_code);
    if (rv != 0)
    {
        return quic_backend_ngtcp2_err(rv);
    }
    return quic_backend_event_push(
        stream->conn->endpoint,
        LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
        stream->conn,
        stream,
        app_error_code,
        0U);
}

static libp2p_quic_err_t quic_backend_stream_conn(
    libp2p_quic_stream_t *stream,
    libp2p_quic_conn_t **out_conn)
{
    if (out_conn != NULL)
    {
        *out_conn = NULL;
    }
    if ((stream == NULL) || (stream->magic != QUIC_BACKEND_STREAM_MAGIC) || (out_conn == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    *out_conn = stream->conn;
    return LIBP2P_QUIC_OK;
}

static const libp2p_quic_backend_vtable_t quic_backend_vtable = {
    .abi_version = LIBP2P_QUIC_BACKEND_ABI_VERSION,
    .name = "ngtcp2+aws-lc",
    .endpoint_storage_size = quic_backend_endpoint_storage_size,
    .endpoint_storage_align = quic_backend_endpoint_storage_align,
    .endpoint_init = quic_backend_endpoint_init,
    .endpoint_deinit = quic_backend_endpoint_deinit,
    .endpoint_bind = quic_backend_endpoint_bind,
    .endpoint_dial = quic_backend_endpoint_dial,
    .endpoint_recv_datagram = quic_backend_endpoint_recv_datagram,
    .endpoint_next_datagram = quic_backend_endpoint_next_datagram,
    .endpoint_poll = quic_backend_endpoint_poll,
    .endpoint_next_deadline = quic_backend_endpoint_next_deadline,
    .endpoint_next_event = quic_backend_endpoint_next_event,
    .endpoint_close = quic_backend_endpoint_close,
    .conn_state = quic_backend_conn_state,
    .conn_peer_id = quic_backend_conn_peer_id,
    .conn_peer_identity = quic_backend_conn_peer_identity,
    .conn_local_addr = quic_backend_conn_local_addr,
    .conn_remote_addr = quic_backend_conn_remote_addr,
    .conn_close = quic_backend_conn_close,
    .conn_open_bidi_stream = quic_backend_conn_open_bidi_stream,
    .conn_accept_stream = quic_backend_conn_accept_stream,
    .stream_id = quic_backend_stream_id,
    .stream_state = quic_backend_stream_state,
    .stream_read = quic_backend_stream_read,
    .stream_write = quic_backend_stream_write,
    .stream_finish = quic_backend_stream_finish,
    .stream_reset = quic_backend_stream_reset,
    .stream_stop_sending = quic_backend_stream_stop_sending,
    .stream_conn = quic_backend_stream_conn,
};

const libp2p_quic_backend_vtable_t *libp2p_quic_backend_ngtcp2_awslc(void)
{
    return &quic_backend_vtable;
}
