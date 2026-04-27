#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "libp2p/libp2p_host.h"
#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/ping/ping.h"
#include "redis_client.h"
#include "transport/quic/quic_identity.h"
#include "transport/quic/quic_service.h"

#define INTEROP_LISTEN_PORT             0U
#define INTEROP_LISTEN_IP_TEXT_BYTES    16U
#define INTEROP_DEFAULT_TIMEOUT_SECONDS 180U
#define INTEROP_HOST_STORAGE_BYTES      (4U * 1024U * 1024U)
#define INTEROP_LISTEN_MULTIADDR_BYTES  128U
#define INTEROP_DIAL_MULTIADDR_BYTES    256U
#define INTEROP_MULTIADDR_TEXT_BYTES    512U
#define INTEROP_REDIS_KEY_BYTES         80U
#define INTEROP_POLL_MAX_MS             50
#define INTEROP_CERT_VALIDITY_SECONDS   UINT64_C(315360000)
#define INTEROP_CERT_BACKDATE_SECONDS   UINT64_C(3600)
#define INTEROP_NSEC_PER_SEC            UINT64_C(1000000000)
#define INTEROP_USEC_PER_SEC            UINT64_C(1000000)
#define INTEROP_USEC_PER_MSEC           UINT64_C(1000)

typedef enum
{
    INTEROP_OK = 0,
    INTEROP_ERR_USAGE = 1,
    INTEROP_ERR_ENV = 2,
    INTEROP_ERR_REDIS = 3,
    INTEROP_ERR_IDENTITY = 4,
    INTEROP_ERR_HOST = 5,
    INTEROP_ERR_TIMEOUT = 6,
    INTEROP_ERR_PROTOCOL = 7
} interop_err_t;

typedef union
{
    max_align_t align;
    uint8_t bytes[INTEROP_HOST_STORAGE_BYTES];
} interop_host_storage_t;

typedef struct
{
    uint8_t private_key[LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES];
    libp2p_host_secp256k1_identity_t host_storage;
    libp2p_host_identity_t host;
    uint8_t cert[LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES];
    uint8_t cert_key[LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES];
    libp2p_quic_local_identity_t quic;
} interop_identity_t;

typedef struct
{
    uint8_t is_dialer;
    uint8_t debug;
    unsigned int timeout_seconds;
    char redis_addr[128];
    char test_key[32];
} interop_env_t;

typedef struct
{
    interop_env_t env;
    interop_identity_t identity;
    libp2p_quic_service_config_t quic_config;
    libp2p_host_config_t host_config;
    libp2p_ping_config_t ping_config;
    libp2p_ping_t ping;
    libp2p_host_protocol_t ping_protocol;
    libp2p_host_t *host;
    libp2p_host_conn_t *conn;
    libp2p_host_time_us_t time_origin_us;
    libp2p_host_time_us_t dial_started_us;
    libp2p_host_time_us_t handshake_plus_ping_us;
    libp2p_host_time_us_t ping_rtt_us;
    uint8_t listen_multiaddr[INTEROP_LISTEN_MULTIADDR_BYTES];
    size_t listen_multiaddr_len;
    uint8_t dial_multiaddr[INTEROP_DIAL_MULTIADDR_BYTES];
    size_t dial_multiaddr_len;
    int ping_started;
    int ping_done;
} interop_app_t;

static interop_host_storage_t g_host_storage;
static volatile sig_atomic_t g_stop_requested = 0;

static void interop_signal_handler(int signo)
{
    (void)signo;
    g_stop_requested = 1;
}

static void *interop_backend_malloc(size_t size, void *user_data)
{
    (void)user_data;
    return malloc(size);
}

static void *interop_backend_calloc(size_t nmemb, size_t size, void *user_data)
{
    (void)user_data;
    return calloc(nmemb, size);
}

static void *interop_backend_realloc(void *ptr, size_t size, void *user_data)
{
    (void)user_data;
    return realloc(ptr, size);
}

static void interop_backend_free(void *ptr, void *user_data)
{
    (void)user_data;
    free(ptr);
}

static libp2p_quic_allocator_t interop_backend_allocator(void)
{
    libp2p_quic_allocator_t allocator;

    /*
     * c-lean-libp2p state remains caller-owned; ngtcp2/AWS-LC still require
     * allocator hooks for backend-owned TLS and QUIC internals.
     */
    allocator.malloc_fn = interop_backend_malloc;
    allocator.calloc_fn = interop_backend_calloc;
    allocator.realloc_fn = interop_backend_realloc;
    allocator.free_fn = interop_backend_free;
    allocator.user_data = NULL;
    return allocator;
}

static interop_err_t interop_read_urandom(uint8_t *out, size_t out_len)
{
    int fd = -1;
    size_t pos = 0U;
    interop_err_t result = INTEROP_OK;

    if ((out == NULL) && (out_len != 0U))
    {
        result = INTEROP_ERR_USAGE;
    }
    if (result == INTEROP_OK)
    {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
        {
            result = INTEROP_ERR_IDENTITY;
        }
    }
    while ((result == INTEROP_OK) && (pos < out_len))
    {
        const ssize_t count = read(fd, &out[pos], out_len - pos);
        if (count > 0)
        {
            pos += (size_t)count;
        }
        else if ((count < 0) && (errno == EINTR))
        {
            result = INTEROP_OK;
        }
        else
        {
            result = INTEROP_ERR_IDENTITY;
        }
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }

    return result;
}

static libp2p_quic_err_t interop_quic_random(uint8_t *out, size_t out_len, void *user_data)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)user_data;
    if (interop_read_urandom(out, out_len) != INTEROP_OK)
    {
        result = LIBP2P_QUIC_ERR_INTERNAL;
    }

    return result;
}

static libp2p_ping_err_t interop_ping_random(uint8_t *out, size_t out_len, void *user_data)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;

    (void)user_data;
    if (interop_read_urandom(out, out_len) != INTEROP_OK)
    {
        result = LIBP2P_PING_ERR_RANDOM;
    }

    return result;
}

static libp2p_quic_err_t interop_unix_time(uint64_t *out_unix_seconds, void *user_data)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;
    const time_t now = time(NULL);

    (void)user_data;
    if ((out_unix_seconds == NULL) || (now < (time_t)0))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_unix_seconds = (uint64_t)now;
    }

    return result;
}

static libp2p_host_time_us_t interop_now_us(void)
{
    struct timespec ts;
    libp2p_host_time_us_t now = 0U;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        now = (((uint64_t)ts.tv_sec) * INTEROP_USEC_PER_SEC) + (((uint64_t)ts.tv_nsec) / 1000U);
    }

    return now;
}

static libp2p_host_time_us_t interop_app_now_us(const interop_app_t *app)
{
    const libp2p_host_time_us_t now = interop_now_us();
    libp2p_host_time_us_t result = now;

    if ((app != NULL) && (now >= app->time_origin_us))
    {
        result = now - app->time_origin_us;
    }

    return result;
}

static libp2p_ping_err_t interop_ping_time(libp2p_host_time_us_t *out_now_us, void *user_data)
{
    libp2p_ping_err_t result = LIBP2P_PING_OK;
    const interop_app_t *app = (const interop_app_t *)user_data;

    if (out_now_us == NULL)
    {
        result = LIBP2P_PING_ERR_INVALID_ARG;
    }
    else
    {
        *out_now_us = interop_app_now_us(app);
    }

    return result;
}

static void interop_log(const interop_app_t *app, const char *message)
{
    if ((app != NULL) && (app->env.debug != 0U) && (message != NULL))
    {
        (void)fprintf(stderr, "c-lean-libp2p interop: %s\n", message);
    }
}

static void interop_log_value(const interop_app_t *app, const char *message, const char *value)
{
    if ((app != NULL) && (app->env.debug != 0U) && (message != NULL) && (value != NULL))
    {
        (void)fprintf(stderr, "c-lean-libp2p interop: %s%s\n", message, value);
    }
}

static void interop_log_u64(const interop_app_t *app, const char *message, uint64_t value)
{
    if ((app != NULL) && (app->env.debug != 0U) && (message != NULL))
    {
        (void)
            fprintf(stderr, "c-lean-libp2p interop: %s%llu\n", message, (unsigned long long)value);
    }
}

static int interop_streq(const char *a, const char *b)
{
    int result = 0;

    if ((a != NULL) && (b != NULL) && (strcmp(a, b) == 0))
    {
        result = 1;
    }

    return result;
}

static interop_err_t interop_copy_env(char *out, size_t out_len, const char *name)
{
    const char *value = getenv(name);
    size_t value_len = 0U;
    interop_err_t result = INTEROP_OK;

    if ((out == NULL) || (out_len == 0U) || (name == NULL))
    {
        result = INTEROP_ERR_USAGE;
    }
    else if (value == NULL)
    {
        result = INTEROP_ERR_ENV;
    }
    else
    {
        value_len = strlen(value);
        if (value_len >= out_len)
        {
            result = INTEROP_ERR_ENV;
        }
        else
        {
            (void)memcpy(out, value, value_len + 1U);
        }
    }

    return result;
}

static interop_err_t interop_parse_timeout(unsigned int *out)
{
    const char *value = getenv("TEST_TIMEOUT_SECS");
    char *end = NULL;
    unsigned long parsed = INTEROP_DEFAULT_TIMEOUT_SECONDS;
    interop_err_t result = INTEROP_OK;

    if (out == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    if ((result == INTEROP_OK) && (value != NULL) && (value[0] != '\0'))
    {
        errno = 0;
        parsed = strtoul(value, &end, 10);
        if ((errno != 0) || (end == value) || (*end != '\0') || (parsed > UINT_MAX) ||
            (parsed == 0UL))
        {
            result = INTEROP_ERR_ENV;
        }
    }
    if (result == INTEROP_OK)
    {
        *out = (unsigned int)parsed;
    }

    return result;
}

static interop_err_t interop_env_load(interop_env_t *env)
{
    char is_dialer[8];
    char transport[32];
    const char *debug = NULL;
    interop_err_t result = INTEROP_OK;

    if (env == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(env, 0, sizeof(*env));
    }
    if (result == INTEROP_OK)
    {
        result = interop_copy_env(is_dialer, sizeof(is_dialer), "IS_DIALER");
    }
    if (result == INTEROP_OK)
    {
        if (interop_streq(is_dialer, "true") != 0)
        {
            env->is_dialer = 1U;
        }
        else if (interop_streq(is_dialer, "false") != 0)
        {
            env->is_dialer = 0U;
        }
        else
        {
            result = INTEROP_ERR_ENV;
        }
    }
    if (result == INTEROP_OK)
    {
        result = interop_copy_env(env->redis_addr, sizeof(env->redis_addr), "REDIS_ADDR");
    }
    if (result == INTEROP_OK)
    {
        result = interop_copy_env(env->test_key, sizeof(env->test_key), "TEST_KEY");
    }
    if (result == INTEROP_OK)
    {
        result = interop_copy_env(transport, sizeof(transport), "TRANSPORT");
    }
    if ((result == INTEROP_OK) && (interop_streq(transport, "quic-v1") == 0))
    {
        result = INTEROP_ERR_ENV;
    }
    if (result == INTEROP_OK)
    {
        result = interop_parse_timeout(&env->timeout_seconds);
    }
    if (result == INTEROP_OK)
    {
        debug = getenv("DEBUG");
        if ((debug != NULL) && (interop_streq(debug, "true") != 0))
        {
            env->debug = 1U;
        }
    }

    return result;
}

static void interop_select_private_key(uint8_t is_dialer, uint8_t out[32])
{
    static const uint8_t dialer_key[32] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                           0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                           0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    static const uint8_t listener_key[32] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                             0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                             0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 2U};

    if (is_dialer != 0U)
    {
        (void)memcpy(out, dialer_key, sizeof(dialer_key));
    }
    else
    {
        (void)memcpy(out, listener_key, sizeof(listener_key));
    }
}

static interop_err_t interop_identity_init(interop_identity_t *identity, uint8_t is_dialer)
{
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t cert_config;
    uint64_t now = 0U;
    interop_err_t result = INTEROP_OK;

    if (identity == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(identity, 0, sizeof(*identity));
        interop_select_private_key(is_dialer, identity->private_key);
    }
    if ((result == INTEROP_OK) && (libp2p_host_secp256k1_identity_init(
                                       &identity->host_storage,
                                       identity->private_key,
                                       sizeof(identity->private_key),
                                       &identity->host) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_IDENTITY;
    }
    if ((result == INTEROP_OK) && (interop_unix_time(&now, NULL) != LIBP2P_QUIC_OK))
    {
        result = INTEROP_ERR_IDENTITY;
    }
    if (result == INTEROP_OK)
    {
        host_key.type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
        host_key.private_key = identity->private_key;
        host_key.private_key_len = sizeof(identity->private_key);
        host_key.public_key_message = identity->host_storage.public_key_message;
        host_key.public_key_message_len = identity->host_storage.public_key_message_len;

        cert_config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
        cert_config.not_before_unix_seconds = now - INTEROP_CERT_BACKDATE_SECONDS;
        cert_config.not_after_unix_seconds = now + INTEROP_CERT_VALIDITY_SECONDS;
        cert_config.random_fn = interop_quic_random;
        cert_config.random_user_data = NULL;
        if (libp2p_quic_identity_write_certificate_der(
                &host_key,
                &cert_config,
                identity->cert,
                sizeof(identity->cert),
                &identity->quic.certificate_der_len,
                identity->cert_key,
                sizeof(identity->cert_key),
                &identity->quic.certificate_private_key_der_len) != LIBP2P_QUIC_OK)
        {
            result = INTEROP_ERR_IDENTITY;
        }
    }
    if (result == INTEROP_OK)
    {
        identity->quic.certificate_der = identity->cert;
        identity->quic.certificate_private_key_der = identity->cert_key;
        identity->quic.peer_id = identity->host_storage.peer_id;
        identity->quic.peer_id_len = identity->host_storage.peer_id_len;
    }

    return result;
}

static interop_err_t interop_make_redis_key(const interop_env_t *env, char *out, size_t out_len)
{
    int written = 0;
    interop_err_t result = INTEROP_OK;

    if ((env == NULL) || (out == NULL) || (out_len == 0U))
    {
        result = INTEROP_ERR_USAGE;
    }
    else
    {
        written = snprintf(out, out_len, "%s_listener_multiaddr", env->test_key);
        if ((written <= 0) || ((size_t)written >= out_len))
        {
            result = INTEROP_ERR_ENV;
        }
    }

    return result;
}

static interop_err_t interop_redis_local_ip4_text(
    const libp2p_interop_redis_client_t *client,
    char *out,
    size_t out_len)
{
    struct sockaddr_storage storage;
    socklen_t storage_len = (socklen_t)sizeof(storage);
    const struct sockaddr_in *addr4 = NULL;
    const uint8_t *ip = NULL;
    int written = 0;
    interop_err_t result = INTEROP_OK;

    if ((client == NULL) || (client->fd < 0) || (out == NULL) || (out_len == 0U))
    {
        result = INTEROP_ERR_REDIS;
    }
    else if (getsockname(client->fd, (struct sockaddr *)&storage, &storage_len) != 0)
    {
        result = INTEROP_ERR_REDIS;
    }
    else if (storage.ss_family != AF_INET)
    {
        result = INTEROP_ERR_REDIS;
    }
    else
    {
        addr4 = (const struct sockaddr_in *)&storage;
        ip = (const uint8_t *)&addr4->sin_addr;
        written = snprintf(
            out,
            out_len,
            "%u.%u.%u.%u",
            (unsigned int)ip[0],
            (unsigned int)ip[1],
            (unsigned int)ip[2],
            (unsigned int)ip[3]);
        if ((written <= 0) || ((size_t)written >= out_len))
        {
            result = INTEROP_ERR_REDIS;
        }
    }

    return result;
}

static interop_err_t interop_configure_host(
    interop_app_t *app,
    const char *listen_ip_text,
    uint16_t listen_port)
{
    char listen_text[80];
    int text_len = 0;
    size_t storage_len = 0U;
    interop_err_t result = INTEROP_OK;

    if ((app == NULL) || (listen_ip_text == NULL))
    {
        result = INTEROP_ERR_USAGE;
    }
    if (result == INTEROP_OK)
    {
        text_len = snprintf(
            listen_text,
            sizeof(listen_text),
            "/ip4/%s/udp/%u/quic-v1",
            listen_ip_text,
            (unsigned int)listen_port);
        if ((text_len <= 0) || ((size_t)text_len >= sizeof(listen_text)))
        {
            result = INTEROP_ERR_HOST;
        }
    }
    if (result == INTEROP_OK)
    {
        if (libp2p_multiaddr_from_string(
                listen_text,
                (size_t)text_len,
                app->listen_multiaddr,
                sizeof(app->listen_multiaddr),
                &app->listen_multiaddr_len) != LIBP2P_MULTIADDR_OK)
        {
            result = INTEROP_ERR_HOST;
        }
    }
    if ((result == INTEROP_OK) &&
        (libp2p_quic_service_config_default(&app->quic_config) != LIBP2P_QUIC_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if (result == INTEROP_OK)
    {
        app->quic_config.endpoint.role =
            (app->env.is_dialer != 0U) ? LIBP2P_QUIC_ROLE_CLIENT : LIBP2P_QUIC_ROLE_SERVER;
        app->quic_config.endpoint.identity = app->identity.quic;
        app->quic_config.endpoint.allocator = interop_backend_allocator();
        app->quic_config.endpoint.random_fn = interop_quic_random;
        app->quic_config.endpoint.random_user_data = NULL;
        app->quic_config.endpoint.unix_time_fn = interop_unix_time;
        app->quic_config.endpoint.unix_time_user_data = NULL;
        app->quic_config.endpoint.max_connections = 4U;
        app->quic_config.endpoint.max_incoming_connections = 4U;
        app->quic_config.endpoint.max_outgoing_connections = 4U;
        app->quic_config.endpoint.max_bidi_streams = 8U;
        app->quic_config.endpoint.idle_timeout_us = UINT64_C(30000000);
        app->quic_config.endpoint.handshake_timeout_us = UINT64_C(10000000);
        app->quic_config.max_rx_datagrams_per_drive = 32U;
        app->quic_config.max_tx_datagrams_per_drive = 32U;
    }
    if ((result == INTEROP_OK) && (libp2p_host_config_default(&app->host_config) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if (result == INTEROP_OK)
    {
        app->host_config.identity = app->identity.host;
        app->host_config.listen_multiaddr = app->listen_multiaddr;
        app->host_config.listen_multiaddr_len = app->listen_multiaddr_len;
        app->host_config.transport = libp2p_host_quic_transport();
        app->host_config.transport_config = &app->quic_config;
        app->host_config.max_protocols = 2U;
        app->host_config.max_connections = 4U;
        app->host_config.max_streams_per_conn = 8U;
        app->host_config.max_pending_dials = 2U;
        app->host_config.max_pending_stream_opens = 4U;
        app->host_config.event_capacity = 32U;
        app->host_config.max_negotiation_steps = 64U;
        if (libp2p_host_storage_size(&app->host_config, &storage_len) != LIBP2P_HOST_OK)
        {
            result = INTEROP_ERR_HOST;
        }
    }
    if ((result == INTEROP_OK) && (storage_len > sizeof(g_host_storage.bytes)))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (libp2p_host_init(
                                       g_host_storage.bytes,
                                       sizeof(g_host_storage.bytes),
                                       &app->host_config,
                                       &app->host) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (libp2p_ping_config_default(&app->ping_config) != LIBP2P_PING_OK))
    {
        result = INTEROP_ERR_PROTOCOL;
    }
    if (result == INTEROP_OK)
    {
        app->ping_config.random_fn = interop_ping_random;
        app->ping_config.random_user_data = NULL;
        app->ping_config.time_fn = interop_ping_time;
        app->ping_config.time_user_data = app;
        if (libp2p_ping_init(&app->ping, &app->ping_config) != LIBP2P_PING_OK)
        {
            result = INTEROP_ERR_PROTOCOL;
        }
    }
    if ((result == INTEROP_OK) &&
        (libp2p_ping_protocol(&app->ping, &app->ping_protocol) != LIBP2P_PING_OK))
    {
        result = INTEROP_ERR_PROTOCOL;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_host_handle(app->host, &app->ping_protocol) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (libp2p_host_start(app->host) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }

    return result;
}

static interop_err_t interop_parse_dial_multiaddr(interop_app_t *app, const char *text)
{
    interop_err_t result = INTEROP_OK;

    if ((app == NULL) || (text == NULL))
    {
        result = INTEROP_ERR_USAGE;
    }
    else if (
        libp2p_multiaddr_from_string(
            text,
            strlen(text),
            app->dial_multiaddr,
            sizeof(app->dial_multiaddr),
            &app->dial_multiaddr_len) != LIBP2P_MULTIADDR_OK)
    {
        result = INTEROP_ERR_PROTOCOL;
    }

    return result;
}

static interop_err_t interop_listener_multiaddr_text(
    const interop_app_t *app,
    char *out,
    size_t out_len)
{
    uint8_t multiaddr[INTEROP_DIAL_MULTIADDR_BYTES];
    size_t multiaddr_len = 0U;
    size_t text_len = 0U;
    interop_err_t result = INTEROP_OK;

    if ((app == NULL) || (out == NULL) || (out_len == 0U))
    {
        result = INTEROP_ERR_USAGE;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_host_listen_multiaddr(
             app->host,
             multiaddr,
             sizeof(multiaddr),
             &multiaddr_len) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_multiaddr_to_string(multiaddr, multiaddr_len, out, out_len, &text_len) !=
         LIBP2P_MULTIADDR_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (text_len >= out_len))
    {
        result = INTEROP_ERR_HOST;
    }
    if (result == INTEROP_OK)
    {
        out[text_len] = '\0';
    }

    return result;
}

static int interop_poll_timeout_ms(const interop_app_t *app, libp2p_host_time_us_t now)
{
    libp2p_host_time_us_t deadline = 0U;
    int timeout_ms = INTEROP_POLL_MAX_MS;

    if ((app != NULL) && (libp2p_host_next_deadline(app->host, &deadline) == LIBP2P_HOST_OK))
    {
        if (deadline <= now)
        {
            timeout_ms = 0;
        }
        else
        {
            const uint64_t delta_ms = (deadline - now) / INTEROP_USEC_PER_MSEC;
            if (delta_ms < (uint64_t)timeout_ms)
            {
                timeout_ms = (int)delta_ms;
            }
        }
    }

    return timeout_ms;
}

static interop_err_t interop_drive_once(interop_app_t *app)
{
    libp2p_host_fd_t host_fd = 0U;
    libp2p_host_interest_t interest = LIBP2P_HOST_INTEREST_NONE;
    libp2p_host_ready_t ready = LIBP2P_HOST_READY_APP | LIBP2P_HOST_READY_TIMER;
    struct pollfd pfd;
    int poll_result = 0;
    interop_err_t result = INTEROP_OK;

    if (app == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    if ((result == INTEROP_OK) && (libp2p_host_fd(app->host, &host_fd) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (host_fd > (libp2p_host_fd_t)INT_MAX))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) && (libp2p_host_io_interest(app->host, &interest) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if (result == INTEROP_OK)
    {
        pfd.fd = (int)host_fd;
        pfd.events = 0;
        pfd.revents = 0;
        if ((interest & LIBP2P_HOST_INTEREST_READ) != 0U)
        {
            pfd.events |= POLLIN;
        }
        if ((interest & LIBP2P_HOST_INTEREST_WRITE) != 0U)
        {
            pfd.events |= POLLOUT;
        }
        poll_result = poll(&pfd, 1U, interop_poll_timeout_ms(app, interop_app_now_us(app)));
        if (poll_result < 0)
        {
            if (errno != EINTR)
            {
                result = INTEROP_ERR_HOST;
            }
        }
        else
        {
            if ((pfd.revents & (POLLIN | POLLERR | POLLHUP)) != 0)
            {
                ready |= LIBP2P_HOST_READY_READ;
            }
            if ((pfd.revents & POLLOUT) != 0)
            {
                ready |= LIBP2P_HOST_READY_WRITE;
            }
        }
    }
    if ((result == INTEROP_OK) &&
        (libp2p_host_drive(app->host, interop_app_now_us(app), ready, NULL) != LIBP2P_HOST_OK))
    {
        result = INTEROP_ERR_HOST;
    }

    return result;
}

static interop_err_t interop_drain_host_events(interop_app_t *app)
{
    libp2p_host_event_t event;
    interop_err_t result = INTEROP_OK;

    if (app == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    while ((result == INTEROP_OK) && (libp2p_host_next_event(app->host, &event) == LIBP2P_HOST_OK))
    {
        if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
        {
            app->conn = event.conn;
            interop_log(app, "host event: connection established");
            if ((app->env.is_dialer != 0U) && (app->ping_started == 0))
            {
                libp2p_host_stream_open_t *open = NULL;
                if (libp2p_ping_initiate(&app->ping, app->host, app->conn, NULL, &open) !=
                    LIBP2P_PING_OK)
                {
                    interop_log(app, "ping initiate failed");
                    result = INTEROP_ERR_PROTOCOL;
                }
                else
                {
                    interop_log(app, "ping initiated");
                    app->ping_started = 1;
                }
            }
        }
        else if (
            (event.type == LIBP2P_HOST_EVENT_DIAL_FAILED) ||
            (event.type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED))
        {
            interop_log_u64(app, "host failure event: ", (uint64_t)event.type);
            interop_log_u64(app, "host failure reason: ", (uint64_t)event.reason);
            interop_log_u64(app, "host failure app error: ", event.app_error_code);
            interop_log_u64(app, "host failure transport error: ", event.transport_error_code);
            result = INTEROP_ERR_PROTOCOL;
        }
        else
        {
            result = INTEROP_OK;
        }
    }

    return result;
}

static interop_err_t interop_drain_ping_events(interop_app_t *app)
{
    libp2p_ping_event_t event;
    interop_err_t result = INTEROP_OK;

    if (app == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    while ((result == INTEROP_OK) && (libp2p_ping_next_event(&app->ping, &event) == LIBP2P_PING_OK))
    {
        if ((app->env.is_dialer != 0U) && (event.type == LIBP2P_PING_EVENT_PONG))
        {
            app->ping_done = 1;
            app->ping_rtt_us = event.rtt_us;
            app->handshake_plus_ping_us = interop_app_now_us(app) - app->dial_started_us;
        }
        else if (event.type == LIBP2P_PING_EVENT_ERROR)
        {
            interop_log(app, "ping error event");
            result = INTEROP_ERR_PROTOCOL;
        }
        else
        {
            result = INTEROP_OK;
        }
    }

    return result;
}

static void interop_print_ms_line(const char *name, libp2p_host_time_us_t value_us)
{
    const uint64_t whole = value_us / INTEROP_USEC_PER_MSEC;
    const uint64_t frac = value_us % INTEROP_USEC_PER_MSEC;

    (void)printf("  %s: %llu.%03llu\n", name, (unsigned long long)whole, (unsigned long long)frac);
}

static void interop_print_results(const interop_app_t *app)
{
    (void)printf("latency:\n");
    interop_print_ms_line("handshake_plus_one_rtt", app->handshake_plus_ping_us);
    interop_print_ms_line("ping_rtt", app->ping_rtt_us);
    (void)printf("  unit: ms\n");
    (void)fflush(stdout);
}

static interop_err_t interop_run_listener(interop_app_t *app)
{
    libp2p_interop_redis_client_t redis;
    char redis_key[INTEROP_REDIS_KEY_BYTES];
    char multiaddr_text[INTEROP_MULTIADDR_TEXT_BYTES];
    char listen_ip_text[INTEROP_LISTEN_IP_TEXT_BYTES];
    interop_err_t result = INTEROP_OK;

    redis.fd = -1;
    if (app == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_interop_redis_connect(&redis, app->env.redis_addr) != LIBP2P_INTEROP_REDIS_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    if ((result == INTEROP_OK) &&
        (interop_redis_local_ip4_text(&redis, listen_ip_text, sizeof(listen_ip_text)) !=
         INTEROP_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    if ((result == INTEROP_OK) &&
        (interop_configure_host(app, listen_ip_text, INTEROP_LISTEN_PORT) != INTEROP_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) &&
        (interop_listener_multiaddr_text(app, multiaddr_text, sizeof(multiaddr_text)) != INTEROP_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if ((result == INTEROP_OK) &&
        (interop_make_redis_key(&app->env, redis_key, sizeof(redis_key)) != INTEROP_OK))
    {
        result = INTEROP_ERR_ENV;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_interop_redis_del(&redis, redis_key) != LIBP2P_INTEROP_REDIS_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_interop_redis_rpush(&redis, redis_key, multiaddr_text) != LIBP2P_INTEROP_REDIS_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    if (result == INTEROP_OK)
    {
        interop_log_value(app, "listener address published: ", multiaddr_text);
    }
    while ((result == INTEROP_OK) && (g_stop_requested == 0))
    {
        result = interop_drive_once(app);
        if (result == INTEROP_OK)
        {
            result = interop_drain_host_events(app);
        }
        if (result == INTEROP_OK)
        {
            result = interop_drain_ping_events(app);
        }
    }
    libp2p_interop_redis_close(&redis);

    return result;
}

static interop_err_t interop_run_dialer(interop_app_t *app)
{
    libp2p_interop_redis_client_t redis;
    char redis_key[INTEROP_REDIS_KEY_BYTES];
    char multiaddr_text[INTEROP_MULTIADDR_TEXT_BYTES];
    size_t multiaddr_text_len = 0U;
    libp2p_host_dial_t *dial = NULL;
    libp2p_host_time_us_t deadline = 0U;
    interop_err_t result = INTEROP_OK;

    redis.fd = -1;
    if (app == NULL)
    {
        result = INTEROP_ERR_USAGE;
    }
    if ((result == INTEROP_OK) &&
        (interop_make_redis_key(&app->env, redis_key, sizeof(redis_key)) != INTEROP_OK))
    {
        result = INTEROP_ERR_ENV;
    }
    if ((result == INTEROP_OK) &&
        (libp2p_interop_redis_connect(&redis, app->env.redis_addr) != LIBP2P_INTEROP_REDIS_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    if (result == INTEROP_OK)
    {
        interop_log(app, "dialer waiting for listener address");
    }
    if ((result == INTEROP_OK) && (libp2p_interop_redis_blpop(
                                       &redis,
                                       redis_key,
                                       app->env.timeout_seconds,
                                       multiaddr_text,
                                       sizeof(multiaddr_text),
                                       &multiaddr_text_len) != LIBP2P_INTEROP_REDIS_OK))
    {
        result = INTEROP_ERR_REDIS;
    }
    libp2p_interop_redis_close(&redis);
    if (result == INTEROP_OK)
    {
        interop_log_value(app, "dialer received listener address: ", multiaddr_text);
    }
    if ((result == INTEROP_OK) && (interop_parse_dial_multiaddr(app, multiaddr_text) != INTEROP_OK))
    {
        interop_log(app, "dialer failed to parse listener address");
        result = INTEROP_ERR_PROTOCOL;
    }
    if ((result == INTEROP_OK) &&
        (interop_configure_host(app, "0.0.0.0", 0U) != INTEROP_OK))
    {
        result = INTEROP_ERR_HOST;
    }
    if (result == INTEROP_OK)
    {
        libp2p_host_err_t dial_err = LIBP2P_HOST_OK;

        app->dial_started_us = interop_app_now_us(app);
        deadline =
            app->dial_started_us + (((uint64_t)app->env.timeout_seconds) * INTEROP_USEC_PER_SEC);
        interop_log(app, "dialer starting host dial");
        dial_err =
            libp2p_host_dial(app->host, app->dial_multiaddr, app->dial_multiaddr_len, NULL, &dial);
        if (dial_err != LIBP2P_HOST_OK)
        {
            interop_log_u64(app, "host dial failed: ", (uint64_t)dial_err);
            result = INTEROP_ERR_PROTOCOL;
        }
    }
    while ((result == INTEROP_OK) && (app->ping_done == 0) && (g_stop_requested == 0))
    {
        if (interop_app_now_us(app) > deadline)
        {
            result = INTEROP_ERR_TIMEOUT;
        }
        if (result == INTEROP_OK)
        {
            result = interop_drive_once(app);
        }
        if (result == INTEROP_OK)
        {
            result = interop_drain_host_events(app);
        }
        if (result == INTEROP_OK)
        {
            result = interop_drain_ping_events(app);
        }
    }
    if ((result == INTEROP_OK) && (app->ping_done != 0))
    {
        interop_print_results(app);
    }

    return result;
}

int main(void)
{
    interop_app_t app;
    interop_err_t result = INTEROP_OK;

    (void)memset(&app, 0, sizeof(app));
    app.time_origin_us = interop_now_us();
    (void)signal(SIGTERM, interop_signal_handler);
    (void)signal(SIGINT, interop_signal_handler);

    result = interop_env_load(&app.env);
    if (result == INTEROP_OK)
    {
        result = interop_identity_init(&app.identity, app.env.is_dialer);
    }
    if (result == INTEROP_OK)
    {
        if (app.env.is_dialer != 0U)
        {
            result = interop_run_dialer(&app);
        }
        else
        {
            result = interop_run_listener(&app);
        }
    }
    if (app.host != NULL)
    {
        libp2p_host_deinit(app.host);
    }
    libp2p_peer_id_zeroize(app.identity.private_key, sizeof(app.identity.private_key));
    if (result != INTEROP_OK)
    {
        (void)fprintf(stderr, "c-lean-libp2p interop failed: %d\n", (int)result);
    }

    return (int)result;
}
