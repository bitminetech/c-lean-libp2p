#define _POSIX_C_SOURCE 200112L

#include "gossipsub_interop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "libp2p/libp2p_host.h"
#include "libp2p/libp2p_host_internal.h"
#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "protocol/gossipsub/gossipsub.h"
#include "protocol/gossipsub/gossipsub_internal.h"
#include "protocol/identify/identify.h"
#include "transport/quic/quic_backend_ngtcp2_internal.h"
#include "transport/quic/quic_identity.h"
#include "transport/quic/quic_service.h"

#define GOSSIPSUB_INTEROP_LISTEN_PORT              9000U
#define GOSSIPSUB_INTEROP_POLL_MAX_MS              50
#define GOSSIPSUB_INTEROP_HOST_STORAGE_BYTES       (16U * 1024U * 1024U)
#define GOSSIPSUB_INTEROP_GOSSIPSUB_STORAGE_BYTES  (96U * 1024U * 1024U)
#define GOSSIPSUB_INTEROP_LISTEN_MULTIADDR_BYTES   128U
#define GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES     512U
#define GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES       128U
#define GOSSIPSUB_INTEROP_HOSTNAME_BYTES           64U
#define GOSSIPSUB_INTEROP_IP_TEXT_BYTES            64U
#define GOSSIPSUB_INTEROP_PATH_BYTES               512U
#define GOSSIPSUB_INTEROP_GOSSIPSUB_PROTOCOLS      LIBP2P_GOSSIPSUB_PROTOCOL_COUNT
#define GOSSIPSUB_INTEROP_PROTOCOLS                (GOSSIPSUB_INTEROP_GOSSIPSUB_PROTOCOLS + 1U)
#define GOSSIPSUB_INTEROP_CERT_VALIDITY_SECONDS    UINT64_C(315360000)
#define GOSSIPSUB_INTEROP_CERT_BACKDATE_SECONDS    UINT64_C(3600)
#define GOSSIPSUB_INTEROP_SHADOW_CERT_UNIX_SECONDS UINT64_C(946684800)
#define GOSSIPSUB_INTEROP_TLS_TRACE_HEX_BYTES      256U
#define GOSSIPSUB_INTEROP_USEC_PER_SEC             UINT64_C(1000000)
#define GOSSIPSUB_INTEROP_USEC_PER_MSEC            UINT64_C(1000)
#define GOSSIPSUB_INTEROP_NSEC_PER_USEC            UINT64_C(1000)
#define GOSSIPSUB_INTEROP_CONNECT_TIMEOUT_SECONDS  UINT64_C(15)
#define GOSSIPSUB_INTEROP_CONNECT_ATTEMPTS         3U
#define GOSSIPSUB_INTEROP_MAX_CONNECTED_PEERS      64U
#define GOSSIPSUB_INTEROP_AUTOPSY_TICK_US          UINT64_C(5000000)
#define GOSSIPSUB_INTEROP_REF_D                    6U
#define GOSSIPSUB_INTEROP_REF_D_LOW                5U
#define GOSSIPSUB_INTEROP_REF_D_HIGH               12U
#define GOSSIPSUB_INTEROP_REF_D_LAZY               6U
#define GOSSIPSUB_INTEROP_REF_HEARTBEAT_US         UINT64_C(1000000)

typedef union
{
    max_align_t align;
    uint8_t bytes[GOSSIPSUB_INTEROP_HOST_STORAGE_BYTES];
} gossipsub_interop_host_storage_t;

typedef union
{
    max_align_t align;
    uint8_t bytes[GOSSIPSUB_INTEROP_GOSSIPSUB_STORAGE_BYTES];
} gossipsub_interop_router_storage_t;

typedef struct
{
    uint8_t private_key[LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES];
    libp2p_host_secp256k1_identity_t host_storage;
    libp2p_host_identity_t host;
    uint8_t cert[LIBP2P_QUIC_CERTIFICATE_DER_MAX_BYTES];
    uint8_t cert_key[LIBP2P_QUIC_CERTIFICATE_KEY_DER_MAX_BYTES];
    libp2p_quic_local_identity_t quic;
} gossipsub_interop_identity_t;

typedef struct
{
    char topic[GOSSIPSUB_INTEROP_MAX_TOPIC_BYTES];
    size_t topic_len;
    uint64_t delay_us;
} gossipsub_interop_validation_topic_t;

typedef struct
{
    libp2p_gossipsub_validation_t *validation;
    uint64_t due_us;
} gossipsub_interop_pending_validation_t;

typedef struct
{
    const char *params_path;
    const char *write_identities_dir;
    int write_identity_count;
} gossipsub_interop_args_t;

typedef struct
{
    int node_id;
    uint8_t debug;
    uint8_t autopsy;
    uint64_t start_us;
    uint64_t next_autopsy_tick_us;
    gossipsub_interop_identity_t identity;
    libp2p_quic_service_config_t quic_config;
    libp2p_host_config_t host_config;
    libp2p_host_protocol_t protocols[GOSSIPSUB_INTEROP_PROTOCOLS];
    libp2p_host_t *host;
    libp2p_identify_config_t identify_config;
    libp2p_identify_t identify;
    libp2p_gossipsub_config_t gossipsub_config;
    libp2p_gossipsub_t *gossipsub;
    uint8_t listen_multiaddr[GOSSIPSUB_INTEROP_LISTEN_MULTIADDR_BYTES];
    size_t listen_multiaddr_len;
    gossipsub_interop_validation_topic_t validation_topics[GOSSIPSUB_INTEROP_MAX_VALIDATION_TOPICS];
    size_t validation_topic_count;
    gossipsub_interop_pending_validation_t
        pending_validations[LIBP2P_GOSSIPSUB_DEFAULT_PENDING_VALIDATIONS];
    size_t pending_validation_count;
    uint8_t connected_peer_ids[GOSSIPSUB_INTEROP_MAX_CONNECTED_PEERS][LIBP2P_PEER_ID_MAX_BYTES];
    size_t connected_peer_id_lens[GOSSIPSUB_INTEROP_MAX_CONNECTED_PEERS];
    size_t connected_peer_count;
    libp2p_host_dial_t *connect_dial;
    uint8_t connect_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t connect_peer_id_len;
    uint8_t connect_complete;
    uint8_t connect_failed;
} gossipsub_interop_app_t;

static gossipsub_interop_host_storage_t g_host_storage;
static gossipsub_interop_router_storage_t g_router_storage;
static uint8_t g_publish_buffer[GOSSIPSUB_INTEROP_MAX_MESSAGE_BYTES];
static volatile sig_atomic_t g_stop_requested = 0;
static const uint8_t g_identify_protocol_version[] = {
    'i',
    'p',
    'f',
    's',
    '/',
    '0',
    '.',
    '1',
    '.',
    '0'};
static const uint8_t g_identify_agent_version[] = {
    'c',
    '-',
    'l',
    'e',
    'a',
    'n',
    '-',
    'l',
    'i',
    'b',
    'p',
    '2',
    'p',
    '/',
    'g',
    'o',
    's',
    's',
    'i',
    'p',
    's',
    'u',
    'b',
    '-',
    'i',
    'n',
    't',
    'e',
    'r',
    'o',
    'p'};

static void gossipsub_interop_trace(const char *message);
static gossipsub_interop_err_t gossipsub_interop_drive_once(gossipsub_interop_app_t *app);

static void gossipsub_interop_signal_handler(int signo)
{
    (void)signo;
    g_stop_requested = 1;
}

static void *gossipsub_interop_backend_malloc(size_t size, void *user_data)
{
    (void)user_data;
    return malloc(size);
}

static void *gossipsub_interop_backend_calloc(size_t nmemb, size_t size, void *user_data)
{
    (void)user_data;
    return calloc(nmemb, size);
}

static void *gossipsub_interop_backend_realloc(void *ptr, size_t size, void *user_data)
{
    (void)user_data;
    return realloc(ptr, size);
}

static void gossipsub_interop_backend_free(void *ptr, void *user_data)
{
    (void)user_data;
    free(ptr);
}

static libp2p_quic_allocator_t gossipsub_interop_backend_allocator(void)
{
    libp2p_quic_allocator_t allocator;

    allocator.malloc_fn = gossipsub_interop_backend_malloc;
    allocator.calloc_fn = gossipsub_interop_backend_calloc;
    allocator.realloc_fn = gossipsub_interop_backend_realloc;
    allocator.free_fn = gossipsub_interop_backend_free;
    allocator.user_data = NULL;
    return allocator;
}

static uint64_t gossipsub_interop_now_us(void)
{
    struct timespec ts;
    uint64_t result = 0U;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        result = ((uint64_t)ts.tv_sec * GOSSIPSUB_INTEROP_USEC_PER_SEC) +
                 ((uint64_t)ts.tv_nsec / GOSSIPSUB_INTEROP_NSEC_PER_USEC);
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_read_urandom(uint8_t *out, size_t out_len)
{
    int fd = -1;
    size_t pos = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((out == NULL) && (out_len != 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (pos < out_len))
    {
        const ssize_t count = read(fd, &out[pos], out_len - pos);
        if (count > 0)
        {
            pos += (size_t)count;
        }
        else if ((count < 0) && (errno == EINTR))
        {
            result = GOSSIPSUB_INTEROP_OK;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }

    return result;
}

static libp2p_quic_err_t gossipsub_interop_quic_random(
    uint8_t *out,
    size_t out_len,
    void *user_data)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    (void)user_data;
    if (gossipsub_interop_read_urandom(out, out_len) != GOSSIPSUB_INTEROP_OK)
    {
        result = LIBP2P_QUIC_ERR_INTERNAL;
    }

    return result;
}

static libp2p_gossipsub_err_t gossipsub_interop_random(
    uint8_t *out,
    size_t out_len,
    void *user_data)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    (void)user_data;
    if (gossipsub_interop_read_urandom(out, out_len) != GOSSIPSUB_INTEROP_OK)
    {
        result = LIBP2P_GOSSIPSUB_ERR_RANDOM;
    }

    return result;
}

static libp2p_quic_err_t gossipsub_interop_unix_time(uint64_t *out_unix_seconds, void *user_data)
{
    const time_t now = time(NULL);
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

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

static uint8_t gossipsub_interop_env_enabled(const char *name)
{
    const char *value = getenv(name);
    uint8_t result = 0U;

    if ((value != NULL) && (value[0] != '\0') && (strcmp(value, "0") != 0))
    {
        result = 1U;
    }

    return result;
}

static void gossipsub_interop_print_hex(const uint8_t *data, size_t data_len)
{
    static const char digits[] = "0123456789abcdef";
    size_t index = 0U;
    size_t limit = data_len;

    if (limit > GOSSIPSUB_INTEROP_TLS_TRACE_HEX_BYTES)
    {
        limit = GOSSIPSUB_INTEROP_TLS_TRACE_HEX_BYTES;
    }
    for (index = 0U; index < limit; index++)
    {
        const uint8_t byte = data[index];
        (void)fputc((int)digits[(byte >> 4U) & 0x0FU], stderr);
        (void)fputc((int)digits[byte & 0x0FU], stderr);
    }
    if (limit < data_len)
    {
        (void)fprintf(stderr, "...(+%zu bytes)", data_len - limit);
    }
}

static void gossipsub_interop_quic_debug(
    libp2p_quic_debug_event_type_t type,
    const void *data,
    size_t data_len,
    void *user_data)
{
    const char *label = "text";
    const uint8_t *bytes = data;

    (void)user_data;
    if ((data != NULL) || (data_len == 0U))
    {
        if (type == LIBP2P_QUIC_DEBUG_EVENT_QLOG)
        {
            label = "qlog";
        }
        else if (type == LIBP2P_QUIC_DEBUG_EVENT_TLS_MESSAGE)
        {
            label = "tls";
        }
        else
        {
            label = "text";
        }

        (void)fprintf(stderr, "c-lean-quic[%s]: ", label);
        if (type == LIBP2P_QUIC_DEBUG_EVENT_TLS_MESSAGE)
        {
            gossipsub_interop_print_hex(bytes, data_len);
        }
        else if ((data != NULL) && (data_len != 0U))
        {
            (void)fwrite(data, 1U, data_len, stderr);
        }
        else
        {
            (void)fprintf(stderr, "<empty>");
        }
        (void)fputc('\n', stderr);
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_make_node_private_key(int node_id, uint8_t out[32])
{
    uint64_t value = (uint64_t)node_id + 1U;
    size_t index = 0U;

    (void)memset(out, 0, 32U);
    for (index = 0U; index < 8U; index++)
    {
        out[31U - index] = (uint8_t)(value & 0xFFU);
        value >>= 8U;
    }
}

static gossipsub_interop_err_t gossipsub_interop_identity_path(
    const char *identity_dir,
    int node_id,
    const char *suffix,
    char *out,
    size_t out_len)
{
    int text_len = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((identity_dir == NULL) || (identity_dir[0] == '\0') || (suffix == NULL) || (out == NULL) ||
        (out_len == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        text_len = snprintf(out, out_len, "%s/node%d-%s.der", identity_dir, node_id, suffix);
        if ((text_len <= 0) || ((size_t)text_len >= out_len))
        {
            result = GOSSIPSUB_INTEROP_ERR_LIMIT;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_read_binary_file(
    const char *path,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    FILE *file = NULL;
    size_t bytes_read = 0U;
    int close_status = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((path == NULL) || (out == NULL) || (written == NULL) || (out_len == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        *written = 0U;
        file = fopen(path, "rb");
        if (file == NULL)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        bytes_read = fread(out, 1U, out_len, file);
        if (ferror(file) != 0)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
        else if (bytes_read == out_len)
        {
            int extra = fgetc(file);
            if (extra != EOF)
            {
                result = GOSSIPSUB_INTEROP_ERR_LIMIT;
            }
            else if (ferror(file) != 0)
            {
                result = GOSSIPSUB_INTEROP_ERR_IO;
            }
            else
            {
                *written = bytes_read;
            }
        }
        else
        {
            *written = bytes_read;
        }
    }
    if (file != NULL)
    {
        close_status = fclose(file);
        if ((result == GOSSIPSUB_INTEROP_OK) && (close_status != 0))
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_write_binary_file(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    FILE *file = NULL;
    size_t bytes_written = 0U;
    int close_status = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((path == NULL) || (data == NULL) || (data_len == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        file = fopen(path, "wb");
        if (file == NULL)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        bytes_written = fwrite(data, 1U, data_len, file);
        if ((bytes_written != data_len) || (ferror(file) != 0))
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (file != NULL)
    {
        close_status = fclose(file);
        if ((result == GOSSIPSUB_INTEROP_OK) && (close_status != 0))
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_identity_init_generated(
    gossipsub_interop_identity_t *identity,
    int node_id,
    uint64_t cert_unix_seconds)
{
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t cert_config;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (identity == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(identity, 0, sizeof(*identity));
        gossipsub_interop_make_node_private_key(node_id, identity->private_key);
        gossipsub_interop_trace("private key ready");
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("host identity init");
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_host_secp256k1_identity_init(
                                                 &identity->host_storage,
                                                 identity->private_key,
                                                 sizeof(identity->private_key),
                                                 &identity->host) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("host identity done");
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("certificate init");
        host_key.type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
        host_key.private_key = identity->private_key;
        host_key.private_key_len = sizeof(identity->private_key);
        host_key.public_key_message = identity->host_storage.public_key_message;
        host_key.public_key_message_len = identity->host_storage.public_key_message_len;

        cert_config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
        cert_config.not_before_unix_seconds =
            cert_unix_seconds - GOSSIPSUB_INTEROP_CERT_BACKDATE_SECONDS;
        cert_config.not_after_unix_seconds =
            cert_unix_seconds + GOSSIPSUB_INTEROP_CERT_VALIDITY_SECONDS;
        cert_config.random_fn = gossipsub_interop_quic_random;
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
            result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("certificate done");
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        identity->quic.certificate_der = identity->cert;
        identity->quic.certificate_private_key_der = identity->cert_key;
        identity->quic.peer_id = identity->host_storage.peer_id;
        identity->quic.peer_id_len = identity->host_storage.peer_id_len;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_identity_init_cached(
    gossipsub_interop_identity_t *identity,
    int node_id,
    const char *identity_dir)
{
    char path[GOSSIPSUB_INTEROP_PATH_BYTES];
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (identity == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(identity, 0, sizeof(*identity));
        gossipsub_interop_make_node_private_key(node_id, identity->private_key);
        gossipsub_interop_trace("private key ready");
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("host identity init");
        if (libp2p_host_secp256k1_identity_init(
                &identity->host_storage,
                identity->private_key,
                sizeof(identity->private_key),
                &identity->host) != LIBP2P_HOST_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("host identity done");
        result = gossipsub_interop_identity_path(identity_dir, node_id, "cert", path, sizeof(path));
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_read_binary_file(
            path,
            identity->cert,
            sizeof(identity->cert),
            &identity->quic.certificate_der_len);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_identity_path(identity_dir, node_id, "key", path, sizeof(path));
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_read_binary_file(
            path,
            identity->cert_key,
            sizeof(identity->cert_key),
            &identity->quic.certificate_private_key_der_len);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        identity->quic.certificate_der = identity->cert;
        identity->quic.certificate_private_key_der = identity->cert_key;
        identity->quic.peer_id = identity->host_storage.peer_id;
        identity->quic.peer_id_len = identity->host_storage.peer_id_len;
        gossipsub_interop_trace("certificate cache loaded");
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_identity_init(
    gossipsub_interop_identity_t *identity,
    int node_id)
{
    const char *identity_dir = getenv("C_LEAN_LIBP2P_GOSSIPSUB_IDENTITY_DIR");
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((identity_dir != NULL) && (identity_dir[0] != '\0'))
    {
        result = gossipsub_interop_identity_init_cached(identity, node_id, identity_dir);
    }
    else
    {
        uint64_t now = 0U;

        if (gossipsub_interop_unix_time(&now, NULL) != LIBP2P_QUIC_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
        }
        else
        {
            result = gossipsub_interop_identity_init_generated(identity, node_id, now);
        }
    }

    return result;
}

static void gossipsub_interop_debug(const gossipsub_interop_app_t *app, const char *message)
{
    if ((app != NULL) && (app->debug != 0U) && (message != NULL))
    {
        (void)fprintf(stderr, "%s\n", message);
    }
}

static uint8_t gossipsub_interop_trace_enabled(void)
{
    uint8_t result = (getenv("C_LEAN_LIBP2P_GOSSIPSUB_TRACE") != NULL) ? 1U : 0U;

    if (result == 0U)
    {
        result = gossipsub_interop_env_enabled("LIBP2P_QUIC_DEBUG");
    }

    return result;
}

static void gossipsub_interop_trace(const char *message)
{
    if ((message != NULL) && (gossipsub_interop_trace_enabled() != 0U))
    {
        (void)fprintf(stderr, "c-lean-gossipsub: %s\n", message);
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_trace_tx_peers(const gossipsub_interop_app_t *app, uint64_t now_us)
{
    if ((app != NULL) && (gossipsub_interop_trace_enabled() != 0U))
    {
        for (size_t peer_index = 0U; peer_index < app->gossipsub_config.capacity.max_peers;
             peer_index++)
        {
            libp2p_gossipsub_tx_peer_stats_t stats;

            (void)memset(&stats, 0, sizeof(stats));
            if (libp2p_gossipsub_tx_peer_stats(app->gossipsub, peer_index, now_us, &stats) ==
                LIBP2P_GOSSIPSUB_OK)
            {
                if ((stats.queue_depth != 0U) || (stats.would_block_count != 0U))
                {
                    (void)fprintf(
                        stderr,
                        "c-lean-gossipsub: tx peer_index=%zu used=%u ready=%u depth=%zu "
                        "oldest_age_us=%llu current_pos=%zu current_len=%zu publish=%u "
                        "bytes_accepted=%llu would_block=%llu last_writable_us=%llu "
                        "last_tx_offset=%llu\n",
                        peer_index,
                        (unsigned int)stats.used,
                        (unsigned int)stats.ready,
                        stats.queue_depth,
                        (unsigned long long)stats.oldest_age_us,
                        stats.current_pos,
                        stats.current_len,
                        (unsigned int)stats.current_publish,
                        (unsigned long long)stats.bytes_accepted,
                        (unsigned long long)stats.would_block_count,
                        (unsigned long long)stats.last_writable_us,
                        (unsigned long long)stats.last_tx_offset);
                }
            }
        }
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_json_escape(FILE *out, const char *text, size_t text_len);

static uint8_t gossipsub_interop_autopsy_enabled(const gossipsub_interop_app_t *app)
{
    uint8_t result = 0U;

    if ((app != NULL) && (app->autopsy != 0U))
    {
        result = 1U;
    }

    return result;
}

static void gossipsub_interop_autopsy_hex(FILE *out, const uint8_t *data, size_t data_len)
{
    static const char hex[] = "0123456789abcdef";

    if ((out != NULL) && (data != NULL))
    {
        for (size_t index = 0U; index < data_len; index++)
        {
            const uint8_t byte = data[index];

            (void)fputc((int)hex[(byte >> 4U) & 0x0FU], out);
            (void)fputc((int)hex[byte & 0x0FU], out);
        }
    }
}

static void gossipsub_interop_autopsy_peer_text(FILE *out, const uint8_t *peer_id, size_t peer_id_len)
{
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    size_t peer_text_len = 0U;

    if ((out != NULL) && (peer_id != NULL) && (peer_id_len != 0U) &&
        (libp2p_peer_id_to_string(peer_id, peer_id_len, peer_text, sizeof(peer_text), &peer_text_len) ==
         LIBP2P_PEER_ID_OK))
    {
        gossipsub_interop_json_escape(out, peer_text, peer_text_len);
    }
}

static size_t gossipsub_interop_autopsy_conn_index(
    const gossipsub_interop_app_t *app,
    const libp2p_host_conn_t *conn)
{
    size_t result = SIZE_MAX;

    if ((app != NULL) && (app->host != NULL) && (conn != NULL))
    {
        for (size_t index = 0U; (index < app->host->conn_capacity) && (result == SIZE_MAX); index++)
        {
            if (&app->host->conns[index] == conn)
            {
                result = index;
            }
        }
    }

    return result;
}

static uint8_t gossipsub_interop_autopsy_tx_topic_match(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_tx_item_t *item,
    const gossipsub_topic_state_t *topic)
{
    uint8_t result = 0U;

    if ((gossipsub != NULL) && (item != NULL) && (topic != NULL) && (item->publish != 0U))
    {
        for (size_t index = 0U;
             (index < gossipsub->config.capacity.mcache_slots) && (result == 0U);
             index++)
        {
            const gossipsub_mcache_entry_t *entry = &gossipsub->mcache[index];

            if ((entry->used != 0U) && (entry->message_id_len == item->message_id_len) &&
                (entry->topic_len == topic->topic_len) &&
                (memcmp(entry->message_id, item->message_id, item->message_id_len) == 0) &&
                (memcmp(entry->topic, topic->topic, topic->topic_len) == 0))
            {
                result = 1U;
            }
        }
    }

    return result;
}

static size_t gossipsub_interop_autopsy_topic_queue_depth(
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_peer_state_t *peer,
    const gossipsub_topic_state_t *topic)
{
    size_t result = 0U;
    size_t item_index = GOSSIPSUB_TX_NO_ITEM;

    if ((gossipsub != NULL) && (peer != NULL) && (topic != NULL))
    {
        item_index = peer->tx_head;
        while (item_index != GOSSIPSUB_TX_NO_ITEM)
        {
            if ((item_index >= gossipsub->config.capacity.max_tx_rpc_queue) ||
                (gossipsub->tx_queue[item_index].used == 0U))
            {
                item_index = GOSSIPSUB_TX_NO_ITEM;
            }
            else
            {
                const gossipsub_tx_item_t *item = &gossipsub->tx_queue[item_index];

                if (gossipsub_interop_autopsy_tx_topic_match(gossipsub, item, topic) != 0U)
                {
                    result++;
                }
                item_index = item->next;
            }
        }
    }

    return result;
}

static void gossipsub_interop_autopsy_dump_peer_topics(
    FILE *out,
    const libp2p_gossipsub_t *gossipsub,
    const gossipsub_peer_state_t *peer,
    size_t peer_index)
{
    if ((out != NULL) && (gossipsub != NULL) && (peer != NULL))
    {
        for (size_t topic_index = 0U; topic_index < gossipsub->config.capacity.max_topics;
             topic_index++)
        {
            const gossipsub_topic_state_t *topic = &gossipsub->topics[topic_index];

            if (topic->used == GOSSIPSUB_TOPIC_USED)
            {
                if (topic_index != 0U)
                {
                    (void)fputc(';', out);
                }
                gossipsub_interop_json_escape(out, (const char *)topic->topic, topic->topic_len);
                (void)fprintf(
                    out,
                    ":mesh=%u,q=%zu",
                    (unsigned int)((gossipsub_mesh_contains(gossipsub, peer_index, topic_index) != 0)
                                       ? 1U
                                       : 0U),
                    gossipsub_interop_autopsy_topic_queue_depth(gossipsub, peer, topic));
            }
        }
    }
}

static void gossipsub_interop_autopsy_dump_peers(
    const gossipsub_interop_app_t *app,
    const char *reason,
    uint64_t now_us)
{
    const libp2p_gossipsub_t *gossipsub = NULL;

    if ((gossipsub_interop_autopsy_enabled(app) != 0U) && (app->gossipsub != NULL))
    {
        gossipsub = app->gossipsub;
        for (size_t peer_index = 0U; peer_index < gossipsub->config.capacity.max_peers; peer_index++)
        {
            const gossipsub_peer_state_t *peer = &gossipsub->peers[peer_index];

            if (peer->used == GOSSIPSUB_PEER_USED)
            {
                const size_t head_index = peer->tx_head;
                const gossipsub_tx_item_t *head = NULL;
                const libp2p_quic_stream_t *quic_stream = NULL;
                int64_t stream_id = -1;
                size_t conn_index = gossipsub_interop_autopsy_conn_index(app, peer->conn);

                if ((head_index != GOSSIPSUB_TX_NO_ITEM) &&
                    (head_index < gossipsub->config.capacity.max_tx_rpc_queue) &&
                    (gossipsub->tx_queue[head_index].used != 0U))
                {
                    head = &gossipsub->tx_queue[head_index];
                }
                if ((peer->stream != NULL) && (peer->stream->transport_stream != NULL))
                {
                    quic_stream = (const libp2p_quic_stream_t *)peer->stream->transport_stream;
                    stream_id = quic_stream->stream_id;
                }
                (void)fprintf(
                    stderr,
                    "c-lean-autopsy-peer: reason=%s node=%d now_us=%llu peer_index=%zu peer_id=\"",
                    (reason != NULL) ? reason : "unknown",
                    app->node_id,
                    (unsigned long long)now_us,
                    peer_index);
                gossipsub_interop_autopsy_peer_text(stderr, peer->peer_id, peer->peer_id_len);
                (void)fprintf(stderr, "\" topics=\"");
                gossipsub_interop_autopsy_dump_peer_topics(stderr, gossipsub, peer, peer_index);
                (void)fprintf(
                    stderr,
                    "\" depth=%zu head_message_id_hex=\"",
                    peer->tx_queue_depth);
                if (head != NULL)
                {
                    gossipsub_interop_autopsy_hex(stderr, head->message_id, head->message_id_len);
                }
                (void)fprintf(
                    stderr,
                    "\" head_offset=%zu head_len=%zu ready=%u stream_id=%lld conn_id=",
                    (head != NULL) ? head->pos : 0U,
                    (head != NULL) ? head->len : 0U,
                    (unsigned int)peer->tx_ready,
                    (long long)stream_id);
                if (conn_index == SIZE_MAX)
                {
                    (void)fprintf(stderr, "none");
                }
                else
                {
                    (void)fprintf(stderr, "%zu", conn_index);
                }
                (void)fprintf(
                    stderr,
                    " last_writable_us=%llu last_tx_offset=%llu would_block=%llu oldest_age_us=",
                    (unsigned long long)peer->tx_last_writable_us,
                    (unsigned long long)peer->tx_last_offset,
                    (unsigned long long)peer->tx_would_block_count);
                if ((head != NULL) && (now_us >= head->enqueued_us))
                {
                    (void)fprintf(stderr, "%llu", (unsigned long long)(now_us - head->enqueued_us));
                }
                else
                {
                    (void)fprintf(stderr, "0");
                }
                (void)fprintf(stderr, "\n");
            }
        }
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_autopsy_dump_quic(
    const gossipsub_interop_app_t *app,
    const char *reason,
    uint64_t now_us)
{
    const libp2p_quic_service_t *service = NULL;

    if ((gossipsub_interop_autopsy_enabled(app) != 0U) && (app->host != NULL))
    {
        service = (const libp2p_quic_service_t *)app->host->transport;
        for (size_t index = 0U; index < app->quic_config.endpoint.max_connections; index++)
        {
            libp2p_quic_service_autopsy_conn_t snapshot;

            (void)memset(&snapshot, 0, sizeof(snapshot));
            if (libp2p_quic_service_autopsy_conn(service, index, now_us, &snapshot) == LIBP2P_QUIC_OK)
            {
                (void)fprintf(
                    stderr,
                    "c-lean-autopsy-quic: reason=%s node=%d now_us=%llu conn_id=%zu peer_id=\"",
                    (reason != NULL) ? reason : "unknown",
                    app->node_id,
                    (unsigned long long)now_us,
                    index);
                gossipsub_interop_autopsy_peer_text(
                    stderr,
                    snapshot.remote_peer_id,
                    snapshot.remote_peer_id_len);
                (void)fprintf(
                    stderr,
                    "\" closed=%u cwnd=%llu bytes_in_flight=%llu tx_buffered=%llu tx_sent=%llu "
                    "tx_acked=%llu tx_lost=%llu last_rx_us=%llu last_tx_us=%llu "
                    "write_data=%llu write_control=%llu write_zero=%llu write_stream_blocked=%llu "
                    "write_stream_shut_wr=%llu write_stream_not_found=%llu write_other_error=%llu "
                    "idle_deadline_us=%llu streams=\"",
                    (unsigned int)snapshot.closed,
                    (unsigned long long)snapshot.cwnd,
                    (unsigned long long)snapshot.bytes_in_flight,
                    (unsigned long long)snapshot.tx_buffered,
                    (unsigned long long)snapshot.tx_sent,
                    (unsigned long long)snapshot.tx_acked,
                    (unsigned long long)snapshot.tx_lost,
                    (unsigned long long)snapshot.last_rx_us,
                    (unsigned long long)snapshot.last_tx_us,
                    (unsigned long long)snapshot.write_data_packets,
                    (unsigned long long)snapshot.write_control_packets,
                    (unsigned long long)snapshot.write_zero_count,
                    (unsigned long long)snapshot.write_stream_blocked_count,
                    (unsigned long long)snapshot.write_stream_shut_wr_count,
                    (unsigned long long)snapshot.write_stream_not_found_count,
                    (unsigned long long)snapshot.write_other_error_count,
                    (unsigned long long)snapshot.idle_deadline_us);
                for (size_t stream_index = 0U;
                     (stream_index < snapshot.stream_count) &&
                     (stream_index < LIBP2P_QUIC_SERVICE_AUTOPSY_MAX_STREAMS);
                     stream_index++)
                {
                    const libp2p_quic_service_autopsy_stream_t *stream =
                        &snapshot.streams[stream_index];

                    if (stream_index != 0U)
                    {
                        (void)fputc(';', stderr);
                    }
                    (void)fprintf(
                        stderr,
                        "%lld:buf=%zu,pending=%zu,base=%llu,credit=%llu",
                        (long long)stream->stream_id,
                        stream->tx_buffered,
                        stream->tx_sent_pending_ack,
                        (unsigned long long)stream->tx_base_offset,
                        (unsigned long long)stream->flow_credit);
                }
                (void)fprintf(stderr, "\"\n");
            }
        }
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_autopsy_tick(gossipsub_interop_app_t *app, uint64_t now_us)
{
    if ((gossipsub_interop_autopsy_enabled(app) != 0U) && (now_us >= app->next_autopsy_tick_us))
    {
        gossipsub_interop_autopsy_dump_quic(app, "tick", now_us);
        app->next_autopsy_tick_us = now_us + GOSSIPSUB_INTEROP_AUTOPSY_TICK_US;
    }
}

static const char *gossipsub_interop_autopsy_outcome_name(gossipsub_autopsy_outcome_t outcome)
{
    const char *result = "unknown";

    switch (outcome)
    {
    case GOSSIPSUB_AUTOPSY_OUTCOME_QUEUED:
        result = "queued";
        break;
    case GOSSIPSUB_AUTOPSY_OUTCOME_SENT:
        result = "sent";
        break;
    case GOSSIPSUB_AUTOPSY_OUTCOME_DROPPED_STALE:
        result = "dropped-stale";
        break;
    case GOSSIPSUB_AUTOPSY_OUTCOME_DROPPED_IDONTWANT:
        result = "dropped-idontwant";
        break;
    case GOSSIPSUB_AUTOPSY_OUTCOME_DROPPED_PEER:
        result = "dropped-peer";
        break;
    default:
        result = "unknown";
        break;
    }

    return result;
}

static void gossipsub_interop_autopsy_dump_delivery_graph(void)
{
    if (gossipsub_autopsy_message_count() != 0U)
    {
        for (size_t message_index = 0U; message_index < gossipsub_autopsy_message_count();
             message_index++)
        {
            const gossipsub_autopsy_message_t *message =
                gossipsub_autopsy_message_at(message_index);
            size_t emitted = 0U;

            if ((message != NULL) && (message->used != 0U))
            {
                (void)fprintf(stderr, "c-lean-autopsy-delivery: message_id_hex=\"");
                gossipsub_interop_autopsy_hex(stderr, message->message_id, message->message_id_len);
                (void)fprintf(stderr, "\" publisher_peer_id=\"");
                gossipsub_interop_autopsy_peer_text(
                    stderr,
                    message->publisher_peer_id,
                    message->publisher_peer_id_len);
                (void)fprintf(
                    stderr,
                    "\" publisher_peer_id_hex=\"");
                gossipsub_interop_autopsy_hex(
                    stderr,
                    message->publisher_peer_id,
                    message->publisher_peer_id_len);
                (void)fprintf(
                    stderr,
                    "\" first_receive_us=%llu attempts=\"",
                    (unsigned long long)message->first_receive_us);
                for (size_t attempt_index = 0U; attempt_index < gossipsub_autopsy_attempt_count();
                     attempt_index++)
                {
                    const gossipsub_autopsy_attempt_t *attempt =
                        gossipsub_autopsy_attempt_at(attempt_index);

                    if ((attempt != NULL) && (attempt->used != 0U) &&
                        (attempt->message_index == message_index))
                    {
                        if (emitted != 0U)
                        {
                            (void)fputc(',', stderr);
                        }
                        gossipsub_interop_autopsy_peer_text(
                            stderr,
                            attempt->peer_id,
                            attempt->peer_id_len);
                        (void)fprintf(
                            stderr,
                            ":%s",
                            gossipsub_interop_autopsy_outcome_name(attempt->outcome));
                        emitted++;
                    }
                }
                (void)fprintf(stderr, "\" acked=\"\"\n");
            }
        }
        (void)fflush(stderr);
    }
}

static void gossipsub_interop_autopsy_exit(gossipsub_interop_app_t *app, const char *reason)
{
    const uint64_t now_us = gossipsub_interop_now_us();

    if (gossipsub_interop_autopsy_enabled(app) != 0U)
    {
        gossipsub_interop_autopsy_dump_peers(app, reason, now_us);
        gossipsub_interop_autopsy_dump_quic(app, reason, now_us);
        gossipsub_interop_autopsy_dump_delivery_graph();
    }
}

static void gossipsub_interop_timestamp(char *out, size_t out_len)
{
    const time_t now = time(NULL);
    struct tm tm_now;

    if ((out != NULL) && (out_len != 0U))
    {
        if ((now >= (time_t)0) && (gmtime_r(&now, &tm_now) != NULL))
        {
            (void)strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm_now);
        }
        else
        {
            (void)snprintf(out, out_len, "1970-01-01T00:00:00Z");
        }
    }
}

static void gossipsub_interop_json_escape(FILE *out, const char *text, size_t text_len)
{
    size_t index = 0U;

    for (index = 0U; index < text_len; index++)
    {
        const unsigned char ch = (unsigned char)text[index];
        if ((ch == (unsigned char)'\\') || (ch == (unsigned char)'"'))
        {
            (void)fputc('\\', out);
            (void)fputc((int)ch, out);
        }
        else if (ch >= (unsigned char)0x20U)
        {
            (void)fputc((int)ch, out);
        }
    }
}

static void gossipsub_interop_log_peer_id(const gossipsub_interop_app_t *app)
{
    char timestamp[40];
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    size_t peer_text_len = 0U;

    if (libp2p_peer_id_to_string(
            app->identity.host_storage.peer_id,
            app->identity.host_storage.peer_id_len,
            peer_text,
            sizeof(peer_text),
            &peer_text_len) == LIBP2P_PEER_ID_OK)
    {
        gossipsub_interop_timestamp(timestamp, sizeof(timestamp));
        (void)printf(
            "{\"time\":\"%s\",\"level\":\"INFO\",\"msg\":\"PeerID\",\"service\":\"gossipsub\","
            "\"id\":\"",
            timestamp);
        gossipsub_interop_json_escape(stdout, peer_text, peer_text_len);
        (void)printf("\",\"node_id\":%d}\n", app->node_id);
        (void)fflush(stdout);
    }
}

static uint64_t gossipsub_interop_message_id_from_bytes(const uint8_t *data, size_t data_len)
{
    uint64_t value = 0U;
    size_t index = 0U;

    if ((data != NULL) && (data_len >= 8U))
    {
        for (index = 0U; index < 8U; index++)
        {
            value = (value << 8U) | (uint64_t)data[index];
        }
    }

    return value;
}

static void gossipsub_interop_log_message(const libp2p_gossipsub_event_t *event)
{
    char timestamp[40];
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    size_t peer_text_len = 0U;
    uint64_t message_id = 0U;

    gossipsub_interop_timestamp(timestamp, sizeof(timestamp));
    message_id =
        gossipsub_interop_message_id_from_bytes(event->message.data.data, event->message.data.len);
    (void)printf(
        "{\"time\":\"%s\",\"level\":\"INFO\",\"msg\":\"Received "
        "Message\",\"service\":\"gossipsub\",",
        timestamp);
    if (libp2p_peer_id_to_string(
            event->peer.data,
            event->peer.len,
            peer_text,
            sizeof(peer_text),
            &peer_text_len) == LIBP2P_PEER_ID_OK)
    {
        (void)printf("\"from\":\"");
        gossipsub_interop_json_escape(stdout, peer_text, peer_text_len);
        (void)printf("\",");
    }
    (void)printf("\"topic\":\"");
    gossipsub_interop_json_escape(stdout, (const char *)event->topic.data, event->topic.len);
    (void)printf("\",\"id\":\"%llu\"}\n", (unsigned long long)message_id);
    (void)fflush(stdout);
}

static const char *gossipsub_interop_event_name(libp2p_gossipsub_event_type_t type)
{
    const char *result = "unknown";

    switch (type)
    {
    case LIBP2P_GOSSIPSUB_EVENT_PEER_OPENED:
        result = "peer_opened";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED:
        result = "peer_closed";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_PEER_FAILED:
        result = "peer_failed";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_SUBSCRIPTION:
        result = "subscription";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_MESSAGE:
        result = "message";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_IDONTWANT:
        result = "idontwant";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_DROPPED:
        result = "dropped";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_ERROR:
        result = "error";
        break;
    case LIBP2P_GOSSIPSUB_EVENT_NONE:
    default:
        result = "none";
        break;
    }

    return result;
}

static void gossipsub_interop_trace_event(const libp2p_gossipsub_event_t *event)
{
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    size_t peer_text_len = 0U;
    uint64_t message_id = 0U;

    if ((event != NULL) && (gossipsub_interop_trace_enabled() != 0U))
    {
        if ((event->peer.len != 0U) && (libp2p_peer_id_to_string(
                                            event->peer.data,
                                            event->peer.len,
                                            peer_text,
                                            sizeof(peer_text),
                                            &peer_text_len) != LIBP2P_PEER_ID_OK))
        {
            peer_text_len = 0U;
        }
        if ((event->message.data.data != NULL) && (event->message.data.len >= 8U))
        {
            message_id = gossipsub_interop_message_id_from_bytes(
                event->message.data.data,
                event->message.data.len);
        }

        (void)fprintf(
            stderr,
            "c-lean-gossipsub: event=%s type=%u peer=\"",
            gossipsub_interop_event_name(event->type),
            (unsigned int)event->type);
        if (peer_text_len != 0U)
        {
            gossipsub_interop_json_escape(stderr, peer_text, peer_text_len);
        }
        (void)fprintf(stderr, "\" topic=\"");
        if ((event->topic.data != NULL) && (event->topic.len != 0U))
        {
            gossipsub_interop_json_escape(
                stderr,
                (const char *)event->topic.data,
                event->topic.len);
        }
        (void)fprintf(
            stderr,
            "\" message_id=%llu drop=%u reason=%u version=%u direction=%u validation=%u\n",
            (unsigned long long)message_id,
            (unsigned int)event->drop_reason,
            (unsigned int)event->reason,
            (unsigned int)event->protocol_version,
            (unsigned int)event->direction,
            (event->validation != NULL) ? 1U : 0U);
        (void)fflush(stderr);
    }
}

static const char *gossipsub_interop_identify_event_name(libp2p_identify_event_type_t type)
{
    const char *result = "none";

    switch (type)
    {
    case LIBP2P_IDENTIFY_EVENT_RECEIVED:
        result = "received";
        break;
    case LIBP2P_IDENTIFY_EVENT_SENT:
        result = "sent";
        break;
    case LIBP2P_IDENTIFY_EVENT_CLOSED:
        result = "closed";
        break;
    case LIBP2P_IDENTIFY_EVENT_ERROR:
        result = "error";
        break;
    case LIBP2P_IDENTIFY_EVENT_NONE:
    default:
        result = "none";
        break;
    }

    return result;
}

static void gossipsub_interop_trace_identify_event(const libp2p_identify_event_t *event)
{
    if ((event != NULL) && (gossipsub_interop_trace_enabled() != 0U))
    {
        (void)fprintf(
            stderr,
            "c-lean-identify: event=%s type=%u direction=%u reason=%u protocols=%zu "
            "listen_addrs=%zu public_key_bytes=%zu\n",
            gossipsub_interop_identify_event_name(event->type),
            (unsigned int)event->type,
            (unsigned int)event->direction,
            (unsigned int)event->reason,
            event->message.protocol_count,
            event->message.listen_addr_count,
            event->message.public_key.len);
        (void)fflush(stderr);
    }
}

static libp2p_gossipsub_err_t gossipsub_interop_message_id_fn(
    const libp2p_gossipsub_message_t *message,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    void *user_data)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;
    size_t index = 0U;

    (void)user_data;
    if ((message == NULL) || (written == NULL) || (message->data.len < 8U))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        *written = 8U;
        if (out_len < 8U)
        {
            result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
        }
        else if (out == NULL)
        {
            result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
        }
        else
        {
            for (index = 0U; index < 8U; index++)
            {
                out[index] = message->data.data[index];
            }
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_configure_identify(
    gossipsub_interop_app_t *app,
    size_t protocol_index)
{
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (protocol_index >= GOSSIPSUB_INTEROP_PROTOCOLS))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_identify_config_default(&app->identify_config) != LIBP2P_IDENTIFY_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        app->identify_config.local_message.protocol_version.data = g_identify_protocol_version;
        app->identify_config.local_message.protocol_version.len =
            sizeof(g_identify_protocol_version);
        app->identify_config.local_message.agent_version.data = g_identify_agent_version;
        app->identify_config.local_message.agent_version.len = sizeof(g_identify_agent_version);
        app->identify_config.local_message.public_key.data =
            app->identity.host_storage.public_key_message;
        app->identify_config.local_message.public_key.len =
            app->identity.host_storage.public_key_message_len;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_identify_init(&app->identify, &app->identify_config) != LIBP2P_IDENTIFY_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_identify_protocol(&app->identify, &app->protocols[protocol_index]) !=
         LIBP2P_IDENTIFY_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_configure_gossipsub(gossipsub_interop_app_t *app)
{
    size_t storage_len = 0U;
    size_t protocol_count = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_gossipsub_config_default(&app->gossipsub_config) != LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        app->gossipsub_config.mesh.d = GOSSIPSUB_INTEROP_REF_D;
        app->gossipsub_config.mesh.d_low = GOSSIPSUB_INTEROP_REF_D_LOW;
        app->gossipsub_config.mesh.d_high = GOSSIPSUB_INTEROP_REF_D_HIGH;
        app->gossipsub_config.mesh.d_lazy = GOSSIPSUB_INTEROP_REF_D_LAZY;
        app->gossipsub_config.mesh.heartbeat_interval_us = GOSSIPSUB_INTEROP_REF_HEARTBEAT_US;
        app->gossipsub_config.random_fn = gossipsub_interop_random;
        app->gossipsub_config.random_user_data = NULL;
        app->gossipsub_config.message_id_fn = gossipsub_interop_message_id_fn;
        app->gossipsub_config.message_id_user_data = NULL;
        app->gossipsub_config.capacity.max_topics = 16U;
        app->gossipsub_config.capacity.max_peers = 64U;
        app->gossipsub_config.capacity.max_peer_topics = 512U;
        app->gossipsub_config.capacity.max_mesh_edges = 512U;
        app->gossipsub_config.capacity.max_fanout_edges = 256U;
        app->gossipsub_config.capacity.max_backoff_entries = 512U;
        app->gossipsub_config.capacity.max_streams = 64U;
        app->gossipsub_config.capacity.max_pending_opens = 64U;
        app->gossipsub_config.capacity.max_tx_rpc_queue = 512U;
        app->gossipsub_config.capacity.tx_buffer_bytes = 4194304U;
        app->gossipsub_config.capacity.mcache_slots = 256U;
        app->gossipsub_config.capacity.mcache_bytes = 4194304U;
        app->gossipsub_config.capacity.seen_entries = 2048U;
        app->gossipsub_config.capacity.pending_validations = 256U;
        app->gossipsub_config.capacity.idontwant_entries = 1024U;
        app->gossipsub_config.capacity.event_capacity = 512U;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_gossipsub_storage_size(&app->gossipsub_config, &storage_len) !=
         LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (storage_len > sizeof(g_router_storage.bytes)))
    {
        (void)fprintf(
            stderr,
            "gossipsub storage required=%zu capacity=%zu\n",
            storage_len,
            sizeof(g_router_storage.bytes));
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_gossipsub_init(
                                                 g_router_storage.bytes,
                                                 sizeof(g_router_storage.bytes),
                                                 &app->gossipsub_config,
                                                 &app->gossipsub) != LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_gossipsub_protocols(
                                                 app->gossipsub,
                                                 app->protocols,
                                                 GOSSIPSUB_INTEROP_GOSSIPSUB_PROTOCOLS,
                                                 &protocol_count) != LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (protocol_count != GOSSIPSUB_INTEROP_GOSSIPSUB_PROTOCOLS))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_configure_identify(app, protocol_count);
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_configure_host(gossipsub_interop_app_t *app)
{
    char listen_text[80];
    int text_len = 0;
    size_t storage_len = 0U;
    size_t index = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        text_len = snprintf(
            listen_text,
            sizeof(listen_text),
            "/ip4/0.0.0.0/udp/%u/quic-v1",
            (unsigned int)GOSSIPSUB_INTEROP_LISTEN_PORT);
        if ((text_len <= 0) || ((size_t)text_len >= sizeof(listen_text)))
        {
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_multiaddr_from_string(
             listen_text,
             (size_t)text_len,
             app->listen_multiaddr,
             sizeof(app->listen_multiaddr),
             &app->listen_multiaddr_len) != LIBP2P_MULTIADDR_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_quic_service_config_default(&app->quic_config) != LIBP2P_QUIC_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        app->quic_config.endpoint.role = LIBP2P_QUIC_ROLE_CLIENT_SERVER;
        app->quic_config.endpoint.identity = app->identity.quic;
        app->quic_config.endpoint.allocator = gossipsub_interop_backend_allocator();
        app->quic_config.endpoint.random_fn = gossipsub_interop_quic_random;
        app->quic_config.endpoint.random_user_data = NULL;
        app->quic_config.endpoint.unix_time_fn = gossipsub_interop_unix_time;
        app->quic_config.endpoint.unix_time_user_data = NULL;
        if (gossipsub_interop_env_enabled("LIBP2P_QUIC_DEBUG") != 0U)
        {
            app->quic_config.endpoint.debug_fn = gossipsub_interop_quic_debug;
            app->quic_config.endpoint.debug_user_data = app;
        }
        app->quic_config.endpoint.max_connections = 64U;
        app->quic_config.endpoint.max_incoming_connections = 64U;
        app->quic_config.endpoint.max_outgoing_connections = 64U;
        app->quic_config.endpoint.max_bidi_streams = 64U;
        app->quic_config.endpoint.idle_timeout_us = UINT64_C(120000000);
        app->quic_config.endpoint.handshake_timeout_us = UINT64_C(10000000);
        app->quic_config.max_rx_datagrams_per_drive = 256U;
        app->quic_config.max_tx_datagrams_per_drive = 256U;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_host_config_default(&app->host_config) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        app->host_config.identity = app->identity.host;
        app->host_config.listen_multiaddr = app->listen_multiaddr;
        app->host_config.listen_multiaddr_len = app->listen_multiaddr_len;
        app->host_config.transport = libp2p_host_quic_transport();
        app->host_config.transport_config = &app->quic_config;
        app->host_config.max_protocols = GOSSIPSUB_INTEROP_PROTOCOLS;
        app->host_config.max_connections = 64U;
        app->host_config.max_streams_per_conn = 64U;
        app->host_config.max_pending_dials = 64U;
        app->host_config.max_pending_stream_opens = 64U;
        app->host_config.event_capacity = 512U;
        app->host_config.max_negotiation_steps = 256U;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_host_storage_size(&app->host_config, &storage_len) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (storage_len > sizeof(g_host_storage.bytes)))
    {
        (void)fprintf(
            stderr,
            "host storage required=%zu capacity=%zu\n",
            storage_len,
            sizeof(g_host_storage.bytes));
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_host_init(
                                                 g_host_storage.bytes,
                                                 sizeof(g_host_storage.bytes),
                                                 &app->host_config,
                                                 &app->host) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    for (index = 0U; (result == GOSSIPSUB_INTEROP_OK) && (index < GOSSIPSUB_INTEROP_PROTOCOLS);
         index++)
    {
        if (libp2p_host_handle(app->host, &app->protocols[index]) != LIBP2P_HOST_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_host_start(app->host) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_gossipsub_start(app->gossipsub, app->host, gossipsub_interop_now_us()) !=
         LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_parse_node_id(int *out_node_id)
{
    const char *env_node_id = getenv("GOSSIPSUB_INTEROP_NODE_ID");
    char hostname[GOSSIPSUB_INTEROP_HOSTNAME_BYTES];
    int parsed = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (out_node_id == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if ((env_node_id != NULL) && (sscanf(env_node_id, "%d", &parsed) == 1))
    {
        *out_node_id = parsed;
    }
    else if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        result = GOSSIPSUB_INTEROP_ERR_IO;
    }
    else
    {
        hostname[sizeof(hostname) - 1U] = '\0';
        if (sscanf(hostname, "node%d", &parsed) != 1)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
        else
        {
            *out_node_id = parsed;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_target_peer_id(
    int node_id,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t private_key[LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES];
    uint8_t public_key[LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES];
    size_t public_key_len = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((out == NULL) || (written == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_make_node_private_key(node_id, private_key);
        if (libp2p_peer_id_public_key_from_private_key(
                private_key,
                sizeof(private_key),
                1,
                public_key,
                sizeof(public_key),
                &public_key_len) != LIBP2P_PEER_ID_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_peer_id_from_secp256k1_public_key(
                                                 public_key,
                                                 public_key_len,
                                                 out,
                                                 out_len,
                                                 written) != LIBP2P_PEER_ID_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
    }
    (void)memset(private_key, 0, sizeof(private_key));

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_target_peer_text(
    int node_id,
    char *out,
    size_t out_len,
    size_t *written)
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((out == NULL) || (written == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_target_peer_id(node_id, peer_id, sizeof(peer_id), &peer_id_len);
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_peer_id_to_string(peer_id, peer_id_len, out, out_len, written) !=
         LIBP2P_PEER_ID_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (*written < out_len))
    {
        out[*written] = '\0';
    }
    else if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_resolve_node_ip(
    int node_id,
    char *out,
    size_t out_len)
{
    char hostname[GOSSIPSUB_INTEROP_HOSTNAME_BYTES];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    const struct sockaddr_in *addr4 = NULL;
    int text_len = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((out == NULL) || (out_len == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        text_len = snprintf(hostname, sizeof(hostname), "node%d", node_id);
        if ((text_len <= 0) || ((size_t)text_len >= sizeof(hostname)))
        {
            result = GOSSIPSUB_INTEROP_ERR_LIMIT;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        (void)memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        if ((res == NULL) || (res->ai_addr == NULL) ||
            (res->ai_addrlen < sizeof(struct sockaddr_in)))
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
        else
        {
            addr4 = (const struct sockaddr_in *)res->ai_addr;
            if (inet_ntop(AF_INET, &addr4->sin_addr, out, (socklen_t)out_len) == NULL)
            {
                result = GOSSIPSUB_INTEROP_ERR_IO;
            }
        }
    }
    if (res != NULL)
    {
        freeaddrinfo(res);
    }

    return result;
}

static uint8_t gossipsub_interop_peer_id_equal(
    const uint8_t *left,
    size_t left_len,
    const uint8_t *right,
    size_t right_len)
{
    uint8_t result = 0U;

    if ((left != NULL) && (right != NULL) && (left_len == right_len) &&
        (memcmp(left, right, left_len) == 0))
    {
        result = 1U;
    }

    return result;
}

static uint8_t gossipsub_interop_peer_connected(
    const gossipsub_interop_app_t *app,
    const uint8_t *peer_id,
    size_t peer_id_len)
{
    size_t index = 0U;
    uint8_t result = 0U;

    if ((app != NULL) && (peer_id != NULL))
    {
        for (index = 0U; (result == 0U) && (index < app->connected_peer_count); index++)
        {
            result = gossipsub_interop_peer_id_equal(
                app->connected_peer_ids[index],
                app->connected_peer_id_lens[index],
                peer_id,
                peer_id_len);
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_remember_peer(
    gossipsub_interop_app_t *app,
    libp2p_host_conn_t *conn)
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (conn == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if (
        libp2p_host_conn_peer_id(conn, peer_id, sizeof(peer_id), &peer_id_len) != LIBP2P_HOST_OK)
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    else if (gossipsub_interop_peer_connected(app, peer_id, peer_id_len) != 0U)
    {
        result = GOSSIPSUB_INTEROP_OK;
    }
    else if (app->connected_peer_count >= GOSSIPSUB_INTEROP_MAX_CONNECTED_PEERS)
    {
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }
    else
    {
        (void)memcpy(app->connected_peer_ids[app->connected_peer_count], peer_id, peer_id_len);
        app->connected_peer_id_lens[app->connected_peer_count] = peer_id_len;
        app->connected_peer_count++;
    }

    return result;
}

static uint8_t gossipsub_interop_conn_matches_connect(
    const gossipsub_interop_app_t *app,
    const libp2p_host_conn_t *conn)
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    uint8_t result = 0U;

    if ((app != NULL) && (conn != NULL) && (app->connect_peer_id_len != 0U) &&
        (libp2p_host_conn_peer_id(conn, peer_id, sizeof(peer_id), &peer_id_len) == LIBP2P_HOST_OK))
    {
        result = gossipsub_interop_peer_id_equal(
            peer_id,
            peer_id_len,
            app->connect_peer_id,
            app->connect_peer_id_len);
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_dial_node(
    gossipsub_interop_app_t *app,
    int node_id)
{
    char ip_text[GOSSIPSUB_INTEROP_IP_TEXT_BYTES];
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    char multiaddr_text[GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES];
    uint8_t multiaddr[GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len = 0U;
    size_t peer_text_len = 0U;
    size_t multiaddr_len = 0U;
    size_t attempt = 0U;
    int text_len = 0;
    libp2p_host_dial_t *dial = NULL;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_resolve_node_ip(node_id, ip_text, sizeof(ip_text));
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_target_peer_id(node_id, peer_id, sizeof(peer_id), &peer_id_len);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_target_peer_text(
            node_id,
            peer_text,
            sizeof(peer_text),
            &peer_text_len);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        text_len = snprintf(
            multiaddr_text,
            sizeof(multiaddr_text),
            "/ip4/%s/udp/%u/quic-v1/p2p/%s",
            ip_text,
            (unsigned int)GOSSIPSUB_INTEROP_LISTEN_PORT,
            peer_text);
        if ((text_len <= 0) || ((size_t)text_len >= sizeof(multiaddr_text)))
        {
            result = GOSSIPSUB_INTEROP_ERR_LIMIT;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_multiaddr_from_string(
                                                 multiaddr_text,
                                                 (size_t)text_len,
                                                 multiaddr,
                                                 sizeof(multiaddr),
                                                 &multiaddr_len) != LIBP2P_MULTIADDR_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) &&
           (gossipsub_interop_peer_connected(app, peer_id, peer_id_len) == 0U) &&
           (attempt < GOSSIPSUB_INTEROP_CONNECT_ATTEMPTS))
    {
        const uint64_t deadline_us =
            gossipsub_interop_now_us() +
            (GOSSIPSUB_INTEROP_CONNECT_TIMEOUT_SECONDS * GOSSIPSUB_INTEROP_USEC_PER_SEC);

        dial = NULL;
        app->connect_dial = NULL;
        app->connect_complete = 0U;
        app->connect_failed = 0U;
        app->connect_peer_id_len = peer_id_len;
        (void)memcpy(app->connect_peer_id, peer_id, peer_id_len);
        gossipsub_interop_debug(app, multiaddr_text);

        if (libp2p_host_dial(app->host, multiaddr, multiaddr_len, NULL, &dial) != LIBP2P_HOST_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
        else
        {
            app->connect_dial = dial;
        }
        while ((result == GOSSIPSUB_INTEROP_OK) && (app->connect_complete == 0U) &&
               (app->connect_failed == 0U) && (g_stop_requested == 0) &&
               (gossipsub_interop_now_us() < deadline_us))
        {
            result = gossipsub_interop_drive_once(app);
        }
        if ((result == GOSSIPSUB_INTEROP_OK) &&
            (gossipsub_interop_peer_connected(app, peer_id, peer_id_len) != 0U))
        {
            app->connect_complete = 1U;
        }
        if ((result == GOSSIPSUB_INTEROP_OK) && (app->connect_complete == 0U))
        {
            if ((app->connect_failed != 0U) &&
                ((attempt + 1U) < GOSSIPSUB_INTEROP_CONNECT_ATTEMPTS))
            {
                result = GOSSIPSUB_INTEROP_OK;
            }
            else
            {
                result = GOSSIPSUB_INTEROP_ERR_HOST;
            }
        }
        app->connect_dial = NULL;
        app->connect_peer_id_len = 0U;
        app->connect_failed = 0U;
        app->connect_complete = 0U;
        attempt++;
    }

    return result;
}

static uint64_t gossipsub_interop_topic_delay(
    const gossipsub_interop_app_t *app,
    const uint8_t *topic,
    size_t topic_len)
{
    size_t index = 0U;
    uint64_t result = 0U;

    if ((app != NULL) && (topic != NULL))
    {
        for (index = 0U; index < app->validation_topic_count; index++)
        {
            if ((app->validation_topics[index].topic_len == topic_len) &&
                (memcmp(app->validation_topics[index].topic, topic, topic_len) == 0))
            {
                result = app->validation_topics[index].delay_us;
            }
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_set_validation_delay(
    gossipsub_interop_app_t *app,
    const gossipsub_interop_instruction_t *instruction)
{
    size_t index = 0U;
    size_t slot = 0U;
    uint8_t found = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (instruction == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    for (index = 0U; (result == GOSSIPSUB_INTEROP_OK) && (index < app->validation_topic_count);
         index++)
    {
        if ((app->validation_topics[index].topic_len == instruction->topic_len) &&
            (memcmp(
                 app->validation_topics[index].topic,
                 instruction->topic,
                 instruction->topic_len) == 0))
        {
            slot = index;
            found = 1U;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (found == 0U))
    {
        if (app->validation_topic_count >= GOSSIPSUB_INTEROP_MAX_VALIDATION_TOPICS)
        {
            result = GOSSIPSUB_INTEROP_ERR_LIMIT;
        }
        else
        {
            slot = app->validation_topic_count;
            app->validation_topic_count++;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        (void)
            memcpy(app->validation_topics[slot].topic, instruction->topic, instruction->topic_len);
        app->validation_topics[slot].topic[instruction->topic_len] = '\0';
        app->validation_topics[slot].topic_len = instruction->topic_len;
        app->validation_topics[slot].delay_us = instruction->delay_us;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_subscribe(
    gossipsub_interop_app_t *app,
    const gossipsub_interop_instruction_t *instruction)
{
    libp2p_gossipsub_topic_config_t topic;
    uint64_t delay_us = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (instruction == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        delay_us = gossipsub_interop_topic_delay(
            app,
            (const uint8_t *)instruction->topic,
            instruction->topic_len);
        topic.topic.data = (const uint8_t *)instruction->topic;
        topic.topic.len = instruction->topic_len;
        topic.validation_mode = (delay_us == 0U) ? LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT_ALL
                                                 : LIBP2P_GOSSIPSUB_VALIDATION_REQUIRE_APP;
        topic.enable_idontwant = 1U;
        topic.idontwant_min_message_bytes = LIBP2P_GOSSIPSUB_DEFAULT_IDONTWANT_MIN_BYTES;
        if (libp2p_gossipsub_subscribe(app->gossipsub, &topic) != LIBP2P_GOSSIPSUB_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_publish(
    gossipsub_interop_app_t *app,
    const gossipsub_interop_instruction_t *instruction)
{
    libp2p_gossipsub_publish_t publish;
    uint64_t value = 0U;
    size_t index = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (instruction == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if (
        (instruction->message_size_bytes < 8U) ||
        (instruction->message_size_bytes > sizeof(g_publish_buffer)))
    {
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }
    else
    {
        (void)memset(g_publish_buffer, 0, instruction->message_size_bytes);
        value = instruction->message_id;
        for (index = 0U; index < 8U; index++)
        {
            g_publish_buffer[7U - index] = (uint8_t)(value & 0xFFU);
            value >>= 8U;
        }
        publish.topic.data = (const uint8_t *)instruction->topic;
        publish.topic.len = instruction->topic_len;
        publish.data.data = g_publish_buffer;
        publish.data.len = instruction->message_size_bytes;
        publish.message_id.data = NULL;
        publish.message_id.len = 0U;
        publish.user_data = NULL;
        if (gossipsub_interop_trace_enabled() != 0U)
        {
            (void)fprintf(
                stderr,
                "c-lean-gossipsub: publish message_id=%llu topic=\"",
                (unsigned long long)instruction->message_id);
            gossipsub_interop_json_escape(
                stderr,
                (const char *)instruction->topic,
                instruction->topic_len);
            (void)fprintf(stderr, "\" bytes=%zu\n", instruction->message_size_bytes);
            (void)fflush(stderr);
        }
        if (libp2p_gossipsub_publish(app->gossipsub, &publish, NULL, 0U, NULL) !=
            LIBP2P_GOSSIPSUB_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_queue_validation(
    gossipsub_interop_app_t *app,
    libp2p_gossipsub_validation_t *validation,
    uint64_t delay_us)
{
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (validation == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if (
        app->pending_validation_count >=
        (sizeof(app->pending_validations) / sizeof(app->pending_validations[0])))
    {
        result = GOSSIPSUB_INTEROP_ERR_LIMIT;
    }
    else
    {
        app->pending_validations[app->pending_validation_count].validation = validation;
        app->pending_validations[app->pending_validation_count].due_us =
            gossipsub_interop_now_us() + delay_us;
        app->pending_validation_count++;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_accept_due_validations(
    gossipsub_interop_app_t *app,
    uint64_t now_us)
{
    size_t index = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (index < app->pending_validation_count))
    {
        if (app->pending_validations[index].due_us <= now_us)
        {
            if (libp2p_gossipsub_report_validation(
                    app->gossipsub,
                    app->pending_validations[index].validation,
                    LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT) != LIBP2P_GOSSIPSUB_OK)
            {
                result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
            }
            else
            {
                app->pending_validations[index] =
                    app->pending_validations[app->pending_validation_count - 1U];
                app->pending_validation_count--;
            }
        }
        else
        {
            index++;
        }
    }

    return result;
}

static int gossipsub_interop_deadline_timeout_ms(
    uint64_t deadline_us,
    uint64_t now_us,
    int current_timeout_ms)
{
    uint64_t delta_us = 0U;
    uint64_t delta_ms = 0U;
    int result = current_timeout_ms;

    if (deadline_us <= now_us)
    {
        result = 0;
    }
    else
    {
        delta_us = deadline_us - now_us;
        delta_ms = delta_us / GOSSIPSUB_INTEROP_USEC_PER_MSEC;
        if ((delta_us % GOSSIPSUB_INTEROP_USEC_PER_MSEC) != 0U)
        {
            delta_ms++;
        }
        if (delta_ms < (uint64_t)result)
        {
            result = (int)delta_ms;
        }
    }

    return result;
}

static int gossipsub_interop_poll_timeout_ms(const gossipsub_interop_app_t *app, uint64_t now_us)
{
    uint64_t deadline = 0U;
    size_t index = 0U;
    int result = GOSSIPSUB_INTEROP_POLL_MAX_MS;

    if ((app != NULL) && (libp2p_host_next_deadline(app->host, &deadline) == LIBP2P_HOST_OK))
    {
        result = gossipsub_interop_deadline_timeout_ms(deadline, now_us, result);
    }
    if ((app != NULL) &&
        (libp2p_gossipsub_next_deadline(app->gossipsub, &deadline) == LIBP2P_GOSSIPSUB_OK))
    {
        result = gossipsub_interop_deadline_timeout_ms(deadline, now_us, result);
    }
    if (app != NULL)
    {
        for (index = 0U; index < app->pending_validation_count; index++)
        {
            deadline = app->pending_validations[index].due_us;
            result = gossipsub_interop_deadline_timeout_ms(deadline, now_us, result);
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_drain_host_events(gossipsub_interop_app_t *app)
{
    libp2p_host_event_t event;
    libp2p_host_stream_open_t *open = NULL;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) &&
           (libp2p_host_next_event(app->host, &event) == LIBP2P_HOST_OK))
    {
        if (libp2p_gossipsub_handle_host_event(app->gossipsub, app->host, &event) !=
            LIBP2P_GOSSIPSUB_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
        }
        else if (event.type == LIBP2P_HOST_EVENT_CONN_ESTABLISHED)
        {
            result = gossipsub_interop_remember_peer(app, event.conn);
            if ((result == GOSSIPSUB_INTEROP_OK) &&
                ((event.dial == app->connect_dial) ||
                 (gossipsub_interop_conn_matches_connect(app, event.conn) != 0U)))
            {
                app->connect_complete = 1U;
            }
            (void)libp2p_gossipsub_open_peer(
                app->gossipsub,
                app->host,
                event.conn,
                LIBP2P_GOSSIPSUB_VERSION_NONE,
                NULL,
                &open);
        }
        else if (
            (event.type == LIBP2P_HOST_EVENT_DIAL_FAILED) ||
            (event.type == LIBP2P_HOST_EVENT_STREAM_OPEN_FAILED))
        {
            (void)fprintf(
                stderr,
                "host event failure type=%u reason=%u app=%llu transport=%llu\n",
                (unsigned int)event.type,
                (unsigned int)event.reason,
                (unsigned long long)event.app_error_code,
                (unsigned long long)event.transport_error_code);
            if ((event.type == LIBP2P_HOST_EVENT_DIAL_FAILED) && (app->connect_dial != NULL) &&
                (event.dial == app->connect_dial))
            {
                app->connect_failed = 1U;
            }
            result = GOSSIPSUB_INTEROP_OK;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_OK;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_drain_identify_events(
    gossipsub_interop_app_t *app)
{
    libp2p_identify_event_t event;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) &&
           (libp2p_identify_next_event(&app->identify, &event) == LIBP2P_IDENTIFY_OK))
    {
        gossipsub_interop_trace_identify_event(&event);
        if (event.type == LIBP2P_IDENTIFY_EVENT_ERROR)
        {
            (void)fprintf(
                stderr,
                "identify event failure type=%u reason=%u\n",
                (unsigned int)event.type,
                (unsigned int)event.reason);
            (void)fflush(stderr);
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_drain_gossipsub_events(
    gossipsub_interop_app_t *app)
{
    libp2p_gossipsub_event_t event;
    uint64_t delay_us = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) &&
           (libp2p_gossipsub_next_event(app->gossipsub, &event) == LIBP2P_GOSSIPSUB_OK))
    {
        gossipsub_interop_trace_event(&event);
        if (event.type == LIBP2P_GOSSIPSUB_EVENT_MESSAGE)
        {
            gossipsub_interop_log_message(&event);
            if (event.validation != NULL)
            {
                delay_us = gossipsub_interop_topic_delay(app, event.topic.data, event.topic.len);
                result = gossipsub_interop_queue_validation(app, event.validation, delay_us);
            }
        }
        else if (event.type == LIBP2P_GOSSIPSUB_EVENT_PEER_CLOSED)
        {
            gossipsub_interop_autopsy_dump_peers(
                app,
                "peer_closed",
                gossipsub_interop_now_us());
            gossipsub_interop_autopsy_dump_quic(app, "peer_closed", gossipsub_interop_now_us());
        }
        else if (
            (event.type == LIBP2P_GOSSIPSUB_EVENT_ERROR) ||
            (event.type == LIBP2P_GOSSIPSUB_EVENT_PEER_FAILED))
        {
            (void)fprintf(
                stderr,
                "gossipsub event failure type=%u reason=%u\n",
                (unsigned int)event.type,
                (unsigned int)event.reason);
            result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_OK;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_drive_once(gossipsub_interop_app_t *app)
{
    libp2p_host_fd_t host_fd = 0U;
    libp2p_host_interest_t interest = LIBP2P_HOST_INTEREST_NONE;
    libp2p_host_ready_t ready = LIBP2P_HOST_READY_APP | LIBP2P_HOST_READY_TIMER;
    libp2p_host_drive_result_t host_drive_result;
    libp2p_gossipsub_drive_result_t gossipsub_drive_result;
    libp2p_host_err_t host_err = LIBP2P_HOST_OK;
    libp2p_gossipsub_err_t gossipsub_err = LIBP2P_GOSSIPSUB_OK;
    struct pollfd pfd;
    uint64_t now_us = 0U;
    int poll_result = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        host_err = libp2p_host_fd(app->host, &host_fd);
        if (host_err != LIBP2P_HOST_OK)
        {
            (void)fprintf(stderr, "host fd failed err=%u\n", (unsigned int)host_err);
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (host_fd > (libp2p_host_fd_t)INT_MAX))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        host_err = libp2p_host_io_interest(app->host, &interest);
        if (host_err != LIBP2P_HOST_OK)
        {
            (void)fprintf(stderr, "host interest failed err=%u\n", (unsigned int)host_err);
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        now_us = gossipsub_interop_now_us();
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
        poll_result = poll(&pfd, 1U, gossipsub_interop_poll_timeout_ms(app, now_us));
        if (poll_result < 0)
        {
            if (errno != EINTR)
            {
                (void)fprintf(stderr, "host poll failed errno=%d\n", errno);
                result = GOSSIPSUB_INTEROP_ERR_HOST;
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
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        (void)memset(&host_drive_result, 0, sizeof(host_drive_result));
        host_err =
            libp2p_host_drive(app->host, gossipsub_interop_now_us(), ready, &host_drive_result);
        if (host_err != LIBP2P_HOST_OK)
        {
            (void)fprintf(
                stderr,
                "host drive failed err=%u ready=%u interest=%u revents=%d "
                "transport_events=%zu negotiation_steps=%zu protocol_events=%zu "
                "host_events=%zu progress=%u\n",
                (unsigned int)host_err,
                (unsigned int)ready,
                (unsigned int)interest,
                (int)pfd.revents,
                host_drive_result.transport_events,
                host_drive_result.negotiation_steps,
                host_drive_result.protocol_events,
                host_drive_result.host_events,
                (unsigned int)host_drive_result.made_progress);
            result = GOSSIPSUB_INTEROP_ERR_HOST;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_drain_host_events(app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_drain_identify_events(app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        (void)memset(&gossipsub_drive_result, 0, sizeof(gossipsub_drive_result));
        gossipsub_err = libp2p_gossipsub_drive(
            app->gossipsub,
            app->host,
            gossipsub_interop_now_us(),
            &gossipsub_drive_result);
        if (gossipsub_err != LIBP2P_GOSSIPSUB_OK)
        {
            (void)fprintf(
                stderr,
                "gossipsub drive failed err=%u heartbeats=%zu encoded=%zu sent=%zu "
                "forwarded=%zu controls=%zu expired=%zu progress=%u\n",
                (unsigned int)gossipsub_err,
                gossipsub_drive_result.heartbeats,
                gossipsub_drive_result.rpcs_encoded,
                gossipsub_drive_result.rpcs_sent,
                gossipsub_drive_result.messages_forwarded,
                gossipsub_drive_result.controls_enqueued,
                gossipsub_drive_result.validations_expired,
                (unsigned int)gossipsub_drive_result.made_progress);
            result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
        }
        else if (gossipsub_drive_result.made_progress != 0U)
        {
            gossipsub_interop_trace_tx_peers(app, gossipsub_interop_now_us());
        }
        else
        {
            result = GOSSIPSUB_INTEROP_OK;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_accept_due_validations(app, gossipsub_interop_now_us());
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_drain_gossipsub_events(app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_autopsy_tick(app, gossipsub_interop_now_us());
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_wait_until(
    gossipsub_interop_app_t *app,
    uint64_t elapsed_seconds)
{
    const uint64_t target = app->start_us + (elapsed_seconds * GOSSIPSUB_INTEROP_USEC_PER_SEC);
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    while ((result == GOSSIPSUB_INTEROP_OK) && (g_stop_requested == 0) &&
           (gossipsub_interop_now_us() < target))
    {
        result = gossipsub_interop_drive_once(app);
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_handle_instruction(
    gossipsub_interop_app_t *app,
    const gossipsub_interop_instruction_t *instruction)
{
    size_t index = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (instruction == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_INIT)
    {
        result = GOSSIPSUB_INTEROP_OK;
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_CONNECT)
    {
        for (index = 0U; (result == GOSSIPSUB_INTEROP_OK) && (index < instruction->connect_count);
             index++)
        {
            result = gossipsub_interop_dial_node(app, instruction->connect_to[index]);
        }
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_WAIT_UNTIL)
    {
        result = gossipsub_interop_wait_until(app, instruction->elapsed_seconds);
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_SET_VALIDATION_DELAY)
    {
        result = gossipsub_interop_set_validation_delay(app, instruction);
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_SUBSCRIBE)
    {
        result = gossipsub_interop_subscribe(app, instruction);
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_PUBLISH)
    {
        result = gossipsub_interop_publish(app, instruction);
    }
    else if (instruction->type == GOSSIPSUB_INTEROP_INSTRUCTION_PARTIAL_UNSUPPORTED)
    {
        result = GOSSIPSUB_INTEROP_ERR_UNSUPPORTED;
    }
    else
    {
        result = GOSSIPSUB_INTEROP_ERR_UNSUPPORTED;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_parse_args(
    int argc,
    char **argv,
    gossipsub_interop_args_t *out_args)
{
    int index = 1;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((argv == NULL) || (out_args == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(out_args, 0, sizeof(*out_args));
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (index < argc))
    {
        if ((strcmp(argv[index], "--params") == 0) && ((index + 1) < argc))
        {
            out_args->params_path = argv[index + 1];
            index += 2;
        }
        else if ((strcmp(argv[index], "--write-identities") == 0) && ((index + 1) < argc))
        {
            out_args->write_identities_dir = argv[index + 1];
            index += 2;
        }
        else if ((strcmp(argv[index], "--node-count") == 0) && ((index + 1) < argc))
        {
            if (sscanf(argv[index + 1], "%d", &out_args->write_identity_count) != 1)
            {
                result = GOSSIPSUB_INTEROP_ERR_USAGE;
            }
            index += 2;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_ERR_USAGE;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (out_args->params_path == NULL) &&
        ((out_args->write_identities_dir == NULL) || (out_args->write_identity_count <= 0)))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (out_args->params_path != NULL) &&
        (out_args->write_identities_dir != NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_write_identities(
    const char *identity_dir,
    int node_count)
{
    gossipsub_interop_identity_t identity;
    char path[GOSSIPSUB_INTEROP_PATH_BYTES];
    int node_id = 0;
    int mkdir_status = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((identity_dir == NULL) || (identity_dir[0] == '\0') || (node_count <= 0))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        mkdir_status = mkdir(identity_dir, 0775);
        if ((mkdir_status != 0) && (errno != EEXIST))
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (node_id < node_count))
    {
        result = gossipsub_interop_identity_init_generated(
            &identity,
            node_id,
            GOSSIPSUB_INTEROP_SHADOW_CERT_UNIX_SECONDS);
        if (result == GOSSIPSUB_INTEROP_OK)
        {
            result =
                gossipsub_interop_identity_path(identity_dir, node_id, "cert", path, sizeof(path));
        }
        if (result == GOSSIPSUB_INTEROP_OK)
        {
            result = gossipsub_interop_write_binary_file(
                path,
                identity.cert,
                identity.quic.certificate_der_len);
        }
        if (result == GOSSIPSUB_INTEROP_OK)
        {
            result =
                gossipsub_interop_identity_path(identity_dir, node_id, "key", path, sizeof(path));
        }
        if (result == GOSSIPSUB_INTEROP_OK)
        {
            result = gossipsub_interop_write_binary_file(
                path,
                identity.cert_key,
                identity.quic.certificate_private_key_der_len);
        }
        (void)memset(&identity, 0, sizeof(identity));
        node_id++;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_app_init(gossipsub_interop_app_t *app)
{
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(app, 0, sizeof(*app));
        app->debug = (getenv("DEBUG") != NULL) ? 1U : 0U;
        app->autopsy = gossipsub_interop_env_enabled("LIBP2P_AUTOPSY");
        gossipsub_autopsy_set_enabled(app->autopsy);
        result = gossipsub_interop_parse_node_id(&app->node_id);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("identity init");
        result = gossipsub_interop_identity_init(&app->identity, app->node_id);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("gossipsub init");
        result = gossipsub_interop_configure_gossipsub(app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("host init");
        result = gossipsub_interop_configure_host(app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        app->start_us = gossipsub_interop_now_us();
        app->next_autopsy_tick_us = app->start_us + GOSSIPSUB_INTEROP_AUTOPSY_TICK_US;
        gossipsub_interop_trace("started");
        gossipsub_interop_log_peer_id(app);
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_interop_run_script(
    gossipsub_interop_app_t *app,
    const char *params_path)
{
    gossipsub_interop_script_t script;
    gossipsub_interop_instruction_t instruction;
    uint8_t has_instruction = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((app == NULL) || (params_path == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_interop_script_load(params_path, &script) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (script.pos < script.script_end) &&
           (g_stop_requested == 0))
    {
        result =
            gossipsub_interop_script_next(&script, app->node_id, &instruction, &has_instruction);
        if ((result == GOSSIPSUB_INTEROP_OK) && (has_instruction != 0U))
        {
            result = gossipsub_interop_handle_instruction(app, &instruction);
        }
        while ((result == GOSSIPSUB_INTEROP_OK) && (has_instruction == 0U) &&
               (script.pos < script.script_end))
        {
            result = gossipsub_interop_script_next(
                &script,
                app->node_id,
                &instruction,
                &has_instruction);
            if ((result == GOSSIPSUB_INTEROP_OK) && (has_instruction != 0U))
            {
                result = gossipsub_interop_handle_instruction(app, &instruction);
            }
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_wait_until(
            app,
            ((gossipsub_interop_now_us() - app->start_us) / GOSSIPSUB_INTEROP_USEC_PER_SEC) + 2U);
    }

    return result;
}

int main(int argc, char **argv)
{
    gossipsub_interop_args_t args;
    gossipsub_interop_app_t app;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;
    uint8_t app_initialized = 0U;

    (void)signal(SIGINT, gossipsub_interop_signal_handler);
    (void)signal(SIGTERM, gossipsub_interop_signal_handler);

    gossipsub_interop_trace("main");
    result = gossipsub_interop_parse_args(argc, argv, &args);
    if ((result == GOSSIPSUB_INTEROP_OK) && (args.write_identities_dir != NULL))
    {
        result = gossipsub_interop_write_identities(
            args.write_identities_dir,
            args.write_identity_count);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        if (args.params_path != NULL)
        {
            gossipsub_interop_trace("app init");
            result = gossipsub_interop_app_init(&app);
            if (result == GOSSIPSUB_INTEROP_OK)
            {
                app_initialized = 1U;
            }
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (args.params_path != NULL))
    {
        result = gossipsub_interop_wait_until(&app, 1U);
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (args.params_path != NULL))
    {
        gossipsub_interop_debug(&app, "starting gossipsub interop script");
        result = gossipsub_interop_run_script(&app, args.params_path);
    }
    if (result != GOSSIPSUB_INTEROP_OK)
    {
        (void)fprintf(stderr, "c-lean-libp2p gossipsub interop failed: %u\n", (unsigned int)result);
    }
    if (app_initialized != 0U)
    {
        gossipsub_interop_autopsy_exit(
            &app,
            (result == GOSSIPSUB_INTEROP_OK) ? "exit" : "error_exit");
    }

    return (result == GOSSIPSUB_INTEROP_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
