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
#include <time.h>
#include <unistd.h>

#include "libp2p/libp2p_host.h"
#include "libp2p/libp2p_host_secp256k1_identity.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id.h"
#include "protocol/gossipsub/gossipsub.h"
#include "transport/quic/quic_identity.h"
#include "transport/quic/quic_service.h"

#define GOSSIPSUB_INTEROP_LISTEN_PORT             9000U
#define GOSSIPSUB_INTEROP_POLL_MAX_MS             50
#define GOSSIPSUB_INTEROP_HOST_STORAGE_BYTES      (16U * 1024U * 1024U)
#define GOSSIPSUB_INTEROP_GOSSIPSUB_STORAGE_BYTES (96U * 1024U * 1024U)
#define GOSSIPSUB_INTEROP_LISTEN_MULTIADDR_BYTES  128U
#define GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES    512U
#define GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES      128U
#define GOSSIPSUB_INTEROP_HOSTNAME_BYTES          64U
#define GOSSIPSUB_INTEROP_IP_TEXT_BYTES           64U
#define GOSSIPSUB_INTEROP_PROTOCOLS               LIBP2P_GOSSIPSUB_PROTOCOL_COUNT
#define GOSSIPSUB_INTEROP_CERT_VALIDITY_SECONDS   UINT64_C(315360000)
#define GOSSIPSUB_INTEROP_CERT_BACKDATE_SECONDS   UINT64_C(3600)
#define GOSSIPSUB_INTEROP_USEC_PER_SEC            UINT64_C(1000000)
#define GOSSIPSUB_INTEROP_USEC_PER_MSEC           UINT64_C(1000)
#define GOSSIPSUB_INTEROP_NSEC_PER_USEC           UINT64_C(1000)

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
    int node_id;
    uint8_t debug;
    uint64_t start_us;
    gossipsub_interop_identity_t identity;
    libp2p_quic_service_config_t quic_config;
    libp2p_host_config_t host_config;
    libp2p_host_protocol_t protocols[GOSSIPSUB_INTEROP_PROTOCOLS];
    libp2p_host_t *host;
    libp2p_gossipsub_config_t gossipsub_config;
    libp2p_gossipsub_t *gossipsub;
    uint8_t listen_multiaddr[GOSSIPSUB_INTEROP_LISTEN_MULTIADDR_BYTES];
    size_t listen_multiaddr_len;
    gossipsub_interop_validation_topic_t validation_topics[GOSSIPSUB_INTEROP_MAX_VALIDATION_TOPICS];
    size_t validation_topic_count;
    gossipsub_interop_pending_validation_t
        pending_validations[LIBP2P_GOSSIPSUB_DEFAULT_PENDING_VALIDATIONS];
    size_t pending_validation_count;
} gossipsub_interop_app_t;

static gossipsub_interop_host_storage_t g_host_storage;
static gossipsub_interop_router_storage_t g_router_storage;
static uint8_t g_publish_buffer[GOSSIPSUB_INTEROP_MAX_MESSAGE_BYTES];
static volatile sig_atomic_t g_stop_requested = 0;

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

static gossipsub_interop_err_t gossipsub_interop_identity_init(
    gossipsub_interop_identity_t *identity,
    int node_id)
{
    libp2p_quic_host_key_t host_key;
    libp2p_quic_certificate_config_t cert_config;
    uint64_t now = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (identity == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        (void)memset(identity, 0, sizeof(*identity));
        gossipsub_interop_make_node_private_key(node_id, identity->private_key);
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_host_secp256k1_identity_init(
                                                 &identity->host_storage,
                                                 identity->private_key,
                                                 sizeof(identity->private_key),
                                                 &identity->host) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_interop_unix_time(&now, NULL) != LIBP2P_QUIC_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        host_key.type = LIBP2P_QUIC_HOST_KEY_SECP256K1;
        host_key.private_key = identity->private_key;
        host_key.private_key_len = sizeof(identity->private_key);
        host_key.public_key_message = identity->host_storage.public_key_message;
        host_key.public_key_message_len = identity->host_storage.public_key_message_len;

        cert_config.certificate_key_type = LIBP2P_QUIC_CERT_KEY_ECDSA_P256;
        cert_config.not_before_unix_seconds = now - GOSSIPSUB_INTEROP_CERT_BACKDATE_SECONDS;
        cert_config.not_after_unix_seconds = now + GOSSIPSUB_INTEROP_CERT_VALIDITY_SECONDS;
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
        identity->quic.certificate_der = identity->cert;
        identity->quic.certificate_private_key_der = identity->cert_key;
        identity->quic.peer_id = identity->host_storage.peer_id;
        identity->quic.peer_id_len = identity->host_storage.peer_id_len;
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

static void gossipsub_interop_trace(const char *message)
{
    if ((message != NULL) && (getenv("C_LEAN_LIBP2P_GOSSIPSUB_TRACE") != NULL))
    {
        (void)fprintf(stderr, "c-lean-gossipsub: %s\n", message);
        (void)fflush(stderr);
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
                                                 GOSSIPSUB_INTEROP_PROTOCOLS,
                                                 &protocol_count) != LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (protocol_count != GOSSIPSUB_INTEROP_PROTOCOLS))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
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

static gossipsub_interop_err_t gossipsub_interop_target_peer_text(
    int node_id,
    char *out,
    size_t out_len,
    size_t *written)
{
    uint8_t private_key[LIBP2P_PEER_ID_SECP256K1_PRIVATE_KEY_BYTES];
    uint8_t public_key[LIBP2P_PEER_ID_SECP256K1_COMPRESSED_PUBLIC_KEY_BYTES];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t public_key_len = 0U;
    size_t peer_id_len = 0U;
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
                                                 peer_id,
                                                 sizeof(peer_id),
                                                 &peer_id_len) != LIBP2P_PEER_ID_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_IDENTITY;
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
    (void)memset(private_key, 0, sizeof(private_key));

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

static gossipsub_interop_err_t gossipsub_interop_dial_node(
    gossipsub_interop_app_t *app,
    int node_id)
{
    char ip_text[GOSSIPSUB_INTEROP_IP_TEXT_BYTES];
    char peer_text[GOSSIPSUB_INTEROP_PEER_ID_TEXT_BYTES];
    char multiaddr_text[GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES];
    uint8_t multiaddr[GOSSIPSUB_INTEROP_DIAL_MULTIADDR_BYTES];
    size_t peer_text_len = 0U;
    size_t multiaddr_len = 0U;
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
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_host_dial(app->host, multiaddr, multiaddr_len, NULL, &dial) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
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

static int gossipsub_interop_poll_timeout_ms(const gossipsub_interop_app_t *app, uint64_t now_us)
{
    uint64_t deadline = 0U;
    size_t index = 0U;
    int result = GOSSIPSUB_INTEROP_POLL_MAX_MS;

    if ((app != NULL) && (libp2p_host_next_deadline(app->host, &deadline) == LIBP2P_HOST_OK))
    {
        if (deadline <= now_us)
        {
            result = 0;
        }
        else if (((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC) < (uint64_t)result)
        {
            result = (int)((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC);
        }
    }
    if ((app != NULL) &&
        (libp2p_gossipsub_next_deadline(app->gossipsub, &deadline) == LIBP2P_GOSSIPSUB_OK))
    {
        if (deadline <= now_us)
        {
            result = 0;
        }
        else if (((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC) < (uint64_t)result)
        {
            result = (int)((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC);
        }
    }
    if (app != NULL)
    {
        for (index = 0U; index < app->pending_validation_count; index++)
        {
            deadline = app->pending_validations[index].due_us;
            if (deadline <= now_us)
            {
                result = 0;
            }
            else if (((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC) < (uint64_t)result)
            {
                result = (int)((deadline - now_us) / GOSSIPSUB_INTEROP_USEC_PER_MSEC);
            }
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
                "host event failure type=%u reason=%u\n",
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
        if (event.type == LIBP2P_GOSSIPSUB_EVENT_MESSAGE)
        {
            gossipsub_interop_log_message(&event);
            if (event.validation != NULL)
            {
                delay_us = gossipsub_interop_topic_delay(app, event.topic.data, event.topic.len);
                result = gossipsub_interop_queue_validation(app, event.validation, delay_us);
            }
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
    struct pollfd pfd;
    uint64_t now_us = 0U;
    int poll_result = 0;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if (app == NULL)
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (libp2p_host_fd(app->host, &host_fd) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (host_fd > (libp2p_host_fd_t)INT_MAX))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_host_io_interest(app->host, &interest) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
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
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_host_drive(app->host, gossipsub_interop_now_us(), ready, NULL) != LIBP2P_HOST_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_HOST;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_drain_host_events(app);
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (libp2p_gossipsub_drive(app->gossipsub, app->host, gossipsub_interop_now_us(), NULL) !=
         LIBP2P_GOSSIPSUB_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PROTOCOL;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_accept_due_validations(app, gossipsub_interop_now_us());
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        result = gossipsub_interop_drain_gossipsub_events(app);
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
    const char **out_params)
{
    int index = 1;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((argv == NULL) || (out_params == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        *out_params = NULL;
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (index < argc))
    {
        if ((strcmp(argv[index], "--params") == 0) && ((index + 1) < argc))
        {
            *out_params = argv[index + 1];
            index += 2;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_ERR_USAGE;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (*out_params == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
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
    const char *params_path = NULL;
    gossipsub_interop_app_t app;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    (void)signal(SIGINT, gossipsub_interop_signal_handler);
    (void)signal(SIGTERM, gossipsub_interop_signal_handler);

    gossipsub_interop_trace("main");
    result = gossipsub_interop_parse_args(argc, argv, &params_path);
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_trace("app init");
        result = gossipsub_interop_app_init(&app);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        gossipsub_interop_debug(&app, "starting gossipsub interop script");
        result = gossipsub_interop_run_script(&app, params_path);
    }
    if (result != GOSSIPSUB_INTEROP_OK)
    {
        (void)fprintf(stderr, "c-lean-libp2p gossipsub interop failed: %u\n", (unsigned int)result);
    }

    return (result == GOSSIPSUB_INTEROP_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
