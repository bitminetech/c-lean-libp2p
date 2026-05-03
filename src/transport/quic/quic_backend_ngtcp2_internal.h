#ifndef LIBP2P_TRANSPORT_QUIC_BACKEND_NGTCP2_INTERNAL_H
#define LIBP2P_TRANSPORT_QUIC_BACKEND_NGTCP2_INTERNAL_H

#if defined(_WIN32)
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
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic_backend.h"

#if defined(_MSC_VER)
#define QUIC_BACKEND_INTERNAL
#elif defined(__GNUC__) || defined(__clang__)
#define QUIC_BACKEND_INTERNAL __attribute__((visibility("hidden")))
#else
#define QUIC_BACKEND_INTERNAL
#endif

#define QUIC_BACKEND_ENDPOINT_MAGIC ((uint32_t)0x71455031U)
#define QUIC_BACKEND_CONN_MAGIC     ((uint32_t)0x71434e31U)
#define QUIC_BACKEND_STREAM_MAGIC   ((uint32_t)0x71535431U)

#define QUIC_BACKEND_ENDPOINT_STORAGE_ALIGN 8U

#define QUIC_BACKEND_CONN_ID_BYTES          8U
#define QUIC_BACKEND_MAX_CONN_IDS_PER_CONN  8U
#define QUIC_BACKEND_EVENTS_PER_CONNECTION  8U
#define QUIC_BACKEND_EXTRA_EVENTS           16U
#define QUIC_BACKEND_ACTIVE_CID_LIMIT       8U
#define QUIC_BACKEND_STREAM_SEND_MULTIPLIER 2U
#define QUIC_BACKEND_STREAM_WRITE_CHUNK     4096U

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
    uint64_t tx_base_offset;
    uint8_t write_blocked;
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
    size_t next_tx_stream;
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
    uint8_t has_time_origin;
    libp2p_quic_time_us_t time_origin_us;
    libp2p_quic_conn_t **connections;
    size_t connection_count;
    size_t incoming_connection_count;
    size_t outgoing_connection_count;
    size_t next_tx_connection;
    libp2p_quic_event_t *events;
    size_t event_cap;
    size_t event_head;
    size_t event_len;
};

extern QUIC_BACKEND_INTERNAL const ngtcp2_callbacks quic_backend_callbacks;

QUIC_BACKEND_INTERNAL int quic_backend_size_mul_overflow(size_t a, size_t b, size_t *out);

QUIC_BACKEND_INTERNAL int quic_backend_size_add_overflow(size_t a, size_t b, size_t *out);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_allocator_normalize(const libp2p_quic_allocator_t *in, libp2p_quic_allocator_t *out);

QUIC_BACKEND_INTERNAL void *quic_backend_calloc(
    libp2p_quic_endpoint_t *endpoint,
    size_t nmemb,
    size_t size);

QUIC_BACKEND_INTERNAL void *quic_backend_realloc(
    libp2p_quic_endpoint_t *endpoint,
    void *ptr,
    size_t size);

QUIC_BACKEND_INTERNAL void quic_backend_free(libp2p_quic_endpoint_t *endpoint, void *ptr);

QUIC_BACKEND_INTERNAL libp2p_quic_endpoint_t *quic_backend_endpoint_from_memory(void *memory);

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t *quic_backend_conn_from_memory(void *memory);

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_stream_from_memory(void *memory);

QUIC_BACKEND_INTERNAL uint8_t *quic_backend_bytes_from_memory(void *memory);

QUIC_BACKEND_INTERNAL libp2p_quic_event_t *quic_backend_events_from_memory(void *memory);

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t **quic_backend_conn_items_from_memory(void *memory);

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t **quic_backend_stream_items_from_memory(void *memory);

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_malloc(size_t size, void *user_data);

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data);

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_realloc(void *ptr, size_t size, void *user_data);

QUIC_BACKEND_INTERNAL void quic_backend_ngtcp2_free(void *ptr, void *user_data);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_validate_endpoint(const libp2p_quic_endpoint_t *endpoint);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_validate_conn(const libp2p_quic_conn_t *conn);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_validate_stream(const libp2p_quic_stream_t *stream);

QUIC_BACKEND_INTERNAL ngtcp2_tstamp quic_backend_time_to_ngtcp2(libp2p_quic_time_us_t now_us);

QUIC_BACKEND_INTERNAL libp2p_quic_time_us_t quic_backend_time_from_ngtcp2(ngtcp2_tstamp ts);

QUIC_BACKEND_INTERNAL ngtcp2_duration
quic_backend_duration_to_ngtcp2(libp2p_quic_time_us_t duration_us);

QUIC_BACKEND_INTERNAL ngtcp2_tstamp quic_backend_endpoint_time_to_ngtcp2(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_time_us_t now_us);

QUIC_BACKEND_INTERNAL libp2p_quic_time_us_t
quic_backend_endpoint_time_from_ngtcp2(const libp2p_quic_endpoint_t *endpoint, ngtcp2_tstamp ts);

QUIC_BACKEND_INTERNAL uint8_t quic_backend_ecn_to_ngtcp2(libp2p_quic_ecn_t ecn);

QUIC_BACKEND_INTERNAL libp2p_quic_ecn_t quic_backend_ecn_from_ngtcp2(uint8_t ecn);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_event_push(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_event_type_t type,
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code,
    uint64_t transport_error_code);

QUIC_BACKEND_INTERNAL void quic_backend_path_from_addrs(
    const libp2p_quic_addr_t *local_addr,
    const libp2p_quic_addr_t *remote_addr,
    ngtcp2_path_storage *path);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_copy_measure(
    const uint8_t *src,
    size_t src_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

QUIC_BACKEND_INTERNAL void quic_backend_debug_bytes(
    const libp2p_quic_conn_t *conn,
    libp2p_quic_debug_event_type_t type,
    const void *data,
    size_t data_len);

QUIC_BACKEND_INTERNAL void quic_backend_debug_text(
    const libp2p_quic_conn_t *conn,
    const char *message);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_ngtcp2_err(int rv);

QUIC_BACKEND_INTERNAL SSL_CTX *quic_backend_ssl_ctx_new(
    libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_role_t role);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_ssl_new_for_conn(libp2p_quic_conn_t *conn);

QUIC_BACKEND_INTERNAL int quic_backend_conn_add_cid(
    libp2p_quic_conn_t *conn,
    const ngtcp2_cid *cid);

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_conn_find_stream(
    const libp2p_quic_conn_t *conn,
    int64_t stream_id);

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_stream_new(
    libp2p_quic_conn_t *conn,
    int64_t stream_id,
    int incoming);

QUIC_BACKEND_INTERNAL void quic_backend_stream_free(libp2p_quic_stream_t *stream);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_id(const libp2p_quic_stream_t *stream, libp2p_quic_stream_id_t *out_id);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_state(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_state_t *out_state);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_read(
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_stream_finish(libp2p_quic_stream_t *stream);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_reset(libp2p_quic_stream_t *stream, uint64_t app_error_code);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_stop_sending(libp2p_quic_stream_t *stream, uint64_t app_error_code);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_stream_conn(libp2p_quic_stream_t *stream, libp2p_quic_conn_t **out_conn);

QUIC_BACKEND_INTERNAL void quic_backend_conn_free(libp2p_quic_conn_t *conn);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_client_new(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_dial_config_t *dial_config,
    libp2p_quic_conn_t **out_conn);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_server_new(
    libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram,
    const ngtcp2_pkt_hd *hd,
    libp2p_quic_conn_t **out_conn);

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t *quic_backend_find_conn_by_packet(
    const libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_handle_conn_error(libp2p_quic_conn_t *conn, int rv);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_write_conn_datagram(
    libp2p_quic_conn_t *conn,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_state(const libp2p_quic_conn_t *conn, libp2p_quic_conn_state_t *out_state);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_peer_identity(const libp2p_quic_conn_t *conn, libp2p_quic_peer_identity_t *out);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_local_addr(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_remote_addr(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_close(libp2p_quic_conn_t *conn, uint64_t app_error_code);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_open_bidi_stream(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream);

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_accept_stream(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream);

#endif /* LIBP2P_TRANSPORT_QUIC_BACKEND_NGTCP2_INTERNAL_H */
