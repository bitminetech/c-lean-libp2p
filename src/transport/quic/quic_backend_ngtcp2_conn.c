/**
 * @file quic_backend_ngtcp2_conn.c
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

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

#define QUIC_BACKEND_DEBUG_MESSAGE_BYTES     96U
#define QUIC_BACKEND_KEEP_ALIVE_TIMEOUT_US   ((libp2p_quic_time_us_t)2000000U)
#define QUIC_BACKEND_KEEP_ALIVE_IDLE_DIVISOR ((libp2p_quic_time_us_t)2U)

static size_t quic_backend_conn_debug_append_text(
    char *out,
    size_t out_len,
    size_t pos,
    const char *text)
{
    size_t next = pos;

    if ((out != NULL) && (text != NULL))
    {
        size_t text_index = 0U;

        while ((text[text_index] != '\0') && (next < out_len))
        {
            out[next] = text[text_index];
            next++;
            text_index++;
        }
    }

    return next;
}

static size_t quic_backend_debug_append_uint(char *out, size_t out_len, size_t pos, uint32_t value)
{
    char digits[10];
    size_t digit_count = 0U;
    size_t next = pos;
    uint32_t remaining = value;

    do
    {
        digits[digit_count] = (char)('0' + (remaining % 10U));
        digit_count++;
        remaining /= 10U;
    } while ((remaining != 0U) && (digit_count < sizeof(digits)));

    while ((digit_count != 0U) && (next < out_len))
    {
        digit_count--;
        out[next] = digits[digit_count];
        next++;
    }

    return next;
}

static void quic_backend_debug_conn_error(
    const libp2p_quic_conn_t *conn,
    int rv,
    libp2p_quic_err_t callback_error)
{
    char message[QUIC_BACKEND_DEBUG_MESSAGE_BYTES];
    size_t pos = 0U;
    uint32_t magnitude = 0U;

    pos = quic_backend_conn_debug_append_text(
        message,
        sizeof(message),
        pos,
        "ngtcp2 connection error rv=");
    if (rv < 0)
    {
        pos = quic_backend_conn_debug_append_text(message, sizeof(message), pos, "-");
        magnitude = (uint32_t)(0U - (uint32_t)rv);
    }
    else
    {
        magnitude = (uint32_t)rv;
    }
    pos = quic_backend_debug_append_uint(message, sizeof(message), pos, magnitude);
    pos = quic_backend_conn_debug_append_text(message, sizeof(message), pos, " callback=");
    pos = quic_backend_debug_append_uint(message, sizeof(message), pos, (uint32_t)callback_error);

    quic_backend_debug_bytes(conn, LIBP2P_QUIC_DEBUG_EVENT_TEXT, message, pos);
}

static void quic_backend_qlog_write_cb(
    void *user_data,
    uint32_t flags,
    const void *data,
    size_t datalen)
{
    const libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);

    if ((data != NULL) && (datalen != 0U))
    {
        quic_backend_debug_bytes(conn, LIBP2P_QUIC_DEBUG_EVENT_QLOG, data, datalen);
    }
    if ((flags & NGTCP2_QLOG_WRITE_FLAG_FIN) != 0U)
    {
        quic_backend_debug_text(conn, "ngtcp2 qlog finished");
    }
}

static void quic_backend_settings_init(
    const libp2p_quic_endpoint_t *endpoint,
    libp2p_quic_conn_t *conn,
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
    settings->rand_ctx.native_handle = conn;
    if (endpoint->config.debug_fn != NULL)
    {
        settings->qlog_write = quic_backend_qlog_write_cb;
    }
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

static ngtcp2_duration quic_backend_keep_alive_timeout(const libp2p_quic_endpoint_t *endpoint)
{
    libp2p_quic_time_us_t timeout_us = QUIC_BACKEND_KEEP_ALIVE_TIMEOUT_US;

    if (endpoint->config.idle_timeout_us <
        (QUIC_BACKEND_KEEP_ALIVE_TIMEOUT_US * QUIC_BACKEND_KEEP_ALIVE_IDLE_DIVISOR))
    {
        timeout_us = endpoint->config.idle_timeout_us / QUIC_BACKEND_KEEP_ALIVE_IDLE_DIVISOR;
        if (timeout_us == 0U)
        {
            timeout_us = 1U;
        }
    }

    return quic_backend_duration_to_ngtcp2(timeout_us);
}

static libp2p_quic_err_t quic_backend_random_cid(libp2p_quic_endpoint_t *endpoint, ngtcp2_cid *cid)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((endpoint == NULL) || (cid == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        cid->datalen = QUIC_BACKEND_CONN_ID_BYTES;
        result =
            endpoint->config.random_fn(cid->data, cid->datalen, endpoint->config.random_user_data);
    }

    return result;
}

QUIC_BACKEND_INTERNAL void quic_backend_conn_free(libp2p_quic_conn_t *conn)
{
    libp2p_quic_endpoint_t *endpoint = NULL;

    if (conn != NULL)
    {
        endpoint = conn->endpoint;
        for (size_t index = 0U; index < conn->streams.len; index++)
        {
            quic_backend_stream_free(conn->streams.items[index]);
        }
        quic_backend_free(endpoint, (void *)conn->streams.items);
        ngtcp2_conn_del(conn->ngconn);
        SSL_free(conn->ssl);
        conn->magic = 0U;
        quic_backend_free(endpoint, conn);
    }
}

static libp2p_quic_err_t quic_backend_conn_add_to_endpoint(libp2p_quic_conn_t *conn)
{
    libp2p_quic_endpoint_t *endpoint = conn->endpoint;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (endpoint->connection_count == endpoint->config.max_connections)
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else if (
        (conn->role == LIBP2P_QUIC_ROLE_CLIENT) &&
        (endpoint->outgoing_connection_count == endpoint->config.max_outgoing_connections))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else if (
        (conn->role == LIBP2P_QUIC_ROLE_SERVER) &&
        (endpoint->incoming_connection_count == endpoint->config.max_incoming_connections))
    {
        result = LIBP2P_QUIC_ERR_LIMIT;
    }
    else
    {
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
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_client_new(
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
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    conn = quic_backend_conn_from_memory(quic_backend_calloc(endpoint, 1U, sizeof(*conn)));
    if (conn == NULL)
    {
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
    }
    else
    {
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
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_backend_random_cid(endpoint, &dcid);
        }
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_backend_random_cid(endpoint, &scid);
        }
        if ((result == LIBP2P_QUIC_OK) && (quic_backend_conn_add_cid(conn, &scid) != 0))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        if (result == LIBP2P_QUIC_OK)
        {
            quic_backend_path_from_addrs(&conn->local_addr, &conn->remote_addr, &path);
            quic_backend_settings_init(endpoint, conn, &settings);
            quic_backend_transport_params_init(endpoint, &params);

            const int rv = ngtcp2_conn_client_new(
                &conn->ngconn,
                &dcid,
                &scid,
                &path.path,
                LIBP2P_QUIC_VERSION_RFC9000,
                &quic_backend_callbacks,
                &settings,
                &params,
                &endpoint->ngtcp2_mem,
                conn);
            if (rv != 0)
            {
                result = quic_backend_ngtcp2_err(rv);
            }
        }
        if (result == LIBP2P_QUIC_OK)
        {
            ngtcp2_conn_set_tls_native_handle(conn->ngconn, conn->ssl);
            ngtcp2_conn_set_keep_alive_timeout(
                conn->ngconn,
                quic_backend_keep_alive_timeout(endpoint));
            result = quic_backend_conn_add_to_endpoint(conn);
        }
        if (result == LIBP2P_QUIC_OK)
        {
            (void)quic_backend_event_push(
                endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                conn,
                NULL,
                0U,
                0U);
            *out_conn = conn;
        }
        else
        {
            quic_backend_conn_free(conn);
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_server_new(
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
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    conn = quic_backend_conn_from_memory(quic_backend_calloc(endpoint, 1U, sizeof(*conn)));
    if (conn == NULL)
    {
        result = LIBP2P_QUIC_ERR_NO_MEMORY;
    }
    else
    {
        conn->magic = QUIC_BACKEND_CONN_MAGIC;
        conn->endpoint = endpoint;
        conn->role = LIBP2P_QUIC_ROLE_SERVER;
        conn->state = LIBP2P_QUIC_CONN_HANDSHAKING;
        conn->local_addr = datagram->local_addr;
        conn->remote_addr = datagram->remote_addr;
        ngtcp2_ccerr_default(&conn->close_error);

        result = quic_backend_ssl_new_for_conn(conn);
        if (result == LIBP2P_QUIC_OK)
        {
            result = quic_backend_random_cid(endpoint, &scid);
        }
        if ((result == LIBP2P_QUIC_OK) && (quic_backend_conn_add_cid(conn, &scid) != 0))
        {
            result = LIBP2P_QUIC_ERR_LIMIT;
        }
        if (result == LIBP2P_QUIC_OK)
        {
            quic_backend_path_from_addrs(&conn->local_addr, &conn->remote_addr, &path);
            quic_backend_settings_init(endpoint, conn, &settings);
            quic_backend_transport_params_init(endpoint, &params);
            params.original_dcid = hd->dcid;
            params.original_dcid_present = 1U;

            const int rv = ngtcp2_conn_server_new(
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
            }
        }
        if (result == LIBP2P_QUIC_OK)
        {
            ngtcp2_conn_set_tls_native_handle(conn->ngconn, conn->ssl);
            ngtcp2_conn_set_keep_alive_timeout(
                conn->ngconn,
                quic_backend_keep_alive_timeout(endpoint));
            result = quic_backend_conn_add_to_endpoint(conn);
        }
        if (result == LIBP2P_QUIC_OK)
        {
            (void)quic_backend_event_push(
                endpoint,
                LIBP2P_QUIC_EVENT_CONN_INCOMING,
                conn,
                NULL,
                0U,
                0U);
            *out_conn = conn;
        }
        else
        {
            quic_backend_conn_free(conn);
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t *quic_backend_find_conn_by_packet(
    const libp2p_quic_endpoint_t *endpoint,
    const libp2p_quic_rx_datagram_t *datagram)
{
    ngtcp2_version_cid version_cid;
    size_t conn_index = 0U;
    libp2p_quic_conn_t *result = NULL;

    for (conn_index = 0U; (conn_index < endpoint->connection_count) && (result == NULL);
         conn_index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[conn_index];

        if (conn != NULL)
        {
            for (size_t cid_index = 0U; (cid_index < conn->cid_count) && (result == NULL);
                 cid_index++)
            {
                (void)memset(&version_cid, 0, sizeof(version_cid));
                if ((ngtcp2_pkt_decode_version_cid(
                         &version_cid,
                         datagram->data,
                         datagram->data_len,
                         conn->cids[cid_index].datalen) == 0) &&
                    (version_cid.dcidlen == conn->cids[cid_index].datalen) &&
                    (memcmp(version_cid.dcid, conn->cids[cid_index].data, version_cid.dcidlen) ==
                     0))
                {
                    result = conn;
                }
            }
        }
    }

    for (conn_index = 0U; (conn_index < endpoint->connection_count) && (result == NULL);
         conn_index++)
    {
        libp2p_quic_conn_t *conn = endpoint->connections[conn_index];

        if ((conn != NULL) &&
            (libp2p_quic_addr_equal(&conn->local_addr, &datagram->local_addr, 0) != 0) &&
            (libp2p_quic_addr_equal(&conn->remote_addr, &datagram->remote_addr, 0) != 0))
        {
            result = conn;
        }
    }

    return result;
}

static uint8_t quic_backend_conn_error_is_endpoint_error(int rv)
{
    uint8_t result = 0U;

    if ((rv == NGTCP2_ERR_NOMEM) || (rv == NGTCP2_ERR_NOBUF) ||
        (rv == NGTCP2_ERR_INVALID_ARGUMENT) || (rv == NGTCP2_ERR_INVALID_STATE))
    {
        result = 1U;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_handle_conn_error(libp2p_quic_conn_t *conn, int rv)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (rv != 0)
    {
        quic_backend_debug_conn_error(conn, rv, conn->callback_error);
        if (quic_backend_conn_error_is_endpoint_error(rv) != 0U)
        {
            result = quic_backend_ngtcp2_err(rv);
        }
        else if (
            (rv == NGTCP2_ERR_CLOSING) || (rv == NGTCP2_ERR_DRAINING) ||
            (rv == NGTCP2_ERR_IDLE_CLOSE) || (rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) ||
            (rv == NGTCP2_ERR_DROP_CONN) || (rv == NGTCP2_ERR_NO_VIABLE_PATH) ||
            (rv == NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE) || (rv == NGTCP2_ERR_AEAD_LIMIT_REACHED))
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
                else
                {
                    app_error_code = 0U;
                }
            }

            conn->state = LIBP2P_QUIC_CONN_CLOSED;
            result = quic_backend_event_push(
                conn->endpoint,
                LIBP2P_QUIC_EVENT_CONN_CLOSED,
                conn,
                NULL,
                app_error_code,
                transport_error_code);
        }
        else
        {
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
            result = quic_backend_event_push(
                conn->endpoint,
                LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
                conn,
                NULL,
                0U,
                0U);
        }
    }

    return result;
}

static libp2p_quic_stream_t *quic_backend_conn_next_tx_stream(libp2p_quic_conn_t *conn)
{
    libp2p_quic_stream_t *result = NULL;

    if (conn->streams.len != 0U)
    {
        size_t start = conn->next_tx_stream;

        if (start >= conn->streams.len)
        {
            start = 0U;
        }

        for (size_t index = 0U; (index < conn->streams.len) && (result == NULL); index++)
        {
            const size_t stream_index = (start + index) % conn->streams.len;
            libp2p_quic_stream_t *stream = conn->streams.items[stream_index];

            if ((stream != NULL) && (stream->state != LIBP2P_QUIC_STREAM_CLOSED) &&
                (stream->state != LIBP2P_QUIC_STREAM_RESET) &&
                ((stream->tx_sent_len < stream->tx_len) ||
                 ((stream->local_fin_queued != 0U) && (stream->local_fin_sent == 0U))))
            {
                result = stream;
                conn->next_tx_stream = (stream_index + 1U) % conn->streams.len;
            }
        }
    }

    return result;
}

static void quic_backend_maybe_wake_stream_after_tx_drain(libp2p_quic_stream_t *stream)
{
    if ((stream != NULL) && (stream->write_blocked != 0U) &&
        (stream->state != LIBP2P_QUIC_STREAM_CLOSED) &&
        (stream->state != LIBP2P_QUIC_STREAM_RESET) && (stream->local_fin_queued == 0U) &&
        (stream->tx_sent_len == stream->tx_len))
    {
        libp2p_quic_err_t err = quic_backend_event_push(
            stream->conn->endpoint,
            LIBP2P_QUIC_EVENT_STREAM_WRITABLE,
            stream->conn,
            stream,
            0U,
            0U);

        if (err == LIBP2P_QUIC_OK)
        {
            stream->write_blocked = 0U;
            quic_backend_debug_stream_state(
                stream,
                "stream_wake_tx_drain",
                (uint64_t)stream->tx_len,
                (uint64_t)stream->tx_sent_len,
                0U);
        }
        else
        {
            quic_backend_debug_stream_state(
                stream,
                "stream_wake_tx_drain_drop",
                (uint64_t)stream->conn->endpoint->event_len,
                (uint64_t)stream->conn->endpoint->event_cap,
                (uint32_t)err);
        }
    }
}

static void quic_backend_conn_record_packet_write(libp2p_quic_conn_t *conn, ngtcp2_tstamp ts)
{
    if (conn->endpoint->defer_tx_time_updates != 0U)
    {
        conn->tx_time_update_unconfirmed = 1U;
    }
    else
    {
        ngtcp2_conn_update_pkt_tx_time(conn->ngconn, ts);
    }
}

QUIC_BACKEND_INTERNAL void
quic_backend_conn_confirm_tx_datagram(libp2p_quic_conn_t *conn, libp2p_quic_time_us_t now_us)
{
    if ((conn != NULL) && (conn->tx_time_update_unconfirmed != 0U))
    {
        const ngtcp2_tstamp ts = quic_backend_endpoint_time_to_ngtcp2(conn->endpoint, now_us);

        ngtcp2_conn_update_pkt_tx_time(conn->ngconn, ts);
        conn->tx_time_update_unconfirmed = 0U;
        conn->tx_time_update_pending = 0U;
    }
}

QUIC_BACKEND_INTERNAL void quic_backend_conn_discard_tx_datagram(libp2p_quic_conn_t *conn)
{
    if (conn != NULL)
    {
        conn->tx_time_update_unconfirmed = 0U;
        conn->tx_time_update_pending = 0U;
    }
}

QUIC_BACKEND_INTERNAL void
quic_backend_conn_flush_tx_time_update(libp2p_quic_conn_t *conn, libp2p_quic_time_us_t now_us)
{
    if ((conn != NULL) && (conn->tx_time_update_pending != 0U))
    {
        const ngtcp2_tstamp ts = quic_backend_endpoint_time_to_ngtcp2(conn->endpoint, now_us);

        ngtcp2_conn_update_pkt_tx_time(conn->ngconn, ts);
        conn->tx_time_update_pending = 0U;
    }
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_write_conn_datagram(
    libp2p_quic_conn_t *conn,
    libp2p_quic_tx_datagram_t *datagram,
    libp2p_quic_time_us_t now_us)
{
    ngtcp2_path_storage path;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite = 0;
    ngtcp2_ssize ndatalen = -1;
    ngtcp2_tstamp ts = quic_backend_endpoint_time_to_ngtcp2(conn->endpoint, now_us);
    libp2p_quic_err_t result = LIBP2P_QUIC_ERR_WOULD_BLOCK;

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
            quic_backend_conn_record_packet_write(conn, ts);
            conn->close_sent = 1U;
            conn->state = LIBP2P_QUIC_CONN_CLOSING;
            conn->autopsy_tx_sent_bytes += (uint64_t)nwrite;
            conn->autopsy_last_tx_us = now_us;
            datagram->local_addr = conn->local_addr;
            datagram->remote_addr = conn->remote_addr;
            datagram->data_len = (size_t)nwrite;
            datagram->ecn = quic_backend_ecn_from_ngtcp2(pi.ecn);
            result = LIBP2P_QUIC_OK;
        }
        else if (nwrite == 0)
        {
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        }
        else
        {
            result = quic_backend_ngtcp2_err((int)nwrite);
        }
    }
    else
    {
        libp2p_quic_stream_t *stream = NULL;
        ngtcp2_vec vec;
        const ngtcp2_vec *vec_ptr = NULL;
        size_t vec_count = 0U;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
        int64_t stream_id = -1;

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
            if ((stream->local_fin_queued != 0U) && (stream->local_fin_sent == 0U) &&
                (remaining == 0U))
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
            quic_backend_conn_record_packet_write(conn, ts);
            conn->autopsy_tx_sent_bytes += (uint64_t)nwrite;
            if (ndatalen >= 0)
            {
                conn->autopsy_write_data_packets++;
            }
            else
            {
                conn->autopsy_write_control_packets++;
            }
            conn->autopsy_last_tx_us = now_us;
            datagram->local_addr = conn->local_addr;
            datagram->remote_addr = conn->remote_addr;
            datagram->data_len = (size_t)nwrite;
            datagram->ecn = quic_backend_ecn_from_ngtcp2(pi.ecn);

            if ((stream != NULL) && (ndatalen >= 0))
            {
                stream->tx_sent_len += (size_t)ndatalen;
                quic_backend_debug_stream_state(
                    stream,
                    "stream_tx",
                    (uint64_t)nwrite,
                    (uint64_t)ndatalen,
                    flags);
                quic_backend_maybe_wake_stream_after_tx_drain(stream);
                if (((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) != 0U) &&
                    (stream->tx_sent_len == stream->tx_len))
                {
                    stream->local_fin_sent = 1U;
                    if (stream->remote_fin != 0U)
                    {
                        stream->state = LIBP2P_QUIC_STREAM_CLOSED;
                    }
                    else
                    {
                        stream->state = LIBP2P_QUIC_STREAM_HALF_CLOSED_LOCAL;
                    }
                }
            }
            result = LIBP2P_QUIC_OK;
        }
        else if (nwrite == 0)
        {
            conn->autopsy_write_zero_count++;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            if (stream != NULL)
            {
                quic_backend_debug_stream_state(stream, "stream_writev_zero", 0U, 0U, 0U);
            }
        }
        else if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)
        {
            conn->autopsy_write_stream_blocked_count++;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            if (stream != NULL)
            {
                quic_backend_debug_stream_state(stream, "stream_writev_blocked", 0U, 0U, 1U);
            }
        }
        else if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR)
        {
            conn->autopsy_write_stream_shut_wr_count++;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            if (stream != NULL)
            {
                quic_backend_debug_stream_state(stream, "stream_writev_blocked", 0U, 0U, 2U);
            }
        }
        else if (nwrite == NGTCP2_ERR_STREAM_NOT_FOUND)
        {
            conn->autopsy_write_stream_not_found_count++;
            result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            if (stream != NULL)
            {
                quic_backend_debug_stream_state(stream, "stream_writev_blocked", 0U, 0U, 3U);
            }
        }
        else
        {
            conn->autopsy_write_other_error_count++;
            result = quic_backend_handle_conn_error(conn, (int)nwrite);
            if (result == LIBP2P_QUIC_OK)
            {
                result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
            }
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_state(const libp2p_quic_conn_t *conn, libp2p_quic_conn_state_t *out_state)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out_state == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out_state = conn->state;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_conn_peer_id(
    const libp2p_quic_conn_t *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (written == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (conn->has_peer_identity == 0U)
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        result = quic_backend_copy_measure(
            conn->peer_identity.peer_id,
            conn->peer_identity.peer_id_len,
            out,
            out_len,
            written);
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_peer_identity(const libp2p_quic_conn_t *conn, libp2p_quic_peer_identity_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (conn->has_peer_identity == 0U)
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }
    else
    {
        *out = conn->peer_identity;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_local_addr(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out = conn->local_addr;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_remote_addr(const libp2p_quic_conn_t *conn, libp2p_quic_addr_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((conn == NULL) || (conn->magic != QUIC_BACKEND_CONN_MAGIC) || (out == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out = conn->remote_addr;
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_close(libp2p_quic_conn_t *conn, uint64_t app_error_code)
{
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (result == LIBP2P_QUIC_OK)
    {
        ngtcp2_ccerr_set_application_error(&conn->close_error, app_error_code, NULL, 0U);
        conn->close_requested = 1U;
        conn->state = LIBP2P_QUIC_CONN_CLOSING;
        result = quic_backend_event_push(
            conn->endpoint,
            LIBP2P_QUIC_EVENT_TX_DATAGRAM_READY,
            conn,
            NULL,
            0U,
            0U);
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_open_bidi_stream(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream)
{
    int64_t stream_id = -1;
    libp2p_quic_stream_t *stream = NULL;
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (out_stream != NULL)
    {
        *out_stream = NULL;
    }
    if ((result == LIBP2P_QUIC_OK) && (out_stream == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    if ((result == LIBP2P_QUIC_OK) && (conn->state != LIBP2P_QUIC_CONN_ESTABLISHED))
    {
        result = LIBP2P_QUIC_ERR_STATE;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        stream = quic_backend_stream_new(conn, -1, 0);
        if (stream == NULL)
        {
            result = LIBP2P_QUIC_ERR_NO_MEMORY;
        }
        else
        {
            const int rv = ngtcp2_conn_open_bidi_stream(conn->ngconn, &stream_id, stream);
            if (rv != 0)
            {
                conn->streams.len--;
                quic_backend_stream_free(stream);
                result = quic_backend_ngtcp2_err(rv);
            }
            else
            {
                stream->stream_id = stream_id;
                *out_stream = stream;
            }
        }
    }

    return result;
}

QUIC_BACKEND_INTERNAL libp2p_quic_err_t
quic_backend_conn_accept_stream(libp2p_quic_conn_t *conn, libp2p_quic_stream_t **out_stream)
{
    libp2p_quic_err_t result = quic_backend_validate_conn(conn);

    if (out_stream != NULL)
    {
        *out_stream = NULL;
    }
    if ((result == LIBP2P_QUIC_OK) && (out_stream == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_QUIC_OK)
    {
        result = LIBP2P_QUIC_ERR_WOULD_BLOCK;
        for (size_t index = 0U;
             (index < conn->streams.len) && (result == LIBP2P_QUIC_ERR_WOULD_BLOCK);
             index++)
        {
            libp2p_quic_stream_t *stream = conn->streams.items[index];

            if ((stream != NULL) && (stream->incoming != 0U) && (stream->accepted == 0U))
            {
                stream->accepted = 1U;
                *out_stream = stream;
                result = LIBP2P_QUIC_OK;
            }
        }
    }

    return result;
}
