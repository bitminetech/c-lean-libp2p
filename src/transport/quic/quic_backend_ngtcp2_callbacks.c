/**
 * @file quic_backend_ngtcp2_callbacks.c
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

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

static void quic_backend_ngtcp2_rand_cb(
    uint8_t *dest,
    size_t destlen,
    const ngtcp2_rand_ctx *rand_ctx)
{
    libp2p_quic_conn_t *conn = NULL;

    if ((dest != NULL) && (rand_ctx != NULL) && (rand_ctx->native_handle != NULL))
    {
        conn = quic_backend_conn_from_memory(rand_ctx->native_handle);
        if (conn->endpoint->config
                .random_fn(dest, destlen, conn->endpoint->config.random_user_data) !=
            LIBP2P_QUIC_OK)
        {
            (void)memset(dest, 0, destlen);
            conn->callback_error = LIBP2P_QUIC_ERR_INTERNAL;
        }
    }
}

static int quic_backend_get_path_challenge_data_cb(
    ngtcp2_conn *ngconn,
    ngtcp2_path_challenge_data *data,
    void *user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    int result = 0;

    (void)ngconn;
    if ((conn == NULL) || (data == NULL) ||
        (conn->endpoint->config
             .random_fn(data->data, sizeof(data->data), conn->endpoint->config.random_user_data) !=
         LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return result;
}

QUIC_BACKEND_INTERNAL int quic_backend_conn_add_cid(libp2p_quic_conn_t *conn, const ngtcp2_cid *cid)
{
    int result = 0;

    if ((conn == NULL) || (cid == NULL) || (cid->datalen == 0U) ||
        (cid->datalen > LIBP2P_QUIC_MAX_CONN_ID_BYTES))
    {
        result = -1;
    }
    else
    {
        for (size_t index = 0U; index < conn->cid_count; index++)
        {
            if (ngtcp2_cid_eq(&conn->cids[index], cid) != 0)
            {
                result = 1;
                break;
            }
        }
        if (result == 1)
        {
            result = 0;
        }
        else if (conn->cid_count == QUIC_BACKEND_MAX_CONN_IDS_PER_CONN)
        {
            result = -1;
        }
        else
        {
            conn->cids[conn->cid_count] = *cid;
            conn->cid_count++;
            result = 0;
        }
    }

    return result;
}

static int quic_backend_get_new_connection_id_cb(
    ngtcp2_conn *ngconn,
    ngtcp2_cid *cid,
    ngtcp2_stateless_reset_token *token,
    size_t cidlen,
    void *user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    int result = 0;

    (void)ngconn;
    if ((conn == NULL) || (cid == NULL) || (token == NULL) || (cidlen == 0U) ||
        (cidlen > LIBP2P_QUIC_MAX_CONN_ID_BYTES))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else if (
        (conn->endpoint->config
             .random_fn(cid->data, cidlen, conn->endpoint->config.random_user_data) !=
         LIBP2P_QUIC_OK) ||
        (conn->endpoint->config.random_fn(
             token->data,
             sizeof(token->data),
             conn->endpoint->config.random_user_data) != LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        cid->datalen = cidlen;
        result = (quic_backend_conn_add_cid(conn, cid) == 0) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return result;
}

static int quic_backend_stream_open_cb(ngtcp2_conn *ngconn, int64_t stream_id, void *user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    libp2p_quic_stream_t *stream = NULL;
    int result = 0;

    (void)ngconn;
    if (conn == NULL)
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        stream = quic_backend_conn_find_stream(conn, stream_id);
        if (stream == NULL)
        {
            stream = quic_backend_stream_new(conn, stream_id, 1);
            if (stream == NULL)
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        if ((result == 0) &&
            (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0))
        {
            result = NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if ((result == 0) && (quic_backend_event_push(
                                  conn->endpoint,
                                  LIBP2P_QUIC_EVENT_STREAM_INCOMING,
                                  conn,
                                  stream,
                                  0U,
                                  0U) != LIBP2P_QUIC_OK))
        {
            result = NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return result;
}

static libp2p_quic_err_t quic_backend_stream_rx_append(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t datalen)
{
    size_t required = 0U;
    uint8_t *new_data = NULL;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((stream == NULL) || ((data == NULL) && (datalen != 0U)))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (datalen == 0U)
    {
        result = LIBP2P_QUIC_OK;
    }
    else
    {
        const size_t available_tail = stream->rx_cap - stream->rx_len;
        if (available_tail < datalen)
        {
            if (quic_backend_size_add_overflow(stream->rx_len, datalen, &required) != 0)
            {
                result = LIBP2P_QUIC_ERR_LIMIT;
            }

            if ((result == LIBP2P_QUIC_OK) && (required < (stream->rx_cap * 2U)))
            {
                required = stream->rx_cap * 2U;
            }
            if ((result == LIBP2P_QUIC_OK) && (required < 1024U))
            {
                required = 1024U;
            }

            if (result == LIBP2P_QUIC_OK)
            {
                new_data = quic_backend_bytes_from_memory(
                    quic_backend_realloc(stream->conn->endpoint, stream->rx_data, required));
                if (new_data == NULL)
                {
                    result = LIBP2P_QUIC_ERR_NO_MEMORY;
                }
                else
                {
                    stream->rx_data = new_data;
                    stream->rx_cap = required;
                }
            }
        }

        if (result == LIBP2P_QUIC_OK)
        {
            (void)memcpy(&stream->rx_data[stream->rx_len], data, datalen);
            stream->rx_len += datalen;
        }
    }

    return result;
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
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    libp2p_quic_stream_t *stream = quic_backend_stream_from_memory(stream_user_data);
    int result = 0;

    (void)ngconn;
    if (conn == NULL)
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        if (stream == NULL)
        {
            stream = quic_backend_conn_find_stream(conn, stream_id);
            if (stream == NULL)
            {
                stream = quic_backend_stream_new(conn, stream_id, 1);
                if (stream == NULL)
                {
                    result = NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            if ((result == 0) &&
                (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0))
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
    }

    if ((result == 0) && (stream == NULL))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if ((result == 0) && (offset != stream->rx_next_offset))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if ((result == 0) && (quic_backend_stream_rx_append(stream, data, datalen) != LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (result == 0)
    {
        stream->rx_next_offset += (uint64_t)datalen;
        if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0U)
        {
            stream->remote_fin = 1U;
            if (stream->local_fin_sent != 0U)
            {
                stream->state = LIBP2P_QUIC_STREAM_CLOSED;
            }
            else
            {
                stream->state = LIBP2P_QUIC_STREAM_HALF_CLOSED_REMOTE;
            }
        }
    }

    if ((result == 0) && (quic_backend_event_push(
                              conn->endpoint,
                              LIBP2P_QUIC_EVENT_STREAM_READABLE,
                              conn,
                              stream,
                              0U,
                              0U) != LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return result;
}

static int quic_backend_stream_close_cb(
    ngtcp2_conn *ngconn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    libp2p_quic_stream_t *stream = quic_backend_stream_from_memory(stream_user_data);
    uint64_t event_error_code = 0U;
    int result = 0;

    (void)ngconn;
    if (conn == NULL)
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        if (stream == NULL)
        {
            stream = quic_backend_conn_find_stream(conn, stream_id);
            if (stream == NULL)
            {
                stream = quic_backend_stream_new(conn, stream_id, 1);
                if (stream == NULL)
                {
                    result = NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            if ((result == 0) &&
                (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0))
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if ((result == 0) && (quic_backend_event_push(
                                      conn->endpoint,
                                      LIBP2P_QUIC_EVENT_STREAM_INCOMING,
                                      conn,
                                      stream,
                                      0U,
                                      0U) != LIBP2P_QUIC_OK))
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    if ((result == 0) && (stream != NULL))
    {
        if ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0U)
        {
            stream->state = LIBP2P_QUIC_STREAM_RESET;
            stream->reset = 1U;
            event_error_code = app_error_code;
        }
        else
        {
            stream->state = LIBP2P_QUIC_STREAM_CLOSED;
            stream->reset = 0U;
        }
    }

    if ((result == 0) && (quic_backend_event_push(
                              conn->endpoint,
                              LIBP2P_QUIC_EVENT_STREAM_CLOSED,
                              conn,
                              stream,
                              event_error_code,
                              0U) != LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return result;
}

static int quic_backend_stream_reset_cb(
    ngtcp2_conn *ngconn,
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    libp2p_quic_stream_t *stream = quic_backend_stream_from_memory(stream_user_data);
    int result = 0;

    (void)ngconn;
    (void)final_size;
    if (conn == NULL)
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        if (stream == NULL)
        {
            stream = quic_backend_conn_find_stream(conn, stream_id);
            if (stream == NULL)
            {
                stream = quic_backend_stream_new(conn, stream_id, 1);
                if (stream == NULL)
                {
                    result = NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            if ((result == 0) &&
                (ngtcp2_conn_set_stream_user_data(conn->ngconn, stream_id, stream) != 0))
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if ((result == 0) && (quic_backend_event_push(
                                      conn->endpoint,
                                      LIBP2P_QUIC_EVENT_STREAM_INCOMING,
                                      conn,
                                      stream,
                                      0U,
                                      0U) != LIBP2P_QUIC_OK))
            {
                result = NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    if ((result == 0) && (stream != NULL))
    {
        stream->state = LIBP2P_QUIC_STREAM_RESET;
        stream->reset = 1U;
    }

    if ((result == 0) && (quic_backend_event_push(
                              conn->endpoint,
                              LIBP2P_QUIC_EVENT_STREAM_CLOSED,
                              conn,
                              stream,
                              app_error_code,
                              0U) != LIBP2P_QUIC_OK))
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return result;
}

static int quic_backend_handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data)
{
    libp2p_quic_conn_t *conn = quic_backend_conn_from_memory(user_data);
    int result = 0;

    (void)ngconn;
    if (conn == NULL)
    {
        result = NGTCP2_ERR_CALLBACK_FAILURE;
    }
    else
    {
        quic_backend_debug_text(conn, "ngtcp2 handshake completed");
        conn->state = LIBP2P_QUIC_CONN_ESTABLISHED;
        if (quic_backend_event_push(
                conn->endpoint,
                LIBP2P_QUIC_EVENT_CONN_ESTABLISHED,
                conn,
                NULL,
                0U,
                0U) != LIBP2P_QUIC_OK)
        {
            result = NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return result;
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

QUIC_BACKEND_INTERNAL const ngtcp2_callbacks quic_backend_callbacks = {
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
