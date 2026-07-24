#ifndef LIBP2P_TEST_HOST_TEST_SUPPORT_H
#define LIBP2P_TEST_HOST_TEST_SUPPORT_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libp2p/libp2p_host.h"
#include "multiformats/multistream-select/multistream_select.h"

#define HOST_TEST_EVENT_CAP      32U
#define HOST_TEST_STREAM_BUF_CAP 4096U
#define HOST_TEST_MULTIADDR_CAP  256U

typedef struct
{
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
    libp2p_host_peer_identity_t identity;
    uint8_t remote_multiaddr[HOST_TEST_MULTIADDR_CAP];
    size_t remote_multiaddr_len;
} host_test_conn_t;

typedef struct
{
    uint8_t read_buf[HOST_TEST_STREAM_BUF_CAP];
    size_t read_len;
    size_t read_pos;
    int read_fin;
    uint8_t write_buf[HOST_TEST_STREAM_BUF_CAP];
    size_t write_len;
    size_t reset_count;
    size_t finish_count;
    size_t stop_count;
} host_test_stream_t;

typedef struct
{
    libp2p_host_transport_event_t events[HOST_TEST_EVENT_CAP];
    size_t event_head;
    size_t event_len;
    host_test_conn_t *conn;
    host_test_stream_t *next_stream;
    libp2p_host_fd_t fd;
    libp2p_host_interest_t interest;
    libp2p_host_time_us_t deadline;
    size_t drive_count;
    size_t close_count;
    size_t release_count;
    libp2p_host_err_t open_stream_result;
    uint8_t listen_multiaddr[HOST_TEST_MULTIADDR_CAP];
    size_t listen_multiaddr_len;
} host_test_transport_fixture_t;

typedef struct
{
    host_test_transport_fixture_t *fixture;
} host_test_transport_config_t;

static inline libp2p_host_err_t host_test_sign(
    void *user_data,
    const uint8_t *message,
    size_t message_len,
    uint8_t *out_sig,
    size_t out_sig_len,
    size_t *written)
{
    (void)user_data;

    if (((message == NULL) && (message_len != 0U)) || (out_sig == NULL) || (written == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *written = message_len;
    if (out_sig_len < message_len)
    {
        return LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    (void)memcpy(out_sig, message, message_len);
    return LIBP2P_HOST_OK;
}

static inline void host_test_fixture_init(
    host_test_transport_fixture_t *fixture,
    host_test_conn_t *conn)
{
    assert(fixture != NULL);
    assert(conn != NULL);
    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(conn, 0, sizeof(*conn));
    fixture->conn = conn;
    fixture->fd = 42U;
    fixture->interest = LIBP2P_HOST_INTEREST_READ;
    fixture->deadline = 12345U;
    conn->peer_id[0] = 0U;
    conn->peer_id[1] = 1U;
    conn->peer_id[2] = 2U;
    conn->peer_id_len = 3U;
    conn->identity.key_type = LIBP2P_HOST_KEY_SECP256K1;
    (void)memcpy(conn->identity.peer_id, conn->peer_id, conn->peer_id_len);
    conn->identity.peer_id_len = conn->peer_id_len;
    conn->identity.public_key_message[0] = 8U;
    conn->identity.public_key_message_len = 1U;
    conn->remote_multiaddr[0] = 4U;
    conn->remote_multiaddr[1] = 127U;
    conn->remote_multiaddr[2] = 0U;
    conn->remote_multiaddr[3] = 0U;
    conn->remote_multiaddr[4] = 1U;
    conn->remote_multiaddr_len = 5U;
}

static inline void host_test_config_init(
    libp2p_host_config_t *config,
    host_test_transport_config_t *transport_config,
    host_test_transport_fixture_t *fixture,
    const libp2p_host_transport_vtable_t *transport)
{
    static const uint8_t listen_addr[] = {1U};
    static const uint8_t peer_id[] = {0U, 1U, 2U};
    static const uint8_t public_key[] = {8U};

    assert(config != NULL);
    assert(transport_config != NULL);
    assert(fixture != NULL);
    assert(libp2p_host_config_default(config) == LIBP2P_HOST_OK);
    transport_config->fixture = fixture;
    config->identity.peer_id = peer_id;
    config->identity.peer_id_len = sizeof(peer_id);
    config->identity.public_key_message = public_key;
    config->identity.public_key_message_len = sizeof(public_key);
    config->identity.sign_fn = host_test_sign;
    config->listen_multiaddr = listen_addr;
    config->listen_multiaddr_len = sizeof(listen_addr);
    config->transport = transport;
    config->transport_config = transport_config;
    config->max_protocols = 4U;
    config->max_connections = 4U;
    config->max_streams_per_conn = 4U;
    config->max_pending_dials = 4U;
    config->max_pending_stream_opens = 4U;
    config->event_capacity = 16U;
    config->max_negotiation_steps = 16U;
}

static inline void host_test_event_push(
    host_test_transport_fixture_t *fixture,
    const libp2p_host_transport_event_t *event)
{
    size_t pos = 0U;

    assert(fixture != NULL);
    assert(event != NULL);
    assert(fixture->event_len < HOST_TEST_EVENT_CAP);
    pos = (fixture->event_head + fixture->event_len) % HOST_TEST_EVENT_CAP;
    fixture->events[pos] = *event;
    fixture->event_len++;
}

static inline void host_test_stream_add_message(
    host_test_stream_t *stream,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t written = 0U;

    assert(stream != NULL);
    assert(
        libp2p_multistream_select_message_encode(
            payload,
            payload_len,
            &stream->read_buf[stream->read_len],
            sizeof(stream->read_buf) - stream->read_len,
            &written) == LIBP2P_MULTISTREAM_SELECT_OK);
    stream->read_len += written;
}

static inline size_t host_test_encoded_message_size(size_t payload_len)
{
    size_t out = 0U;

    assert(
        libp2p_multistream_select_message_size(payload_len, &out) == LIBP2P_MULTISTREAM_SELECT_OK);
    return out;
}

static inline libp2p_host_err_t host_test_storage_size(const void *config, size_t *out_len)
{
    const host_test_transport_config_t *mock_config = (const host_test_transport_config_t *)config;

    if ((mock_config == NULL) || (mock_config->fixture == NULL) || (out_len == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_len = sizeof(host_test_transport_fixture_t *);
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_storage_align(size_t *out_align)
{
    if (out_align == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_align = 8U;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_init(
    void *storage,
    size_t storage_len,
    const void *config,
    const uint8_t *listen_multiaddr,
    size_t listen_multiaddr_len,
    void **out_transport)
{
    const host_test_transport_config_t *mock_config = (const host_test_transport_config_t *)config;
    host_test_transport_fixture_t **slot = (host_test_transport_fixture_t **)storage;

    if ((storage == NULL) || (storage_len < sizeof(*slot)) || (mock_config == NULL) ||
        (mock_config->fixture == NULL) || (listen_multiaddr == NULL) ||
        (listen_multiaddr_len > sizeof(mock_config->fixture->listen_multiaddr)) ||
        (out_transport == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    (void)memcpy(mock_config->fixture->listen_multiaddr, listen_multiaddr, listen_multiaddr_len);
    mock_config->fixture->listen_multiaddr_len = listen_multiaddr_len;
    *slot = mock_config->fixture;
    *out_transport = mock_config->fixture;
    return LIBP2P_HOST_OK;
}

static inline void host_test_deinit(void *transport)
{
    (void)transport;
}

static inline libp2p_host_err_t host_test_fd(const void *transport, libp2p_host_fd_t *out_fd)
{
    const host_test_transport_fixture_t *fixture = (const host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (out_fd == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_fd = fixture->fd;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_io_interest(
    const void *transport,
    libp2p_host_interest_t *out_interest)
{
    const host_test_transport_fixture_t *fixture = (const host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (out_interest == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_interest = fixture->interest;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_next_deadline(
    const void *transport,
    libp2p_host_time_us_t *out_deadline_us)
{
    const host_test_transport_fixture_t *fixture = (const host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (out_deadline_us == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_deadline_us = fixture->deadline;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_drive(
    void *transport,
    libp2p_host_time_us_t now_us,
    libp2p_host_ready_t ready)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    (void)now_us;
    (void)ready;
    if (fixture == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    fixture->drive_count++;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_next_event(
    void *transport,
    libp2p_host_transport_event_t *out_event)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (out_event == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (fixture->event_len == 0U)
    {
        (void)memset(out_event, 0, sizeof(*out_event));
        out_event->type = LIBP2P_HOST_TRANSPORT_EVENT_NONE;
        return LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    *out_event = fixture->events[fixture->event_head];
    fixture->event_head = (fixture->event_head + 1U) % HOST_TEST_EVENT_CAP;
    fixture->event_len--;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_listen_multiaddr(
    const void *transport,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const host_test_transport_fixture_t *fixture = (const host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (written == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *written = fixture->listen_multiaddr_len;
    if ((out == NULL) || (out_len < fixture->listen_multiaddr_len))
    {
        return LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    if (fixture->listen_multiaddr_len != 0U)
    {
        (void)memcpy(out, fixture->listen_multiaddr, fixture->listen_multiaddr_len);
    }
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_dial(
    void *transport,
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    void *user_data,
    void **out_attempt)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    (void)user_data;
    if ((fixture == NULL) || (multiaddr == NULL) || (multiaddr_len == 0U) || (out_attempt == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_attempt = fixture->conn;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_open_stream(
    void *transport,
    void *conn,
    void **out_stream)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    if ((fixture == NULL) || (conn == NULL) || (out_stream == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (fixture->open_stream_result != LIBP2P_HOST_OK)
    {
        return fixture->open_stream_result;
    }
    if (fixture->next_stream == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out_stream = fixture->next_stream;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_conn_peer_id(
    const void *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const host_test_conn_t *mock_conn = (const host_test_conn_t *)conn;

    if ((mock_conn == NULL) || (written == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *written = mock_conn->peer_id_len;
    if ((out == NULL) || (out_len < mock_conn->peer_id_len))
    {
        return LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    (void)memcpy(out, mock_conn->peer_id, mock_conn->peer_id_len);
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_conn_peer_identity(
    const void *conn,
    libp2p_host_peer_identity_t *out)
{
    const host_test_conn_t *mock_conn = (const host_test_conn_t *)conn;

    if ((mock_conn == NULL) || (out == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *out = mock_conn->identity;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_conn_remote_multiaddr(
    const void *conn,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    const host_test_conn_t *mock_conn = (const host_test_conn_t *)conn;

    if ((mock_conn == NULL) || (written == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    *written = mock_conn->remote_multiaddr_len;
    if ((out == NULL) || (out_len < mock_conn->remote_multiaddr_len))
    {
        return LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    if (mock_conn->remote_multiaddr_len != 0U)
    {
        (void)memcpy(out, mock_conn->remote_multiaddr, mock_conn->remote_multiaddr_len);
    }
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_conn_close(
    void *transport,
    void *conn,
    uint64_t app_error_code)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    (void)conn;
    (void)app_error_code;
    if (fixture == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    fixture->close_count++;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_conn_release(void *transport, void *conn)
{
    host_test_transport_fixture_t *fixture = (host_test_transport_fixture_t *)transport;

    (void)conn;
    if (fixture == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    fixture->release_count++;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_stream_read(
    void *transport,
    void *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    host_test_stream_t *mock_stream = (host_test_stream_t *)stream;
    size_t available = 0U;
    size_t count = 0U;

    (void)transport;
    if ((mock_stream == NULL) || (out == NULL) || (read_len == NULL) || (fin == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (mock_stream->read_pos == mock_stream->read_len)
    {
        *read_len = 0U;
        *fin = mock_stream->read_fin;
        if (mock_stream->read_fin != 0)
        {
            mock_stream->read_fin = 0;
            return LIBP2P_HOST_OK;
        }
        return LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    available = mock_stream->read_len - mock_stream->read_pos;
    count = (available < out_len) ? available : out_len;
    (void)memcpy(out, &mock_stream->read_buf[mock_stream->read_pos], count);
    mock_stream->read_pos += count;
    *read_len = count;
    *fin =
        ((mock_stream->read_pos == mock_stream->read_len) && (mock_stream->read_fin != 0)) ? 1 : 0;
    if (*fin != 0)
    {
        mock_stream->read_fin = 0;
    }
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_stream_write(
    void *transport,
    void *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    host_test_stream_t *mock_stream = (host_test_stream_t *)stream;

    (void)transport;
    (void)fin;
    if ((mock_stream == NULL) || ((data == NULL) && (data_len != 0U)) || (accepted == NULL))
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    if (data_len > (sizeof(mock_stream->write_buf) - mock_stream->write_len))
    {
        return LIBP2P_HOST_ERR_LIMIT;
    }
    if (data_len != 0U)
    {
        (void)memcpy(&mock_stream->write_buf[mock_stream->write_len], data, data_len);
    }
    mock_stream->write_len += data_len;
    *accepted = data_len;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_stream_finish(void *transport, void *stream)
{
    host_test_stream_t *mock_stream = (host_test_stream_t *)stream;

    (void)transport;
    if (mock_stream == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    mock_stream->finish_count++;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_stream_reset(
    void *transport,
    void *stream,
    uint64_t app_error_code)
{
    host_test_stream_t *mock_stream = (host_test_stream_t *)stream;

    (void)transport;
    (void)app_error_code;
    if (mock_stream == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    mock_stream->reset_count++;
    return LIBP2P_HOST_OK;
}

static inline libp2p_host_err_t host_test_stream_stop_sending(
    void *transport,
    void *stream,
    uint64_t app_error_code)
{
    host_test_stream_t *mock_stream = (host_test_stream_t *)stream;

    (void)transport;
    (void)app_error_code;
    if (mock_stream == NULL)
    {
        return LIBP2P_HOST_ERR_INVALID_ARG;
    }
    mock_stream->stop_count++;
    return LIBP2P_HOST_OK;
}

static inline const libp2p_host_transport_vtable_t *host_test_transport(void)
{
    static const libp2p_host_transport_vtable_t transport =
        {2U,
         "mock",
         host_test_storage_size,
         host_test_storage_align,
         host_test_init,
         host_test_deinit,
         host_test_fd,
         host_test_io_interest,
         host_test_next_deadline,
         host_test_drive,
         host_test_next_event,
         host_test_listen_multiaddr,
         host_test_dial,
         host_test_open_stream,
         host_test_conn_peer_id,
         host_test_conn_remote_multiaddr,
         host_test_conn_peer_identity,
         host_test_conn_close,
         host_test_conn_release,
         host_test_stream_read,
         host_test_stream_write,
         host_test_stream_finish,
         host_test_stream_reset,
         host_test_stream_stop_sending};

    return &transport;
}

#endif /* LIBP2P_TEST_HOST_TEST_SUPPORT_H */
