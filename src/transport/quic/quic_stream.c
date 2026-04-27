/**
 * @file quic_stream.c
 * @brief Public QUIC stream dispatch.
 */

#include "transport/quic/quic_stream.h"

#include "transport/quic/quic_backend.h"

static const libp2p_quic_backend_vtable_t *quic_stream_backend(void)
{
    return libp2p_quic_backend_ngtcp2_awslc();
}

static libp2p_quic_err_t quic_stream_backend_validate(const libp2p_quic_backend_vtable_t *backend)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if ((backend == NULL) || (backend->abi_version != LIBP2P_QUIC_BACKEND_ABI_VERSION))
    {
        result = LIBP2P_QUIC_ERR_BACKEND;
    }
    else if ((backend->conn_open_bidi_stream == NULL) || (backend->conn_accept_stream == NULL) ||
             (backend->stream_id == NULL) || (backend->stream_state == NULL) ||
             (backend->stream_read == NULL) || (backend->stream_write == NULL) ||
             (backend->stream_finish == NULL) || (backend->stream_reset == NULL) ||
             (backend->stream_stop_sending == NULL) || (backend->stream_conn == NULL))
    {
        result = LIBP2P_QUIC_ERR_BACKEND;
    }
    else
    {
        result = LIBP2P_QUIC_OK;
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_open_bidi_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_open_bidi_stream(conn, out_stream);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_conn_accept_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->conn_accept_stream(conn, out_stream);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_id(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_id_t *out_id)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_id(stream, out_id);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_state(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_state_t *out_state)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_state(stream, out_state);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_read(
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_read(stream, out, out_len, read_len, fin);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_write(stream, data, data_len, fin, accepted);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_finish(libp2p_quic_stream_t *stream)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_finish(stream);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_reset(libp2p_quic_stream_t *stream, uint64_t app_error_code)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_reset(stream, app_error_code);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_stop_sending(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_stop_sending(stream, app_error_code);
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_stream_conn(
    libp2p_quic_stream_t *stream,
    libp2p_quic_conn_t **out_conn)
{
    const libp2p_quic_backend_vtable_t *backend = quic_stream_backend();
    libp2p_quic_err_t result = quic_stream_backend_validate(backend);

    if (result == LIBP2P_QUIC_OK)
    {
        result = backend->stream_conn(stream, out_conn);
    }

    return result;
}
