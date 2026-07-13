/**
 * @file quic_stream.h
 * @brief Reliable byte-stream API for libp2p over QUIC.
 *
 * The initial production scope exposes bidirectional streams only. HTTP/3,
 * WebTransport, unidirectional streams, and 0-RTT streams are outside the
 * first c-lean-libp2p QUIC API.
 *
 * QUIC already provides secure stream multiplexing for this transport. There is
 * no yamux/mplex negotiation at the QUIC transport layer; higher-level libp2p
 * protocols are negotiated on each opened stream.
 */

#ifndef LIBP2P_QUIC_STREAM_H
#define LIBP2P_QUIC_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic_types.h"

/**
 * Open a locally initiated bidirectional stream.
 *
 * Returns LIBP2P_QUIC_ERR_WOULD_BLOCK if the peer's stream limit is exhausted.
 */
libp2p_quic_err_t libp2p_quic_conn_open_bidi_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream);

/**
 * Accept the next peer-initiated bidirectional stream.
 *
 * Returns LIBP2P_QUIC_ERR_WOULD_BLOCK when no stream is currently pending.
 */
libp2p_quic_err_t libp2p_quic_conn_accept_stream(
    libp2p_quic_conn_t *conn,
    libp2p_quic_stream_t **out_stream);

/**
 * Return a stream's QUIC stream ID.
 */
libp2p_quic_err_t libp2p_quic_stream_id(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_id_t *out_id);

/**
 * Return a stream's current high-level state.
 */
libp2p_quic_err_t libp2p_quic_stream_state(
    const libp2p_quic_stream_t *stream,
    libp2p_quic_stream_state_t *out_state);

/**
 * Read ordered bytes from a stream.
 *
 * @param[out] read_len  Bytes copied to out.
 * @param[out] fin       Non-zero when the peer's send side has finished.
 * @return LIBP2P_QUIC_OK on bytes or FIN,
 *         LIBP2P_QUIC_ERR_WOULD_BLOCK when no bytes are currently available,
 *         LIBP2P_QUIC_ERR_CLOSED after buffered bytes from a terminal stream are consumed.
 */
libp2p_quic_err_t libp2p_quic_stream_read(
    libp2p_quic_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *read_len,
    int *fin);

/**
 * Queue ordered bytes for transmission on a stream.
 *
 * @param[in]  fin       Non-zero to finish the local send side after data.
 * @param[out] accepted  Bytes accepted by the transport send buffer.
 * @return LIBP2P_QUIC_OK on success,
 *         LIBP2P_QUIC_ERR_WOULD_BLOCK when no send buffer is available.
 */
libp2p_quic_err_t libp2p_quic_stream_write(
    libp2p_quic_stream_t *stream,
    const uint8_t *data,
    size_t data_len,
    int fin,
    size_t *accepted);

/**
 * Finish the local send side of a stream.
 */
libp2p_quic_err_t libp2p_quic_stream_finish(libp2p_quic_stream_t *stream);

/**
 * Reset the local send side with an application error code.
 */
libp2p_quic_err_t libp2p_quic_stream_reset(libp2p_quic_stream_t *stream, uint64_t app_error_code);

/**
 * Request that the peer stop sending on this stream.
 */
libp2p_quic_err_t libp2p_quic_stream_stop_sending(
    libp2p_quic_stream_t *stream,
    uint64_t app_error_code);

/**
 * Return the owning connection for a stream.
 */
libp2p_quic_err_t libp2p_quic_stream_conn(
    libp2p_quic_stream_t *stream,
    libp2p_quic_conn_t **out_conn);

#endif /* LIBP2P_QUIC_STREAM_H */
