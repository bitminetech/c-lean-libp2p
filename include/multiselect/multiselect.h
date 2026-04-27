/**
 * @file multiselect.h
 * @brief libp2p multistream-select 1.0 protocol negotiation.
 *
 * multistream-select negotiates the protocol spoken on a bidirectional byte
 * stream. Messages are unsigned-varint length-prefixed UTF-8 byte strings with
 * a trailing newline included in the length. The c-lean-libp2p implementation
 * keeps the transport boundary generic: callers provide read/write callbacks,
 * so the same negotiation code can run over QUIC streams or test streams.
 *
 * @see https://github.com/multiformats/multistream-select
 * @see https://github.com/libp2p/specs/blob/master/connections/README.md#multistream-select
 */

#ifndef LIBP2P_MULTISELECT_H
#define LIBP2P_MULTISELECT_H

#include <stddef.h>
#include <stdint.h>

/** multistream-select protocol id. */
#define LIBP2P_MULTISELECT_PROTOCOL_ID "/multistream/1.0.0"

/** Length of LIBP2P_MULTISELECT_PROTOCOL_ID, excluding the trailing NUL. */
#define LIBP2P_MULTISELECT_PROTOCOL_ID_LEN 18U

/** Not-available response payload. */
#define LIBP2P_MULTISELECT_NA "na"

/** Length of LIBP2P_MULTISELECT_NA, excluding the trailing NUL. */
#define LIBP2P_MULTISELECT_NA_LEN 2U

/** Optional list request payload. */
#define LIBP2P_MULTISELECT_LS "ls"

/** Length of LIBP2P_MULTISELECT_LS, excluding the trailing NUL. */
#define LIBP2P_MULTISELECT_LS_LEN 2U

/**
 * Maximum multistream message length value in bytes, including the trailing
 * newline. This follows the de-facto go-multistream interoperability limit.
 */
#define LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES 1024U

/** Maximum payload bytes in a single multistream message, excluding newline. */
#define LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES (LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES - 1U)

/** Maximum bytes emitted for a valid encoded message. */
#define LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES (LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES + 2U)

/** Error codes returned by multiselect operations. */
typedef enum
{
    LIBP2P_MULTISELECT_OK = 0,
    LIBP2P_MULTISELECT_ERR_INVALID_ARG,
    LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL,
    LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE,
    LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT,
    LIBP2P_MULTISELECT_ERR_TRUNCATED,
    LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE,
    LIBP2P_MULTISELECT_ERR_PROTOCOL_MISMATCH,
    LIBP2P_MULTISELECT_ERR_NOT_AVAILABLE,
    LIBP2P_MULTISELECT_ERR_UNRECOGNIZED_RESPONSE,
    LIBP2P_MULTISELECT_ERR_IO,
    LIBP2P_MULTISELECT_ERR_WOULD_BLOCK
} libp2p_multiselect_err_t;

/** Immutable protocol id byte span. */
typedef struct
{
    const uint8_t *id;
    size_t id_len;
} libp2p_multiselect_protocol_t;

/**
 * Read callback for a bidirectional byte stream.
 *
 * The callback may return fewer bytes than requested. Returning OK with zero
 * bytes is treated as an I/O error by the synchronous helpers.
 */
typedef libp2p_multiselect_err_t (
    *libp2p_multiselect_read_fn_t)(void *user_data, uint8_t *out, size_t out_len, size_t *read_len);

/** Write callback for a bidirectional byte stream. */
typedef libp2p_multiselect_err_t (*libp2p_multiselect_write_fn_t)(
    void *user_data,
    const uint8_t *data,
    size_t data_len,
    size_t *written);

/** Generic byte-stream adapter used by the negotiation helpers. */
typedef struct
{
    libp2p_multiselect_read_fn_t read_fn;
    libp2p_multiselect_write_fn_t write_fn;
    void *user_data;
} libp2p_multiselect_stream_t;

/** Visitor used while decoding an ls response payload. */
typedef libp2p_multiselect_err_t (*libp2p_multiselect_protocol_visit_fn_t)(
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    void *user_data);

/**
 * Return the encoded size of a single multistream message.
 *
 * @param[in]  payload_len  Message payload length, excluding the newline.
 * @param[out] out_len      Required encoded frame length in bytes.
 */
libp2p_multiselect_err_t libp2p_multiselect_message_size(size_t payload_len, size_t *out_len);

/**
 * Encode one multistream message as varint(length) + payload + '\n'.
 *
 * Passing out=NULL/out_len=0 returns ERR_BUF_TOO_SMALL with *written set to the
 * required encoded size.
 */
libp2p_multiselect_err_t libp2p_multiselect_message_encode(
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Decode one multistream message from a byte buffer.
 *
 * The decoded payload excludes the trailing newline. *read_len receives the
 * number of input bytes consumed when the frame is complete, including on
 * ERR_BUF_TOO_SMALL.
 */
libp2p_multiselect_err_t libp2p_multiselect_message_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    size_t *read_len);

/** Write one framed multistream message to a generic stream. */
libp2p_multiselect_err_t libp2p_multiselect_write_message(
    libp2p_multiselect_stream_t *stream,
    const uint8_t *payload,
    size_t payload_len);

/** Read one framed multistream message from a generic stream. */
libp2p_multiselect_err_t libp2p_multiselect_read_message(
    libp2p_multiselect_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/** Measure the payload of an ls response containing the given protocols. */
libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_size(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *out_len);

/** Encode the payload of an ls response as embedded multistream messages. */
libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_encode(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/** Decode an ls response payload and visit each embedded protocol id. */
libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_decode(
    const uint8_t *payload,
    size_t payload_len,
    libp2p_multiselect_protocol_visit_fn_t visit_fn,
    void *user_data,
    size_t *protocol_count);

/**
 * Initiator-side protocol selection.
 *
 * The first candidate is pipelined with the multistream-select protocol id, as
 * recommended by the spec. Later candidates are sent after an "na" response.
 */
libp2p_multiselect_err_t libp2p_multiselect_select_one(
    libp2p_multiselect_stream_t *stream,
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *selected_index);

/**
 * Responder-side protocol negotiation.
 *
 * Handles the optional "ls" command by returning the supplied protocol list.
 * Supported protocol ids are matched by exact byte equality and echoed back.
 */
libp2p_multiselect_err_t libp2p_multiselect_accept(
    libp2p_multiselect_stream_t *stream,
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *selected_index);

/**
 * Initiator-side optional "ls" request.
 *
 * Sends the multistream-select protocol id and "ls" request, then decodes the
 * responder's list payload with visit_fn.
 */
libp2p_multiselect_err_t libp2p_multiselect_request_ls(
    libp2p_multiselect_stream_t *stream,
    libp2p_multiselect_protocol_visit_fn_t visit_fn,
    void *user_data,
    size_t *protocol_count);

#endif /* LIBP2P_MULTISELECT_H */
