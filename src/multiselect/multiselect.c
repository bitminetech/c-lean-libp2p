/**
 * @file multiselect.c
 * @brief multistream-select 1.0 implementation.
 */

#include "multiselect/multiselect.h"

#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define MULTISELECT_NEWLINE ((uint8_t)'\n')

static libp2p_multiselect_err_t multiselect_protocols_valid(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count)
{
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if ((protocols == NULL) && (protocol_count != 0U))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        size_t index = 0U;

        for (index = 0U; (index < protocol_count) && (result == LIBP2P_MULTISELECT_OK); index++)
        {
            if ((protocols[index].id == NULL) || (protocols[index].id_len == 0U))
            {
                result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
            }
            else if (protocols[index].id_len > LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES)
            {
                result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
            }
            else
            {
                result = LIBP2P_MULTISELECT_OK;
            }
        }
    }

    return result;
}

static int multiselect_bytes_equal(
    const uint8_t *left,
    size_t left_len,
    const uint8_t *right,
    size_t right_len)
{
    int result = 0;

    if (left_len == right_len)
    {
        if (left_len == 0U)
        {
            result = 1;
        }
        else if ((left != NULL) && (right != NULL) && (memcmp(left, right, left_len) == 0))
        {
            result = 1;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

static int multiselect_is_literal(
    const uint8_t *payload,
    size_t payload_len,
    const char *literal,
    size_t literal_len)
{
    return multiselect_bytes_equal(payload, payload_len, (const uint8_t *)literal, literal_len);
}

static libp2p_multiselect_err_t multiselect_message_metadata(
    const uint8_t *in,
    size_t in_len,
    size_t *payload_offset,
    size_t *payload_len,
    size_t *read_len)
{
    uint64_t message_len_u64 = UINT64_C(0);
    size_t prefix_len = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (payload_offset != NULL)
    {
        *payload_offset = 0U;
    }
    if (payload_len != NULL)
    {
        *payload_len = 0U;
    }
    if (read_len != NULL)
    {
        *read_len = 0U;
    }

    if (in == NULL)
    {
        result =
            (in_len == 0U) ? LIBP2P_MULTISELECT_ERR_TRUNCATED : LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        const libp2p_uvarint_err_t varint_result =
            libp2p_uvarint_decode(in, in_len, &message_len_u64, &prefix_len);

        if (varint_result == LIBP2P_UVARINT_ERR_TRUNCATED)
        {
            result = LIBP2P_MULTISELECT_ERR_TRUNCATED;
        }
        else if (varint_result != LIBP2P_UVARINT_OK)
        {
            result = LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT;
        }
        else if (message_len_u64 > (uint64_t)LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES)
        {
            result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
        }
        else if (message_len_u64 == 0ULL)
        {
            result = LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE;
        }
        else
        {
            const size_t message_len = (size_t)message_len_u64;
            const size_t frame_len = prefix_len + message_len;

            if (in_len < frame_len)
            {
                result = LIBP2P_MULTISELECT_ERR_TRUNCATED;
            }
            else if (in[frame_len - 1U] != MULTISELECT_NEWLINE)
            {
                if (read_len != NULL)
                {
                    *read_len = frame_len;
                }
                result = LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE;
            }
            else
            {
                if (payload_offset != NULL)
                {
                    *payload_offset = prefix_len;
                }
                if (payload_len != NULL)
                {
                    *payload_len = message_len - 1U;
                }
                if (read_len != NULL)
                {
                    *read_len = frame_len;
                }
                result = LIBP2P_MULTISELECT_OK;
            }
        }
    }

    return result;
}

static libp2p_multiselect_err_t multiselect_read_exact(
    libp2p_multiselect_stream_t *stream,
    uint8_t *out,
    size_t out_len)
{
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if ((stream == NULL) || (stream->read_fn == NULL) || ((out == NULL) && (out_len != 0U)))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        size_t total = 0U;

        while ((total < out_len) && (result == LIBP2P_MULTISELECT_OK))
        {
            size_t read_len = 0U;

            result = stream->read_fn(stream->user_data, &out[total], out_len - total, &read_len);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                if ((read_len == 0U) || (read_len > (out_len - total)))
                {
                    result = LIBP2P_MULTISELECT_ERR_IO;
                }
                else
                {
                    total += read_len;
                }
            }
        }
    }

    return result;
}

static libp2p_multiselect_err_t multiselect_write_exact(
    libp2p_multiselect_stream_t *stream,
    const uint8_t *data,
    size_t data_len)
{
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if ((stream == NULL) || (stream->write_fn == NULL) || ((data == NULL) && (data_len != 0U)))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        size_t total = 0U;

        while ((total < data_len) && (result == LIBP2P_MULTISELECT_OK))
        {
            size_t written = 0U;

            result = stream->write_fn(stream->user_data, &data[total], data_len - total, &written);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                if ((written == 0U) || (written > (data_len - total)))
                {
                    result = LIBP2P_MULTISELECT_ERR_IO;
                }
                else
                {
                    total += written;
                }
            }
        }
    }

    return result;
}

static libp2p_multiselect_err_t multiselect_write_two_messages(
    libp2p_multiselect_stream_t *stream,
    const uint8_t *first,
    size_t first_len,
    const uint8_t *second,
    size_t second_len)
{
    uint8_t frame[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES * 2U];
    size_t first_written = 0U;
    size_t second_written = 0U;
    libp2p_multiselect_err_t result =
        libp2p_multiselect_message_encode(first, first_len, frame, sizeof(frame), &first_written);

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = libp2p_multiselect_message_encode(
            second,
            second_len,
            &frame[first_written],
            sizeof(frame) - first_written,
            &second_written);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_write_exact(stream, frame, first_written + second_written);
    }

    return result;
}

static size_t multiselect_find_protocol(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t found = protocol_count;
    size_t index = 0U;

    for (index = 0U; (index < protocol_count) && (found == protocol_count); index++)
    {
        if (multiselect_bytes_equal(
                protocols[index].id,
                protocols[index].id_len,
                payload,
                payload_len) != 0)
        {
            found = index;
        }
    }

    return found;
}

static libp2p_multiselect_err_t multiselect_read_expected_protocol_id(
    libp2p_multiselect_stream_t *stream)
{
    uint8_t payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES];
    size_t payload_len = 0U;
    libp2p_multiselect_err_t result =
        libp2p_multiselect_read_message(stream, payload, sizeof(payload), &payload_len);

    if (result == LIBP2P_MULTISELECT_OK)
    {
        if (multiselect_is_literal(
                payload,
                payload_len,
                LIBP2P_MULTISELECT_PROTOCOL_ID,
                LIBP2P_MULTISELECT_PROTOCOL_ID_LEN) == 0)
        {
            result = LIBP2P_MULTISELECT_ERR_PROTOCOL_MISMATCH;
        }
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_message_size(size_t payload_len, size_t *out_len)
{
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (out_len == NULL)
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else if (payload_len > LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES)
    {
        result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
    }
    else
    {
        const uint64_t message_len = (uint64_t)payload_len + UINT64_C(1);
        const size_t prefix_len = (size_t)libp2p_uvarint_size(message_len);

        *out_len = prefix_len + payload_len + 1U;
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_message_encode(
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((payload == NULL) && (payload_len != 0U))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        result = libp2p_multiselect_message_size(payload_len, &required);
    }

    if (written != NULL)
    {
        *written = required;
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        if ((out == NULL) || (out_len < required))
        {
            result = LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL;
        }
        else
        {
            const uint64_t message_len = (uint64_t)payload_len + UINT64_C(1);
            size_t prefix_len = 0U;

            if (libp2p_uvarint_encode(message_len, out, out_len, &prefix_len) != LIBP2P_UVARINT_OK)
            {
                result = LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT;
            }
            else
            {
                if (payload_len != 0U)
                {
                    (void)memcpy(&out[prefix_len], payload, payload_len);
                }
                out[prefix_len + payload_len] = MULTISELECT_NEWLINE;
                result = LIBP2P_MULTISELECT_OK;
            }
        }
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_message_decode(
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_len,
    size_t *written,
    size_t *read_len)
{
    size_t payload_offset = 0U;
    size_t payload_len = 0U;
    size_t frame_len = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (written != NULL)
    {
        *written = 0U;
    }
    if (read_len != NULL)
    {
        *read_len = 0U;
    }

    result = multiselect_message_metadata(in, in_len, &payload_offset, &payload_len, &frame_len);
    if (result == LIBP2P_MULTISELECT_OK)
    {
        if (written != NULL)
        {
            *written = payload_len;
        }
        if (read_len != NULL)
        {
            *read_len = frame_len;
        }

        if ((payload_len != 0U) && ((out == NULL) || (out_len < payload_len)))
        {
            result = LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL;
        }
        else
        {
            if (payload_len != 0U)
            {
                (void)memcpy(out, &in[payload_offset], payload_len);
            }
            result = LIBP2P_MULTISELECT_OK;
        }
    }
    if ((result != LIBP2P_MULTISELECT_OK) && (read_len != NULL))
    {
        *read_len = frame_len;
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_write_message(
    libp2p_multiselect_stream_t *stream,
    const uint8_t *payload,
    size_t payload_len)
{
    uint8_t frame[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES];
    size_t written = 0U;
    libp2p_multiselect_err_t result =
        libp2p_multiselect_message_encode(payload, payload_len, frame, sizeof(frame), &written);

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_write_exact(stream, frame, written);
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_read_message(
    libp2p_multiselect_stream_t *stream,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    uint8_t prefix[LIBP2P_UVARINT_MAX_BYTES];
    uint8_t message[LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES];
    uint64_t message_len_u64 = UINT64_C(0);
    size_t prefix_len = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((stream == NULL) || (stream->read_fn == NULL))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        size_t index = 0U;
        int done = 0;

        for (index = 0U; (index < (size_t)LIBP2P_UVARINT_MAX_BYTES) && (done == 0); index++)
        {
            result = multiselect_read_exact(stream, &prefix[index], 1U);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                const libp2p_uvarint_err_t varint_result =
                    libp2p_uvarint_decode(prefix, index + 1U, &message_len_u64, &prefix_len);

                if (varint_result == LIBP2P_UVARINT_OK)
                {
                    done = 1;
                }
                else if (varint_result == LIBP2P_UVARINT_ERR_TRUNCATED)
                {
                    result = LIBP2P_MULTISELECT_OK;
                }
                else
                {
                    result = LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT;
                    done = 1;
                }
            }
            else
            {
                done = 1;
            }
        }

        if ((result == LIBP2P_MULTISELECT_OK) && (done == 0))
        {
            result = LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT;
        }
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        if (message_len_u64 > (uint64_t)LIBP2P_MULTISELECT_MAX_MESSAGE_BYTES)
        {
            result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
        }
        else if (message_len_u64 == 0ULL)
        {
            result = LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE;
        }
        else
        {
            const size_t message_len = (size_t)message_len_u64;

            result = multiselect_read_exact(stream, message, message_len);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                if (message[message_len - 1U] != MULTISELECT_NEWLINE)
                {
                    result = LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE;
                }
                else
                {
                    const size_t payload_len = message_len - 1U;

                    if (written != NULL)
                    {
                        *written = payload_len;
                    }

                    if ((payload_len != 0U) && ((out == NULL) || (out_len < payload_len)))
                    {
                        result = LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL;
                    }
                    else
                    {
                        if (payload_len != 0U)
                        {
                            (void)memcpy(out, message, payload_len);
                        }
                        result = LIBP2P_MULTISELECT_OK;
                    }
                }
            }
        }
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_size(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *out_len)
{
    size_t required = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if (out_len == NULL)
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        result = multiselect_protocols_valid(protocols, protocol_count);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        size_t index = 0U;

        for (index = 0U; (index < protocol_count) && (result == LIBP2P_MULTISELECT_OK); index++)
        {
            size_t message_size = 0U;

            result = libp2p_multiselect_message_size(protocols[index].id_len, &message_size);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                if (message_size > (LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES - required))
                {
                    result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
                }
                else
                {
                    required += message_size;
                }
            }
        }
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        *out_len = required;
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_encode(
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t required = 0U;
    libp2p_multiselect_err_t result =
        libp2p_multiselect_ls_response_payload_size(protocols, protocol_count, &required);

    if (written != NULL)
    {
        *written = required;
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        if ((required != 0U) && ((out == NULL) || (out_len < required)))
        {
            result = LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL;
        }
        else
        {
            size_t offset = 0U;
            size_t index = 0U;

            for (index = 0U; (index < protocol_count) && (result == LIBP2P_MULTISELECT_OK); index++)
            {
                size_t message_written = 0U;

                result = libp2p_multiselect_message_encode(
                    protocols[index].id,
                    protocols[index].id_len,
                    &out[offset],
                    out_len - offset,
                    &message_written);
                if (result == LIBP2P_MULTISELECT_OK)
                {
                    offset += message_written;
                }
            }
        }
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_ls_response_payload_decode(
    const uint8_t *payload,
    size_t payload_len,
    libp2p_multiselect_protocol_visit_fn_t visit_fn,
    void *user_data,
    size_t *protocol_count)
{
    size_t count = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (protocol_count != NULL)
    {
        *protocol_count = 0U;
    }

    if ((payload == NULL) && (payload_len != 0U))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else if (payload_len > LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES)
    {
        result = LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE;
    }
    else
    {
        size_t offset = 0U;

        while ((offset < payload_len) && (result == LIBP2P_MULTISELECT_OK))
        {
            size_t payload_offset = 0U;
            size_t protocol_len = 0U;
            size_t frame_len = 0U;

            result = multiselect_message_metadata(
                &payload[offset],
                payload_len - offset,
                &payload_offset,
                &protocol_len,
                &frame_len);
            if (result == LIBP2P_MULTISELECT_OK)
            {
                if (visit_fn != NULL)
                {
                    result = visit_fn(&payload[offset + payload_offset], protocol_len, user_data);
                }
                if (result == LIBP2P_MULTISELECT_OK)
                {
                    count++;
                    offset += frame_len;
                }
            }
        }
    }

    if ((result == LIBP2P_MULTISELECT_OK) && (protocol_count != NULL))
    {
        *protocol_count = count;
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_select_one(
    libp2p_multiselect_stream_t *stream,
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *selected_index)
{
    uint8_t response[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES];
    size_t response_len = 0U;
    size_t index = 0U;
    int selected = 0;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (selected_index != NULL)
    {
        *selected_index = protocol_count;
    }

    if (stream == NULL)
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        result = multiselect_protocols_valid(protocols, protocol_count);
    }

    if ((result == LIBP2P_MULTISELECT_OK) && (protocol_count == 0U))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_write_two_messages(
            stream,
            (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
            LIBP2P_MULTISELECT_PROTOCOL_ID_LEN,
            protocols[0].id,
            protocols[0].id_len);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_read_expected_protocol_id(stream);
    }

    while ((result == LIBP2P_MULTISELECT_OK) && (index < protocol_count) && (selected == 0))
    {
        result = libp2p_multiselect_read_message(stream, response, sizeof(response), &response_len);
        if (result == LIBP2P_MULTISELECT_OK)
        {
            if (multiselect_bytes_equal(
                    response,
                    response_len,
                    protocols[index].id,
                    protocols[index].id_len) != 0)
            {
                if (selected_index != NULL)
                {
                    *selected_index = index;
                }
                selected = 1;
            }
            else if (
                multiselect_is_literal(
                    response,
                    response_len,
                    LIBP2P_MULTISELECT_NA,
                    LIBP2P_MULTISELECT_NA_LEN) != 0)
            {
                index++;
                if (index < protocol_count)
                {
                    result = libp2p_multiselect_write_message(
                        stream,
                        protocols[index].id,
                        protocols[index].id_len);
                }
            }
            else
            {
                result = LIBP2P_MULTISELECT_ERR_UNRECOGNIZED_RESPONSE;
            }
        }
    }

    if ((result == LIBP2P_MULTISELECT_OK) && (selected == 0))
    {
        result = LIBP2P_MULTISELECT_ERR_NOT_AVAILABLE;
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_accept(
    libp2p_multiselect_stream_t *stream,
    const libp2p_multiselect_protocol_t *protocols,
    size_t protocol_count,
    size_t *selected_index)
{
    uint8_t request[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES];
    uint8_t ls_payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES];
    size_t request_len = 0U;
    int selected = 0;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (selected_index != NULL)
    {
        *selected_index = protocol_count;
    }

    if (stream == NULL)
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        result = multiselect_protocols_valid(protocols, protocol_count);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = libp2p_multiselect_write_message(
            stream,
            (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
            LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_read_expected_protocol_id(stream);
    }

    while ((result == LIBP2P_MULTISELECT_OK) && (selected == 0))
    {
        result = libp2p_multiselect_read_message(stream, request, sizeof(request), &request_len);
        if (result == LIBP2P_MULTISELECT_OK)
        {
            if (multiselect_is_literal(
                    request,
                    request_len,
                    LIBP2P_MULTISELECT_LS,
                    LIBP2P_MULTISELECT_LS_LEN) != 0)
            {
                size_t ls_payload_len = 0U;

                result = libp2p_multiselect_ls_response_payload_encode(
                    protocols,
                    protocol_count,
                    ls_payload,
                    sizeof(ls_payload),
                    &ls_payload_len);
                if (result == LIBP2P_MULTISELECT_OK)
                {
                    result = libp2p_multiselect_write_message(stream, ls_payload, ls_payload_len);
                }
            }
            else
            {
                const size_t index =
                    multiselect_find_protocol(protocols, protocol_count, request, request_len);

                if (index < protocol_count)
                {
                    result = libp2p_multiselect_write_message(stream, request, request_len);
                    if (result == LIBP2P_MULTISELECT_OK)
                    {
                        if (selected_index != NULL)
                        {
                            *selected_index = index;
                        }
                        selected = 1;
                    }
                }
                else
                {
                    result = libp2p_multiselect_write_message(
                        stream,
                        (const uint8_t *)LIBP2P_MULTISELECT_NA,
                        LIBP2P_MULTISELECT_NA_LEN);
                }
            }
        }
    }

    return result;
}

libp2p_multiselect_err_t libp2p_multiselect_request_ls(
    libp2p_multiselect_stream_t *stream,
    libp2p_multiselect_protocol_visit_fn_t visit_fn,
    void *user_data,
    size_t *protocol_count)
{
    uint8_t response[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES];
    size_t response_len = 0U;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (protocol_count != NULL)
    {
        *protocol_count = 0U;
    }

    if (stream == NULL)
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        result = multiselect_write_two_messages(
            stream,
            (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
            LIBP2P_MULTISELECT_PROTOCOL_ID_LEN,
            (const uint8_t *)LIBP2P_MULTISELECT_LS,
            LIBP2P_MULTISELECT_LS_LEN);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = multiselect_read_expected_protocol_id(stream);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        result = libp2p_multiselect_read_message(stream, response, sizeof(response), &response_len);
    }

    if (result == LIBP2P_MULTISELECT_OK)
    {
        if (multiselect_is_literal(
                response,
                response_len,
                LIBP2P_MULTISELECT_NA,
                LIBP2P_MULTISELECT_NA_LEN) != 0)
        {
            result = LIBP2P_MULTISELECT_ERR_NOT_AVAILABLE;
        }
        else
        {
            result = libp2p_multiselect_ls_response_payload_decode(
                response,
                response_len,
                visit_fn,
                user_data,
                protocol_count);
        }
    }

    return result;
}
