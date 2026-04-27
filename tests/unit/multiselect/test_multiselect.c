#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiselect/multiselect.h"

#define TEST_STREAM_BUF_BYTES 4096U

typedef struct
{
    uint8_t read_buf[TEST_STREAM_BUF_BYTES];
    size_t read_len;
    size_t read_pos;
    uint8_t write_buf[TEST_STREAM_BUF_BYTES];
    size_t write_len;
    size_t max_read_chunk;
    size_t max_write_chunk;
} test_stream_t;

typedef struct
{
    const libp2p_multiselect_protocol_t *expected;
    size_t expected_count;
    size_t seen_count;
} test_visit_state_t;

static size_t test_min_size(size_t left, size_t right)
{
    return (left < right) ? left : right;
}

static libp2p_multiselect_err_t test_read_fn(
    void *user_data,
    uint8_t *out,
    size_t out_len,
    size_t *read_len)
{
    test_stream_t *stream = (test_stream_t *)user_data;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (read_len != NULL)
    {
        *read_len = 0U;
    }

    if ((stream == NULL) || ((out == NULL) && (out_len != 0U)))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else if (stream->read_pos >= stream->read_len)
    {
        result = LIBP2P_MULTISELECT_ERR_WOULD_BLOCK;
    }
    else
    {
        size_t available = stream->read_len - stream->read_pos;
        size_t limit = out_len;

        if ((stream->max_read_chunk != 0U) && (stream->max_read_chunk < limit))
        {
            limit = stream->max_read_chunk;
        }

        available = test_min_size(available, limit);
        if (available != 0U)
        {
            (void)memcpy(out, &stream->read_buf[stream->read_pos], available);
            stream->read_pos += available;
        }
        if (read_len != NULL)
        {
            *read_len = available;
        }
    }

    return result;
}

static libp2p_multiselect_err_t test_write_fn(
    void *user_data,
    const uint8_t *data,
    size_t data_len,
    size_t *written)
{
    test_stream_t *stream = (test_stream_t *)user_data;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if (written != NULL)
    {
        *written = 0U;
    }

    if ((stream == NULL) || ((data == NULL) && (data_len != 0U)))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else if (stream->write_len >= sizeof(stream->write_buf))
    {
        result = LIBP2P_MULTISELECT_ERR_IO;
    }
    else
    {
        size_t available = sizeof(stream->write_buf) - stream->write_len;
        size_t limit = data_len;

        if ((stream->max_write_chunk != 0U) && (stream->max_write_chunk < limit))
        {
            limit = stream->max_write_chunk;
        }

        available = test_min_size(available, limit);
        if (available != 0U)
        {
            (void)memcpy(&stream->write_buf[stream->write_len], data, available);
            stream->write_len += available;
        }
        if (written != NULL)
        {
            *written = available;
        }
    }

    return result;
}

static libp2p_multiselect_stream_t test_stream_view(test_stream_t *stream)
{
    libp2p_multiselect_stream_t view;

    view.read_fn = test_read_fn;
    view.write_fn = test_write_fn;
    view.user_data = stream;
    return view;
}

static void test_append_bytes(
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    const uint8_t *data,
    size_t data_len)
{
    assert(out != NULL);
    assert(out_len != NULL);
    assert(data != NULL);
    assert((*out_len + data_len) <= out_cap);
    (void)memcpy(&out[*out_len], data, data_len);
    *out_len += data_len;
}

static void test_append_message(
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t written = 0U;

    assert(out != NULL);
    assert(out_len != NULL);
    assert(
        libp2p_multiselect_message_encode(
            payload,
            payload_len,
            &out[*out_len],
            out_cap - *out_len,
            &written) == LIBP2P_MULTISELECT_OK);
    *out_len += written;
}

static libp2p_multiselect_err_t test_visit_protocol(
    const uint8_t *protocol_id,
    size_t protocol_id_len,
    void *user_data)
{
    test_visit_state_t *state = (test_visit_state_t *)user_data;
    libp2p_multiselect_err_t result = LIBP2P_MULTISELECT_OK;

    if ((state == NULL) || (state->seen_count >= state->expected_count))
    {
        result = LIBP2P_MULTISELECT_ERR_INVALID_ARG;
    }
    else
    {
        const libp2p_multiselect_protocol_t *expected = &state->expected[state->seen_count];

        assert(expected->id_len == protocol_id_len);
        assert(memcmp(expected->id, protocol_id, protocol_id_len) == 0);
        state->seen_count++;
    }

    return result;
}

static void multiselect_test_message_encode_decode(void)
{
    static const uint8_t na_payload[] = {'n', 'a'};
    static const uint8_t na_frame[] = {0x03U, 'n', 'a', '\n'};
    static const uint8_t empty_frame[] = {0x01U, '\n'};
    uint8_t frame[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES] = {0U};
    uint8_t decoded[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    size_t written = 0U;
    size_t read_len = 0U;
    size_t required = 0U;

    assert(libp2p_multiselect_message_size(sizeof(na_payload), &required) == LIBP2P_MULTISELECT_OK);
    assert(required == sizeof(na_frame));

    assert(
        libp2p_multiselect_message_encode(NULL, 0U, frame, sizeof(frame), &written) ==
        LIBP2P_MULTISELECT_OK);
    assert(written == sizeof(empty_frame));
    assert(memcmp(frame, empty_frame, sizeof(empty_frame)) == 0);

    assert(
        libp2p_multiselect_message_encode(na_payload, sizeof(na_payload), NULL, 0U, &written) ==
        LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL);
    assert(written == sizeof(na_frame));

    assert(
        libp2p_multiselect_message_encode(
            na_payload,
            sizeof(na_payload),
            frame,
            sizeof(frame),
            &written) == LIBP2P_MULTISELECT_OK);
    assert(written == sizeof(na_frame));
    assert(memcmp(frame, na_frame, sizeof(na_frame)) == 0);

    assert(
        libp2p_multiselect_message_decode(
            frame,
            written,
            decoded,
            sizeof(decoded),
            &required,
            &read_len) == LIBP2P_MULTISELECT_OK);
    assert(required == sizeof(na_payload));
    assert(read_len == sizeof(na_frame));
    assert(memcmp(decoded, na_payload, sizeof(na_payload)) == 0);
}

static void multiselect_test_message_decode_errors(void)
{
    static const uint8_t non_minimal[] = {0x83U, 0x00U, 'n', 'a', '\n'};
    static const uint8_t oversized[] = {0x81U, 0x08U};
    static const uint8_t truncated_varint[] = {0x80U};
    static const uint8_t truncated_payload[] = {0x03U, 'n'};
    static const uint8_t missing_newline[] = {0x03U, 'n', 'a', '!'};
    static const uint8_t zero_length[] = {0x00U};
    static const uint8_t valid[] = {0x03U, 'n', 'a', '\n'};
    uint8_t out[1] = {0U};
    size_t written = 0U;
    size_t read_len = 0U;

    assert(
        libp2p_multiselect_message_decode(
            non_minimal,
            sizeof(non_minimal),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_MALFORMED_VARINT);
    assert(
        libp2p_multiselect_message_decode(
            oversized,
            sizeof(oversized),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE);
    assert(
        libp2p_multiselect_message_decode(
            truncated_varint,
            sizeof(truncated_varint),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_TRUNCATED);
    assert(
        libp2p_multiselect_message_decode(
            truncated_payload,
            sizeof(truncated_payload),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_TRUNCATED);
    assert(
        libp2p_multiselect_message_decode(
            missing_newline,
            sizeof(missing_newline),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE);
    assert(read_len == sizeof(missing_newline));
    assert(
        libp2p_multiselect_message_decode(
            zero_length,
            sizeof(zero_length),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_MISSING_NEWLINE);

    assert(
        libp2p_multiselect_message_decode(
            valid,
            sizeof(valid),
            out,
            sizeof(out),
            &written,
            &read_len) == LIBP2P_MULTISELECT_ERR_BUF_TOO_SMALL);
    assert(written == 2U);
    assert(read_len == sizeof(valid));

    assert(
        libp2p_multiselect_message_encode(
            (const uint8_t *)"x",
            LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES + 1U,
            out,
            sizeof(out),
            &written) == LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE);
}

static void multiselect_test_stream_read_write_partial(void)
{
    static const uint8_t payload[] = {'/', 'p', '/', '1'};
    uint8_t decoded[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    test_stream_t stream = {{0U}, 0U, 0U, {0U}, 0U, 1U, 1U};
    libp2p_multiselect_stream_t view = test_stream_view(&stream);
    size_t written = 0U;

    assert(
        libp2p_multiselect_write_message(&view, payload, sizeof(payload)) == LIBP2P_MULTISELECT_OK);
    assert(stream.write_len == 6U);

    test_append_bytes(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        stream.write_buf,
        stream.write_len);

    assert(
        libp2p_multiselect_read_message(&view, decoded, sizeof(decoded), &written) ==
        LIBP2P_MULTISELECT_OK);
    assert(written == sizeof(payload));
    assert(memcmp(decoded, payload, sizeof(payload)) == 0);
}

static void multiselect_test_ls_payload(void)
{
    static const uint8_t proto_a[] = "/ipfs/kad/0.2.3";
    static const uint8_t proto_b[] = "/ipfs/kad/1.0.0";
    static const libp2p_multiselect_protocol_t protocols[] =
        {{proto_a, sizeof(proto_a) - 1U}, {proto_b, sizeof(proto_b) - 1U}};
    uint8_t payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    uint8_t too_large_id[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    libp2p_multiselect_protocol_t too_large_protocol = {too_large_id, sizeof(too_large_id)};
    test_visit_state_t state = {protocols, 2U, 0U};
    size_t payload_len = 0U;
    size_t count = 0U;
    size_t index = 0U;

    for (index = 0U; index < sizeof(too_large_id); index++)
    {
        too_large_id[index] = 'x';
    }

    assert(
        libp2p_multiselect_ls_response_payload_size(protocols, 2U, &payload_len) ==
        LIBP2P_MULTISELECT_OK);
    assert(payload_len == 34U);

    assert(
        libp2p_multiselect_ls_response_payload_encode(
            protocols,
            2U,
            payload,
            sizeof(payload),
            &payload_len) == LIBP2P_MULTISELECT_OK);
    assert(payload_len == 34U);

    assert(
        libp2p_multiselect_ls_response_payload_decode(
            payload,
            payload_len,
            test_visit_protocol,
            &state,
            &count) == LIBP2P_MULTISELECT_OK);
    assert(count == 2U);
    assert(state.seen_count == 2U);

    payload_len = 17U;
    assert(
        libp2p_multiselect_ls_response_payload_encode(NULL, 0U, NULL, 0U, &payload_len) ==
        LIBP2P_MULTISELECT_OK);
    assert(payload_len == 0U);

    assert(
        libp2p_multiselect_ls_response_payload_size(&too_large_protocol, 1U, &payload_len) ==
        LIBP2P_MULTISELECT_ERR_MESSAGE_TOO_LARGE);
}

static void multiselect_test_select_one_success_first(void)
{
    static const uint8_t proto[] = "/proto/1.0.0";
    static const libp2p_multiselect_protocol_t protocols[] = {{proto, sizeof(proto) - 1U}};
    test_stream_t stream = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    libp2p_multiselect_stream_t view = test_stream_view(&stream);
    uint8_t expected_write[128] = {0U};
    size_t expected_write_len = 0U;
    size_t selected = 99U;

    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        proto,
        sizeof(proto) - 1U);

    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        proto,
        sizeof(proto) - 1U);

    assert(libp2p_multiselect_select_one(&view, protocols, 1U, &selected) == LIBP2P_MULTISELECT_OK);
    assert(selected == 0U);
    assert(stream.write_len == expected_write_len);
    assert(memcmp(stream.write_buf, expected_write, expected_write_len) == 0);
}

static void multiselect_test_select_one_fallback_and_errors(void)
{
    static const uint8_t bad[] = "/bad/1.0.0";
    static const uint8_t good[] = "/good/1.0.0";
    static const uint8_t weird[] = "weird";
    static const libp2p_multiselect_protocol_t protocols[] =
        {{bad, sizeof(bad) - 1U}, {good, sizeof(good) - 1U}};
    test_stream_t stream = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    test_stream_t mismatch = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    test_stream_t unrecognized = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    test_stream_t unavailable = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    libp2p_multiselect_stream_t view = test_stream_view(&stream);
    libp2p_multiselect_stream_t mismatch_view = test_stream_view(&mismatch);
    libp2p_multiselect_stream_t unrecognized_view = test_stream_view(&unrecognized);
    libp2p_multiselect_stream_t unavailable_view = test_stream_view(&unavailable);
    size_t selected = 99U;

    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        good,
        sizeof(good) - 1U);

    assert(libp2p_multiselect_select_one(&view, protocols, 2U, &selected) == LIBP2P_MULTISELECT_OK);
    assert(selected == 1U);

    test_append_message(
        mismatch.read_buf,
        sizeof(mismatch.read_buf),
        &mismatch.read_len,
        bad,
        sizeof(bad) - 1U);
    assert(
        libp2p_multiselect_select_one(&mismatch_view, protocols, 2U, &selected) ==
        LIBP2P_MULTISELECT_ERR_PROTOCOL_MISMATCH);

    test_append_message(
        unrecognized.read_buf,
        sizeof(unrecognized.read_buf),
        &unrecognized.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        unrecognized.read_buf,
        sizeof(unrecognized.read_buf),
        &unrecognized.read_len,
        weird,
        sizeof(weird) - 1U);
    assert(
        libp2p_multiselect_select_one(&unrecognized_view, protocols, 2U, &selected) ==
        LIBP2P_MULTISELECT_ERR_UNRECOGNIZED_RESPONSE);

    test_append_message(
        unavailable.read_buf,
        sizeof(unavailable.read_buf),
        &unavailable.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        unavailable.read_buf,
        sizeof(unavailable.read_buf),
        &unavailable.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN);
    test_append_message(
        unavailable.read_buf,
        sizeof(unavailable.read_buf),
        &unavailable.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN);
    assert(
        libp2p_multiselect_select_one(&unavailable_view, protocols, 2U, &selected) ==
        LIBP2P_MULTISELECT_ERR_NOT_AVAILABLE);
}

static void multiselect_test_accept_ls_na_and_success(void)
{
    static const uint8_t supported[] = "/supported/1.0.0";
    static const uint8_t unsupported[] = "/unsupported/1.0.0";
    static const libp2p_multiselect_protocol_t protocols[] = {{supported, sizeof(supported) - 1U}};
    test_stream_t stream = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    libp2p_multiselect_stream_t view = test_stream_view(&stream);
    uint8_t expected_write[256] = {0U};
    uint8_t ls_payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    size_t expected_write_len = 0U;
    size_t ls_payload_len = 0U;
    size_t selected = 99U;

    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_LS,
        LIBP2P_MULTISELECT_LS_LEN);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        unsupported,
        sizeof(unsupported) - 1U);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        supported,
        sizeof(supported) - 1U);

    assert(
        libp2p_multiselect_ls_response_payload_encode(
            protocols,
            1U,
            ls_payload,
            sizeof(ls_payload),
            &ls_payload_len) == LIBP2P_MULTISELECT_OK);

    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        ls_payload,
        ls_payload_len);
    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN);
    test_append_message(
        expected_write,
        sizeof(expected_write),
        &expected_write_len,
        supported,
        sizeof(supported) - 1U);

    assert(libp2p_multiselect_accept(&view, protocols, 1U, &selected) == LIBP2P_MULTISELECT_OK);
    assert(selected == 0U);
    assert(stream.write_len == expected_write_len);
    assert(memcmp(stream.write_buf, expected_write, expected_write_len) == 0);
}

static void multiselect_test_request_ls(void)
{
    static const uint8_t proto_a[] = "/a/1.0.0";
    static const uint8_t proto_b[] = "/b/1.0.0";
    static const libp2p_multiselect_protocol_t protocols[] =
        {{proto_a, sizeof(proto_a) - 1U}, {proto_b, sizeof(proto_b) - 1U}};
    test_stream_t stream = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    test_stream_t unavailable = {{0U}, 0U, 0U, {0U}, 0U, 0U, 0U};
    libp2p_multiselect_stream_t view = test_stream_view(&stream);
    libp2p_multiselect_stream_t unavailable_view = test_stream_view(&unavailable);
    uint8_t ls_payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    test_visit_state_t state = {protocols, 2U, 0U};
    size_t ls_payload_len = 0U;
    size_t count = 0U;

    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    assert(
        libp2p_multiselect_ls_response_payload_encode(
            protocols,
            2U,
            ls_payload,
            sizeof(ls_payload),
            &ls_payload_len) == LIBP2P_MULTISELECT_OK);
    test_append_message(
        stream.read_buf,
        sizeof(stream.read_buf),
        &stream.read_len,
        ls_payload,
        ls_payload_len);

    assert(
        libp2p_multiselect_request_ls(&view, test_visit_protocol, &state, &count) ==
        LIBP2P_MULTISELECT_OK);
    assert(count == 2U);
    assert(state.seen_count == 2U);

    test_append_message(
        unavailable.read_buf,
        sizeof(unavailable.read_buf),
        &unavailable.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN);
    test_append_message(
        unavailable.read_buf,
        sizeof(unavailable.read_buf),
        &unavailable.read_len,
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN);
    count = 7U;
    assert(
        libp2p_multiselect_request_ls(&unavailable_view, NULL, NULL, &count) ==
        LIBP2P_MULTISELECT_ERR_NOT_AVAILABLE);
    assert(count == 0U);
}

int main(void)
{
    multiselect_test_message_encode_decode();
    multiselect_test_message_decode_errors();
    multiselect_test_stream_read_write_partial();
    multiselect_test_ls_payload();
    multiselect_test_select_one_success_first();
    multiselect_test_select_one_fallback_and_errors();
    multiselect_test_accept_ls_na_and_success();
    multiselect_test_request_ls();
    return 0;
}
