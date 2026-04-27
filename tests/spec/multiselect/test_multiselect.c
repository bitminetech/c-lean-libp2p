#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiselect/multiselect.h"

/*
 * The upstream multistream-select repository currently ships prose examples but
 * no machine-readable vector files. These vectors are the README examples
 * encoded as length-prefixed messages.
 */

static void multiselect_spec_check_message(
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *expected,
    size_t expected_len)
{
    uint8_t encoded[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES] = {0U};
    uint8_t decoded[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    size_t written = 0U;
    size_t read_len = 0U;

    assert(
        libp2p_multiselect_message_encode(
            payload,
            payload_len,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTISELECT_OK);
    assert(written == expected_len);
    assert(memcmp(encoded, expected, expected_len) == 0);

    assert(
        libp2p_multiselect_message_decode(
            expected,
            expected_len,
            decoded,
            sizeof(decoded),
            &written,
            &read_len) == LIBP2P_MULTISELECT_OK);
    assert(written == payload_len);
    assert(read_len == expected_len);
    assert(memcmp(decoded, payload, payload_len) == 0);
}

static void multiselect_spec_test_canonical_messages(void)
{
    static const uint8_t multistream_frame[] = "\x13/multistream/1.0.0\n";
    static const uint8_t na_frame[] = "\x03na\n";
    static const uint8_t ls_frame[] = "\x03ls\n";

    multiselect_spec_check_message(
        (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
        LIBP2P_MULTISELECT_PROTOCOL_ID_LEN,
        multistream_frame,
        sizeof(multistream_frame) - 1U);
    multiselect_spec_check_message(
        (const uint8_t *)LIBP2P_MULTISELECT_NA,
        LIBP2P_MULTISELECT_NA_LEN,
        na_frame,
        sizeof(na_frame) - 1U);
    multiselect_spec_check_message(
        (const uint8_t *)LIBP2P_MULTISELECT_LS,
        LIBP2P_MULTISELECT_LS_LEN,
        ls_frame,
        sizeof(ls_frame) - 1U);
}

static void multiselect_spec_test_pipelined_selection_vector(void)
{
    static const uint8_t protocol[] = "/ipfs/kad/1.0.0";
    static const uint8_t expected_packet[] = "\x13/multistream/1.0.0\n"
                                             "\x10/ipfs/kad/1.0.0\n";
    uint8_t packet[128] = {0U};
    size_t packet_len = 0U;
    size_t written = 0U;

    assert(
        libp2p_multiselect_message_encode(
            (const uint8_t *)LIBP2P_MULTISELECT_PROTOCOL_ID,
            LIBP2P_MULTISELECT_PROTOCOL_ID_LEN,
            packet,
            sizeof(packet),
            &written) == LIBP2P_MULTISELECT_OK);
    packet_len += written;

    assert(
        libp2p_multiselect_message_encode(
            protocol,
            sizeof(protocol) - 1U,
            &packet[packet_len],
            sizeof(packet) - packet_len,
            &written) == LIBP2P_MULTISELECT_OK);
    packet_len += written;

    assert(packet_len == (sizeof(expected_packet) - 1U));
    assert(memcmp(packet, expected_packet, packet_len) == 0);
}

static void multiselect_spec_test_ls_response_vector(void)
{
    static const uint8_t kad_023[] = "/ipfs/kad/0.2.3";
    static const uint8_t kad_100[] = "/ipfs/kad/1.0.0";
    static const uint8_t bitswap_043[] = "/ipfs/bitswap/0.4.3";
    static const uint8_t bitswap_100[] = "/ipfs/bitswap/1.0.0";
    static const libp2p_multiselect_protocol_t protocols[] =
        {{kad_023, sizeof(kad_023) - 1U},
         {kad_100, sizeof(kad_100) - 1U},
         {bitswap_043, sizeof(bitswap_043) - 1U},
         {bitswap_100, sizeof(bitswap_100) - 1U}};
    static const uint8_t expected_payload[] = "\x10/ipfs/kad/0.2.3\n"
                                              "\x10/ipfs/kad/1.0.0\n"
                                              "\x14/ipfs/bitswap/0.4.3\n"
                                              "\x14/ipfs/bitswap/1.0.0\n";
    static const uint8_t expected_response[] = "\x4d"
                                               "\x10/ipfs/kad/0.2.3\n"
                                               "\x10/ipfs/kad/1.0.0\n"
                                               "\x14/ipfs/bitswap/0.4.3\n"
                                               "\x14/ipfs/bitswap/1.0.0\n"
                                               "\n";
    uint8_t payload[LIBP2P_MULTISELECT_MAX_PAYLOAD_BYTES] = {0U};
    uint8_t response[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES] = {0U};
    size_t payload_len = 0U;
    size_t response_len = 0U;
    size_t count = 0U;

    assert(
        libp2p_multiselect_ls_response_payload_encode(
            protocols,
            sizeof(protocols) / sizeof(protocols[0]),
            payload,
            sizeof(payload),
            &payload_len) == LIBP2P_MULTISELECT_OK);
    assert(payload_len == (sizeof(expected_payload) - 1U));
    assert(memcmp(payload, expected_payload, payload_len) == 0);

    assert(
        libp2p_multiselect_message_encode(
            payload,
            payload_len,
            response,
            sizeof(response),
            &response_len) == LIBP2P_MULTISELECT_OK);
    assert(response_len == (sizeof(expected_response) - 1U));
    assert(memcmp(response, expected_response, response_len) == 0);

    assert(
        libp2p_multiselect_ls_response_payload_decode(payload, payload_len, NULL, NULL, &count) ==
        LIBP2P_MULTISELECT_OK);
    assert(count == 4U);
}

static void multiselect_spec_test_empty_ls_response_vector(void)
{
    static const uint8_t expected_response[] = "\x01\n";
    uint8_t response[LIBP2P_MULTISELECT_MAX_ENCODED_MESSAGE_BYTES] = {0U};
    size_t payload_len = 99U;
    size_t response_len = 0U;
    size_t count = 99U;

    assert(
        libp2p_multiselect_ls_response_payload_encode(NULL, 0U, NULL, 0U, &payload_len) ==
        LIBP2P_MULTISELECT_OK);
    assert(payload_len == 0U);

    assert(
        libp2p_multiselect_message_encode(NULL, 0U, response, sizeof(response), &response_len) ==
        LIBP2P_MULTISELECT_OK);
    assert(response_len == (sizeof(expected_response) - 1U));
    assert(memcmp(response, expected_response, response_len) == 0);

    assert(
        libp2p_multiselect_ls_response_payload_decode(NULL, 0U, NULL, NULL, &count) ==
        LIBP2P_MULTISELECT_OK);
    assert(count == 0U);
}

int main(void)
{
    multiselect_spec_test_canonical_messages();
    multiselect_spec_test_pipelined_selection_vector();
    multiselect_spec_test_ls_response_vector();
    multiselect_spec_test_empty_ls_response_vector();
    return 0;
}
