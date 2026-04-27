#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol/identify/identify.h"

static void identify_spec_test_protocol_ids(void)
{
    assert(strlen(LIBP2P_IDENTIFY_PROTOCOL_ID) == LIBP2P_IDENTIFY_PROTOCOL_ID_LEN);
    assert(strcmp(LIBP2P_IDENTIFY_PROTOCOL_ID, "/ipfs/id/1.0.0") == 0);
    assert(strlen(LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID) == LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID_LEN);
    assert(strcmp(LIBP2P_IDENTIFY_PUSH_PROTOCOL_ID, "/ipfs/id/push/1.0.0") == 0);
}

static void identify_spec_test_canonical_message_encoding(void)
{
    static const uint8_t public_key[] = {0x08U, 0x02U};
    static const uint8_t addr[] =
        {0x04U, 0x7FU, 0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U};
    static const uint8_t protocol_version[] = "ipfs/0.1.0";
    static const uint8_t agent_version[] = "c-lean-libp2p/test";
    static const uint8_t identify_id[] = LIBP2P_IDENTIFY_PROTOCOL_ID;
    static const uint8_t ping_id[] = "/ipfs/ping/1.0.0";
    static const uint8_t expected[] = {0x0AU, 0x02U, 0x08U, 0x02U, 0x12U, 0x0BU, 0x04U, 0x7FU,
                                       0x00U, 0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU,
                                       0x03U, 0x1AU, 0x0EU, '/',   'i',   'p',   'f',   's',
                                       '/',   'i',   'd',   '/',   '1',   '.',   '0',   '.',
                                       '0',   0x1AU, 0x10U, '/',   'i',   'p',   'f',   's',
                                       '/',   'p',   'i',   'n',   'g',   '/',   '1',   '.',
                                       '0',   '.',   '0',   0x22U, 0x0BU, 0x04U, 0x7FU, 0x00U,
                                       0x00U, 0x01U, 0x91U, 0x02U, 0x0FU, 0xA1U, 0xCDU, 0x03U,
                                       0x2AU, 0x0AU, 'i',   'p',   'f',   's',   '/',   '0',
                                       '.',   '1',   '.',   '0',   0x32U, 0x12U, 'c',   '-',
                                       'l',   'e',   'a',   'n',   '-',   'l',   'i',   'b',
                                       'p',   '2',   'p',   '/',   't',   'e',   's',   't'};
    libp2p_identify_message_t message;
    libp2p_identify_message_t decoded;
    uint8_t encoded[128];
    size_t written = 0U;

    (void)memset(&message, 0, sizeof(message));
    message.public_key.data = public_key;
    message.public_key.len = sizeof(public_key);
    message.listen_addrs[0].data = addr;
    message.listen_addrs[0].len = sizeof(addr);
    message.listen_addr_count = 1U;
    message.protocols[0].data = identify_id;
    message.protocols[0].len = sizeof(identify_id) - 1U;
    message.protocols[1].data = ping_id;
    message.protocols[1].len = sizeof(ping_id) - 1U;
    message.protocol_count = 2U;
    message.observed_addr.data = addr;
    message.observed_addr.len = sizeof(addr);
    message.protocol_version.data = protocol_version;
    message.protocol_version.len = sizeof(protocol_version) - 1U;
    message.agent_version.data = agent_version;
    message.agent_version.len = sizeof(agent_version) - 1U;

    assert(
        libp2p_identify_message_encode(&message, encoded, sizeof(encoded), &written) ==
        LIBP2P_IDENTIFY_OK);
    assert(written == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(
        libp2p_identify_message_decode(expected, sizeof(expected), &decoded) == LIBP2P_IDENTIFY_OK);
    assert(decoded.protocol_count == 2U);
    assert(decoded.listen_addr_count == 1U);
    assert(decoded.protocol_version.len == (sizeof(protocol_version) - 1U));
}

int main(void)
{
    identify_spec_test_protocol_ids();
    identify_spec_test_canonical_message_encoding();
    return 0;
}
