#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol/ping/ping.h"

static void ping_spec_test_constants(void)
{
    assert(strlen(LIBP2P_PING_PROTOCOL_ID) == LIBP2P_PING_PROTOCOL_ID_LEN);
    assert(strcmp(LIBP2P_PING_PROTOCOL_ID, "/ipfs/ping/1.0.0") == 0);
    assert(LIBP2P_PING_PAYLOAD_BYTES == 32U);
}

static void ping_spec_test_payload_is_raw_32_bytes(void)
{
    uint8_t payload[LIBP2P_PING_PAYLOAD_BYTES];
    size_t index = 0U;

    for (index = 0U; index < sizeof(payload); index++)
    {
        payload[index] = (uint8_t)index;
    }
    assert(sizeof(payload) == 32U);
    assert(payload[0] == 0U);
    assert(payload[31] == 31U);
}

int main(void)
{
    ping_spec_test_constants();
    ping_spec_test_payload_is_raw_32_bytes();
    return 0;
}
