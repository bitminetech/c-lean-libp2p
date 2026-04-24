#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/quic/quic_addr.h"

static const char quic_addr_peer_text[] = "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";

static int quic_addr_hex_nibble(char character, uint8_t *value)
{
    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'a'));
        return 1;
    }
    if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(10U + (uint8_t)(character - 'A'));
        return 1;
    }

    *value = 0U;
    return 0;
}

static int quic_addr_parse_hex(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    size_t text_len = strlen(text);
    size_t index = 0U;

    if ((text_len % 2U) != 0U)
    {
        return 0;
    }
    if ((text_len / 2U) > out_capacity)
    {
        return 0;
    }

    for (index = 0U; index < text_len; index += 2U)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((quic_addr_hex_nibble(text[index], &high) == 0) ||
            (quic_addr_hex_nibble(text[index + 1U], &low) == 0))
        {
            return 0;
        }

        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
    return 1;
}

static void quic_addr_load_peer_id(uint8_t *out, size_t out_len, size_t *written)
{
    static const char peer_id_hex[] =
        "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47";

    assert(quic_addr_parse_hex(peer_id_hex, out, out_len, written) != 0);
}

static void quic_addr_test_ip4_roundtrip(void)
{
    const uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    libp2p_quic_addr_t addr;
    libp2p_quic_addr_t parsed;
    uint8_t multiaddr[64];
    size_t written = 0U;

    assert(libp2p_quic_addr_from_ip4(ip4, 4001U, &addr) == LIBP2P_QUIC_OK);
    assert(addr.family == LIBP2P_QUIC_ADDR_IP4);
    assert(addr.port == 4001U);
    assert(libp2p_quic_addr_validate(&addr) == LIBP2P_QUIC_OK);

    assert(
        libp2p_quic_addr_to_multiaddr(&addr, NULL, 0U, &written) == LIBP2P_QUIC_ERR_BUF_TOO_SMALL);
    assert(written == 11U);

    assert(
        libp2p_quic_addr_to_multiaddr(&addr, multiaddr, sizeof(multiaddr), &written) ==
        LIBP2P_QUIC_OK);
    assert(written == 11U);

    assert(libp2p_quic_addr_from_multiaddr(multiaddr, written, &parsed) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_equal(&addr, &parsed, 1) != 0);
}

static void quic_addr_test_ip6_roundtrip_with_peer(void)
{
    const uint8_t ip6[16] =
        {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    libp2p_quic_addr_t addr;
    libp2p_quic_addr_t parsed;
    uint8_t peer_id[64];
    uint8_t multiaddr[128];
    size_t peer_id_len = 0U;
    size_t written = 0U;

    quic_addr_load_peer_id(peer_id, sizeof(peer_id), &peer_id_len);

    assert(libp2p_quic_addr_from_ip6(ip6, 443U, &addr) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_set_peer_id(&addr, peer_id, peer_id_len) == LIBP2P_QUIC_OK);
    assert(
        libp2p_quic_addr_to_multiaddr(&addr, multiaddr, sizeof(multiaddr), &written) ==
        LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_from_multiaddr(multiaddr, written, &parsed) == LIBP2P_QUIC_OK);
    assert(libp2p_quic_addr_equal(&addr, &parsed, 1) != 0);
    assert(libp2p_quic_addr_equal(&addr, &parsed, 0) != 0);
}

static void quic_addr_test_parse_text_multiaddr(void)
{
    const char text_prefix[] = "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/";
    char text[128];
    uint8_t bytes[128];
    size_t text_len = 0U;
    size_t bytes_len = 0U;
    libp2p_quic_addr_t addr;

    (void)memcpy(text, text_prefix, sizeof(text_prefix) - 1U);
    (void)memcpy(
        &text[sizeof(text_prefix) - 1U],
        quic_addr_peer_text,
        sizeof(quic_addr_peer_text) - 1U);
    text_len = (sizeof(text_prefix) - 1U) + (sizeof(quic_addr_peer_text) - 1U);

    assert(
        libp2p_multiaddr_from_string(text, text_len, bytes, sizeof(bytes), &bytes_len) ==
        LIBP2P_MULTIADDR_OK);
    assert(libp2p_quic_addr_from_multiaddr(bytes, bytes_len, &addr) == LIBP2P_QUIC_OK);
    assert(addr.family == LIBP2P_QUIC_ADDR_IP4);
    assert(addr.port == 4001U);
    assert(addr.has_peer_id != 0U);
}

static void quic_addr_test_rejects_unsupported_shapes(void)
{
    const uint8_t ip4[4] = {127U, 0U, 0U, 1U};
    const uint8_t udp[2] = {0x0fU, 0xa1U};
    uint8_t bytes[32];
    size_t pos = 0U;
    libp2p_quic_addr_t addr;

    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_MULTIADDR_CODE_IP4,
            ip4,
            sizeof(ip4),
            bytes,
            sizeof(bytes),
            &pos) == LIBP2P_MULTIADDR_OK);
    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_MULTIADDR_CODE_UDP,
            udp,
            sizeof(udp),
            bytes,
            sizeof(bytes),
            &pos) == LIBP2P_MULTIADDR_OK);
    assert(libp2p_quic_addr_from_multiaddr(bytes, pos, &addr) == LIBP2P_QUIC_ERR_ADDR);

    assert(
        libp2p_multiaddr_append_component(
            LIBP2P_MULTIADDR_CODE_QUIC_V1,
            NULL,
            0U,
            bytes,
            sizeof(bytes),
            &pos) == LIBP2P_MULTIADDR_OK);
    bytes[pos++] = 0x06U;
    assert(libp2p_quic_addr_from_multiaddr(bytes, pos, &addr) == LIBP2P_QUIC_ERR_ADDR);
}

int main(void)
{
    quic_addr_test_ip4_roundtrip();
    quic_addr_test_ip6_roundtrip_with_peer();
    quic_addr_test_parse_text_multiaddr();
    quic_addr_test_rejects_unsupported_shapes();

    return 0;
}
