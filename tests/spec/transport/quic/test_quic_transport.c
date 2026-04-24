#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/quic/quic_addr.h"
#include "transport/quic/quic_types.h"

static void quic_spec_parse_example(
    const char *text,
    libp2p_quic_addr_family_t family,
    uint16_t port)
{
    uint8_t bytes[128];
    size_t bytes_len = 0U;
    libp2p_quic_addr_t addr;

    assert(
        libp2p_multiaddr_from_string(text, strlen(text), bytes, sizeof(bytes), &bytes_len) ==
        LIBP2P_MULTIADDR_OK);
    assert(libp2p_quic_addr_from_multiaddr(bytes, bytes_len, &addr) == LIBP2P_QUIC_OK);
    assert(addr.family == family);
    assert(addr.port == port);
    assert(addr.has_peer_id == 0U);
}

static void quic_spec_test_rfc9000_multiaddrs(void)
{
    quic_spec_parse_example("/ip4/127.0.0.1/udp/1234/quic-v1", LIBP2P_QUIC_ADDR_IP4, 1234U);
    quic_spec_parse_example(
        "/ip6/2001:db8:3333:4444:5555:6666:7777:8888/udp/443/quic-v1",
        LIBP2P_QUIC_ADDR_IP6,
        443U);
}

static void quic_spec_test_draft_quic_multiaddr_rejected(void)
{
    const char draft_text[] = "/ip4/12.34.56.78/udp/4321/quic";
    uint8_t bytes[128];
    size_t bytes_len = 0U;
    libp2p_quic_addr_t addr;
    libp2p_multiaddr_err_t parse_result = libp2p_multiaddr_from_string(
        draft_text,
        strlen(draft_text),
        bytes,
        sizeof(bytes),
        &bytes_len);

    if (parse_result == LIBP2P_MULTIADDR_OK)
    {
        assert(libp2p_quic_addr_from_multiaddr(bytes, bytes_len, &addr) == LIBP2P_QUIC_ERR_ADDR);
    }
    else
    {
        assert(parse_result == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    }
}

static void quic_spec_test_version_and_alpn(void)
{
    assert(LIBP2P_QUIC_VERSION_RFC9000 == UINT32_C(0x00000001));
    assert(LIBP2P_QUIC_ALPN_LEN == 6U);
    assert(memcmp(LIBP2P_QUIC_ALPN, "libp2p", LIBP2P_QUIC_ALPN_LEN) == 0);
}

int main(void)
{
    quic_spec_test_rfc9000_multiaddrs();
    quic_spec_test_draft_quic_multiaddr_rejected();
    quic_spec_test_version_and_alpn();
    return 0;
}
