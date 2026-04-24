/**
 * @file quic_addr.h
 * @brief Conversion between libp2p multiaddrs and QUIC UDP endpoints.
 *
 * The initial c-lean-libp2p QUIC transport accepts only:
 *
 *   /ip4/<addr>/udp/<port>/quic-v1[/p2p/<peer-id>]
 *   /ip6/<addr>/udp/<port>/quic-v1[/p2p/<peer-id>]
 *
 * Draft QUIC multiaddrs and non-UDP transports are intentionally rejected.
 */

#ifndef LIBP2P_QUIC_ADDR_H
#define LIBP2P_QUIC_ADDR_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id/peer_id.h"
#include "transport/quic/quic_types.h"

/** IP address family carried by a QUIC UDP endpoint. */
typedef enum
{
    LIBP2P_QUIC_ADDR_IP4,
    LIBP2P_QUIC_ADDR_IP6
} libp2p_quic_addr_family_t;

/**
 * QUIC UDP endpoint derived from a supported multiaddr.
 *
 * port is stored in host byte order. For IPv4, ip[0..3] contains the address
 * and ip[4..15] is zeroed by constructors. For IPv6, ip[0..15] contains the
 * full 128-bit address.
 */
typedef struct
{
    libp2p_quic_addr_family_t family;
    uint8_t ip[16];
    uint16_t port;
    uint8_t has_peer_id;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
} libp2p_quic_addr_t;

/**
 * Build an IPv4 QUIC endpoint from raw address bytes and a host-order UDP port.
 */
libp2p_quic_err_t libp2p_quic_addr_from_ip4(
    const uint8_t ip4[4],
    uint16_t port,
    libp2p_quic_addr_t *out);

/**
 * Build an IPv6 QUIC endpoint from raw address bytes and a host-order UDP port.
 */
libp2p_quic_err_t libp2p_quic_addr_from_ip6(
    const uint8_t ip6[16],
    uint16_t port,
    libp2p_quic_addr_t *out);

/**
 * Attach an expected peer ID to an address.
 *
 * The peer ID is used by dialers to bind the authenticated TLS certificate to
 * the multiaddr target. Passing peer_id_len equal to 0 clears the peer ID.
 */
libp2p_quic_err_t libp2p_quic_addr_set_peer_id(
    libp2p_quic_addr_t *addr,
    const uint8_t *peer_id,
    size_t peer_id_len);

/**
 * Validate that an address is usable for c-lean-libp2p QUIC.
 */
libp2p_quic_err_t libp2p_quic_addr_validate(const libp2p_quic_addr_t *addr);

/**
 * Parse a binary multiaddr into a QUIC UDP endpoint.
 *
 * @param[in]  multiaddr      Binary multiaddr bytes.
 * @param[in]  multiaddr_len  Length of multiaddr in bytes.
 * @param[out] out            Parsed endpoint.
 * @return LIBP2P_QUIC_OK on success,
 *         LIBP2P_QUIC_ERR_ADDR for malformed or unsupported address shapes.
 */
libp2p_quic_err_t libp2p_quic_addr_from_multiaddr(
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    libp2p_quic_addr_t *out);

/**
 * Format a QUIC UDP endpoint as a binary multiaddr.
 *
 * Output is:
 *   /ip4|ip6/.../udp/.../quic-v1
 * plus /p2p/... when addr->has_peer_id is non-zero.
 *
 * @param[out] written  Bytes written, or required size on
 *                      LIBP2P_QUIC_ERR_BUF_TOO_SMALL.
 */
libp2p_quic_err_t libp2p_quic_addr_to_multiaddr(
    const libp2p_quic_addr_t *addr,
    uint8_t *out,
    size_t out_len,
    size_t *written);

/**
 * Compare two addresses.
 *
 * If compare_peer_id is zero, only IP family, IP bytes, and port are compared.
 * Returns non-zero when the selected fields are equal.
 */
int libp2p_quic_addr_equal(
    const libp2p_quic_addr_t *a,
    const libp2p_quic_addr_t *b,
    int compare_peer_id);

#endif /* LIBP2P_QUIC_ADDR_H */
