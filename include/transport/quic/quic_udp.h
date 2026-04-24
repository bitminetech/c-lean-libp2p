/**
 * @file quic_udp.h
 * @brief POSIX UDP socket adapter for the packet-driven QUIC endpoint API.
 *
 * The core QUIC endpoint remains event-loop agnostic: callers may still feed
 * and drain UDP datagrams manually. This adapter provides a small production
 * bridge for POSIX sockets without exposing ngtcp2 or AWS-LC details.
 */

#ifndef LIBP2P_QUIC_UDP_H
#define LIBP2P_QUIC_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "transport/quic/quic.h"

#define LIBP2P_QUIC_UDP_INVALID_FD (-1)

/** Caller-owned UDP socket wrapper. */
typedef struct
{
    int fd;
    libp2p_quic_addr_t local_addr;
    uint8_t open;
    uint8_t nonblocking;
} libp2p_quic_udp_socket_t;

/**
 * Initialize a socket wrapper to the closed state.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_init(libp2p_quic_udp_socket_t *socket);

/**
 * Open and bind a UDP socket.
 *
 * local_addr may use port 0. After a successful bind, socket->local_addr and
 * libp2p_quic_udp_socket_local_addr() report the kernel-assigned port.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_open(
    libp2p_quic_udp_socket_t *socket,
    const libp2p_quic_addr_t *local_addr,
    int nonblocking);

/**
 * Close a UDP socket wrapper. Safe to call on an already-closed wrapper.
 */
void libp2p_quic_udp_socket_close(libp2p_quic_udp_socket_t *socket);

/**
 * Return the underlying file descriptor for integration with poll/kqueue/epoll.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_fd(const libp2p_quic_udp_socket_t *socket, int *out_fd);

/**
 * Return the bound local address.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_local_addr(
    const libp2p_quic_udp_socket_t *socket,
    libp2p_quic_addr_t *out_addr);

/**
 * Receive one UDP datagram and feed it into an endpoint.
 *
 * buffer is caller-owned scratch storage. A nonblocking socket returns
 * LIBP2P_QUIC_ERR_WOULD_BLOCK when no datagram is available.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_recv(
    libp2p_quic_udp_socket_t *socket,
    libp2p_quic_endpoint_t *endpoint,
    uint8_t *buffer,
    size_t buffer_len,
    libp2p_quic_time_us_t now_us);

/**
 * Drain one endpoint datagram and send it on the UDP socket.
 *
 * buffer is caller-owned scratch storage. The endpoint decides the remote
 * address for each datagram.
 */
libp2p_quic_err_t libp2p_quic_udp_socket_send(
    libp2p_quic_udp_socket_t *socket,
    libp2p_quic_endpoint_t *endpoint,
    uint8_t *buffer,
    size_t buffer_len,
    libp2p_quic_time_us_t now_us);

#endif /* LIBP2P_QUIC_UDP_H */
