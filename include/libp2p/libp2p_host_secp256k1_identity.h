/**
 * @file libp2p_host_secp256k1_identity.h
 * @brief Default secp256k1 host identity adapter.
 */

#ifndef LIBP2P_HOST_SECP256K1_IDENTITY_H
#define LIBP2P_HOST_SECP256K1_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p/libp2p_host.h"

/**
 * Caller-owned secp256k1 identity adapter storage.
 *
 * The raw private key is borrowed, not copied. The derived public key message
 * and peer ID live in this structure and must outlive any host using the
 * returned libp2p_host_identity_t view.
 */
typedef struct
{
    const uint8_t *private_key;
    size_t private_key_len;
    uint8_t public_key_message[LIBP2P_PEER_ID_SECP256K1_PUBLIC_KEY_MESSAGE_MAX_BYTES];
    size_t public_key_message_len;
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t peer_id_len;
} libp2p_host_secp256k1_identity_t;

/**
 * Initialize a host identity view backed by a borrowed raw secp256k1 secret.
 */
libp2p_host_err_t libp2p_host_secp256k1_identity_init(
    libp2p_host_secp256k1_identity_t *identity,
    const uint8_t *private_key,
    size_t private_key_len,
    libp2p_host_identity_t *out);

#endif /* LIBP2P_HOST_SECP256K1_IDENTITY_H */
