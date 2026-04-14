/**
 * @file multicodec.h
 * @brief Multicodec registry lookup.
 *
 * A multicodec is an unsigned varint code from a shared registry that
 * identifies formats, protocols, hash functions, and other values across
 * the multiformats family.
 *
 * This module exposes only the subset of codes used by c-lean-libp2p.
 *
 * @see https://github.com/multiformats/multicodec
 */

#ifndef LIBP2P_MULTICODEC_H
#define LIBP2P_MULTICODEC_H

#include <stddef.h>
#include <stdint.h>

/** Tag categories used by the multicodec table. */
typedef enum
{
    LIBP2P_MULTICODEC_TAG_MULTIHASH,
    LIBP2P_MULTICODEC_TAG_MULTIADDR,
    LIBP2P_MULTICODEC_TAG_KEY,
    LIBP2P_MULTICODEC_TAG_IPLD,
    LIBP2P_MULTICODEC_TAG_NAMESPACE,
    LIBP2P_MULTICODEC_TAG_SERIALIZATION,
    LIBP2P_MULTICODEC_TAG_HASH
} libp2p_multicodec_tag_t;

/** Error codes returned by multicodec operations. */
typedef enum
{
    LIBP2P_MULTICODEC_OK,
    LIBP2P_MULTICODEC_ERR_UNSUPPORTED,
    LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME
} libp2p_multicodec_err_t;

/**
 * Look up canonical name and tag for a supported multicodec code.
 *
 * @param[in]  code  Multicodec code.
 * @param[out] name  Pointer to a static NUL-terminated canonical name string.
 * @param[out] tag   Tag category for the code.
 * @return LIBP2P_MULTICODEC_OK on success,
 *         LIBP2P_MULTICODEC_ERR_UNSUPPORTED if code is outside the supported subset.
 */
libp2p_multicodec_err_t libp2p_multicodec_lookup(
    uint64_t code,
    const char **name,
    libp2p_multicodec_tag_t *tag);

/**
 * Resolve a canonical name to its multicodec code.
 *
 * @param[in]  name      Canonical name bytes (not required to be NUL-terminated).
 * @param[in]  name_len  Length of name in bytes.
 * @param[out] code      Resolved multicodec code.
 * @return LIBP2P_MULTICODEC_OK on success,
 *         LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME if name is not in the supported subset.
 */
libp2p_multicodec_err_t libp2p_multicodec_from_name(
    const char *name,
    size_t name_len,
    uint64_t *code);

#endif /* LIBP2P_MULTICODEC_H */
