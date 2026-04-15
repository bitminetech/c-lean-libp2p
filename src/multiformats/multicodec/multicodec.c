/**
 * @file multicodec.c
 * @brief Fixed multicodec subset used by c-lean-libp2p.
 */

#include "multiformats/multicodec/multicodec.h"

#include <string.h>

typedef struct
{
    uint64_t code;
    const char *name;
    libp2p_multicodec_tag_t tag;
} libp2p_multicodec_entry_t;

static const libp2p_multicodec_entry_t multicodec_table[] =
    {{UINT64_C(0x00), "identity", LIBP2P_MULTICODEC_TAG_MULTIHASH},
     {UINT64_C(0x04), "ip4", LIBP2P_MULTICODEC_TAG_MULTIADDR},
     {UINT64_C(0x12), "sha2-256", LIBP2P_MULTICODEC_TAG_MULTIHASH},
     {UINT64_C(0x29), "ip6", LIBP2P_MULTICODEC_TAG_MULTIADDR},
     {UINT64_C(0x72), "libp2p-key", LIBP2P_MULTICODEC_TAG_IPLD},
     {UINT64_C(0x0111), "udp", LIBP2P_MULTICODEC_TAG_MULTIADDR},
     {UINT64_C(0x01a5), "p2p", LIBP2P_MULTICODEC_TAG_MULTIADDR},
     {UINT64_C(0x01cc), "quic", LIBP2P_MULTICODEC_TAG_MULTIADDR},
     {UINT64_C(0x01cd), "quic-v1", LIBP2P_MULTICODEC_TAG_MULTIADDR}};

static size_t multicodec_table_len(void)
{
    return sizeof(multicodec_table) / sizeof(multicodec_table[0]);
}

libp2p_multicodec_err_t libp2p_multicodec_lookup(
    uint64_t code,
    const char **name,
    libp2p_multicodec_tag_t *tag)
{
    size_t index = 0U;

    for (index = 0U; index < multicodec_table_len(); index++)
    {
        const libp2p_multicodec_entry_t *const entry = &multicodec_table[index];

        if (entry->code == code)
        {
            if (name != NULL)
            {
                *name = entry->name;
            }
            if (tag != NULL)
            {
                *tag = entry->tag;
            }

            return LIBP2P_MULTICODEC_OK;
        }
    }

    return LIBP2P_MULTICODEC_ERR_UNSUPPORTED;
}

libp2p_multicodec_err_t libp2p_multicodec_from_name(
    const char *name,
    size_t name_len,
    uint64_t *code)
{
    size_t index = 0U;

    if (name == NULL)
    {
        return LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME;
    }

    for (index = 0U; index < multicodec_table_len(); index++)
    {
        const libp2p_multicodec_entry_t *const entry = &multicodec_table[index];
        const size_t entry_name_len = strlen(entry->name);

        if ((entry_name_len == name_len) && (memcmp(entry->name, name, name_len) == 0))
        {
            if (code != NULL)
            {
                *code = entry->code;
            }

            return LIBP2P_MULTICODEC_OK;
        }
    }

    return LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME;
}
