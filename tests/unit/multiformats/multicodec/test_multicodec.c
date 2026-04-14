#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"

static void multicodec_unit_test_lookup_supported_entries(void)
{
    static const struct
    {
        uint64_t code;
        const char *name;
        libp2p_multicodec_tag_t tag;
    } cases[] =
        {{UINT64_C(0x00), "identity", LIBP2P_MULTICODEC_TAG_MULTIHASH},
         {UINT64_C(0x04), "ip4", LIBP2P_MULTICODEC_TAG_MULTIADDR},
         {UINT64_C(0x12), "sha2-256", LIBP2P_MULTICODEC_TAG_MULTIHASH},
         {UINT64_C(0x29), "ip6", LIBP2P_MULTICODEC_TAG_MULTIADDR},
         {UINT64_C(0x72), "libp2p-key", LIBP2P_MULTICODEC_TAG_IPLD},
         {UINT64_C(0x0111), "udp", LIBP2P_MULTICODEC_TAG_MULTIADDR},
         {UINT64_C(0x01A5), "p2p", LIBP2P_MULTICODEC_TAG_MULTIADDR},
         {UINT64_C(0x01CC), "quic", LIBP2P_MULTICODEC_TAG_MULTIADDR},
         {UINT64_C(0x01CD), "quic-v1", LIBP2P_MULTICODEC_TAG_MULTIADDR}};
    size_t index = 0U;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); index++)
    {
        const char *name = NULL;
        libp2p_multicodec_tag_t tag = LIBP2P_MULTICODEC_TAG_HASH;

        assert(libp2p_multicodec_lookup(cases[index].code, &name, &tag) == LIBP2P_MULTICODEC_OK);
        assert(name != NULL);
        assert(strcmp(name, cases[index].name) == 0);
        assert(tag == cases[index].tag);
    }
}

static void multicodec_unit_test_lookup_unsupported(void)
{
    const char *name = "sentinel";
    libp2p_multicodec_tag_t tag = LIBP2P_MULTICODEC_TAG_HASH;

    assert(
        libp2p_multicodec_lookup(UINT64_C(0x06), &name, &tag) == LIBP2P_MULTICODEC_ERR_UNSUPPORTED);
    assert(strcmp(name, "sentinel") == 0);
    assert(tag == LIBP2P_MULTICODEC_TAG_HASH);
}

static void multicodec_unit_test_from_name_supported_entries(void)
{
    static const struct
    {
        const char *name;
        uint64_t code;
    } cases[] =
        {{"identity", UINT64_C(0x00)},
         {"ip4", UINT64_C(0x04)},
         {"sha2-256", UINT64_C(0x12)},
         {"ip6", UINT64_C(0x29)},
         {"libp2p-key", UINT64_C(0x72)},
         {"udp", UINT64_C(0x0111)},
         {"p2p", UINT64_C(0x01A5)},
         {"quic", UINT64_C(0x01CC)},
         {"quic-v1", UINT64_C(0x01CD)}};
    size_t index = 0U;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); index++)
    {
        char buffer[32];
        uint64_t code = UINT64_C(0);

        (void)memset(buffer, 0, sizeof(buffer));
        (void)memcpy(buffer + 2U, cases[index].name, strlen(cases[index].name));

        assert(
            libp2p_multicodec_from_name(buffer + 2U, strlen(cases[index].name), &code) ==
            LIBP2P_MULTICODEC_OK);
        assert(code == cases[index].code);
    }
}

static void multicodec_unit_test_from_name_errors(void)
{
    uint64_t code = UINT64_C(0xFF);

    assert(libp2p_multicodec_from_name(NULL, 1U, &code) == LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME);
    assert(code == UINT64_C(0xFF));

    assert(libp2p_multicodec_from_name("", 0U, &code) == LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME);
    assert(code == UINT64_C(0xFF));

    assert(libp2p_multicodec_from_name("tcp", 3U, &code) == LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME);
    assert(code == UINT64_C(0xFF));
}

int main(void)
{
    multicodec_unit_test_lookup_supported_entries();
    multicodec_unit_test_lookup_unsupported();
    multicodec_unit_test_from_name_supported_entries();
    multicodec_unit_test_from_name_errors();
    return 0;
}
