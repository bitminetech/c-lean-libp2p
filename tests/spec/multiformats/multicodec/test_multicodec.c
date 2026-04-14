#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/multiformats_test_utils.h"
#include "multiformats/multicodec/multicodec.h"

#define LIBP2P_MULTICODEC_SPEC_PATH "docs/multiformats-specs/multicodec/table.csv"

static int multicodec_spec_supported_code(uint64_t code)
{
    switch (code)
    {
    case UINT64_C(0x00):
    case UINT64_C(0x04):
    case UINT64_C(0x12):
    case UINT64_C(0x29):
    case UINT64_C(0x72):
    case UINT64_C(0x0111):
    case UINT64_C(0x01A5):
    case UINT64_C(0x01CC):
    case UINT64_C(0x01CD):
        return 1;

    default:
        return 0;
    }
}

static int multicodec_spec_tag_from_text(const char *text, libp2p_multicodec_tag_t *tag)
{
    if ((text == NULL) || (tag == NULL))
    {
        return 0;
    }
    if (strcmp(text, "multihash") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_MULTIHASH;
        return 1;
    }
    if (strcmp(text, "multiaddr") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_MULTIADDR;
        return 1;
    }
    if (strcmp(text, "key") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_KEY;
        return 1;
    }
    if (strcmp(text, "ipld") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_IPLD;
        return 1;
    }
    if (strcmp(text, "namespace") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_NAMESPACE;
        return 1;
    }
    if (strcmp(text, "serialization") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_SERIALIZATION;
        return 1;
    }
    if (strcmp(text, "hash") == 0)
    {
        *tag = LIBP2P_MULTICODEC_TAG_HASH;
        return 1;
    }

    return 0;
}

static int multicodec_spec_test_table_csv(const char *repo_root)
{
    char path[512];
    char line[1024];
    FILE *table_file = NULL;
    size_t row_count = 0U;

    LIBP2P_TEST_ASSERT(
        libp2p_test_join_path(repo_root, LIBP2P_MULTICODEC_SPEC_PATH, path, sizeof(path)) != 0);

    table_file = fopen(path, "r");
    LIBP2P_TEST_ASSERT(table_file != NULL);

    while (fgets(line, (int)sizeof(line), table_file) != NULL)
    {
        char *fields[5] = {NULL, NULL, NULL, NULL, NULL};
        size_t field_count = 0U;
        char *name = NULL;
        char *tag_text = NULL;
        char *code_text = NULL;
        uint64_t code = UINT64_C(0);

        field_count = libp2p_test_csv_split(line, fields, sizeof(fields) / sizeof(fields[0]));
        if (field_count < 4U)
        {
            continue;
        }

        name = libp2p_test_trim(fields[0]);
        tag_text = libp2p_test_trim(fields[1]);
        code_text = libp2p_test_trim(fields[2]);

        if ((name == NULL) || (tag_text == NULL) || (code_text == NULL) || (name[0] == '\0') ||
            (strcmp(name, "name") == 0))
        {
            continue;
        }

        LIBP2P_TEST_ASSERT(libp2p_test_parse_u64_hex(code_text, &code) != 0);
        row_count++;

        if (multicodec_spec_supported_code(code) != 0)
        {
            const char *resolved_name = NULL;
            libp2p_multicodec_tag_t expected_tag = LIBP2P_MULTICODEC_TAG_HASH;
            libp2p_multicodec_tag_t resolved_tag = LIBP2P_MULTICODEC_TAG_HASH;
            uint64_t resolved_code = UINT64_C(0);

            LIBP2P_TEST_ASSERT(multicodec_spec_tag_from_text(tag_text, &expected_tag) != 0);
            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_MULTICODEC_OK,
                libp2p_multicodec_lookup(code, &resolved_name, &resolved_tag));
            LIBP2P_TEST_ASSERT(resolved_name != NULL);
            LIBP2P_TEST_ASSERT_STR_EQ(name, resolved_name);
            LIBP2P_TEST_ASSERT_EQ_INT(expected_tag, resolved_tag);

            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_MULTICODEC_OK,
                libp2p_multicodec_from_name(name, strlen(name), &resolved_code));
            LIBP2P_TEST_ASSERT_EQ_U64(code, resolved_code);
        }
        else
        {
            uint64_t resolved_code = UINT64_C(0);

            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_MULTICODEC_ERR_UNSUPPORTED,
                libp2p_multicodec_lookup(code, NULL, NULL));
            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME,
                libp2p_multicodec_from_name(name, strlen(name), &resolved_code));
            LIBP2P_TEST_ASSERT_EQ_U64(UINT64_C(0), resolved_code);
        }
    }

    LIBP2P_TEST_ASSERT(fclose(table_file) == 0);
    LIBP2P_TEST_ASSERT(row_count > 600U);
    return 0;
}

int main(int argc, char **argv)
{
    const char *repo_root = ".";
    size_t case_count = 0U;

    if (argc > 1)
    {
        repo_root = argv[1];
    }

    if (multicodec_spec_test_table_csv(repo_root) != 0)
    {
        (void)fprintf(stderr, "multicodec_spec: table_csv failed\n");
        return 1;
    }
    case_count = 1U;

    (void)fprintf(stderr, "multicodec_spec: %zu cases passed\n", case_count);
    return 0;
}
