#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/multiformats_test_utils.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_UNSIGNED_VARINT_SPEC_PATH "docs/multiformats-specs/unsigned-varint/README.md"

static int unsigned_varint_spec_parse_example(
    char *line,
    uint64_t *value,
    uint8_t *bytes,
    size_t bytes_capacity,
    size_t *bytes_len)
{
    char *trimmed = libp2p_test_trim(line);
    char *space = NULL;
    char *hex_start = NULL;
    char *hex_end = NULL;
    char saved_character = '\0';

    if ((trimmed == NULL) || (trimmed[0] == '\0'))
    {
        return 0;
    }
    if ((trimmed[0] < '0') || (trimmed[0] > '9'))
    {
        return 0;
    }

    space = strchr(trimmed, ' ');
    hex_start = strrchr(trimmed, '(');
    hex_end = strrchr(trimmed, ')');

    if ((space == NULL) || (hex_start == NULL) || (hex_end == NULL) || (hex_start >= hex_end))
    {
        return 0;
    }

    saved_character = *space;
    *space = '\0';
    if (libp2p_test_parse_u64_decimal(trimmed, value) == 0)
    {
        *space = saved_character;
        return 0;
    }
    *space = saved_character;

    *hex_end = '\0';
    if (libp2p_test_parse_hex(hex_start + 1, bytes, bytes_capacity, bytes_len) == 0)
    {
        *hex_end = ')';
        return 0;
    }
    *hex_end = ')';
    return 1;
}

static int unsigned_varint_spec_test_readme_examples(const char *repo_root)
{
    char path[512];
    char line[512];
    FILE *spec_file = NULL;
    size_t example_count = 0U;
    int found_non_minimal_text = 0;

    LIBP2P_TEST_ASSERT(
        libp2p_test_join_path(repo_root, LIBP2P_UNSIGNED_VARINT_SPEC_PATH, path, sizeof(path)) !=
        0);

    spec_file = fopen(path, "r");
    LIBP2P_TEST_ASSERT(spec_file != NULL);

    while (fgets(line, (int)sizeof(line), spec_file) != NULL)
    {
        uint64_t value = UINT64_C(0);
        uint8_t expected[LIBP2P_UVARINT_MAX_BYTES + 1U] = {0U};
        size_t expected_len = 0U;

        if (strstr(line, "{0x81 0x00}") != NULL)
        {
            found_non_minimal_text = 1;
        }

        if (unsigned_varint_spec_parse_example(
                line,
                &value,
                expected,
                sizeof(expected),
                &expected_len) != 0)
        {
            uint8_t encoded[LIBP2P_UVARINT_MAX_BYTES + 1U] = {0U};
            uint64_t decoded = UINT64_C(0);
            size_t written = 0U;
            size_t read = 0U;

            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_UVARINT_OK,
                libp2p_uvarint_encode(value, encoded, sizeof(encoded), &written));
            LIBP2P_TEST_ASSERT_EQ_SIZE(expected_len, written);
            LIBP2P_TEST_ASSERT_EQ_SIZE(expected_len, (size_t)libp2p_uvarint_size(value));
            LIBP2P_TEST_ASSERT_MEM_EQ(expected, encoded, expected_len);

            LIBP2P_TEST_ASSERT_EQ_INT(
                LIBP2P_UVARINT_OK,
                libp2p_uvarint_decode(expected, expected_len, &decoded, &read));
            LIBP2P_TEST_ASSERT_EQ_U64(value, decoded);
            LIBP2P_TEST_ASSERT_EQ_SIZE(expected_len, read);

            example_count++;
        }
    }

    LIBP2P_TEST_ASSERT(fclose(spec_file) == 0);
    LIBP2P_TEST_ASSERT_EQ_SIZE(6U, example_count);
    LIBP2P_TEST_ASSERT(found_non_minimal_text != 0);
    LIBP2P_TEST_ASSERT_EQ_INT(
        LIBP2P_UVARINT_ERR_NON_MINIMAL,
        libp2p_uvarint_decode((const uint8_t[]){0x81U, 0x00U}, 2U, NULL, NULL));
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

    if (unsigned_varint_spec_test_readme_examples(repo_root) != 0)
    {
        (void)fprintf(stderr, "unsigned_varint_spec: readme_examples failed\n");
        return 1;
    }
    case_count = 1U;

    (void)fprintf(stderr, "unsigned_varint_spec: %zu cases passed\n", case_count);
    return 0;
}
