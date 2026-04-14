#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"

#define LIBP2P_UNSIGNED_VARINT_SPEC_PATH "docs/multiformats-specs/unsigned-varint/README.md"

static int unsigned_varint_spec_is_space(char character)
{
    return ((character == ' ') || (character == '\t') || (character == '\n') || (character == '\r'))
               ? 1
               : 0;
}

static int unsigned_varint_spec_join_path(
    const char *root,
    const char *relative_path,
    char *out,
    size_t out_len)
{
    size_t root_len = 0U;
    size_t relative_len = 0U;
    size_t total_len = 0U;

    if ((root == NULL) || (relative_path == NULL) || (out == NULL) || (out_len == 0U))
    {
        return 0;
    }

    root_len = strlen(root);
    relative_len = strlen(relative_path);
    total_len = root_len;
    if ((root_len != 0U) && (root[root_len - 1U] != '/'))
    {
        total_len += 1U;
    }
    total_len += relative_len;

    if ((total_len + 1U) > out_len)
    {
        return 0;
    }

    (void)memcpy(out, root, root_len);
    if ((root_len != 0U) && (root[root_len - 1U] != '/'))
    {
        out[root_len] = '/';
        root_len++;
    }

    (void)memcpy(out + root_len, relative_path, relative_len);
    out[root_len + relative_len] = '\0';
    return 1;
}

static char *unsigned_varint_spec_trim(char *text)
{
    char *trimmed = text;
    size_t length = 0U;

    if (text == NULL)
    {
        return NULL;
    }

    while (unsigned_varint_spec_is_space(*trimmed) != 0)
    {
        trimmed++;
    }

    if (trimmed != text)
    {
        (void)memmove(text, trimmed, strlen(trimmed) + 1U);
    }

    length = strlen(text);
    while ((length != 0U) && (unsigned_varint_spec_is_space(text[length - 1U]) != 0))
    {
        text[length - 1U] = '\0';
        length--;
    }

    return text;
}

static int unsigned_varint_spec_hex_nibble(char character, uint8_t *value)
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

static int unsigned_varint_spec_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t index = 0U;
    size_t output_len = 0U;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }
    if (text == NULL)
    {
        return 0;
    }
    if ((text[0] == '0') && ((text[1] == 'x') || (text[1] == 'X')))
    {
        text += 2;
    }

    while (text[index] != '\0')
    {
        index++;
    }
    if ((index % 2U) != 0U)
    {
        return 0;
    }

    output_len = index / 2U;
    if ((out == NULL) || (output_len > out_capacity))
    {
        return 0;
    }

    for (index = 0U; index < output_len; index++)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((unsigned_varint_spec_hex_nibble(text[index * 2U], &high) == 0) ||
            (unsigned_varint_spec_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
        {
            return 0;
        }

        out[index] = (uint8_t)((high << 4U) | low);
    }

    if (out_len != NULL)
    {
        *out_len = output_len;
    }

    return 1;
}

static int unsigned_varint_spec_parse_u64_decimal(const char *text, uint64_t *value)
{
    uint64_t parsed = UINT64_C(0);
    size_t index = 0U;

    if ((text == NULL) || (value == NULL) || (text[0] == '\0'))
    {
        return 0;
    }

    while (text[index] != '\0')
    {
        const char character = text[index];
        const uint64_t digit = (uint64_t)(character - '0');

        if ((character < '0') || (character > '9'))
        {
            return 0;
        }
        if (parsed > ((UINT64_MAX - digit) / UINT64_C(10)))
        {
            return 0;
        }

        parsed = (parsed * UINT64_C(10)) + digit;
        index++;
    }

    *value = parsed;
    return 1;
}

static int unsigned_varint_spec_parse_example(
    char *line,
    uint64_t *value,
    uint8_t *bytes,
    size_t bytes_capacity,
    size_t *bytes_len)
{
    char *trimmed = unsigned_varint_spec_trim(line);
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
    if (unsigned_varint_spec_parse_u64_decimal(trimmed, value) == 0)
    {
        *space = saved_character;
        return 0;
    }
    *space = saved_character;

    *hex_end = '\0';
    if (unsigned_varint_spec_parse_hex(hex_start + 1, bytes, bytes_capacity, bytes_len) == 0)
    {
        *hex_end = ')';
        return 0;
    }
    *hex_end = ')';
    return 1;
}

static void unsigned_varint_spec_test_readme_examples(const char *repo_root)
{
    char path[512];
    char line[512];
    FILE *spec_file = NULL;
    size_t example_count = 0U;
    int found_non_minimal_text = 0;

    assert(
        unsigned_varint_spec_join_path(
            repo_root,
            LIBP2P_UNSIGNED_VARINT_SPEC_PATH,
            path,
            sizeof(path)) != 0);

    spec_file = fopen(path, "r");
    assert(spec_file != NULL);

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

            assert(
                libp2p_uvarint_encode(value, encoded, sizeof(encoded), &written) ==
                LIBP2P_UVARINT_OK);
            assert(written == expected_len);
            assert((size_t)libp2p_uvarint_size(value) == expected_len);
            assert(memcmp(encoded, expected, expected_len) == 0);

            assert(
                libp2p_uvarint_decode(expected, expected_len, &decoded, &read) ==
                LIBP2P_UVARINT_OK);
            assert(decoded == value);
            assert(read == expected_len);

            example_count++;
        }
    }

    assert(fclose(spec_file) == 0);
    assert(example_count == 6U);
    assert(found_non_minimal_text != 0);
    assert(
        libp2p_uvarint_decode((const uint8_t[]){0x81U, 0x00U}, 2U, NULL, NULL) ==
        LIBP2P_UVARINT_ERR_NON_MINIMAL);
}

int main(int argc, char **argv)
{
    const char *repo_root = ".";

    if (argc > 1)
    {
        repo_root = argv[1];
    }

    unsigned_varint_spec_test_readme_examples(repo_root);
    return 0;
}
