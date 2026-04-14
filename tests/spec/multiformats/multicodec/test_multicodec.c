#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"

#define LIBP2P_MULTICODEC_SPEC_PATH "docs/multiformats-specs/multicodec/table.csv"

static int multicodec_spec_is_space(char character)
{
    return ((character == ' ') || (character == '\t') || (character == '\n') || (character == '\r'))
               ? 1
               : 0;
}

static int multicodec_spec_hex_nibble(char character, uint8_t *value)
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

static int multicodec_spec_join_path(
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

static char *multicodec_spec_trim(char *text)
{
    char *trimmed = text;
    size_t length = 0U;

    if (text == NULL)
    {
        return NULL;
    }

    while (multicodec_spec_is_space(*trimmed) != 0)
    {
        trimmed++;
    }

    if (trimmed != text)
    {
        (void)memmove(text, trimmed, strlen(trimmed) + 1U);
    }

    length = strlen(text);
    while ((length != 0U) && (multicodec_spec_is_space(text[length - 1U]) != 0))
    {
        text[length - 1U] = '\0';
        length--;
    }

    return text;
}

static size_t multicodec_spec_csv_split(char *line, char **fields, size_t max_fields)
{
    size_t field_count = 0U;
    int in_quotes = 0;
    char *source = line;
    char *dest = line;

    if ((line == NULL) || (fields == NULL) || (max_fields == 0U))
    {
        return 0U;
    }

    fields[field_count] = dest;
    field_count++;

    while (*source != '\0')
    {
        const char character = *source;

        if ((character == '\n') || (character == '\r'))
        {
            source++;
            continue;
        }
        if (character == '"')
        {
            in_quotes = (in_quotes == 0) ? 1 : 0;
            source++;
            continue;
        }
        if ((character == ',') && (in_quotes == 0) && (field_count < max_fields))
        {
            *dest = '\0';
            dest++;
            fields[field_count] = dest;
            field_count++;
            source++;
            continue;
        }

        *dest = character;
        dest++;
        source++;
    }

    *dest = '\0';
    return field_count;
}

static int multicodec_spec_parse_u64_hex(const char *text, uint64_t *value)
{
    uint64_t parsed = UINT64_C(0);
    size_t index = 0U;

    if ((text == NULL) || (value == NULL) || (text[0] == '\0'))
    {
        return 0;
    }
    if ((text[0] == '0') && ((text[1] == 'x') || (text[1] == 'X')))
    {
        text += 2;
    }
    if (text[0] == '\0')
    {
        return 0;
    }

    while (text[index] != '\0')
    {
        uint8_t nibble = 0U;

        if (multicodec_spec_hex_nibble(text[index], &nibble) == 0)
        {
            return 0;
        }
        if (parsed > (UINT64_MAX >> 4U))
        {
            return 0;
        }

        parsed = (parsed << 4U) | (uint64_t)nibble;
        index++;
    }

    *value = parsed;
    return 1;
}

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

static void multicodec_spec_test_table_csv(const char *repo_root)
{
    char path[512];
    char line[1024];
    FILE *table_file = NULL;
    size_t row_count = 0U;

    assert(
        multicodec_spec_join_path(repo_root, LIBP2P_MULTICODEC_SPEC_PATH, path, sizeof(path)) != 0);

    table_file = fopen(path, "r");
    assert(table_file != NULL);

    while (fgets(line, (int)sizeof(line), table_file) != NULL)
    {
        char *fields[5] = {NULL, NULL, NULL, NULL, NULL};
        size_t field_count = 0U;
        char *name = NULL;
        char *tag_text = NULL;
        char *code_text = NULL;
        uint64_t code = UINT64_C(0);

        field_count = multicodec_spec_csv_split(line, fields, sizeof(fields) / sizeof(fields[0]));
        if (field_count < 4U)
        {
            continue;
        }

        name = multicodec_spec_trim(fields[0]);
        tag_text = multicodec_spec_trim(fields[1]);
        code_text = multicodec_spec_trim(fields[2]);
        if ((name == NULL) || (tag_text == NULL) || (code_text == NULL) || (name[0] == '\0') ||
            (strcmp(name, "name") == 0))
        {
            continue;
        }

        assert(multicodec_spec_parse_u64_hex(code_text, &code) != 0);
        row_count++;

        if (multicodec_spec_supported_code(code) != 0)
        {
            const char *resolved_name = NULL;
            libp2p_multicodec_tag_t expected_tag = LIBP2P_MULTICODEC_TAG_HASH;
            libp2p_multicodec_tag_t resolved_tag = LIBP2P_MULTICODEC_TAG_HASH;
            uint64_t resolved_code = UINT64_C(0);

            assert(multicodec_spec_tag_from_text(tag_text, &expected_tag) != 0);
            assert(
                libp2p_multicodec_lookup(code, &resolved_name, &resolved_tag) ==
                LIBP2P_MULTICODEC_OK);
            assert(resolved_name != NULL);
            assert(strcmp(name, resolved_name) == 0);
            assert(resolved_tag == expected_tag);

            assert(
                libp2p_multicodec_from_name(name, strlen(name), &resolved_code) ==
                LIBP2P_MULTICODEC_OK);
            assert(resolved_code == code);
        }
        else
        {
            uint64_t resolved_code = UINT64_C(0);

            assert(libp2p_multicodec_lookup(code, NULL, NULL) == LIBP2P_MULTICODEC_ERR_UNSUPPORTED);
            assert(
                libp2p_multicodec_from_name(name, strlen(name), &resolved_code) ==
                LIBP2P_MULTICODEC_ERR_UNKNOWN_NAME);
            assert(resolved_code == UINT64_C(0));
        }
    }

    assert(fclose(table_file) == 0);
    assert(row_count > 600U);
}

int main(int argc, char **argv)
{
    const char *repo_root = ".";

    if (argc > 1)
    {
        repo_root = argv[1];
    }

    multicodec_spec_test_table_csv(repo_root);
    return 0;
}
