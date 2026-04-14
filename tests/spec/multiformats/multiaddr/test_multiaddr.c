#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"

#define LIBP2P_TEST_MULTIADDR_CODE_P2P UINT64_C(0x01A5)

static const char multiaddr_spec_source_suffix[] =
    "c-lean-libp2p/tests/spec/multiformats/multiaddr/test_multiaddr.c";
static const char multiaddr_spec_peer_id[] = "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";

static int multiaddr_spec_is_space(char character)
{
    return ((character == ' ') || (character == '\t') || (character == '\n') || (character == '\r'))
               ? 1
               : 0;
}

static int multiaddr_spec_hex_nibble(char character, uint8_t *value)
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

static int multiaddr_spec_join_path(
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

static int multiaddr_spec_repo_path(
    const char *source_file,
    const char *source_suffix,
    const char *relative_path,
    char *out,
    size_t out_len)
{
    const char *match = NULL;

    if ((source_file == NULL) || (source_suffix == NULL) || (relative_path == NULL))
    {
        return 0;
    }

    match = strstr(source_file, source_suffix);
    if (match == NULL)
    {
        return 0;
    }
    if (match == source_file)
    {
        if (strlen(relative_path) >= out_len)
        {
            return 0;
        }

        (void)memcpy(out, relative_path, strlen(relative_path) + 1U);
        return 1;
    }

    {
        char root[512];
        const size_t root_len = (size_t)(match - source_file);

        if ((root_len + 1U) > sizeof(root))
        {
            return 0;
        }

        (void)memcpy(root, source_file, root_len);
        root[root_len] = '\0';
        return multiaddr_spec_join_path(root, relative_path, out, out_len);
    }
}

static char *multiaddr_spec_trim(char *text)
{
    char *trimmed = text;
    size_t length = 0U;

    if (text == NULL)
    {
        return NULL;
    }

    while (multiaddr_spec_is_space(*trimmed) != 0)
    {
        trimmed++;
    }

    if (trimmed != text)
    {
        (void)memmove(text, trimmed, strlen(trimmed) + 1U);
    }

    length = strlen(text);
    while ((length != 0U) && (multiaddr_spec_is_space(text[length - 1U]) != 0))
    {
        text[length - 1U] = '\0';
        length--;
    }

    return text;
}

static size_t multiaddr_spec_csv_split(char *line, char **fields, size_t max_fields)
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

static int multiaddr_spec_parse_u64_hex(const char *text, uint64_t *value)
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

        if (multiaddr_spec_hex_nibble(text[index], &nibble) == 0)
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

static int multiaddr_spec_parse_hex(
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

        if ((multiaddr_spec_hex_nibble(text[index * 2U], &high) == 0) ||
            (multiaddr_spec_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
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

static int multiaddr_spec_parse_u64(const char *text, uint64_t *value)
{
    uint64_t parsed = UINT64_C(0);
    size_t index = 0U;

    if ((text == NULL) || (text[0] == '\0') || (value == NULL))
    {
        return 0;
    }

    for (index = 0U; text[index] != '\0'; index++)
    {
        const char character = text[index];

        if ((character < '0') || (character > '9'))
        {
            return 0;
        }

        parsed = (parsed * 10U) + (uint64_t)(character - '0');
    }

    *value = parsed;
    return 1;
}

static int multiaddr_spec_is_supported_name(const char *name)
{
    return ((strcmp(name, "ip4") == 0) || (strcmp(name, "ip6") == 0) ||
            (strcmp(name, "udp") == 0) || (strcmp(name, "p2p") == 0) ||
            (strcmp(name, "quic-v1") == 0))
               ? 1
               : 0;
}

static int multiaddr_spec_expected_class(
    const char *size_text,
    libp2p_multiaddr_value_class_t *value_class,
    size_t *fixed_size)
{
    uint64_t bits = UINT64_C(0);

    if ((size_text == NULL) || (value_class == NULL) || (fixed_size == NULL))
    {
        return 0;
    }
    if (strcmp(size_text, "V") == 0)
    {
        *value_class = LIBP2P_MULTIADDR_VALUE_VARIABLE;
        *fixed_size = 0U;
        return 1;
    }
    if (multiaddr_spec_parse_u64(size_text, &bits) == 0)
    {
        return 0;
    }
    if (bits == UINT64_C(0))
    {
        *value_class = LIBP2P_MULTIADDR_VALUE_NONE;
        *fixed_size = 0U;
        return 1;
    }

    *value_class = LIBP2P_MULTIADDR_VALUE_FIXED;
    *fixed_size = (size_t)(bits / 8U);
    return ((bits % UINT64_C(8)) == UINT64_C(0)) ? 1 : 0;
}

static int multiaddr_spec_spaced_hex_to_bytes(
    const char *text,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t out_index = 0U;
    size_t index = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }
    if (text == NULL)
    {
        return 0;
    }

    while (text[index] != '\0')
    {
        char token[5];
        size_t token_len = 0U;
        uint64_t parsed = UINT64_C(0);

        while ((text[index] == ' ') || (text[index] == '\t'))
        {
            index++;
        }
        if (text[index] == '\0')
        {
            break;
        }

        while ((text[index] != '\0') && (text[index] != ' ') && (text[index] != '\t'))
        {
            if (token_len >= (sizeof(token) - 1U))
            {
                return 0;
            }

            token[token_len] = text[index];
            token_len++;
            index++;
        }
        token[token_len] = '\0';

        if ((out == NULL) || (out_index >= out_len))
        {
            return 0;
        }
        if (multiaddr_spec_parse_u64_hex(token, &parsed) == 0)
        {
            return 0;
        }
        if (parsed > UINT64_C(0xFF))
        {
            return 0;
        }

        out[out_index] = (uint8_t)parsed;
        out_index++;
    }

    if (written != NULL)
    {
        *written = out_index;
    }

    return 1;
}

static int multiaddr_spec_extract_backtick(const char *line, char *out, size_t out_len)
{
    const char *start = strchr(line, '`');
    const char *end = NULL;
    size_t length = 0U;

    if ((start == NULL) || (out == NULL) || (out_len == 0U))
    {
        return 0;
    }

    end = strchr(start + 1, '`');
    if (end == NULL)
    {
        return 0;
    }

    length = (size_t)(end - (start + 1));
    if (out_len <= length)
    {
        return 0;
    }

    (void)memcpy(out, start + 1, length);
    out[length] = '\0';
    return 1;
}

static void multiaddr_spec_run_supported_readme_example(
    const char *address_text,
    const char *packed_text)
{
    uint8_t expected[32];
    uint8_t actual[32];
    char roundtrip[64];
    size_t expected_len = 0U;
    size_t actual_len = 0U;
    size_t roundtrip_len = 0U;

    assert(
        multiaddr_spec_spaced_hex_to_bytes(
            packed_text,
            expected,
            sizeof(expected),
            &expected_len) != 0);
    assert(
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            actual,
            sizeof(actual),
            &actual_len) == LIBP2P_MULTIADDR_OK);
    assert(actual_len == expected_len);
    assert(memcmp(actual, expected, expected_len) == 0);
    assert(libp2p_multiaddr_validate(actual, actual_len) == LIBP2P_MULTIADDR_OK);
    assert(
        libp2p_multiaddr_to_string(
            actual,
            actual_len,
            roundtrip,
            sizeof(roundtrip),
            &roundtrip_len) == LIBP2P_MULTIADDR_OK);
    assert(roundtrip_len == strlen(address_text));
    assert(memcmp(roundtrip, address_text, roundtrip_len) == 0);
}

static void multiaddr_spec_readme_example(void)
{
    char path[256];
    char line[512];
    char address_text[128];
    char packed_text[128];
    FILE *readme = NULL;
    int found_address = 0;
    int found_packed = 0;

    assert(
        multiaddr_spec_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/README.md",
            path,
            sizeof(path)) != 0);

    readme = fopen(path, "r");
    assert(readme != NULL);

    while (fgets(line, sizeof(line), readme) != NULL)
    {
        multiaddr_spec_trim(line);

        if ((found_address == 0) && (strstr(line, "Example: `") != NULL))
        {
            found_address =
                multiaddr_spec_extract_backtick(line, address_text, sizeof(address_text));
        }
        if ((found_packed == 0) && (strstr(line, "Same example: ") != NULL))
        {
            found_packed = multiaddr_spec_extract_backtick(line, packed_text, sizeof(packed_text));
        }
    }

    assert(fclose(readme) == 0);
    assert(found_address != 0);
    assert(found_packed != 0);
    multiaddr_spec_run_supported_readme_example(address_text, packed_text);
}

static void multiaddr_spec_run_string_scenario(const char *address_text, const char *packed_text)
{
    uint8_t packed[32];
    size_t packed_len = 0U;
    char out[128];
    size_t written = 0U;

    assert(multiaddr_spec_parse_hex(packed_text, packed, sizeof(packed), &packed_len) != 0);
    assert(
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            packed,
            sizeof(packed),
            &written) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_validate(packed, packed_len) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_to_string(packed, packed_len, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
}

static void multiaddr_spec_run_packed_scenario(const char *packed_text, const char *address_text)
{
    uint8_t packed[32];
    size_t packed_len = 0U;
    char out[128];
    size_t written = 0U;

    assert(multiaddr_spec_parse_hex(packed_text, packed, sizeof(packed), &packed_len) != 0);
    assert(
        libp2p_multiaddr_validate(packed, packed_len) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_to_string(packed, packed_len, out, sizeof(out), &written) ==
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
    assert(
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            packed,
            sizeof(packed),
            &written) == LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
}

static void multiaddr_spec_feature_file(void)
{
    char path[256];
    char line[512];
    char given_value[256];
    char expected_value[256];
    FILE *feature = NULL;
    int scenario_count = 0;

    assert(
        multiaddr_spec_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/test/multiaddr.feature",
            path,
            sizeof(path)) != 0);

    feature = fopen(path, "r");
    assert(feature != NULL);

    given_value[0] = '\0';
    expected_value[0] = '\0';

    while (fgets(line, sizeof(line), feature) != NULL)
    {
        multiaddr_spec_trim(line);

        if (strncmp(line, "Given the multiaddr ", 20U) == 0)
        {
            (void)memcpy(given_value, line + 20U, strlen(line + 20U) + 1U);
        }
        else if (strncmp(line, "Then the packed form is ", 24U) == 0)
        {
            (void)memcpy(expected_value, line + 24U, strlen(line + 24U) + 1U);
            multiaddr_spec_run_string_scenario(given_value, expected_value);
            scenario_count++;
        }
        else if (strncmp(line, "Then the string form is ", 24U) == 0)
        {
            (void)memcpy(expected_value, line + 24U, strlen(line + 24U) + 1U);
            multiaddr_spec_run_packed_scenario(given_value, expected_value);
            scenario_count++;
        }
    }

    assert(fclose(feature) == 0);
    assert(scenario_count == 2);
}

static void multiaddr_spec_protocol_table(void)
{
    char path[256];
    char line[512];
    char alias_text[128];
    char canonical_text[128];
    uint8_t alias_bytes[128];
    uint8_t canonical_bytes[128];
    FILE *protocols = NULL;
    int row_count = 0;
    int saw_alias = 0;

    assert(
        multiaddr_spec_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/protocols.csv",
            path,
            sizeof(path)) != 0);

    protocols = fopen(path, "r");
    assert(protocols != NULL);

    while (fgets(line, sizeof(line), protocols) != NULL)
    {
        char *fields[4] = {NULL, NULL, NULL, NULL};
        size_t field_count = 0U;
        uint64_t code = UINT64_C(0);
        char *size_text = NULL;
        char *name_text = NULL;

        multiaddr_spec_trim(line);
        if ((line[0] == '\0') || (strcmp(line, "code,\tsize,\tname,\tcomment") == 0))
        {
            continue;
        }

        field_count = multiaddr_spec_csv_split(line, fields, 4U);
        assert(field_count >= 3U);
        size_text = multiaddr_spec_trim(fields[1]);
        name_text = multiaddr_spec_trim(fields[2]);
        assert(multiaddr_spec_parse_u64(fields[0], &code) != 0);

        if (strcmp(name_text, "ipfs") == 0)
        {
            const char *name = NULL;
            libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
            size_t fixed_size = 1U;
            size_t alias_len = 0U;
            size_t canonical_len = 0U;
            int written = 0;

            assert(code == LIBP2P_TEST_MULTIADDR_CODE_P2P);
            assert(
                libp2p_multiaddr_protocol_info(code, &name, &value_class, &fixed_size) ==
                LIBP2P_MULTIADDR_OK);
            assert(strcmp(name, "p2p") == 0);
            assert(value_class == LIBP2P_MULTIADDR_VALUE_VARIABLE);
            assert(fixed_size == 0U);

            written = snprintf(alias_text, sizeof(alias_text), "/ipfs/%s", multiaddr_spec_peer_id);
            assert(written >= 0);
            alias_len = (size_t)written;
            assert(alias_len < sizeof(alias_text));

            written =
                snprintf(canonical_text, sizeof(canonical_text), "/p2p/%s", multiaddr_spec_peer_id);
            assert(written >= 0);
            canonical_len = (size_t)written;
            assert(canonical_len < sizeof(canonical_text));

            assert(
                libp2p_multiaddr_from_string(
                    alias_text,
                    alias_len,
                    alias_bytes,
                    sizeof(alias_bytes),
                    &alias_len) == LIBP2P_MULTIADDR_OK);
            assert(
                libp2p_multiaddr_from_string(
                    canonical_text,
                    canonical_len,
                    canonical_bytes,
                    sizeof(canonical_bytes),
                    &canonical_len) == LIBP2P_MULTIADDR_OK);
            assert(alias_len == canonical_len);
            assert(memcmp(alias_bytes, canonical_bytes, canonical_len) == 0);
            saw_alias = 1;
        }
        else if (multiaddr_spec_is_supported_name(name_text) != 0)
        {
            const char *name = NULL;
            libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
            libp2p_multiaddr_value_class_t expected_class = LIBP2P_MULTIADDR_VALUE_NONE;
            size_t fixed_size = 0U;
            size_t expected_fixed_size = 0U;

            assert(
                multiaddr_spec_expected_class(size_text, &expected_class, &expected_fixed_size) !=
                0);
            assert(
                libp2p_multiaddr_protocol_info(code, &name, &value_class, &fixed_size) ==
                LIBP2P_MULTIADDR_OK);
            assert(strcmp(name, name_text) == 0);
            assert(value_class == expected_class);
            assert(fixed_size == expected_fixed_size);
        }
        else
        {
            assert(
                libp2p_multiaddr_protocol_info(code, NULL, NULL, NULL) ==
                LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL);
        }

        row_count++;
    }

    assert(fclose(protocols) == 0);
    assert(saw_alias != 0);
    assert(row_count > 0);
}

int main(void)
{
    multiaddr_spec_readme_example();
    multiaddr_spec_feature_file();
    multiaddr_spec_protocol_table();
    return 0;
}
