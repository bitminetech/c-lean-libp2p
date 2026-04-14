#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"

typedef struct
{
    const char *relative_path;
    size_t total_rows;
    size_t supported_rows;
    size_t unsupported_rows;
} multibase_spec_file_stats_t;

static int multibase_spec_join_path(
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

static int multibase_spec_parse_quoted_field(
    const char *line,
    size_t line_len,
    size_t start_index,
    char *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t index = start_index;
    size_t written = 0U;

    if ((index >= line_len) || (line[index] != '"'))
    {
        return 0;
    }
    index++;

    while ((index < line_len) && (line[index] != '"'))
    {
        char value = line[index];

        if ((value == '\\') && ((index + 3U) < line_len) && (line[index + 1U] == 'x'))
        {
            uint8_t high = 0U;
            uint8_t low = 0U;
            char high_char = line[index + 2U];
            char low_char = line[index + 3U];

            if ((high_char >= '0') && (high_char <= '9'))
            {
                high = (uint8_t)(high_char - '0');
            }
            else if ((high_char >= 'a') && (high_char <= 'f'))
            {
                high = (uint8_t)(10U + (uint8_t)(high_char - 'a'));
            }
            else if ((high_char >= 'A') && (high_char <= 'F'))
            {
                high = (uint8_t)(10U + (uint8_t)(high_char - 'A'));
            }
            else
            {
                return 0;
            }

            if ((low_char >= '0') && (low_char <= '9'))
            {
                low = (uint8_t)(low_char - '0');
            }
            else if ((low_char >= 'a') && (low_char <= 'f'))
            {
                low = (uint8_t)(10U + (uint8_t)(low_char - 'a'));
            }
            else if ((low_char >= 'A') && (low_char <= 'F'))
            {
                low = (uint8_t)(10U + (uint8_t)(low_char - 'A'));
            }
            else
            {
                return 0;
            }

            if (written >= out_capacity)
            {
                return 0;
            }

            out[written] = (char)((high << 4U) | low);
            written++;
            index += 4U;
            continue;
        }

        if (written >= out_capacity)
        {
            return 0;
        }

        out[written] = value;
        written++;
        index++;
    }

    if ((index >= line_len) || (line[index] != '"'))
    {
        return 0;
    }

    *out_len = written;
    return 1;
}

static int multibase_spec_parse_csv_row(
    const char *line,
    char *encoding,
    size_t encoding_capacity,
    size_t *encoding_len,
    char *value,
    size_t value_capacity,
    size_t *value_len)
{
    size_t comma_index = 0U;
    size_t copied = 0U;
    size_t line_len = strlen(line);

    while ((comma_index < line_len) && (line[comma_index] != ','))
    {
        comma_index++;
    }

    if ((comma_index == 0U) || (comma_index >= line_len) || (comma_index >= encoding_capacity))
    {
        return 0;
    }

    for (copied = 0U; copied < comma_index; copied++)
    {
        encoding[copied] = line[copied];
    }
    encoding[comma_index] = '\0';
    *encoding_len = comma_index;

    comma_index++;
    while ((comma_index < line_len) && (line[comma_index] == ' '))
    {
        comma_index++;
    }

    return multibase_spec_parse_quoted_field(
        line,
        line_len,
        comma_index,
        value,
        value_capacity,
        value_len);
}

static int multibase_spec_encoding_to_base(
    const char *encoding,
    size_t encoding_len,
    libp2p_multibase_t *base)
{
    if ((encoding_len == 9U) && (memcmp(encoding, "base58btc", 9U) == 0))
    {
        *base = LIBP2P_MULTIBASE_BASE58BTC;
        return 1;
    }
    if ((encoding_len == 9U) && (memcmp(encoding, "base64url", 9U) == 0))
    {
        *base = LIBP2P_MULTIBASE_BASE64URL;
        return 1;
    }

    return 0;
}

static void multibase_spec_run_file(multibase_spec_file_stats_t *stats, const char *repo_root)
{
    FILE *file = NULL;
    char path[512];
    char line[1024];
    char encoding[64];
    char value[512];
    char input_bytes[256];
    size_t input_len = 0U;
    size_t encoding_len = 0U;
    size_t value_len = 0U;

    assert(multibase_spec_join_path(repo_root, stats->relative_path, path, sizeof(path)) != 0);

    file = fopen(path, "r");
    assert(file != NULL);

    assert(fgets(line, (int)sizeof(line), file) != NULL);
    assert(
        multibase_spec_parse_csv_row(
            line,
            encoding,
            sizeof(encoding),
            &encoding_len,
            input_bytes,
            sizeof(input_bytes),
            &input_len) != 0);

    while (fgets(line, (int)sizeof(line), file) != NULL)
    {
        libp2p_multibase_t base = LIBP2P_MULTIBASE_BASE58BTC;
        uint8_t decoded[256];
        char encoded[512];
        size_t decoded_len = 0U;
        size_t encoded_len = 0U;
        int is_supported = 0;

        if ((line[0] == '\n') || (line[0] == '\r'))
        {
            continue;
        }

        assert(
            multibase_spec_parse_csv_row(
                line,
                encoding,
                sizeof(encoding),
                &encoding_len,
                value,
                sizeof(value),
                &value_len) != 0);

        stats->total_rows++;
        is_supported = multibase_spec_encoding_to_base(encoding, encoding_len, &base);
        if (is_supported != 0)
        {
            stats->supported_rows++;

            assert(
                libp2p_multibase_encode(
                    base,
                    (const uint8_t *)input_bytes,
                    input_len,
                    encoded,
                    sizeof(encoded),
                    &encoded_len) == LIBP2P_MULTIBASE_OK);
            assert(encoded_len == value_len);
            assert(memcmp(encoded, value, value_len) == 0);

            assert(
                libp2p_multibase_decode(
                    value,
                    value_len,
                    &base,
                    decoded,
                    sizeof(decoded),
                    &decoded_len) == LIBP2P_MULTIBASE_OK);
            assert(decoded_len == input_len);
            assert(memcmp(decoded, input_bytes, input_len) == 0);
        }
        else
        {
            stats->unsupported_rows++;

            assert(
                libp2p_multibase_decode(
                    value,
                    value_len,
                    &base,
                    decoded,
                    sizeof(decoded),
                    &decoded_len) == LIBP2P_MULTIBASE_ERR_UNSUPPORTED_BASE);
        }
    }

    assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    multibase_spec_file_stats_t files[] =
        {{"docs/multiformats-specs/multibase/tests/basic.csv", 0U, 0U, 0U},
         {"docs/multiformats-specs/multibase/tests/case_insensitivity.csv", 0U, 0U, 0U},
         {"docs/multiformats-specs/multibase/tests/leading_zero.csv", 0U, 0U, 0U},
         {"docs/multiformats-specs/multibase/tests/two_leading_zeros.csv", 0U, 0U, 0U}};
    const char *repo_root = ".";
    size_t index = 0U;
    size_t total_rows = 0U;
    size_t total_supported = 0U;
    size_t total_unsupported = 0U;

    if (argc > 1)
    {
        repo_root = argv[1];
    }

    for (index = 0U; index < (sizeof(files) / sizeof(files[0])); index++)
    {
        multibase_spec_run_file(&files[index], repo_root);
        total_rows += files[index].total_rows;
        total_supported += files[index].supported_rows;
        total_unsupported += files[index].unsupported_rows;
    }

    (void)total_rows;
    (void)total_supported;
    (void)total_unsupported;
    return 0;
}
