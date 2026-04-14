#include "multiformats_test_utils.h"

#include <stdarg.h>

static int libp2p_test_is_space(char character)
{
    return ((character == ' ') || (character == '\t') || (character == '\n') || (character == '\r'))
               ? 1
               : 0;
}

static int libp2p_test_hex_nibble(char character, uint8_t *value)
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

void libp2p_test_context_init(libp2p_test_context_t *ctx)
{
    if (ctx != NULL)
    {
        ctx->cases_run = 0U;
        ctx->failures = 0U;
    }
}

void libp2p_test_failf(libp2p_test_context_t *ctx, const char *file, int line, const char *fmt, ...)
{
    va_list args;

    if (ctx != NULL)
    {
        ctx->failures += 1U;
    }

    (void)fprintf(stderr, "%s:%d: ", file, line);
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);
    (void)fprintf(stderr, "\n");
}

int libp2p_test_run_case(
    const char *suite_name,
    const char *case_name,
    libp2p_test_case_fn_t case_fn,
    size_t *case_count)
{
    const int result = case_fn();

    if (case_count != NULL)
    {
        *case_count += 1U;
    }

    if (result != 0)
    {
        (void)fprintf(stderr, "%s: %s failed\n", suite_name, case_name);
        return 1;
    }

    return 0;
}

int libp2p_test_join_path(const char *root, const char *relative_path, char *out, size_t out_len)
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

int libp2p_test_repo_path(
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
        return libp2p_test_join_path(root, relative_path, out, out_len);
    }
}

char *libp2p_test_trim(char *text)
{
    char *trimmed = text;
    size_t length = 0U;

    if (text == NULL)
    {
        return NULL;
    }

    while (libp2p_test_is_space(*trimmed) != 0)
    {
        trimmed++;
    }

    if (trimmed != text)
    {
        (void)memmove(text, trimmed, strlen(trimmed) + 1U);
    }

    length = strlen(text);
    while ((length != 0U) && (libp2p_test_is_space(text[length - 1U]) != 0))
    {
        text[length - 1U] = '\0';
        length--;
    }

    return text;
}

size_t libp2p_test_csv_split(char *line, char **fields, size_t max_fields)
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

size_t libp2p_test_split_csv_line(char *line, char **fields, size_t max_fields)
{
    return libp2p_test_csv_split(line, fields, max_fields);
}

int libp2p_test_parse_hex(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
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

        if ((libp2p_test_hex_nibble(text[index * 2U], &high) == 0) ||
            (libp2p_test_hex_nibble(text[(index * 2U) + 1U], &low) == 0))
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

int libp2p_test_hex_to_bytes(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    return libp2p_test_parse_hex(text, out, out_capacity, out_len);
}

int libp2p_test_parse_u64_decimal(const char *text, uint64_t *value)
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

int libp2p_test_parse_size_decimal(const char *text, size_t *value)
{
    uint64_t parsed = UINT64_C(0);

    if ((value == NULL) || (libp2p_test_parse_u64_decimal(text, &parsed) == 0))
    {
        return 0;
    }

    if (parsed > (uint64_t)SIZE_MAX)
    {
        return 0;
    }

    *value = (size_t)parsed;
    return 1;
}

int libp2p_test_parse_u64_hex(const char *text, uint64_t *value)
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

        if (libp2p_test_hex_nibble(text[index], &nibble) == 0)
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

int libp2p_test_parse_escaped_bytes(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t in_index = 0U;
    size_t written = 0U;

    if (out_len != NULL)
    {
        *out_len = 0U;
    }

    if ((text == NULL) || (out == NULL))
    {
        return 0;
    }

    while (text[in_index] != '\0')
    {
        uint8_t byte = 0U;

        if (written >= out_capacity)
        {
            return 0;
        }

        if ((text[in_index] == '\\') && (text[in_index + 1U] == 'x'))
        {
            uint8_t high = 0U;
            uint8_t low = 0U;

            if ((text[in_index + 2U] == '\0') || (text[in_index + 3U] == '\0'))
            {
                return 0;
            }
            if ((libp2p_test_hex_nibble(text[in_index + 2U], &high) == 0) ||
                (libp2p_test_hex_nibble(text[in_index + 3U], &low) == 0))
            {
                return 0;
            }

            byte = (uint8_t)((high << 4U) | low);
            in_index += 4U;
        }
        else
        {
            byte = (uint8_t)text[in_index];
            in_index++;
        }

        out[written] = byte;
        written++;
    }

    if (out_len != NULL)
    {
        *out_len = written;
    }

    return 1;
}

int libp2p_test_unescape_bytes(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    return libp2p_test_parse_escaped_bytes(text, out, out_capacity, out_len);
}

int libp2p_test_find_table_value(
    const char *line,
    const char *column_name,
    char *out,
    size_t out_len)
{
    const char *match = NULL;
    const char *value_start = NULL;
    const char *value_end = NULL;
    size_t value_len = 0U;

    if ((line == NULL) || (column_name == NULL) || (out == NULL) || (out_len == 0U))
    {
        return 0;
    }

    match = strstr(line, column_name);
    if (match == NULL)
    {
        return 0;
    }

    value_start = match + strlen(column_name);
    while ((*value_start == ' ') || (*value_start == '|'))
    {
        value_start++;
    }

    value_end = value_start;
    while ((*value_end != '\0') && (*value_end != '|'))
    {
        value_end++;
    }

    while ((value_end > value_start) && (libp2p_test_is_space(value_end[-1]) != 0))
    {
        value_end--;
    }

    value_len = (size_t)(value_end - value_start);
    if (value_len >= out_len)
    {
        return 0;
    }

    (void)memcpy(out, value_start, value_len);
    out[value_len] = '\0';
    return 1;
}
