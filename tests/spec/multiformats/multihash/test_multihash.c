#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"

static FILE *libp2p_multihash_spec_open(const char *path)
{
    static const char *const prefixes[] = {"", "../", "../../", "../../../"};
    size_t index = 0U;

    for (index = 0U; index < (sizeof(prefixes) / sizeof(prefixes[0])); index++)
    {
        char full_path[256];
        int written = snprintf(full_path, sizeof(full_path), "%s%s", prefixes[index], path);

        if ((written <= 0) || ((size_t)written >= sizeof(full_path)))
        {
            continue;
        }

        {
            FILE *const file = fopen(full_path, "r");

            if (file != NULL)
            {
                return file;
            }
        }
    }

    return NULL;
}

static int libp2p_multihash_spec_expect(int condition, const char *case_name, const char *message)
{
    if (condition == 0)
    {
        (void)fprintf(stderr, "%s: %s\n", case_name, message);
        return 0;
    }

    return 1;
}

static void libp2p_multihash_spec_trim_newline(char *text)
{
    const size_t length = strlen(text);

    if ((length != 0U) && (text[length - 1U] == '\n'))
    {
        text[length - 1U] = '\0';
    }
}

static int libp2p_multihash_spec_hex_value(char character, uint8_t *value)
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

static int libp2p_multihash_spec_parse_hex(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t text_len = strlen(text);
    size_t index = 0U;

    *out_len = 0U;

    if ((text_len % 2U) != 0U)
    {
        return 0;
    }

    if ((text_len / 2U) > out_capacity)
    {
        return 0;
    }

    for (index = 0U; index < text_len; index += 2U)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if ((libp2p_multihash_spec_hex_value(text[index], &high) == 0) ||
            (libp2p_multihash_spec_hex_value(text[index + 1U], &low) == 0))
        {
            return 0;
        }

        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
    return 1;
}

static int libp2p_multihash_spec_split_csv_line(char *line, char **fields, size_t field_count)
{
    size_t index = 0U;
    char *cursor = line;

    for (index = 0U; index < field_count; index++)
    {
        char *comma = strchr(cursor, ',');

        fields[index] = cursor;
        if (comma == NULL)
        {
            return (index == (field_count - 1U)) ? 1 : 0;
        }

        *comma = '\0';
        cursor = comma + 1;
    }

    return 1;
}

static int libp2p_multihash_spec_algorithm_code(const char *algorithm, uint64_t *code)
{
    if (strcmp(algorithm, "sha1") == 0)
    {
        *code = UINT64_C(0x11);
        return 1;
    }
    if (strcmp(algorithm, "sha2-256") == 0)
    {
        *code = LIBP2P_MULTIHASH_CODE_SHA2_256;
        return 1;
    }
    if (strcmp(algorithm, "sha2-512") == 0)
    {
        *code = UINT64_C(0x13);
        return 1;
    }
    if (strcmp(algorithm, "sha3") == 0)
    {
        *code = UINT64_C(0x14);
        return 1;
    }

    *code = UINT64_C(0);
    return 0;
}

static int libp2p_multihash_spec_parse_decimal_bits(const char *text, size_t *value)
{
    size_t result = 0U;
    size_t index = 0U;

    if ((text == NULL) || (text[0] == '\0'))
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

        result = (result * 10U) + (size_t)(character - '0');
    }

    *value = result;
    return 1;
}

static int libp2p_multihash_spec_test_case_row(
    const char *algorithm,
    const char *bits_text,
    const char *multihash_hex,
    size_t row_number)
{
    char case_name[96];
    uint8_t multihash_bytes[128];
    size_t multihash_len = 0U;
    uint64_t expected_code = UINT64_C(0);
    uint64_t parsed_code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t digest_len = 0U;
    size_t digest_offset = 0U;
    size_t read = 0U;
    size_t bits = 0U;
    libp2p_multihash_err_t expected_err = LIBP2P_MULTIHASH_OK;
    int name_written =
        snprintf(case_name, sizeof(case_name), "test_cases.csv:%lu", (unsigned long)row_number);

    if ((name_written <= 0) || ((size_t)name_written >= sizeof(case_name)))
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_spec_algorithm_code(algorithm, &expected_code) != 0,
            case_name,
            "unknown algorithm in upstream CSV") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_spec_parse_decimal_bits(bits_text, &bits) != 0,
            case_name,
            "invalid bit count in upstream CSV") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect((bits % 8U) == 0U, case_name, "bit count not byte aligned") ==
        0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_spec_parse_hex(
                multihash_hex,
                multihash_bytes,
                sizeof(multihash_bytes),
                &multihash_len) != 0,
            case_name,
            "invalid multihash hex") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_read_header(
                multihash_bytes,
                multihash_len,
                &parsed_code,
                &digest_len,
                &digest_offset) == LIBP2P_MULTIHASH_OK,
            case_name,
            "read_header failed for upstream vector") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            (parsed_code == expected_code) && (digest_len == (bits / 8U)) &&
                (digest_offset <= multihash_len) && ((digest_offset + digest_len) == multihash_len),
            case_name,
            "header fields do not match upstream vector") == 0)
    {
        return 0;
    }

    if ((expected_code == LIBP2P_MULTIHASH_CODE_SHA2_256) && (digest_len == 32U))
    {
        expected_err = LIBP2P_MULTIHASH_OK;
    }
    else if (expected_code == LIBP2P_MULTIHASH_CODE_SHA2_256)
    {
        expected_err = LIBP2P_MULTIHASH_ERR_DIGEST_SIZE_MISMATCH;
    }
    else
    {
        expected_err = LIBP2P_MULTIHASH_ERR_UNSUPPORTED_CODE;
    }

    if (expected_err == LIBP2P_MULTIHASH_OK)
    {
        uint8_t encoded[128];
        size_t written = 0U;
        size_t size = 0U;

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_decode(
                    multihash_bytes,
                    multihash_len,
                    &parsed_code,
                    &digest,
                    &digest_len,
                    &read) == LIBP2P_MULTIHASH_OK,
                case_name,
                "decode failed for supported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                (parsed_code == expected_code) && (digest_len == 32U) && (read == multihash_len) &&
                    (digest == (multihash_bytes + digest_offset)),
                case_name,
                "decode result mismatch for supported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_size(expected_code, digest_len, &size) == LIBP2P_MULTIHASH_OK,
                case_name,
                "size failed for supported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(size == multihash_len, case_name, "wrong encoded size") ==
            0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_encode(
                    expected_code,
                    digest,
                    digest_len,
                    encoded,
                    sizeof(encoded),
                    &written) == LIBP2P_MULTIHASH_OK,
                case_name,
                "encode failed for supported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                (written == multihash_len) &&
                    (memcmp(encoded, multihash_bytes, multihash_len) == 0),
                case_name,
                "round-trip bytes did not match upstream vector") == 0)
        {
            return 0;
        }
    }
    else
    {
        size_t written = 99U;
        size_t size = 99U;

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_decode(multihash_bytes, multihash_len, NULL, NULL, NULL, &read) ==
                    expected_err,
                case_name,
                "decode returned wrong error for unsupported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_size(expected_code, digest_len, &size) == expected_err,
                case_name,
                "size returned wrong error for unsupported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                size == 0U,
                case_name,
                "size output not cleared on error") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_encode(
                    expected_code,
                    multihash_bytes + digest_offset,
                    digest_len,
                    multihash_bytes,
                    sizeof(multihash_bytes),
                    &written) == expected_err,
                case_name,
                "encode returned wrong error for unsupported vector") == 0)
        {
            return 0;
        }

        if (libp2p_multihash_spec_expect(
                written == 0U,
                case_name,
                "encode written not reset on error") == 0)
        {
            return 0;
        }
    }

    return 1;
}

static int libp2p_multihash_spec_test_case_vectors(size_t *case_count)
{
    FILE *file =
        libp2p_multihash_spec_open("docs/multiformats-specs/multihash/tests/values/test_cases.csv");
    char line[512];
    size_t row_number = 0U;

    if (file == NULL)
    {
        (void)fprintf(stderr, "failed to open multihash test_cases.csv\n");
        return 0;
    }

    if (fgets(line, sizeof(line), file) == NULL)
    {
        (void)fprintf(stderr, "multihash test_cases.csv is empty\n");
        (void)fclose(file);
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *fields[4] = {NULL, NULL, NULL, NULL};

        libp2p_multihash_spec_trim_newline(line);
        row_number++;
        if (line[0] == '\0')
        {
            continue;
        }

        if (libp2p_multihash_spec_expect(
                libp2p_multihash_spec_split_csv_line(line, fields, 4U) != 0,
                "test_cases.csv",
                "failed to split CSV line") == 0)
        {
            (void)fclose(file);
            return 0;
        }

        if (libp2p_multihash_spec_test_case_row(fields[0], fields[1], fields[3], row_number) == 0)
        {
            (void)fclose(file);
            return 0;
        }

        *case_count += 1U;
    }

    (void)fclose(file);
    return 1;
}

static int libp2p_multihash_spec_identity_row(const char *hex_text, size_t row_number)
{
    char case_name[96];
    uint8_t input[64];
    uint8_t encoded[66];
    uint64_t code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t input_len = 0U;
    size_t digest_len = 0U;
    size_t read = 0U;
    size_t size = 0U;
    size_t written = 0U;
    int name_written =
        snprintf(case_name, sizeof(case_name), "random_vals.csv:%lu", (unsigned long)row_number);

    if ((name_written <= 0) || ((size_t)name_written >= sizeof(case_name)))
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_spec_parse_hex(hex_text, input, sizeof(input), &input_len) != 0,
            case_name,
            "invalid identity input hex") == 0)
    {
        return 0;
    }

    if ((input_len == 0U) || (input_len >= sizeof(input)))
    {
        (void)fprintf(
            stderr,
            "%s: unexpected random input length (%lu)\n",
            case_name,
            (unsigned long)input_len);
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, input_len, &size) ==
                LIBP2P_MULTIHASH_OK,
            case_name,
            "size failed for identity vector") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(size == (input_len + 2U), case_name, "wrong identity size") ==
        0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_encode(
                LIBP2P_MULTIHASH_CODE_IDENTITY,
                input,
                input_len,
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_OK,
            case_name,
            "encode failed for identity vector") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            (written == (input_len + 2U)) && (encoded[0] == 0x00U) &&
                (encoded[1] == (uint8_t)input_len) && (memcmp(encoded + 2U, input, input_len) == 0),
            case_name,
            "identity encoding did not match spec format") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            libp2p_multihash_decode(encoded, written, &code, &digest, &digest_len, &read) ==
                LIBP2P_MULTIHASH_OK,
            case_name,
            "decode failed for identity vector") == 0)
    {
        return 0;
    }

    if (libp2p_multihash_spec_expect(
            (code == LIBP2P_MULTIHASH_CODE_IDENTITY) && (digest == (encoded + 2U)) &&
                (digest_len == input_len) && (read == written) &&
                (memcmp(digest, input, input_len) == 0),
            case_name,
            "identity decode mismatch") == 0)
    {
        return 0;
    }

    return 1;
}

static int libp2p_multihash_spec_random_identity_vectors(size_t *case_count)
{
    FILE *file = libp2p_multihash_spec_open(
        "docs/multiformats-specs/multihash/tests/values/random_vals.csv");
    char line[256];
    size_t row_number = 0U;

    if (file == NULL)
    {
        (void)fprintf(stderr, "failed to open multihash random_vals.csv\n");
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        libp2p_multihash_spec_trim_newline(line);
        row_number++;
        if (line[0] == '\0')
        {
            continue;
        }

        if (libp2p_multihash_spec_identity_row(line, row_number) == 0)
        {
            (void)fclose(file);
            return 0;
        }

        *case_count += 1U;
    }

    (void)fclose(file);
    return 1;
}

int main(void)
{
    size_t case_count = 0U;

    if (libp2p_multihash_spec_test_case_vectors(&case_count) == 0)
    {
        return 1;
    }

    if (libp2p_multihash_spec_random_identity_vectors(&case_count) == 0)
    {
        return 1;
    }

    (void)printf("multihash spec: %lu vectors passed\n", (unsigned long)case_count);
    return 0;
}
