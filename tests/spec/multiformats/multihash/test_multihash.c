#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "multiformats/multihash/multihash.h"

#define MULTIHASH_SPEC_TEST_CASES_PATH \
    "docs/multiformats-specs/multihash/tests/values/test_cases.csv"
#define MULTIHASH_SPEC_RANDOM_VALS_PATH \
    "docs/multiformats-specs/multihash/tests/values/random_vals.csv"

static int multihash_spec_join_path(
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

static void multihash_spec_trim_newline(char *text)
{
    const size_t length = strlen(text);

    if ((length != 0U) && (text[length - 1U] == '\n'))
    {
        text[length - 1U] = '\0';
    }
}

static int multihash_spec_hex_value(char character, uint8_t *value)
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

static int multihash_spec_parse_hex(
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

        if ((multihash_spec_hex_value(text[index], &high) == 0) ||
            (multihash_spec_hex_value(text[index + 1U], &low) == 0))
        {
            return 0;
        }

        out[index / 2U] = (uint8_t)((high << 4U) | low);
    }

    *out_len = text_len / 2U;
    return 1;
}

static int multihash_spec_split_csv_line(char *line, char **fields, size_t field_count)
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

static int multihash_spec_algorithm_code(const char *algorithm, uint64_t *code)
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

static int multihash_spec_parse_decimal_bits(const char *text, size_t *value)
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

static void multihash_spec_test_case_row(
    const char *algorithm,
    const char *bits_text,
    const char *multihash_hex)
{
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

    assert(multihash_spec_algorithm_code(algorithm, &expected_code) != 0);
    assert(multihash_spec_parse_decimal_bits(bits_text, &bits) != 0);
    assert((bits % 8U) == 0U);
    assert(
        multihash_spec_parse_hex(
            multihash_hex,
            multihash_bytes,
            sizeof(multihash_bytes),
            &multihash_len) != 0);

    assert(
        libp2p_multihash_read_header(
            multihash_bytes,
            multihash_len,
            &parsed_code,
            &digest_len,
            &digest_offset) == LIBP2P_MULTIHASH_OK);
    assert(parsed_code == expected_code);
    assert(digest_len == (bits / 8U));
    assert(digest_offset <= multihash_len);
    assert((digest_offset + digest_len) == multihash_len);

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

        assert(
            libp2p_multihash_decode(
                multihash_bytes,
                multihash_len,
                &parsed_code,
                &digest,
                &digest_len,
                &read) == LIBP2P_MULTIHASH_OK);
        assert(parsed_code == expected_code);
        assert(digest_len == 32U);
        assert(read == multihash_len);
        assert(digest == (multihash_bytes + digest_offset));

        assert(libp2p_multihash_size(expected_code, digest_len, &size) == LIBP2P_MULTIHASH_OK);
        assert(size == multihash_len);

        assert(
            libp2p_multihash_encode(
                expected_code,
                digest,
                digest_len,
                encoded,
                sizeof(encoded),
                &written) == LIBP2P_MULTIHASH_OK);
        assert(written == multihash_len);
        assert(memcmp(encoded, multihash_bytes, multihash_len) == 0);
    }
    else
    {
        size_t written = 99U;
        size_t size = 99U;

        assert(
            libp2p_multihash_decode(multihash_bytes, multihash_len, NULL, NULL, NULL, &read) ==
            expected_err);
        assert(libp2p_multihash_size(expected_code, digest_len, &size) == expected_err);
        assert(size == 0U);
        assert(
            libp2p_multihash_encode(
                expected_code,
                multihash_bytes + digest_offset,
                digest_len,
                multihash_bytes,
                sizeof(multihash_bytes),
                &written) == expected_err);
        assert(written == 0U);
    }
}

static void multihash_spec_test_case_vectors(const char *repo_root, size_t *case_count)
{
    FILE *file = NULL;
    char path[512];
    char line[512];

    assert(
        multihash_spec_join_path(
            repo_root,
            MULTIHASH_SPEC_TEST_CASES_PATH,
            path,
            sizeof(path)) != 0);

    file = fopen(path, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *fields[4] = {NULL, NULL, NULL, NULL};

        multihash_spec_trim_newline(line);
        if (line[0] == '\0')
        {
            continue;
        }

        assert(multihash_spec_split_csv_line(line, fields, 4U) != 0);
        multihash_spec_test_case_row(fields[0], fields[1], fields[3]);
        *case_count += 1U;
    }

    assert(fclose(file) == 0);
}

static void multihash_spec_identity_row(const char *hex_text)
{
    uint8_t input[64];
    uint8_t encoded[66];
    uint64_t code = UINT64_C(0);
    const uint8_t *digest = NULL;
    size_t input_len = 0U;
    size_t digest_len = 0U;
    size_t read = 0U;
    size_t size = 0U;
    size_t written = 0U;

    assert(multihash_spec_parse_hex(hex_text, input, sizeof(input), &input_len) != 0);
    assert((input_len != 0U) && (input_len < sizeof(input)));

    assert(
        libp2p_multihash_size(LIBP2P_MULTIHASH_CODE_IDENTITY, input_len, &size) ==
        LIBP2P_MULTIHASH_OK);
    assert(size == (input_len + 2U));

    assert(
        libp2p_multihash_encode(
            LIBP2P_MULTIHASH_CODE_IDENTITY,
            input,
            input_len,
            encoded,
            sizeof(encoded),
            &written) == LIBP2P_MULTIHASH_OK);
    assert(written == (input_len + 2U));
    assert(encoded[0] == 0x00U);
    assert(encoded[1] == (uint8_t)input_len);
    assert(memcmp(encoded + 2U, input, input_len) == 0);

    assert(
        libp2p_multihash_decode(encoded, written, &code, &digest, &digest_len, &read) ==
        LIBP2P_MULTIHASH_OK);
    assert(code == LIBP2P_MULTIHASH_CODE_IDENTITY);
    assert(digest == (encoded + 2U));
    assert(digest_len == input_len);
    assert(read == written);
    assert(memcmp(digest, input, input_len) == 0);
}

static void multihash_spec_random_identity_vectors(const char *repo_root, size_t *case_count)
{
    FILE *file = NULL;
    char path[512];
    char line[256];

    assert(
        multihash_spec_join_path(
            repo_root,
            MULTIHASH_SPEC_RANDOM_VALS_PATH,
            path,
            sizeof(path)) != 0);

    file = fopen(path, "r");
    assert(file != NULL);

    while (fgets(line, sizeof(line), file) != NULL)
    {
        multihash_spec_trim_newline(line);
        if (line[0] == '\0')
        {
            continue;
        }

        multihash_spec_identity_row(line);
        *case_count += 1U;
    }

    assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    const char *repo_root = ".";
    size_t case_count = 0U;

    if (argc > 1)
    {
        repo_root = argv[1];
    }

    multihash_spec_test_case_vectors(repo_root, &case_count);
    multihash_spec_random_identity_vectors(repo_root, &case_count);
    assert(case_count > 0U);
    return 0;
}
