#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/multiformats_test_utils.h"
#include "multiformats/multiaddr/multiaddr.h"

#define LIBP2P_TEST_MULTIADDR_CODE_P2P UINT64_C(0x01A5)

static const char multiaddr_spec_source_suffix[] =
    "c-lean-libp2p/tests/spec/multiformats/multiaddr/test_multiaddr.c";
static const char multiaddr_spec_peer_id[] = "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk";

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
        if (libp2p_test_parse_u64_hex(token, &parsed) == 0)
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

static int multiaddr_spec_run_supported_readme_example(
    libp2p_test_context_t *ctx,
    const char *address_text,
    const char *packed_text)
{
    uint8_t expected[32];
    uint8_t actual[32];
    char roundtrip[64];
    size_t expected_len = 0U;
    size_t actual_len = 0U;
    size_t roundtrip_len = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        multiaddr_spec_spaced_hex_to_bytes(
            packed_text,
            expected,
            sizeof(expected),
            &expected_len) != 0,
        "README packed example parse");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            actual,
            sizeof(actual),
            &actual_len),
        LIBP2P_MULTIADDR_OK,
        "README from_string");
    LIBP2P_TEST_CHECK_BYTES(ctx, actual, actual_len, expected, expected_len, "README packed bytes");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(actual, actual_len),
        LIBP2P_MULTIADDR_OK,
        "README validate");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(
            actual,
            actual_len,
            roundtrip,
            sizeof(roundtrip),
            &roundtrip_len),
        LIBP2P_MULTIADDR_OK,
        "README to_string");
    LIBP2P_TEST_CHECK_BYTES(
        ctx,
        roundtrip,
        roundtrip_len,
        address_text,
        strlen(address_text),
        "README roundtrip");

    return 1;
}

static int multiaddr_spec_readme_example(libp2p_test_context_t *ctx)
{
    char path[256];
    char line[512];
    char address_text[128];
    char packed_text[128];
    FILE *readme = NULL;
    int found_address = 0;
    int found_packed = 0;

    LIBP2P_TEST_CHECK(
        ctx,
        libp2p_test_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/README.md",
            path,
            sizeof(path)) != 0,
        "resolve multiaddr README path");

    readme = fopen(path, "r");
    LIBP2P_TEST_CHECK(ctx, readme != NULL, "open multiaddr README");

    while (fgets(line, sizeof(line), readme) != NULL)
    {
        libp2p_test_trim(line);

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

    (void)fclose(readme);

    LIBP2P_TEST_CHECK(ctx, found_address != 0, "find README address example");
    LIBP2P_TEST_CHECK(ctx, found_packed != 0, "find README packed example");

    return multiaddr_spec_run_supported_readme_example(ctx, address_text, packed_text);
}

static int multiaddr_spec_run_string_scenario(
    libp2p_test_context_t *ctx,
    const char *address_text,
    const char *packed_text)
{
    uint8_t packed[32];
    size_t packed_len = 0U;
    char out[128];
    size_t written = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        libp2p_test_hex_to_bytes(packed_text, packed, sizeof(packed), &packed_len) != 0,
        "feature parse packed hex");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            packed,
            sizeof(packed),
            &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature string scenario unsupported");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(packed, packed_len),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature validate unsupported");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(packed, packed_len, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature to_string unsupported");

    return 1;
}

static int multiaddr_spec_run_packed_scenario(
    libp2p_test_context_t *ctx,
    const char *packed_text,
    const char *address_text)
{
    uint8_t packed[32];
    size_t packed_len = 0U;
    char out[128];
    size_t written = 0U;

    LIBP2P_TEST_BEGIN_CASE(ctx);
    LIBP2P_TEST_CHECK(
        ctx,
        libp2p_test_hex_to_bytes(packed_text, packed, sizeof(packed), &packed_len) != 0,
        "feature packed parse");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_validate(packed, packed_len),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature packed validate");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_to_string(packed, packed_len, out, sizeof(out), &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature packed to_string");
    LIBP2P_TEST_CHECK_INT(
        ctx,
        libp2p_multiaddr_from_string(
            address_text,
            strlen(address_text),
            packed,
            sizeof(packed),
            &written),
        LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
        "feature packed string unsupported");

    return 1;
}

static int multiaddr_spec_feature_file(libp2p_test_context_t *ctx)
{
    char path[256];
    char line[512];
    char given_value[256];
    char expected_value[256];
    FILE *feature = NULL;
    int scenario_count = 0;

    LIBP2P_TEST_CHECK(
        ctx,
        libp2p_test_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/test/multiaddr.feature",
            path,
            sizeof(path)) != 0,
        "resolve feature path");

    feature = fopen(path, "r");
    LIBP2P_TEST_CHECK(ctx, feature != NULL, "open multiaddr feature");

    given_value[0] = '\0';
    expected_value[0] = '\0';

    while (fgets(line, sizeof(line), feature) != NULL)
    {
        libp2p_test_trim(line);

        if (strncmp(line, "Given the multiaddr ", 20U) == 0)
        {
            (void)memcpy(given_value, line + 20U, strlen(line + 20U) + 1U);
        }
        else if (strncmp(line, "Then the packed form is ", 24U) == 0)
        {
            (void)memcpy(expected_value, line + 24U, strlen(line + 24U) + 1U);
            LIBP2P_TEST_CHECK(
                ctx,
                multiaddr_spec_run_string_scenario(ctx, given_value, expected_value) != 0,
                "run string scenario");
            scenario_count++;
        }
        else if (strncmp(line, "Then the string form is ", 24U) == 0)
        {
            (void)memcpy(expected_value, line + 24U, strlen(line + 24U) + 1U);
            LIBP2P_TEST_CHECK(
                ctx,
                multiaddr_spec_run_packed_scenario(ctx, given_value, expected_value) != 0,
                "run packed scenario");
            scenario_count++;
        }
    }

    (void)fclose(feature);

    LIBP2P_TEST_CHECK_INT(ctx, scenario_count, 2, "feature scenario count");
    return 1;
}

static int multiaddr_spec_protocol_table(libp2p_test_context_t *ctx)
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

    LIBP2P_TEST_CHECK(
        ctx,
        libp2p_test_repo_path(
            __FILE__,
            multiaddr_spec_source_suffix,
            "docs/multiformats-specs/multiaddr/protocols.csv",
            path,
            sizeof(path)) != 0,
        "resolve protocols path");

    protocols = fopen(path, "r");
    LIBP2P_TEST_CHECK(ctx, protocols != NULL, "open protocols.csv");

    while (fgets(line, sizeof(line), protocols) != NULL)
    {
        char *fields[4];
        size_t field_count = 0U;
        uint64_t code = UINT64_C(0);
        char *size_text = NULL;
        char *name_text = NULL;

        libp2p_test_trim(line);
        if ((line[0] == '\0') || (strcmp(line, "code,\tsize,\tname,\tcomment") == 0))
        {
            continue;
        }

        field_count = libp2p_test_split_csv_line(line, fields, 4U);
        LIBP2P_TEST_CHECK(ctx, field_count >= 3U, "protocols.csv field count");
        size_text = libp2p_test_trim(fields[1]);
        name_text = libp2p_test_trim(fields[2]);
        LIBP2P_TEST_CHECK(
            ctx,
            multiaddr_spec_parse_u64(fields[0], &code) != 0,
            "protocols.csv code parse");

        LIBP2P_TEST_BEGIN_CASE(ctx);
        if (strcmp(name_text, "ipfs") == 0)
        {
            const char *name = NULL;
            libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
            size_t fixed_size = 1U;
            size_t alias_len = 0U;
            size_t canonical_len = 0U;

            LIBP2P_TEST_CHECK_U64(ctx, code, LIBP2P_TEST_MULTIADDR_CODE_P2P, "ipfs alias code");
            LIBP2P_TEST_CHECK_INT(
                ctx,
                libp2p_multiaddr_protocol_info(code, &name, &value_class, &fixed_size),
                LIBP2P_MULTIADDR_OK,
                "ipfs alias protocol_info");
            LIBP2P_TEST_CHECK(ctx, strcmp(name, "p2p") == 0, "ipfs alias canonical name");
            LIBP2P_TEST_CHECK_INT(
                ctx,
                value_class,
                LIBP2P_MULTIADDR_VALUE_VARIABLE,
                "ipfs alias value class");
            LIBP2P_TEST_CHECK_SIZE(ctx, fixed_size, 0U, "ipfs alias fixed size");

            alias_len = (size_t)
                snprintf(alias_text, sizeof(alias_text), "/ipfs/%s", multiaddr_spec_peer_id);
            canonical_len = (size_t)
                snprintf(canonical_text, sizeof(canonical_text), "/p2p/%s", multiaddr_spec_peer_id);
            LIBP2P_TEST_CHECK(ctx, alias_len < sizeof(alias_text), "format alias text");
            LIBP2P_TEST_CHECK(ctx, canonical_len < sizeof(canonical_text), "format canonical text");
            LIBP2P_TEST_CHECK_INT(
                ctx,
                libp2p_multiaddr_from_string(
                    alias_text,
                    alias_len,
                    alias_bytes,
                    sizeof(alias_bytes),
                    &alias_len),
                LIBP2P_MULTIADDR_OK,
                "from_string ipfs alias");
            LIBP2P_TEST_CHECK_INT(
                ctx,
                libp2p_multiaddr_from_string(
                    canonical_text,
                    canonical_len,
                    canonical_bytes,
                    sizeof(canonical_bytes),
                    &canonical_len),
                LIBP2P_MULTIADDR_OK,
                "from_string p2p canonical");
            LIBP2P_TEST_CHECK_BYTES(
                ctx,
                alias_bytes,
                alias_len,
                canonical_bytes,
                canonical_len,
                "ipfs alias bytes");
            saw_alias = 1;
        }
        else if (multiaddr_spec_is_supported_name(name_text) != 0)
        {
            const char *name = NULL;
            libp2p_multiaddr_value_class_t value_class = LIBP2P_MULTIADDR_VALUE_NONE;
            libp2p_multiaddr_value_class_t expected_class = LIBP2P_MULTIADDR_VALUE_NONE;
            size_t fixed_size = 0U;
            size_t expected_fixed_size = 0U;

            LIBP2P_TEST_CHECK(
                ctx,
                multiaddr_spec_expected_class(size_text, &expected_class, &expected_fixed_size) !=
                    0,
                "protocols.csv expected class");
            LIBP2P_TEST_CHECK_INT(
                ctx,
                libp2p_multiaddr_protocol_info(code, &name, &value_class, &fixed_size),
                LIBP2P_MULTIADDR_OK,
                "protocol_info supported");
            LIBP2P_TEST_CHECK(ctx, strcmp(name, name_text) == 0, "protocol_info canonical name");
            LIBP2P_TEST_CHECK_INT(ctx, value_class, expected_class, "protocol_info value class");
            LIBP2P_TEST_CHECK_SIZE(
                ctx,
                fixed_size,
                expected_fixed_size,
                "protocol_info fixed size");
        }
        else
        {
            LIBP2P_TEST_CHECK_INT(
                ctx,
                libp2p_multiaddr_protocol_info(code, NULL, NULL, NULL),
                LIBP2P_MULTIADDR_ERR_UNSUPPORTED_PROTOCOL,
                "protocol_info unsupported row");
        }

        row_count++;
    }

    (void)fclose(protocols);

    LIBP2P_TEST_CHECK(ctx, saw_alias != 0, "saw ipfs alias row");
    LIBP2P_TEST_CHECK(ctx, row_count > 0, "protocol table rows");
    return 1;
}

int main(void)
{
    libp2p_test_context_t ctx;

    libp2p_test_context_init(&ctx);

    if ((multiaddr_spec_readme_example(&ctx) == 0) || (multiaddr_spec_feature_file(&ctx) == 0) ||
        (multiaddr_spec_protocol_table(&ctx) == 0))
    {
        (void)fprintf(
            stderr,
            "multiaddr spec: %zu cases, %zu failures\n",
            ctx.cases_run,
            ctx.failures);
        return 1;
    }

    (void)printf("multiaddr spec: %zu cases\n", ctx.cases_run);
    return 0;
}
