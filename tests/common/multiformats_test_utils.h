#ifndef C_LEAN_LIBP2P_TESTS_COMMON_MULTIFORMATS_TEST_UTILS_H
#define C_LEAN_LIBP2P_TESTS_COMMON_MULTIFORMATS_TEST_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*libp2p_test_case_fn_t)(void);

typedef struct
{
    size_t cases_run;
    size_t failures;
} libp2p_test_context_t;

void libp2p_test_context_init(libp2p_test_context_t *ctx);

void libp2p_test_failf(
    libp2p_test_context_t *ctx,
    const char *file,
    int line,
    const char *fmt,
    ...);

int libp2p_test_run_case(
    const char *suite_name,
    const char *case_name,
    libp2p_test_case_fn_t case_fn,
    size_t *case_count);

int libp2p_test_join_path(const char *root, const char *relative_path, char *out, size_t out_len);

int libp2p_test_repo_path(
    const char *source_file,
    const char *source_suffix,
    const char *relative_path,
    char *out,
    size_t out_len);

char *libp2p_test_trim(char *text);

size_t libp2p_test_csv_split(char *line, char **fields, size_t max_fields);

size_t libp2p_test_split_csv_line(char *line, char **fields, size_t max_fields);

int libp2p_test_parse_hex(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len);

int libp2p_test_hex_to_bytes(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len);

int libp2p_test_parse_u64_decimal(const char *text, uint64_t *value);

int libp2p_test_parse_size_decimal(const char *text, size_t *value);

int libp2p_test_parse_u64_hex(const char *text, uint64_t *value);

int libp2p_test_parse_escaped_bytes(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int libp2p_test_unescape_bytes(
    const char *text,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int libp2p_test_find_table_value(
    const char *line,
    const char *column_name,
    char *out,
    size_t out_len);

#define LIBP2P_TEST_BEGIN_CASE(ctx) ((ctx)->cases_run += 1U)

#define LIBP2P_TEST_CHECK(ctx, condition, message)                         \
    do                                                                     \
    {                                                                      \
        if (!(condition))                                                  \
        {                                                                  \
            libp2p_test_failf((ctx), __FILE__, __LINE__, "%s", (message)); \
            return 0;                                                      \
        }                                                                  \
    } while (0)

#define LIBP2P_TEST_CHECK_INT(ctx, actual, expected, label)         \
    do                                                              \
    {                                                               \
        const int libp2p_test_actual_value = (int)(actual);         \
        const int libp2p_test_expected_value = (int)(expected);     \
                                                                    \
        if (libp2p_test_actual_value != libp2p_test_expected_value) \
        {                                                           \
            libp2p_test_failf(                                      \
                (ctx),                                              \
                __FILE__,                                           \
                __LINE__,                                           \
                "%s: expected %d, got %d",                          \
                (label),                                            \
                libp2p_test_expected_value,                         \
                libp2p_test_actual_value);                          \
            return 0;                                               \
        }                                                           \
    } while (0)

#define LIBP2P_TEST_CHECK_U64(ctx, actual, expected, label)               \
    do                                                                    \
    {                                                                     \
        const uint64_t libp2p_test_actual_value = (uint64_t)(actual);     \
        const uint64_t libp2p_test_expected_value = (uint64_t)(expected); \
                                                                          \
        if (libp2p_test_actual_value != libp2p_test_expected_value)       \
        {                                                                 \
            libp2p_test_failf(                                            \
                (ctx),                                                    \
                __FILE__,                                                 \
                __LINE__,                                                 \
                "%s: expected 0x%llx, got 0x%llx",                        \
                (label),                                                  \
                (unsigned long long)libp2p_test_expected_value,           \
                (unsigned long long)libp2p_test_actual_value);            \
            return 0;                                                     \
        }                                                                 \
    } while (0)

#define LIBP2P_TEST_CHECK_SIZE(ctx, actual, expected, label)          \
    do                                                                \
    {                                                                 \
        const size_t libp2p_test_actual_value = (size_t)(actual);     \
        const size_t libp2p_test_expected_value = (size_t)(expected); \
                                                                      \
        if (libp2p_test_actual_value != libp2p_test_expected_value)   \
        {                                                             \
            libp2p_test_failf(                                        \
                (ctx),                                                \
                __FILE__,                                             \
                __LINE__,                                             \
                "%s: expected %zu, got %zu",                          \
                (label),                                              \
                libp2p_test_expected_value,                           \
                libp2p_test_actual_value);                            \
            return 0;                                                 \
        }                                                             \
    } while (0)

#define LIBP2P_TEST_CHECK_BYTES(ctx, actual, actual_len, expected, expected_len, label)        \
    do                                                                                         \
    {                                                                                          \
        const size_t libp2p_test_actual_len = (size_t)(actual_len);                            \
        const size_t libp2p_test_expected_len = (size_t)(expected_len);                        \
                                                                                               \
        if (libp2p_test_actual_len != libp2p_test_expected_len)                                \
        {                                                                                      \
            libp2p_test_failf(                                                                 \
                (ctx),                                                                         \
                __FILE__,                                                                      \
                __LINE__,                                                                      \
                "%s: expected %zu bytes, got %zu",                                             \
                (label),                                                                       \
                libp2p_test_expected_len,                                                      \
                libp2p_test_actual_len);                                                       \
            return 0;                                                                          \
        }                                                                                      \
        if ((libp2p_test_actual_len != 0U) &&                                                  \
            (memcmp((actual), (expected), libp2p_test_actual_len) != 0))                       \
        {                                                                                      \
            libp2p_test_failf((ctx), __FILE__, __LINE__, "%s: byte comparison failed", label); \
            return 0;                                                                          \
        }                                                                                      \
    } while (0)

#define LIBP2P_TEST_ASSERT(condition)                                                             \
    do                                                                                            \
    {                                                                                             \
        if (!(condition))                                                                         \
        {                                                                                         \
            (void)                                                                                \
                fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                                             \
        }                                                                                         \
    } while (0)

#define LIBP2P_TEST_ASSERT_EQ_U64(expected, actual)                     \
    do                                                                  \
    {                                                                   \
        const uint64_t libp2p_test_expected_u64 = (uint64_t)(expected); \
        const uint64_t libp2p_test_actual_u64 = (uint64_t)(actual);     \
                                                                        \
        if (libp2p_test_expected_u64 != libp2p_test_actual_u64)         \
        {                                                               \
            (void)fprintf(                                              \
                stderr,                                                 \
                "%s:%d: expected 0x%llx but got 0x%llx\n",              \
                __FILE__,                                               \
                __LINE__,                                               \
                (unsigned long long)libp2p_test_expected_u64,           \
                (unsigned long long)libp2p_test_actual_u64);            \
            return 1;                                                   \
        }                                                               \
    } while (0)

#define LIBP2P_TEST_ASSERT_EQ_SIZE(expected, actual)                 \
    do                                                               \
    {                                                                \
        const size_t libp2p_test_expected_size = (size_t)(expected); \
        const size_t libp2p_test_actual_size = (size_t)(actual);     \
                                                                     \
        if (libp2p_test_expected_size != libp2p_test_actual_size)    \
        {                                                            \
            (void)fprintf(                                           \
                stderr,                                              \
                "%s:%d: expected %zu but got %zu\n",                 \
                __FILE__,                                            \
                __LINE__,                                            \
                libp2p_test_expected_size,                           \
                libp2p_test_actual_size);                            \
            return 1;                                                \
        }                                                            \
    } while (0)

#define LIBP2P_TEST_ASSERT_EQ_INT(expected, actual)             \
    do                                                          \
    {                                                           \
        const int libp2p_test_expected_int = (int)(expected);   \
        const int libp2p_test_actual_int = (int)(actual);       \
                                                                \
        if (libp2p_test_expected_int != libp2p_test_actual_int) \
        {                                                       \
            (void)fprintf(                                      \
                stderr,                                         \
                "%s:%d: expected %d but got %d\n",              \
                __FILE__,                                       \
                __LINE__,                                       \
                libp2p_test_expected_int,                       \
                libp2p_test_actual_int);                        \
            return 1;                                           \
        }                                                       \
    } while (0)

#define LIBP2P_TEST_ASSERT_MEM_EQ(expected, actual, length)        \
    do                                                             \
    {                                                              \
        const size_t libp2p_test_length = (size_t)(length);        \
                                                                   \
        if (memcmp((expected), (actual), libp2p_test_length) != 0) \
        {                                                          \
            (void)fprintf(                                         \
                stderr,                                            \
                "%s:%d: memory comparison failed for %zu bytes\n", \
                __FILE__,                                          \
                __LINE__,                                          \
                libp2p_test_length);                               \
            return 1;                                              \
        }                                                          \
    } while (0)

#define LIBP2P_TEST_ASSERT_STR_EQ(expected, actual)        \
    do                                                     \
    {                                                      \
        if (strcmp((expected), (actual)) != 0)             \
        {                                                  \
            (void)fprintf(                                 \
                stderr,                                    \
                "%s:%d: expected \"%s\" but got \"%s\"\n", \
                __FILE__,                                  \
                __LINE__,                                  \
                (expected),                                \
                (actual));                                 \
            return 1;                                      \
        }                                                  \
    } while (0)

#endif
