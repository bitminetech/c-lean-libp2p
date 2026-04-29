#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "gossipsub_interop.h"

typedef struct
{
    const char *data;
    size_t len;
} gossipsub_json_span_t;

static uint8_t gossipsub_json_is_space(char ch)
{
    uint8_t result = 0U;

    if ((ch == ' ') || (ch == '\n') || (ch == '\r') || (ch == '\t'))
    {
        result = 1U;
    }

    return result;
}

static uint8_t gossipsub_json_key_matches(
    const gossipsub_json_span_t *span,
    size_t pos,
    const char *key,
    size_t key_len)
{
    size_t index = 0U;
    uint8_t result = 0U;

    if ((span != NULL) && (key != NULL) && ((pos + key_len + 2U) <= span->len) &&
        (span->data[pos] == '"') && (span->data[pos + key_len + 1U] == '"'))
    {
        result = 1U;
        for (index = 0U; index < key_len; index++)
        {
            if (span->data[pos + 1U + index] != key[index])
            {
                result = 0U;
            }
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_find_key(
    const gossipsub_json_span_t *span,
    const char *key,
    size_t *out_colon)
{
    size_t key_len = 0U;
    size_t pos = 0U;
    size_t cursor = 0U;
    uint8_t in_string = 0U;
    uint8_t escaped = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_ERR_PARSE;

    if ((span == NULL) || (span->data == NULL) || (key == NULL) || (out_colon == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else
    {
        key_len = strlen(key);
    }
    while ((result == GOSSIPSUB_INTEROP_ERR_PARSE) && (pos < span->len))
    {
        const char ch = span->data[pos];
        if (in_string != 0U)
        {
            if (escaped != 0U)
            {
                escaped = 0U;
            }
            else if (ch == '\\')
            {
                escaped = 1U;
            }
            else if (ch == '"')
            {
                in_string = 0U;
            }
            else
            {
                in_string = 1U;
            }
            pos++;
        }
        else if (gossipsub_json_key_matches(span, pos, key, key_len) != 0U)
        {
            cursor = pos + key_len + 2U;
            while ((cursor < span->len) && (gossipsub_json_is_space(span->data[cursor]) != 0U))
            {
                cursor++;
            }
            if ((cursor < span->len) && (span->data[cursor] == ':'))
            {
                *out_colon = cursor;
                result = GOSSIPSUB_INTEROP_OK;
            }
            else
            {
                pos++;
            }
        }
        else
        {
            if (ch == '"')
            {
                in_string = 1U;
            }
            pos++;
        }
    }

    return result;
}

static size_t gossipsub_json_value_start(const gossipsub_json_span_t *span, size_t colon)
{
    size_t result = colon + 1U;

    while ((result < span->len) && (gossipsub_json_is_space(span->data[result]) != 0U))
    {
        result++;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_string_field(
    const gossipsub_json_span_t *span,
    const char *key,
    char *out,
    size_t out_len,
    size_t *written)
{
    size_t colon = 0U;
    size_t pos = 0U;
    size_t count = 0U;
    uint8_t escaped = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (key == NULL) || (out == NULL) || (out_len == 0U) || (written == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_json_find_key(span, key, &colon) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        pos = gossipsub_json_value_start(span, colon);
        if ((pos >= span->len) || (span->data[pos] != '"'))
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
        else
        {
            pos++;
        }
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (pos < span->len) && (span->data[pos] != '"'))
    {
        if (escaped != 0U)
        {
            escaped = 0U;
        }
        else if (span->data[pos] == '\\')
        {
            escaped = 1U;
        }
        if ((escaped == 0U) && (span->data[pos] != '\\'))
        {
            if ((count + 1U) >= out_len)
            {
                result = GOSSIPSUB_INTEROP_ERR_LIMIT;
            }
            else
            {
                out[count] = span->data[pos];
                count++;
            }
        }
        pos++;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (pos >= span->len))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        out[count] = '\0';
        *written = count;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_u64_field(
    const gossipsub_json_span_t *span,
    const char *key,
    uint64_t *out)
{
    size_t colon = 0U;
    size_t pos = 0U;
    uint64_t value = 0U;
    uint8_t saw_digit = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (key == NULL) || (out == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_json_find_key(span, key, &colon) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        pos = gossipsub_json_value_start(span, colon);
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (pos < span->len) && (span->data[pos] >= '0') &&
           (span->data[pos] <= '9'))
    {
        value = (value * 10U) + (uint64_t)(span->data[pos] - '0');
        saw_digit = 1U;
        pos++;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (saw_digit == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        *out = value;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_bool_field_optional(
    const gossipsub_json_span_t *span,
    const char *key,
    uint8_t *out)
{
    size_t colon = 0U;
    size_t pos = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (key == NULL) || (out == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    else if (gossipsub_json_find_key(span, key, &colon) != GOSSIPSUB_INTEROP_OK)
    {
        *out = 0U;
    }
    else
    {
        pos = gossipsub_json_value_start(span, colon);
        if (((pos + 4U) <= span->len) && (memcmp(&span->data[pos], "true", 4U) == 0))
        {
            *out = 1U;
        }
        else
        {
            *out = 0U;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_seconds_field_us(
    const gossipsub_json_span_t *span,
    const char *key,
    uint64_t *out)
{
    size_t colon = 0U;
    size_t pos = 0U;
    uint64_t whole = 0U;
    uint64_t frac = 0U;
    uint64_t scale = 100000U;
    uint8_t saw_digit = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (key == NULL) || (out == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_json_find_key(span, key, &colon) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        pos = gossipsub_json_value_start(span, colon);
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (pos < span->len) && (span->data[pos] >= '0') &&
           (span->data[pos] <= '9'))
    {
        whole = (whole * 10U) + (uint64_t)(span->data[pos] - '0');
        saw_digit = 1U;
        pos++;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (pos < span->len) && (span->data[pos] == '.'))
    {
        pos++;
        while ((pos < span->len) && (span->data[pos] >= '0') && (span->data[pos] <= '9') &&
               (scale != 0U))
        {
            frac += ((uint64_t)(span->data[pos] - '0') * scale);
            scale /= 10U;
            saw_digit = 1U;
            pos++;
        }
    }
    if ((result == GOSSIPSUB_INTEROP_OK) && (saw_digit == 0U))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        *out = (whole * 1000000U) + frac;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_find_matching(
    const char *data,
    size_t len,
    size_t start,
    char open_ch,
    char close_ch,
    size_t *out_end)
{
    size_t pos = start;
    size_t depth = 0U;
    uint8_t in_string = 0U;
    uint8_t escaped = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_ERR_PARSE;

    if ((data == NULL) || (out_end == NULL) || (start >= len) || (data[start] != open_ch))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    while ((result == GOSSIPSUB_INTEROP_ERR_PARSE) && (pos < len))
    {
        const char ch = data[pos];
        if (in_string != 0U)
        {
            if (escaped != 0U)
            {
                escaped = 0U;
            }
            else if (ch == '\\')
            {
                escaped = 1U;
            }
            else if (ch == '"')
            {
                in_string = 0U;
            }
            else
            {
                in_string = 1U;
            }
        }
        else if (ch == '"')
        {
            in_string = 1U;
        }
        else if (ch == open_ch)
        {
            depth++;
        }
        else if (ch == close_ch)
        {
            depth--;
            if (depth == 0U)
            {
                *out_end = pos;
                result = GOSSIPSUB_INTEROP_OK;
            }
        }
        pos++;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_instruction_object(
    const gossipsub_json_span_t *span,
    gossipsub_json_span_t *out)
{
    size_t colon = 0U;
    size_t pos = 0U;
    size_t end = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (out == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_json_find_key(span, "instruction", &colon) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        pos = gossipsub_json_value_start(span, colon);
        if (gossipsub_json_find_matching(span->data, span->len, pos, '{', '}', &end) !=
            GOSSIPSUB_INTEROP_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        out->data = &span->data[pos];
        out->len = (end - pos) + 1U;
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_connect_list(
    const gossipsub_json_span_t *span,
    gossipsub_interop_instruction_t *out)
{
    size_t colon = 0U;
    size_t pos = 0U;
    uint64_t value = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((span == NULL) || (out == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if ((result == GOSSIPSUB_INTEROP_OK) &&
        (gossipsub_json_find_key(span, "connectTo", &colon) != GOSSIPSUB_INTEROP_OK))
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        pos = gossipsub_json_value_start(span, colon);
        if ((pos >= span->len) || (span->data[pos] != '['))
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
        else
        {
            pos++;
        }
    }
    while ((result == GOSSIPSUB_INTEROP_OK) && (pos < span->len) && (span->data[pos] != ']'))
    {
        while ((pos < span->len) &&
               ((gossipsub_json_is_space(span->data[pos]) != 0U) || (span->data[pos] == ',')))
        {
            pos++;
        }
        value = 0U;
        if ((pos < span->len) && (span->data[pos] >= '0') && (span->data[pos] <= '9'))
        {
            while ((pos < span->len) && (span->data[pos] >= '0') && (span->data[pos] <= '9'))
            {
                value = (value * 10U) + (uint64_t)(span->data[pos] - '0');
                pos++;
            }
            if (out->connect_count >= GOSSIPSUB_INTEROP_MAX_CONNECT_PEERS)
            {
                result = GOSSIPSUB_INTEROP_ERR_LIMIT;
            }
            else
            {
                out->connect_to[out->connect_count] = (int)value;
                out->connect_count++;
            }
        }
        else if ((pos < span->len) && (span->data[pos] != ']'))
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
    }

    return result;
}

static gossipsub_interop_err_t gossipsub_json_parse_instruction(
    const gossipsub_json_span_t *span,
    int node_id,
    gossipsub_interop_instruction_t *out_instruction,
    uint8_t *out_has_instruction)
{
    char type[48];
    size_t type_len = 0U;
    uint64_t value = 0U;
    gossipsub_json_span_t nested;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    (void)memset(out_instruction, 0, sizeof(*out_instruction));
    *out_has_instruction = 0U;
    if (gossipsub_json_string_field(span, "type", type, sizeof(type), &type_len) !=
        GOSSIPSUB_INTEROP_OK)
    {
        result = GOSSIPSUB_INTEROP_ERR_PARSE;
    }
    else if (strcmp(type, "ifNodeIDEquals") == 0)
    {
        if (gossipsub_json_u64_field(span, "nodeID", &value) != GOSSIPSUB_INTEROP_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
        else if ((int)value != node_id)
        {
            *out_has_instruction = 0U;
        }
        else if (gossipsub_json_instruction_object(span, &nested) != GOSSIPSUB_INTEROP_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
        else
        {
            result = gossipsub_json_parse_instruction(
                &nested,
                node_id,
                out_instruction,
                out_has_instruction);
        }
    }
    else
    {
        *out_has_instruction = 1U;
        if (strcmp(type, "initGossipSub") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_INIT;
        }
        else if (strcmp(type, "connect") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_CONNECT;
            result = gossipsub_json_connect_list(span, out_instruction);
        }
        else if (strcmp(type, "waitUntil") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_WAIT_UNTIL;
            result =
                gossipsub_json_u64_field(span, "elapsedSeconds", &out_instruction->elapsed_seconds);
        }
        else if (strcmp(type, "subscribeToTopic") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_SUBSCRIBE;
            result = gossipsub_json_string_field(
                span,
                "topicID",
                out_instruction->topic,
                sizeof(out_instruction->topic),
                &out_instruction->topic_len);
            if (result == GOSSIPSUB_INTEROP_OK)
            {
                result =
                    gossipsub_json_bool_field_optional(span, "partial", &out_instruction->partial);
            }
            if ((result == GOSSIPSUB_INTEROP_OK) && (out_instruction->partial != 0U))
            {
                out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_PARTIAL_UNSUPPORTED;
            }
        }
        else if (strcmp(type, "setTopicValidationDelay") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_SET_VALIDATION_DELAY;
            result = gossipsub_json_string_field(
                span,
                "topicID",
                out_instruction->topic,
                sizeof(out_instruction->topic),
                &out_instruction->topic_len);
            if (result == GOSSIPSUB_INTEROP_OK)
            {
                result = gossipsub_json_seconds_field_us(
                    span,
                    "delaySeconds",
                    &out_instruction->delay_us);
            }
        }
        else if (strcmp(type, "publish") == 0)
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_PUBLISH;
            result = gossipsub_json_string_field(
                span,
                "topicID",
                out_instruction->topic,
                sizeof(out_instruction->topic),
                &out_instruction->topic_len);
            if (result == GOSSIPSUB_INTEROP_OK)
            {
                result = gossipsub_json_u64_field(span, "messageID", &out_instruction->message_id);
            }
            if (result == GOSSIPSUB_INTEROP_OK)
            {
                result = gossipsub_json_u64_field(span, "messageSizeBytes", &value);
                out_instruction->message_size_bytes = (size_t)value;
            }
        }
        else if ((strcmp(type, "addPartialMessage") == 0) || (strcmp(type, "publishPartial") == 0))
        {
            out_instruction->type = GOSSIPSUB_INTEROP_INSTRUCTION_PARTIAL_UNSUPPORTED;
        }
        else
        {
            result = GOSSIPSUB_INTEROP_ERR_UNSUPPORTED;
        }
    }

    return result;
}

gossipsub_interop_err_t gossipsub_interop_script_load(
    const char *path,
    gossipsub_interop_script_t *script)
{
    FILE *file = NULL;
    size_t read_len = 0U;
    gossipsub_json_span_t span;
    size_t colon = 0U;
    size_t array_start = 0U;
    size_t array_end = 0U;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((path == NULL) || (script == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        (void)memset(script, 0, sizeof(*script));
        file = fopen(path, "rb");
        if (file == NULL)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        read_len = fread(script->data, 1U, sizeof(script->data) - 1U, file);
        if (ferror(file) != 0)
        {
            result = GOSSIPSUB_INTEROP_ERR_IO;
        }
        else
        {
            script->len = read_len;
            script->data[script->len] = '\0';
        }
    }
    if (file != NULL)
    {
        (void)fclose(file);
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        span.data = script->data;
        span.len = script->len;
        if (gossipsub_json_find_key(&span, "script", &colon) != GOSSIPSUB_INTEROP_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        array_start = gossipsub_json_value_start(&span, colon);
        if (gossipsub_json_find_matching(
                script->data,
                script->len,
                array_start,
                '[',
                ']',
                &array_end) != GOSSIPSUB_INTEROP_OK)
        {
            result = GOSSIPSUB_INTEROP_ERR_PARSE;
        }
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        script->pos = array_start + 1U;
        script->script_end = array_end;
    }

    return result;
}

gossipsub_interop_err_t gossipsub_interop_script_next(
    gossipsub_interop_script_t *script,
    int node_id,
    gossipsub_interop_instruction_t *out_instruction,
    uint8_t *out_has_instruction)
{
    size_t start = 0U;
    size_t end = 0U;
    gossipsub_json_span_t span;
    gossipsub_interop_err_t result = GOSSIPSUB_INTEROP_OK;

    if ((script == NULL) || (out_instruction == NULL) || (out_has_instruction == NULL))
    {
        result = GOSSIPSUB_INTEROP_ERR_USAGE;
    }
    if (result == GOSSIPSUB_INTEROP_OK)
    {
        *out_has_instruction = 0U;
        while ((script->pos < script->script_end) && (script->data[script->pos] != '{'))
        {
            script->pos++;
        }
        if (script->pos >= script->script_end)
        {
            result = GOSSIPSUB_INTEROP_OK;
        }
        else
        {
            start = script->pos;
            if (gossipsub_json_find_matching(script->data, script->len, start, '{', '}', &end) !=
                GOSSIPSUB_INTEROP_OK)
            {
                result = GOSSIPSUB_INTEROP_ERR_PARSE;
            }
            else
            {
                script->pos = end + 1U;
                span.data = &script->data[start];
                span.len = (end - start) + 1U;
                result = gossipsub_json_parse_instruction(
                    &span,
                    node_id,
                    out_instruction,
                    out_has_instruction);
            }
        }
    }

    return result;
}
