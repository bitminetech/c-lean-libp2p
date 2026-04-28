#include <stdint.h>
#include <string.h>

#include "gossipsub_internal.h"

int gossipsub_size_add(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (out == NULL)
    {
        result = 1;
    }
    else if (b > (SIZE_MAX - a))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a + b;
    }

    return result;
}

int gossipsub_size_mul(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (out == NULL)
    {
        result = 1;
    }
    else if ((a != 0U) && (b > (SIZE_MAX / a)))
    {
        *out = SIZE_MAX;
        result = 1;
    }
    else
    {
        *out = a * b;
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_align_up(size_t value, size_t alignment, size_t *out)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((alignment == 0U) || (out == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        const size_t remainder = value % alignment;

        if (remainder == 0U)
        {
            *out = value;
        }
        else
        {
            const size_t adjustment = alignment - remainder;

            if (adjustment > (SIZE_MAX - value))
            {
                result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
            }
            else
            {
                *out = value + adjustment;
            }
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_reserve(
    size_t *cursor,
    size_t alignment,
    size_t size,
    size_t *out_offset)
{
    size_t aligned = 0U;
    size_t next = 0U;
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_OK;

    if ((cursor == NULL) || (out_offset == NULL))
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else
    {
        result = gossipsub_align_up(*cursor, alignment, &aligned);
        if ((result == LIBP2P_GOSSIPSUB_OK) && (gossipsub_size_add(aligned, size, &next) != 0))
        {
            result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
        }
        if (result == LIBP2P_GOSSIPSUB_OK)
        {
            *out_offset = aligned;
            *cursor = next;
        }
    }

    return result;
}

void gossipsub_pointer_store(void *destination, const void *value)
{
    (void)memcpy(destination, (const void *)&value, sizeof value);
}

uint8_t *gossipsub_storage_bytes(const void *storage)
{
    uint8_t *result = NULL;

    gossipsub_pointer_store((void *)&result, storage);

    return result;
}

libp2p_gossipsub_t *gossipsub_storage_router(const void *storage)
{
    libp2p_gossipsub_t *result = NULL;

    gossipsub_pointer_store((void *)&result, storage);

    return result;
}

void *gossipsub_storage_at(const void *storage, size_t offset)
{
    uint8_t *bytes = gossipsub_storage_bytes(storage);
    void *result = NULL;

    if (bytes != NULL)
    {
        result = (void *)&bytes[offset];
    }

    return result;
}

int gossipsub_bytes_present(const libp2p_gossipsub_bytes_t *bytes)
{
    int result = 0;

    if ((bytes != NULL) && (bytes->data != NULL) && (bytes->len != 0U))
    {
        result = 1;
    }

    return result;
}

int gossipsub_bytes_equal(
    const uint8_t *left,
    size_t left_len,
    const uint8_t *right,
    size_t right_len)
{
    int result = 0;

    if ((left != NULL) && (right != NULL) && (left_len == right_len))
    {
        if ((left_len == 0U) || (memcmp(left, right, left_len) == 0))
        {
            result = 1;
        }
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_uvarint_err(libp2p_uvarint_err_t err)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;

    if (err == LIBP2P_UVARINT_OK)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else if (err == LIBP2P_UVARINT_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_UVARINT_ERR_TRUNCATED)
    {
        result = LIBP2P_GOSSIPSUB_ERR_TRUNCATED;
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_ERR_MALFORMED;
    }

    return result;
}

libp2p_host_err_t gossipsub_host_err(libp2p_gossipsub_err_t err)
{
    libp2p_host_err_t result = LIBP2P_HOST_ERR_PROTOCOL;

    if (err == LIBP2P_GOSSIPSUB_OK)
    {
        result = LIBP2P_HOST_OK;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_INVALID_ARG)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_HOST_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_LIMIT)
    {
        result = LIBP2P_HOST_ERR_LIMIT;
    }
    else if (err == LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK)
    {
        result = LIBP2P_HOST_ERR_WOULD_BLOCK;
    }
    else
    {
        result = LIBP2P_HOST_ERR_PROTOCOL;
    }

    return result;
}

libp2p_gossipsub_err_t gossipsub_host_to_err(libp2p_host_err_t err)
{
    libp2p_gossipsub_err_t result = LIBP2P_GOSSIPSUB_ERR_HOST;

    if (err == LIBP2P_HOST_OK)
    {
        result = LIBP2P_GOSSIPSUB_OK;
    }
    else if (err == LIBP2P_HOST_ERR_INVALID_ARG)
    {
        result = LIBP2P_GOSSIPSUB_ERR_INVALID_ARG;
    }
    else if (err == LIBP2P_HOST_ERR_BUF_TOO_SMALL)
    {
        result = LIBP2P_GOSSIPSUB_ERR_BUF_TOO_SMALL;
    }
    else if (err == LIBP2P_HOST_ERR_LIMIT)
    {
        result = LIBP2P_GOSSIPSUB_ERR_LIMIT;
    }
    else if (err == LIBP2P_HOST_ERR_WOULD_BLOCK)
    {
        result = LIBP2P_GOSSIPSUB_ERR_WOULD_BLOCK;
    }
    else if (err == LIBP2P_HOST_ERR_NOT_FOUND)
    {
        result = LIBP2P_GOSSIPSUB_ERR_NOT_FOUND;
    }
    else
    {
        result = LIBP2P_GOSSIPSUB_ERR_HOST;
    }

    return result;
}

libp2p_gossipsub_t *gossipsub_from_protocol_user_data(void *user_data)
{
    gossipsub_protocol_user_data_t *data = NULL;
    libp2p_gossipsub_t *result = NULL;

    (void)memcpy((void *)&data, (const void *)&user_data, sizeof user_data);
    if (data != NULL)
    {
        result = data->gossipsub;
    }

    return result;
}

libp2p_gossipsub_protocol_version_t gossipsub_version_from_protocol_user_data(void *user_data)
{
    gossipsub_protocol_user_data_t *data = NULL;
    libp2p_gossipsub_protocol_version_t result = LIBP2P_GOSSIPSUB_VERSION_NONE;

    (void)memcpy((void *)&data, (const void *)&user_data, sizeof user_data);
    if (data != NULL)
    {
        result = data->version;
    }

    return result;
}

void gossipsub_keep_mutable_host_arg(libp2p_host_t *host)
{
    volatile libp2p_host_t *sink = host;

    (void)sink;
}

void gossipsub_keep_mutable_stream_arg(libp2p_host_stream_t *stream)
{
    volatile libp2p_host_stream_t *sink = stream;

    (void)sink;
}

void gossipsub_keep_mutable_void_arg(void *user_data)
{
    void *volatile sink = user_data;

    (void)sink;
}
