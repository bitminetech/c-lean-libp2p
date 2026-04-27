/**
 * @file quic_backend_ngtcp2_alloc.c
 * @brief ngtcp2 + AWS-LC backend for libp2p QUIC v1.
 */

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <stdint.h>
#include <string.h>

#include "quic_backend_ngtcp2_internal.h"

QUIC_BACKEND_INTERNAL int quic_backend_size_mul_overflow(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if ((a != 0U) && (b > (SIZE_MAX / a)))
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

QUIC_BACKEND_INTERNAL int quic_backend_size_add_overflow(size_t a, size_t b, size_t *out)
{
    int result = 0;

    if (b > (SIZE_MAX - a))
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

QUIC_BACKEND_INTERNAL libp2p_quic_err_t quic_backend_allocator_normalize(
    const libp2p_quic_allocator_t *in,
    libp2p_quic_allocator_t *out)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (out == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((in == NULL) || (in->malloc_fn == NULL) || (in->calloc_fn == NULL) ||
             (in->realloc_fn == NULL) ||
             (in->free_fn == NULL))
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else
    {
        *out = *in;
    }

    return result;
}

static void *quic_backend_malloc(libp2p_quic_endpoint_t *endpoint, size_t size)
{
    return endpoint->allocator.malloc_fn(size, endpoint->allocator.user_data);
}

QUIC_BACKEND_INTERNAL void *quic_backend_calloc(libp2p_quic_endpoint_t *endpoint, size_t nmemb, size_t size)
{
    return endpoint->allocator.calloc_fn(nmemb, size, endpoint->allocator.user_data);
}

QUIC_BACKEND_INTERNAL void *quic_backend_realloc(libp2p_quic_endpoint_t *endpoint, void *ptr, size_t size)
{
    return endpoint->allocator.realloc_fn(ptr, size, endpoint->allocator.user_data);
}

QUIC_BACKEND_INTERNAL void quic_backend_free(libp2p_quic_endpoint_t *endpoint, void *ptr)
{
    if ((endpoint != NULL) && (ptr != NULL))
    {
        endpoint->allocator.free_fn(ptr, endpoint->allocator.user_data);
    }
}

QUIC_BACKEND_INTERNAL libp2p_quic_endpoint_t *quic_backend_endpoint_from_memory(void *memory)
{
    libp2p_quic_endpoint_t *endpoint = NULL;

    (void)memcpy((void *)&endpoint, (const void *)&memory, sizeof memory);

    return endpoint;
}

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t *quic_backend_conn_from_memory(void *memory)
{
    libp2p_quic_conn_t *conn = NULL;

    (void)memcpy((void *)&conn, (const void *)&memory, sizeof memory);

    return conn;
}

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t *quic_backend_stream_from_memory(void *memory)
{
    libp2p_quic_stream_t *stream = NULL;

    (void)memcpy((void *)&stream, (const void *)&memory, sizeof memory);

    return stream;
}

QUIC_BACKEND_INTERNAL uint8_t *quic_backend_bytes_from_memory(void *memory)
{
    uint8_t *bytes = NULL;

    (void)memcpy((void *)&bytes, (const void *)&memory, sizeof memory);

    return bytes;
}

QUIC_BACKEND_INTERNAL libp2p_quic_event_t *quic_backend_events_from_memory(void *memory)
{
    libp2p_quic_event_t *events = NULL;

    (void)memcpy((void *)&events, (const void *)&memory, sizeof memory);

    return events;
}

QUIC_BACKEND_INTERNAL libp2p_quic_conn_t **quic_backend_conn_items_from_memory(void *memory)
{
    libp2p_quic_conn_t **items = NULL;

    (void)memcpy((void *)&items, (const void *)&memory, sizeof memory);

    return items;
}

QUIC_BACKEND_INTERNAL libp2p_quic_stream_t **quic_backend_stream_items_from_memory(void *memory)
{
    libp2p_quic_stream_t **items = NULL;

    (void)memcpy((void *)&items, (const void *)&memory, sizeof memory);

    return items;
}

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_malloc(size_t size, void *user_data)
{
    return quic_backend_malloc(user_data, size);
}

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data)
{
    return quic_backend_calloc(user_data, nmemb, size);
}

QUIC_BACKEND_INTERNAL void *quic_backend_ngtcp2_realloc(void *ptr, size_t size, void *user_data)
{
    return quic_backend_realloc(user_data, ptr, size);
}

QUIC_BACKEND_INTERNAL void quic_backend_ngtcp2_free(void *ptr, void *user_data)
{
    quic_backend_free(user_data, ptr);
}
