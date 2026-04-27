#ifndef LIBP2P_INTEROP_REDIS_CLIENT_H
#define LIBP2P_INTEROP_REDIS_CLIENT_H

#include <stddef.h>

typedef enum
{
    LIBP2P_INTEROP_REDIS_OK = 0,
    LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG,
    LIBP2P_INTEROP_REDIS_ERR_ADDR,
    LIBP2P_INTEROP_REDIS_ERR_CONNECT,
    LIBP2P_INTEROP_REDIS_ERR_IO,
    LIBP2P_INTEROP_REDIS_ERR_PROTOCOL,
    LIBP2P_INTEROP_REDIS_ERR_NOT_FOUND,
    LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL
} libp2p_interop_redis_err_t;

typedef struct
{
    int fd;
} libp2p_interop_redis_client_t;

libp2p_interop_redis_err_t libp2p_interop_redis_connect(
    libp2p_interop_redis_client_t *client,
    const char *redis_addr);

void libp2p_interop_redis_close(libp2p_interop_redis_client_t *client);

libp2p_interop_redis_err_t libp2p_interop_redis_del(
    libp2p_interop_redis_client_t *client,
    const char *key);

libp2p_interop_redis_err_t libp2p_interop_redis_rpush(
    libp2p_interop_redis_client_t *client,
    const char *key,
    const char *value);

libp2p_interop_redis_err_t libp2p_interop_redis_blpop(
    libp2p_interop_redis_client_t *client,
    const char *key,
    unsigned int timeout_seconds,
    char *out,
    size_t out_len,
    size_t *written);

#endif /* LIBP2P_INTEROP_REDIS_CLIENT_H */
