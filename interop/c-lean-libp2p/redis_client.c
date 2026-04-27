#define _POSIX_C_SOURCE 200112L

#include "redis_client.h"

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REDIS_CLIENT_HOST_MAX 255U
#define REDIS_CLIENT_PORT_MAX 15U
#define REDIS_CLIENT_LINE_MAX 256U

static libp2p_interop_redis_err_t redis_client_parse_addr(
    const char *redis_addr,
    char *host,
    size_t host_len,
    char *port,
    size_t port_len)
{
    const char *colon = NULL;
    size_t host_part_len = 0U;
    size_t port_part_len = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((redis_addr == NULL) || (host == NULL) || (host_len == 0U) || (port == NULL) ||
        (port_len == 0U))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    else
    {
        colon = strrchr(redis_addr, ':');
        if ((colon == NULL) || (colon == redis_addr) || (colon[1] == '\0'))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_ADDR;
        }
    }

    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        host_part_len = (size_t)(colon - redis_addr);
        port_part_len = strlen(&colon[1]);
        if ((host_part_len >= host_len) || (port_part_len >= port_len))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        (void)memcpy(host, redis_addr, host_part_len);
        host[host_part_len] = '\0';
        (void)memcpy(port, &colon[1], port_part_len);
        port[port_part_len] = '\0';
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)buf;
    size_t sent = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((fd < 0) || ((buf == NULL) && (len != 0U)))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (sent < len))
    {
        const ssize_t count = send(fd, &bytes[sent], len - sent, 0);
        if (count > 0)
        {
            sent += (size_t)count;
        }
        else if ((count < 0) && (errno == EINTR))
        {
            result = LIBP2P_INTEROP_REDIS_OK;
        }
        else
        {
            result = LIBP2P_INTEROP_REDIS_ERR_IO;
        }
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_recv_all(int fd, void *buf, size_t len)
{
    uint8_t *bytes = (uint8_t *)buf;
    size_t got = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((fd < 0) || ((buf == NULL) && (len != 0U)))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (got < len))
    {
        const ssize_t count = recv(fd, &bytes[got], len - got, 0);
        if (count > 0)
        {
            got += (size_t)count;
        }
        else if ((count < 0) && (errno == EINTR))
        {
            result = LIBP2P_INTEROP_REDIS_OK;
        }
        else
        {
            result = LIBP2P_INTEROP_REDIS_ERR_IO;
        }
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_read_line(int fd, char *line, size_t line_len)
{
    size_t pos = 0U;
    int done = 0;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((fd < 0) || (line == NULL) || (line_len == 0U))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (done == 0))
    {
        char ch = '\0';
        const ssize_t count = recv(fd, &ch, 1U, 0);
        if (count == 1)
        {
            if (pos >= (line_len - 1U))
            {
                result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
            }
            else if (ch == '\n')
            {
                if ((pos > 0U) && (line[pos - 1U] == '\r'))
                {
                    pos--;
                }
                line[pos] = '\0';
                done = 1;
            }
            else
            {
                line[pos] = ch;
                pos++;
            }
        }
        else if ((count < 0) && (errno == EINTR))
        {
            result = LIBP2P_INTEROP_REDIS_OK;
        }
        else
        {
            result = LIBP2P_INTEROP_REDIS_ERR_IO;
        }
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_send_bulk(
    const libp2p_interop_redis_client_t *client,
    const char *value)
{
    char header[64];
    int header_len = 0;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (client->fd < 0) || (value == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        header_len = snprintf(header, sizeof(header), "$%zu\r\n", strlen(value));
        if ((header_len <= 0) || ((size_t)header_len >= sizeof(header)))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_all(client->fd, header, (size_t)header_len);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_all(client->fd, value, strlen(value));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_all(client->fd, "\r\n", 2U);
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_send_array(
    const libp2p_interop_redis_client_t *client,
    const char *const *args,
    size_t arg_count)
{
    char header[64];
    int header_len = 0;
    size_t index = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (client->fd < 0) || (args == NULL) || (arg_count == 0U))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        header_len = snprintf(header, sizeof(header), "*%zu\r\n", arg_count);
        if ((header_len <= 0) || ((size_t)header_len >= sizeof(header)))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_all(client->fd, header, (size_t)header_len);
    }
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (index < arg_count))
    {
        result = redis_client_send_bulk(client, args[index]);
        index++;
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_expect_ok_or_int(
    libp2p_interop_redis_client_t *client)
{
    char line[REDIS_CLIENT_LINE_MAX];
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (client->fd < 0))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    else
    {
        result = redis_client_read_line(client->fd, line, sizeof(line));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        if ((line[0] != '+') && (line[0] != ':'))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_PROTOCOL;
        }
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_parse_bulk_len(const char *line, size_t *out_len)
{
    char *end = NULL;
    unsigned long value = 0UL;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((line == NULL) || (out_len == NULL) || (line[0] != '$'))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_PROTOCOL;
    }
    else
    {
        errno = 0;
        value = strtoul(&line[1], &end, 10);
        if ((errno != 0) || (end == &line[1]) || (*end != '\0'))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_PROTOCOL;
        }
        else
        {
            *out_len = (size_t)value;
        }
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_read_bulk_discard(
    libp2p_interop_redis_client_t *client)
{
    char line[REDIS_CLIENT_LINE_MAX];
    char discard[128];
    size_t bulk_len = 0U;
    size_t remaining = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (client->fd < 0))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    else
    {
        result = redis_client_read_line(client->fd, line, sizeof(line));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_parse_bulk_len(line, &bulk_len);
    }
    remaining = bulk_len + 2U;
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (remaining != 0U))
    {
        const size_t chunk = (remaining > sizeof(discard)) ? sizeof(discard) : remaining;
        result = redis_client_recv_all(client->fd, discard, chunk);
        remaining -= chunk;
    }

    return result;
}

static libp2p_interop_redis_err_t redis_client_read_bulk_string(
    libp2p_interop_redis_client_t *client,
    char *out,
    size_t out_len,
    size_t *written)
{
    char line[REDIS_CLIENT_LINE_MAX];
    char crlf[2];
    size_t bulk_len = 0U;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if (written != NULL)
    {
        *written = 0U;
    }
    if ((client == NULL) || (client->fd < 0) || (out == NULL) || (out_len == 0U) ||
        (written == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    else
    {
        result = redis_client_read_line(client->fd, line, sizeof(line));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_parse_bulk_len(line, &bulk_len);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        *written = bulk_len;
        if (bulk_len >= out_len)
        {
            result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_recv_all(client->fd, out, bulk_len);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_recv_all(client->fd, crlf, sizeof(crlf));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        if ((crlf[0] != '\r') || (crlf[1] != '\n'))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_PROTOCOL;
        }
        else
        {
            out[bulk_len] = '\0';
        }
    }

    return result;
}

libp2p_interop_redis_err_t libp2p_interop_redis_connect(
    libp2p_interop_redis_client_t *client,
    const char *redis_addr)
{
    char host[REDIS_CLIENT_HOST_MAX + 1U];
    char port[REDIS_CLIENT_PORT_MAX + 1U];
    struct addrinfo hints;
    struct addrinfo *addrs = NULL;
    struct addrinfo *cursor = NULL;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if (client != NULL)
    {
        client->fd = -1;
    }
    if ((client == NULL) || (redis_addr == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_parse_addr(redis_addr, host, sizeof(host), port, sizeof(port));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        (void)memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (getaddrinfo(host, port, &hints, &addrs) != 0)
        {
            result = LIBP2P_INTEROP_REDIS_ERR_ADDR;
        }
    }
    cursor = addrs;
    while ((result == LIBP2P_INTEROP_REDIS_OK) && (cursor != NULL) && (client->fd < 0))
    {
        const int fd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);
        if (fd >= 0)
        {
            if (connect(fd, cursor->ai_addr, cursor->ai_addrlen) == 0)
            {
                client->fd = fd;
            }
            else
            {
                (void)close(fd);
            }
        }
        cursor = cursor->ai_next;
    }
    if ((result == LIBP2P_INTEROP_REDIS_OK) && (client->fd < 0))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_CONNECT;
    }
    if (addrs != NULL)
    {
        freeaddrinfo(addrs);
    }

    return result;
}

void libp2p_interop_redis_close(libp2p_interop_redis_client_t *client)
{
    if (client != NULL)
    {
        if (client->fd >= 0)
        {
            (void)close(client->fd);
        }
        client->fd = -1;
    }
}

libp2p_interop_redis_err_t libp2p_interop_redis_del(
    libp2p_interop_redis_client_t *client,
    const char *key)
{
    const char *args[2] = {"DEL", key};
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (key == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_array(client, args, 2U);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_expect_ok_or_int(client);
    }

    return result;
}

libp2p_interop_redis_err_t libp2p_interop_redis_rpush(
    libp2p_interop_redis_client_t *client,
    const char *key,
    const char *value)
{
    const char *args[3] = {"RPUSH", key, value};
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if ((client == NULL) || (key == NULL) || (value == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_array(client, args, 3U);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_expect_ok_or_int(client);
    }

    return result;
}

libp2p_interop_redis_err_t libp2p_interop_redis_blpop(
    libp2p_interop_redis_client_t *client,
    const char *key,
    unsigned int timeout_seconds,
    char *out,
    size_t out_len,
    size_t *written)
{
    char timeout_text[16];
    char line[REDIS_CLIENT_LINE_MAX];
    const char *args[3] = {"BLPOP", key, timeout_text};
    int timeout_len = 0;
    libp2p_interop_redis_err_t result = LIBP2P_INTEROP_REDIS_OK;

    if (written != NULL)
    {
        *written = 0U;
    }
    if ((client == NULL) || (key == NULL) || (out == NULL) || (out_len == 0U) || (written == NULL))
    {
        result = LIBP2P_INTEROP_REDIS_ERR_INVALID_ARG;
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        timeout_len = snprintf(timeout_text, sizeof(timeout_text), "%u", timeout_seconds);
        if ((timeout_len <= 0) || ((size_t)timeout_len >= sizeof(timeout_text)))
        {
            result = LIBP2P_INTEROP_REDIS_ERR_BUF_TOO_SMALL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_send_array(client, args, 3U);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_read_line(client->fd, line, sizeof(line));
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        if (strcmp(line, "*-1") == 0)
        {
            result = LIBP2P_INTEROP_REDIS_ERR_NOT_FOUND;
        }
        else if (strcmp(line, "*2") != 0)
        {
            result = LIBP2P_INTEROP_REDIS_ERR_PROTOCOL;
        }
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_read_bulk_discard(client);
    }
    if (result == LIBP2P_INTEROP_REDIS_OK)
    {
        result = redis_client_read_bulk_string(client, out, out_len, written);
    }

    return result;
}
