/**
 * @file quic_addr.c
 * @brief QUIC multiaddr conversion helpers.
 */

#include "transport/quic/quic_addr.h"

#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"

static libp2p_quic_err_t quic_addr_peer_id_is_valid(const uint8_t *peer_id, size_t peer_id_len)
{
    char text[1];
    size_t written = 0U;
    libp2p_peer_id_err_t err = LIBP2P_PEER_ID_OK;

    if ((peer_id == NULL) || (peer_id_len == 0U) || (peer_id_len > LIBP2P_PEER_ID_MAX_BYTES))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    err = libp2p_peer_id_to_string(peer_id, peer_id_len, text, 0U, &written);
    return (err == LIBP2P_PEER_ID_ERR_BUF_TOO_SMALL) ? LIBP2P_QUIC_OK : LIBP2P_QUIC_ERR_ADDR;
}

static void quic_addr_clear(libp2p_quic_addr_t *out)
{
    (void)memset(out, 0, sizeof(*out));
}

static libp2p_quic_err_t quic_addr_append_component(
    uint64_t code,
    const uint8_t *value,
    size_t value_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos,
    int *too_small)
{
    const libp2p_multiaddr_err_t err =
        libp2p_multiaddr_append_component(code, value, value_len, out, out_len, pos);

    if (err == LIBP2P_MULTIADDR_OK)
    {
        return LIBP2P_QUIC_OK;
    }
    if (err == LIBP2P_MULTIADDR_ERR_BUF_TOO_SMALL)
    {
        *too_small = 1;
        return LIBP2P_QUIC_OK;
    }

    return LIBP2P_QUIC_ERR_ADDR;
}

libp2p_quic_err_t libp2p_quic_addr_from_ip4(
    const uint8_t ip4[4],
    uint16_t port,
    libp2p_quic_addr_t *out)
{
    if ((ip4 == NULL) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    quic_addr_clear(out);
    out->family = LIBP2P_QUIC_ADDR_IP4;
    (void)memcpy(out->ip, ip4, 4U);
    out->port = port;

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_addr_from_ip6(
    const uint8_t ip6[16],
    uint16_t port,
    libp2p_quic_addr_t *out)
{
    if ((ip6 == NULL) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    quic_addr_clear(out);
    out->family = LIBP2P_QUIC_ADDR_IP6;
    (void)memcpy(out->ip, ip6, 16U);
    out->port = port;

    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_addr_set_peer_id(
    libp2p_quic_addr_t *addr,
    const uint8_t *peer_id,
    size_t peer_id_len)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (addr == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if (peer_id_len == 0U)
    {
        addr->has_peer_id = 0U;
        addr->peer_id_len = 0U;
        (void)memset(addr->peer_id, 0, sizeof(addr->peer_id));
    }
    else
    {
        result = quic_addr_peer_id_is_valid(peer_id, peer_id_len);
        if (result == LIBP2P_QUIC_OK)
        {
            (void)memcpy(addr->peer_id, peer_id, peer_id_len);
            addr->peer_id_len = peer_id_len;
            addr->has_peer_id = 1U;
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_addr_validate(const libp2p_quic_addr_t *addr)
{
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (addr == NULL)
    {
        result = LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    else if ((addr->family != LIBP2P_QUIC_ADDR_IP4) && (addr->family != LIBP2P_QUIC_ADDR_IP6))
    {
        result = LIBP2P_QUIC_ERR_ADDR;
    }
    else if (addr->family == LIBP2P_QUIC_ADDR_IP4)
    {
        size_t index = 4U;

        for (index = 4U; index < sizeof(addr->ip); index++)
        {
            if (addr->ip[index] != 0U)
            {
                result = LIBP2P_QUIC_ERR_ADDR;
                break;
            }
        }
    }
    if (result == LIBP2P_QUIC_OK)
    {
        if ((addr->has_peer_id != 0U) &&
            (quic_addr_peer_id_is_valid(addr->peer_id, addr->peer_id_len) != LIBP2P_QUIC_OK))
        {
            result = LIBP2P_QUIC_ERR_ADDR;
        }
        else if ((addr->has_peer_id == 0U) && (addr->peer_id_len != 0U))
        {
            result = LIBP2P_QUIC_ERR_ADDR;
        }
        else
        {
            /* Valid. */
        }
    }

    return result;
}

libp2p_quic_err_t libp2p_quic_addr_from_multiaddr(
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    libp2p_quic_addr_t *out)
{
    libp2p_multiaddr_cursor_t cursor;
    uint64_t code = 0U;
    const uint8_t *value = NULL;
    size_t value_len = 0U;
    uint8_t saw_ip = 0U;
    uint8_t saw_udp = 0U;
    uint8_t saw_quic = 0U;
    libp2p_quic_addr_t parsed;
    libp2p_multiaddr_err_t err = LIBP2P_MULTIADDR_OK;

    if ((multiaddr == NULL) || (multiaddr_len == 0U) || (out == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }

    quic_addr_clear(&parsed);
    cursor.buf = multiaddr;
    cursor.buf_len = multiaddr_len;
    cursor.offset = 0U;

    while ((err = libp2p_multiaddr_next_component(&cursor, &code, &value, &value_len)) ==
           LIBP2P_MULTIADDR_OK)
    {
        if (code == LIBP2P_MULTIADDR_CODE_IP4)
        {
            if ((saw_ip != 0U) || (saw_udp != 0U) || (saw_quic != 0U) || (value_len != 4U))
            {
                return LIBP2P_QUIC_ERR_ADDR;
            }
            parsed.family = LIBP2P_QUIC_ADDR_IP4;
            (void)memcpy(parsed.ip, value, 4U);
            saw_ip = 1U;
        }
        else if (code == LIBP2P_MULTIADDR_CODE_IP6)
        {
            if ((saw_ip != 0U) || (saw_udp != 0U) || (saw_quic != 0U) || (value_len != 16U))
            {
                return LIBP2P_QUIC_ERR_ADDR;
            }
            parsed.family = LIBP2P_QUIC_ADDR_IP6;
            (void)memcpy(parsed.ip, value, 16U);
            saw_ip = 1U;
        }
        else if (code == LIBP2P_MULTIADDR_CODE_UDP)
        {
            if ((saw_ip == 0U) || (saw_udp != 0U) || (saw_quic != 0U) || (value_len != 2U))
            {
                return LIBP2P_QUIC_ERR_ADDR;
            }
            parsed.port = (uint16_t)((((uint16_t)value[0]) << 8U) | ((uint16_t)value[1]));
            saw_udp = 1U;
        }
        else if (code == LIBP2P_MULTIADDR_CODE_QUIC_V1)
        {
            if ((saw_ip == 0U) || (saw_udp == 0U) || (saw_quic != 0U) || (value_len != 0U))
            {
                return LIBP2P_QUIC_ERR_ADDR;
            }
            saw_quic = 1U;
        }
        else if (code == LIBP2P_MULTIADDR_CODE_P2P)
        {
            if ((saw_quic == 0U) || (parsed.has_peer_id != 0U) ||
                (libp2p_quic_addr_set_peer_id(&parsed, value, value_len) != LIBP2P_QUIC_OK))
            {
                return LIBP2P_QUIC_ERR_ADDR;
            }
        }
        else
        {
            return LIBP2P_QUIC_ERR_ADDR;
        }
    }

    if (err != LIBP2P_MULTIADDR_ERR_END)
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }
    if ((saw_ip == 0U) || (saw_udp == 0U) || (saw_quic == 0U))
    {
        return LIBP2P_QUIC_ERR_ADDR;
    }

    *out = parsed;
    return LIBP2P_QUIC_OK;
}

libp2p_quic_err_t libp2p_quic_addr_to_multiaddr(
    const libp2p_quic_addr_t *addr,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    size_t pos = 0U;
    uint8_t port_value[2];
    int too_small = 0;
    libp2p_quic_err_t result = LIBP2P_QUIC_OK;

    if (written != NULL)
    {
        *written = 0U;
    }
    if ((addr == NULL) || (written == NULL))
    {
        return LIBP2P_QUIC_ERR_INVALID_ARG;
    }
    result = libp2p_quic_addr_validate(addr);
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    result = quic_addr_append_component(
        (addr->family == LIBP2P_QUIC_ADDR_IP4) ? LIBP2P_MULTIADDR_CODE_IP4
                                               : LIBP2P_MULTIADDR_CODE_IP6,
        addr->ip,
        (addr->family == LIBP2P_QUIC_ADDR_IP4) ? 4U : 16U,
        out,
        out_len,
        &pos,
        &too_small);

    port_value[0] = (uint8_t)(addr->port >> 8U);
    port_value[1] = (uint8_t)(addr->port & 0xffU);

    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_addr_append_component(
            LIBP2P_MULTIADDR_CODE_UDP,
            port_value,
            2U,
            out,
            out_len,
            &pos,
            &too_small);
    }
    if (result == LIBP2P_QUIC_OK)
    {
        result = quic_addr_append_component(
            LIBP2P_MULTIADDR_CODE_QUIC_V1,
            NULL,
            0U,
            out,
            out_len,
            &pos,
            &too_small);
    }
    if ((result == LIBP2P_QUIC_OK) && (addr->has_peer_id != 0U))
    {
        result = quic_addr_append_component(
            LIBP2P_MULTIADDR_CODE_P2P,
            addr->peer_id,
            addr->peer_id_len,
            out,
            out_len,
            &pos,
            &too_small);
    }

    *written = pos;
    if (result != LIBP2P_QUIC_OK)
    {
        return result;
    }

    return (too_small == 0) ? LIBP2P_QUIC_OK : LIBP2P_QUIC_ERR_BUF_TOO_SMALL;
}

int libp2p_quic_addr_equal(
    const libp2p_quic_addr_t *a,
    const libp2p_quic_addr_t *b,
    int compare_peer_id)
{
    size_t ip_len = 0U;

    if ((a == NULL) || (b == NULL) || (a->family != b->family) || (a->port != b->port))
    {
        return 0;
    }

    ip_len = (a->family == LIBP2P_QUIC_ADDR_IP4) ? 4U : 16U;
    if (memcmp(a->ip, b->ip, ip_len) != 0)
    {
        return 0;
    }

    if (compare_peer_id != 0)
    {
        if ((a->has_peer_id != b->has_peer_id) || (a->peer_id_len != b->peer_id_len))
        {
            return 0;
        }
        if ((a->has_peer_id != 0U) && (memcmp(a->peer_id, b->peer_id, a->peer_id_len) != 0))
        {
            return 0;
        }
    }

    return 1;
}
