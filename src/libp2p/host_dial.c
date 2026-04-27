#include <string.h>

#include "host_internal.h"

libp2p_host_dial_t *host_dial_find(libp2p_host_t *host, const void *transport_attempt)
{
    libp2p_host_dial_t *result = NULL;

    if ((host != NULL) && (transport_attempt != NULL))
    {
        size_t index = 0U;

        for (index = 0U; index < host->dial_capacity; index++)
        {
            if ((host->dials[index].state == HOST_DIAL_PENDING) &&
                (host->dials[index].transport_attempt == transport_attempt))
            {
                result = &host->dials[index];
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t host_dial_mark_evented(libp2p_host_dial_t *dial)
{
    libp2p_host_err_t result = LIBP2P_HOST_OK;

    if (dial == NULL)
    {
        result = LIBP2P_HOST_ERR_INVALID_ARG;
    }
    else
    {
        dial->state = HOST_DIAL_EVENTED;
    }

    return result;
}

static libp2p_host_dial_t *host_dial_alloc(libp2p_host_t *host)
{
    libp2p_host_dial_t *result = NULL;

    if (host != NULL)
    {
        size_t index;

        for (index = 0U; index < host->dial_capacity; index++)
        {
            if (host->dials[index].state == HOST_DIAL_FREE)
            {
                result = &host->dials[index];
                (void)memset(result, 0, sizeof(*result));
                result->host = host;
                result->state = HOST_DIAL_PENDING;
                break;
            }
        }
    }

    return result;
}

libp2p_host_err_t libp2p_host_dial(
    libp2p_host_t *host,
    const uint8_t *multiaddr,
    size_t multiaddr_len,
    void *user_data,
    libp2p_host_dial_t **out_dial)
{
    libp2p_host_dial_t *dial = NULL;
    void *transport_attempt = NULL;
    libp2p_host_err_t result = host_validate_started(host);

    if (out_dial != NULL)
    {
        *out_dial = NULL;
    }
    if (result == LIBP2P_HOST_OK)
    {
        if ((multiaddr == NULL) || (multiaddr_len == 0U) || (out_dial == NULL))
        {
            result = LIBP2P_HOST_ERR_INVALID_ARG;
        }
        else if (host->state == HOST_STATE_CLOSING)
        {
            result = LIBP2P_HOST_ERR_CLOSED;
        }
        else
        {
            dial = host_dial_alloc(host);
            if (dial == NULL)
            {
                result = LIBP2P_HOST_ERR_LIMIT;
            }
        }
    }
    if (result == LIBP2P_HOST_OK)
    {
        result =
            host->config.transport
                ->dial(host->transport, multiaddr, multiaddr_len, user_data, &transport_attempt);
        if (result == LIBP2P_HOST_OK)
        {
            dial->transport_attempt = transport_attempt;
            dial->user_data = user_data;
            *out_dial = dial;
        }
        else
        {
            dial->state = HOST_DIAL_FREE;
        }
    }

    return result;
}
