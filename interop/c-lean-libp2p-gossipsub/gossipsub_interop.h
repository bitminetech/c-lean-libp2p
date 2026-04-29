#ifndef LIBP2P_GOSSIPSUB_INTEROP_H
#define LIBP2P_GOSSIPSUB_INTEROP_H

#include <stddef.h>
#include <stdint.h>

#define GOSSIPSUB_INTEROP_MAX_TOPIC_BYTES       256U
#define GOSSIPSUB_INTEROP_MAX_CONNECT_PEERS     64U
#define GOSSIPSUB_INTEROP_MAX_MESSAGE_BYTES     131072U
#define GOSSIPSUB_INTEROP_MAX_PARAMS_BYTES      1048576U
#define GOSSIPSUB_INTEROP_MAX_VALIDATION_TOPICS 16U

typedef enum
{
    GOSSIPSUB_INTEROP_OK = 0,
    GOSSIPSUB_INTEROP_ERR_USAGE = 1,
    GOSSIPSUB_INTEROP_ERR_IO = 2,
    GOSSIPSUB_INTEROP_ERR_PARSE = 3,
    GOSSIPSUB_INTEROP_ERR_IDENTITY = 4,
    GOSSIPSUB_INTEROP_ERR_HOST = 5,
    GOSSIPSUB_INTEROP_ERR_PROTOCOL = 6,
    GOSSIPSUB_INTEROP_ERR_LIMIT = 7,
    GOSSIPSUB_INTEROP_ERR_UNSUPPORTED = 8
} gossipsub_interop_err_t;

typedef enum
{
    GOSSIPSUB_INTEROP_INSTRUCTION_NONE = 0,
    GOSSIPSUB_INTEROP_INSTRUCTION_INIT,
    GOSSIPSUB_INTEROP_INSTRUCTION_CONNECT,
    GOSSIPSUB_INTEROP_INSTRUCTION_WAIT_UNTIL,
    GOSSIPSUB_INTEROP_INSTRUCTION_SUBSCRIBE,
    GOSSIPSUB_INTEROP_INSTRUCTION_SET_VALIDATION_DELAY,
    GOSSIPSUB_INTEROP_INSTRUCTION_PUBLISH,
    GOSSIPSUB_INTEROP_INSTRUCTION_PARTIAL_UNSUPPORTED
} gossipsub_interop_instruction_type_t;

typedef struct
{
    gossipsub_interop_instruction_type_t type;
    int connect_to[GOSSIPSUB_INTEROP_MAX_CONNECT_PEERS];
    size_t connect_count;
    char topic[GOSSIPSUB_INTEROP_MAX_TOPIC_BYTES];
    size_t topic_len;
    uint64_t elapsed_seconds;
    uint64_t message_id;
    size_t message_size_bytes;
    uint64_t delay_us;
    uint8_t partial;
} gossipsub_interop_instruction_t;

typedef struct
{
    char data[GOSSIPSUB_INTEROP_MAX_PARAMS_BYTES];
    size_t len;
    size_t pos;
    size_t script_end;
} gossipsub_interop_script_t;

gossipsub_interop_err_t gossipsub_interop_script_load(
    const char *path,
    gossipsub_interop_script_t *script);

gossipsub_interop_err_t gossipsub_interop_script_next(
    gossipsub_interop_script_t *script,
    int node_id,
    gossipsub_interop_instruction_t *out_instruction,
    uint8_t *out_has_instruction);

#endif /* LIBP2P_GOSSIPSUB_INTEROP_H */
