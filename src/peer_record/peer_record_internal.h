#ifndef PEER_RECORD_INTERNAL_H
#define PEER_RECORD_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_record/peer_record.h"

#define PEER_RECORD_WIRE_VARINT 0U
#define PEER_RECORD_WIRE_LEN    2U

#define PEER_RECORD_FIELD_ENVELOPE_PUBLIC_KEY   1U
#define PEER_RECORD_FIELD_ENVELOPE_PAYLOAD_TYPE 2U
#define PEER_RECORD_FIELD_ENVELOPE_PAYLOAD      3U
#define PEER_RECORD_FIELD_ENVELOPE_SIGNATURE    5U

#define PEER_RECORD_FIELD_RECORD_PEER_ID   1U
#define PEER_RECORD_FIELD_RECORD_SEQNO     2U
#define PEER_RECORD_FIELD_RECORD_ADDRESSES 3U

#define PEER_RECORD_FIELD_ADDRESS_MULTIADDR 1U

int peer_record_size_add(size_t a, size_t b, size_t *out);

int peer_record_bytes_present(libp2p_peer_record_bytes_t bytes);

libp2p_peer_record_err_t peer_record_uvarint_err(libp2p_uvarint_err_t err);

libp2p_peer_record_err_t peer_record_peer_id_err(libp2p_peer_id_err_t err);

libp2p_peer_record_err_t peer_record_host_err(libp2p_host_err_t err);

libp2p_peer_record_err_t peer_record_len_field_size(uint32_t field, size_t data_len, size_t *total);

libp2p_peer_record_err_t peer_record_varint_field_size(
    uint32_t field,
    uint64_t value,
    size_t *total);

libp2p_peer_record_err_t peer_record_write_uvarint(
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos);

libp2p_peer_record_err_t peer_record_write_key(
    uint32_t field,
    uint32_t wire_type,
    uint8_t *out,
    size_t out_len,
    size_t *pos);

libp2p_peer_record_err_t peer_record_write_len_field(
    uint32_t field,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t *pos);

libp2p_peer_record_err_t peer_record_write_varint_field(
    uint32_t field,
    uint64_t value,
    uint8_t *out,
    size_t out_len,
    size_t *pos);

libp2p_peer_record_err_t peer_record_read_key(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint32_t *field,
    uint32_t *wire_type);

libp2p_peer_record_err_t peer_record_read_uvarint(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint64_t *value);

libp2p_peer_record_err_t peer_record_read_len_span(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    libp2p_peer_record_bytes_t *out);

libp2p_peer_record_err_t peer_record_skip_value(
    const uint8_t *in,
    size_t in_len,
    size_t *pos,
    uint32_t wire_type);

libp2p_peer_record_bytes_t peer_record_const_bytes(const char *text, size_t len);

#endif /* PEER_RECORD_INTERNAL_H */
