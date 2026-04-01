/**
 * @file    packet_codec.h
 * @brief   Binary packet parser (byte-by-byte state machine), encoder,
 *          and CRC-16/CCITT-FALSE.
 */
#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include <stdint.h>
#include <stdbool.h>
#include "app_config.h"

/* ------------------------------------------------------------------ */
/*  Decoded packet                                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  flags;
    uint16_t request_id;
    uint16_t payload_len;
    uint8_t  payload[PACKET_MAX_PAYLOAD];
} fac_packet_t;

/* ------------------------------------------------------------------ */
/*  Parser internals                                                   */
/* ------------------------------------------------------------------ */
typedef enum {
    PARSE_WAIT_START,
    PARSE_VERSION,
    PARSE_TYPE,
    PARSE_FLAGS,
    PARSE_REQID_HI,
    PARSE_REQID_LO,
    PARSE_LEN_HI,
    PARSE_LEN_LO,
    PARSE_PAYLOAD,
    PARSE_CRC_HI,
    PARSE_CRC_LO,
    PARSE_WAIT_END,
} parser_state_t;

typedef struct {
    parser_state_t state;
    fac_packet_t   pkt;
    uint16_t       payload_idx;
    uint16_t       crc_received;
    /* CRC is computed over bytes from VERSION through end of PAYLOAD */
    uint8_t        crc_buf[PACKET_HEADER_SIZE + PACKET_MAX_PAYLOAD];
    uint16_t       crc_buf_len;
} packet_parser_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/** Reset parser to initial state. */
void parser_init(packet_parser_t *p);

/**
 * Feed one byte into the parser.
 * Returns true when a complete, CRC-valid packet is ready in p->pkt.
 * After returning true the parser auto-resets for the next packet.
 */
bool parser_feed_byte(packet_parser_t *p, uint8_t byte);

/**
 * Compute CRC-16/CCITT-FALSE over a buffer.
 * Poly 0x1021, init 0xFFFF.
 */
uint16_t crc16_ccitt(const uint8_t *data, uint16_t len);

/**
 * Encode a packet into a transmit buffer.
 * @param pkt       filled-in packet (version, msg_type, flags, request_id,
 *                  payload_len, payload).
 * @param buf       output buffer (must be >= PACKET_MAX_SIZE).
 * @param buf_size  size of buf.
 * @return          total encoded byte count, or 0 on error.
 */
uint16_t packet_encode(const fac_packet_t *pkt, uint8_t *buf, uint16_t buf_size);

#endif /* PACKET_CODEC_H */
