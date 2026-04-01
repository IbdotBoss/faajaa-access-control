/**
 * @file    packet_codec.c
 * @brief   Byte-by-byte packet parser, encoder, and CRC-16/CCITT-FALSE.
 *
 * Packet layout (see packet_spec.md):
 *   START(1) | VERSION(1) | TYPE(1) | FLAGS(1) | REQID(2) | LEN(2)
 *   | PAYLOAD(N) | CRC16(2) | END(1)
 *
 * CRC is computed over VERSION through end of PAYLOAD.
 */
#include "packet_codec.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  CRC-16/CCITT-FALSE lookup table  (poly 0x1021, init 0xFFFF)        */
/* ------------------------------------------------------------------ */
static const uint16_t crc_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x4864, 0x5845, 0x6826, 0x7807, 0x08E0, 0x18C1, 0x28A2, 0x38A3,
    0xC94C, 0xD96D, 0xE90E, 0xF92F, 0x89C8, 0x99E9, 0xA98A, 0xB9AB,
    0x5A75, 0x4A54, 0x7A37, 0x6A16, 0x1AF1, 0x0AD0, 0x3AB3, 0x2A92,
    0xDB7D, 0xCB5C, 0xFB3F, 0xEB1E, 0x9BF9, 0x8BD8, 0xBBBB, 0xAB9A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBBAA,
    0x4A45, 0x5A64, 0x6A07, 0x7A26, 0x0AC1, 0x1AE0, 0x2A83, 0x3AA2,
    0xFD3E, 0xED1F, 0xDD7C, 0xCD5D, 0xBDBA, 0xAD9B, 0x9DF8, 0x8DD9,
    0x7C36, 0x6C17, 0x5C74, 0x4C55, 0x3CB2, 0x2C93, 0x1CF0, 0x0CD1,
    0xEF0F, 0xFF2E, 0xCF4D, 0xDF6C, 0xAF8B, 0xBFAA, 0x8FC9, 0x9FE8,
    0x6E07, 0x7E26, 0x4E45, 0x5E64, 0x2E83, 0x3EA2, 0x0EC1, 0x1EE0,
};

uint16_t crc16_ccitt(const uint8_t *data, uint16_t len)
{
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < len; i++) {
        uint8_t idx = (uint8_t)((crc >> 8) ^ data[i]);
        crc = (crc << 8) ^ crc_table[idx];
    }
    return crc;
}

/* ------------------------------------------------------------------ */
/*  Parser                                                             */
/* ------------------------------------------------------------------ */
void parser_init(packet_parser_t *p)
{
    memset(p, 0, sizeof(*p));
    p->state = PARSE_WAIT_START;
}

/**
 * Internal: accumulate a byte into the CRC buffer.
 */
static void crc_buf_push(packet_parser_t *p, uint8_t byte)
{
    if (p->crc_buf_len < sizeof(p->crc_buf)) {
        p->crc_buf[p->crc_buf_len++] = byte;
    }
}

bool parser_feed_byte(packet_parser_t *p, uint8_t byte)
{
    switch (p->state) {

    /* ---- Wait for start delimiter ---- */
    case PARSE_WAIT_START:
        if (byte == PROTO_START_BYTE) {
            /* reset accumulation state */
            p->crc_buf_len  = 0;
            p->payload_idx  = 0;
            p->crc_received = 0;
            memset(&p->pkt, 0, sizeof(p->pkt));
            p->state = PARSE_VERSION;
        }
        /* else: discard */
        break;

    /* ---- Fixed header fields ---- */
    case PARSE_VERSION:
        p->pkt.version = byte;
        crc_buf_push(p, byte);
        p->state = PARSE_TYPE;
        break;

    case PARSE_TYPE:
        p->pkt.msg_type = byte;
        crc_buf_push(p, byte);
        p->state = PARSE_FLAGS;
        break;

    case PARSE_FLAGS:
        p->pkt.flags = byte;
        crc_buf_push(p, byte);
        p->state = PARSE_REQID_HI;
        break;

    case PARSE_REQID_HI:
        p->pkt.request_id = (uint16_t)byte << 8;
        crc_buf_push(p, byte);
        p->state = PARSE_REQID_LO;
        break;

    case PARSE_REQID_LO:
        p->pkt.request_id |= byte;
        crc_buf_push(p, byte);
        p->state = PARSE_LEN_HI;
        break;

    case PARSE_LEN_HI:
        p->pkt.payload_len = (uint16_t)byte << 8;
        crc_buf_push(p, byte);
        p->state = PARSE_LEN_LO;
        break;

    case PARSE_LEN_LO:
        p->pkt.payload_len |= byte;
        crc_buf_push(p, byte);

        /* bounds check */
        if (p->pkt.payload_len > PACKET_MAX_PAYLOAD) {
            p->state = PARSE_WAIT_START;   /* reject oversized */
            break;
        }
        if (p->pkt.payload_len == 0) {
            p->state = PARSE_CRC_HI;      /* no payload to read */
        } else {
            p->payload_idx = 0;
            p->state = PARSE_PAYLOAD;
        }
        break;

    /* ---- Variable-length payload ---- */
    case PARSE_PAYLOAD:
        p->pkt.payload[p->payload_idx++] = byte;
        crc_buf_push(p, byte);
        if (p->payload_idx >= p->pkt.payload_len) {
            p->state = PARSE_CRC_HI;
        }
        break;

    /* ---- CRC (big-endian) ---- */
    case PARSE_CRC_HI:
        p->crc_received = (uint16_t)byte << 8;
        p->state = PARSE_CRC_LO;
        break;

    case PARSE_CRC_LO:
        p->crc_received |= byte;
        p->state = PARSE_WAIT_END;
        break;

    /* ---- End delimiter ---- */
    case PARSE_WAIT_END:
        if (byte == PROTO_END_BYTE) {
            /* verify CRC */
            uint16_t crc_calc = crc16_ccitt(p->crc_buf, p->crc_buf_len);
            if (crc_calc == p->crc_received) {
                /* valid packet is now in p->pkt */
                p->state = PARSE_WAIT_START;
                return true;
            }
        }
        /* bad end byte or CRC mismatch — discard and resync */
        p->state = PARSE_WAIT_START;
        break;

    default:
        p->state = PARSE_WAIT_START;
        break;
    }

    return false;
}

/* ------------------------------------------------------------------ */
/*  Encoder                                                            */
/* ------------------------------------------------------------------ */
uint16_t packet_encode(const fac_packet_t *pkt, uint8_t *buf, uint16_t buf_size)
{
    /* total = START(1) + header(8) + payload(N) + CRC(2) + END(1) */
    uint16_t total = 1 + PACKET_HEADER_SIZE + pkt->payload_len + 2 + 1;
    if (total > buf_size || pkt->payload_len > PACKET_MAX_PAYLOAD) {
        return 0;
    }

    uint16_t idx = 0;

    /* START */
    buf[idx++] = PROTO_START_BYTE;

    /* Header — these bytes are included in CRC */
    uint16_t crc_start = idx;
    buf[idx++] = pkt->version;
    buf[idx++] = pkt->msg_type;
    buf[idx++] = pkt->flags;
    buf[idx++] = (uint8_t)(pkt->request_id >> 8);
    buf[idx++] = (uint8_t)(pkt->request_id & 0xFF);
    buf[idx++] = (uint8_t)(pkt->payload_len >> 8);
    buf[idx++] = (uint8_t)(pkt->payload_len & 0xFF);

    /* Payload */
    for (uint16_t i = 0; i < pkt->payload_len; i++) {
        buf[idx++] = pkt->payload[i];
    }

    /* CRC over VERSION through end of PAYLOAD */
    uint16_t crc = crc16_ccitt(&buf[crc_start], PACKET_HEADER_SIZE + pkt->payload_len);
    buf[idx++] = (uint8_t)(crc >> 8);
    buf[idx++] = (uint8_t)(crc & 0xFF);

    /* END */
    buf[idx++] = PROTO_END_BYTE;

    return idx;
}
