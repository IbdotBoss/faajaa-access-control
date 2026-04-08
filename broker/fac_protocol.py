"""
fac_protocol.py — Shared FAC binary packet protocol.

Packet wire format:
  0x7E | VERSION(1) | TYPE(1) | FLAGS(1) | REQID(2 BE) | LEN(2 BE)
       | PAYLOAD(N) | CRC16(2 BE) | 0x7F

CRC-16/CCITT-FALSE  poly=0x1021  init=0xFFFF  over VERSION..end-of-PAYLOAD.

This module is pure data + functions (no I/O, no async).
Used by: fac_broker.py, fac_serial_test.py, and future GUIs.
"""

import struct

# ── Protocol framing ─────────────────────────────────────────────────────────
START           = 0x7E
END             = 0x7F
PROTO_VERSION   = 0x01

# ── Message types ────────────────────────────────────────────────────────────
MSG_PASS_TRY        = 0x01
MSG_PASS_RESULT     = 0x02
MSG_REQUEST_ADMIN   = 0x03
MSG_NONCE_ISSUED    = 0x04
MSG_ADMIN_APPROVE   = 0x05
MSG_ADMIN_DENY      = 0x06
MSG_STATUS_UPDATE   = 0x07
MSG_ERROR           = 0x08
MSG_LOCKOUT_NOTICE  = 0x09
MSG_PING            = 0x0A
MSG_PONG            = 0x0B

# ── PASS_RESULT payload codes ────────────────────────────────────────────────
RESULT_DENIED           = 0x00
RESULT_GRANTED          = 0x01
RESULT_LOCKOUT_ACTIVE   = 0x02

# ── STATUS_UPDATE state codes ────────────────────────────────────────────────
STATE_LOCKED_IDLE   = 0x10
STATE_VALIDATING    = 0x11
STATE_PENDING_ADMIN = 0x12
STATE_UNLOCKED      = 0x13
STATE_DENIED        = 0x14
STATE_LOCKOUT       = 0x15
STATE_FAULT         = 0x16

# ── ERROR payload codes ─────────────────────────────────────────────────────
ERR_MALFORMED_PACKET    = 0x20
ERR_CRC_MISMATCH        = 0x21
ERR_INVALID_TRANSITION  = 0x22
ERR_NONCE_EXPIRED       = 0x23
ERR_NONCE_INVALID       = 0x24
ERR_ADMIN_TOKEN_INVALID = 0x25
ERR_UNSUPPORTED_VERSION = 0x26

# ── Name maps ────────────────────────────────────────────────────────────────
MSG_NAMES = {
    MSG_PASS_TRY:       "PASS_TRY",
    MSG_PASS_RESULT:    "PASS_RESULT",
    MSG_REQUEST_ADMIN:  "REQUEST_ADMIN",
    MSG_NONCE_ISSUED:   "NONCE_ISSUED",
    MSG_ADMIN_APPROVE:  "ADMIN_APPROVE",
    MSG_ADMIN_DENY:     "ADMIN_DENY",
    MSG_STATUS_UPDATE:  "STATUS_UPDATE",
    MSG_ERROR:          "ERROR",
    MSG_LOCKOUT_NOTICE: "LOCKOUT_NOTICE",
    MSG_PING:           "PING",
    MSG_PONG:           "PONG",
}

STATE_NAMES = {
    STATE_LOCKED_IDLE:   "LOCKED_IDLE",
    STATE_VALIDATING:    "VALIDATING",
    STATE_PENDING_ADMIN: "PENDING_ADMIN",
    STATE_UNLOCKED:      "UNLOCKED",
    STATE_DENIED:        "DENIED",
    STATE_LOCKOUT:       "LOCKOUT",
    STATE_FAULT:         "SYSTEM_FAULT",
}

RESULT_NAMES = {
    RESULT_DENIED:          "DENIED",
    RESULT_GRANTED:         "GRANTED",
    RESULT_LOCKOUT_ACTIVE:  "LOCKOUT_ACTIVE",
}

ERROR_NAMES = {
    ERR_MALFORMED_PACKET:    "MALFORMED_PACKET",
    ERR_CRC_MISMATCH:        "CRC_MISMATCH",
    ERR_INVALID_TRANSITION:  "INVALID_TRANSITION",
    ERR_NONCE_EXPIRED:       "NONCE_EXPIRED",
    ERR_NONCE_INVALID:       "NONCE_INVALID",
    ERR_ADMIN_TOKEN_INVALID: "ADMIN_TOKEN_INVALID",
    ERR_UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
}

# ── CRC-16/CCITT-FALSE lookup table ─────────────────────────────────────────
_CRC_TABLE = [0] * 256
for _i in range(256):
    _crc = _i << 8
    for _ in range(8):
        _crc = ((_crc << 1) ^ 0x1021) if (_crc & 0x8000) else (_crc << 1)
        _crc &= 0xFFFF
    _CRC_TABLE[_i] = _crc & 0xFFFF


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE over a byte sequence."""
    crc = 0xFFFF
    for b in data:
        idx = ((crc >> 8) ^ b) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFF
    return crc


# ── Packet encode / decode ───────────────────────────────────────────────────

def encode_packet(msg_type: int, payload: bytes = b'',
                  flags: int = 0, request_id: int = 0) -> bytes:
    """Build a framed FAC packet ready to transmit."""
    header = struct.pack('>BBBHH', PROTO_VERSION, msg_type, flags,
                         request_id, len(payload))
    crc = crc16_ccitt(header + payload)
    return bytes([START]) + header + payload + struct.pack('>H', crc) + bytes([END])


def decode_packet(raw: bytes) -> dict | None:
    """
    Parse a raw byte sequence that starts with 0x7E and ends with 0x7F.
    Returns a dict with keys: version, msg_type, flags, request_id,
    payload_len, payload, crc_ok.
    Returns None if the frame is malformed.
    """
    if len(raw) < 11 or raw[0] != START or raw[-1] != END:
        return None

    version     = raw[1]
    msg_type    = raw[2]
    flags       = raw[3]
    request_id  = (raw[4] << 8) | raw[5]
    payload_len = (raw[6] << 8) | raw[7]

    if len(raw) != 1 + 7 + payload_len + 2 + 1:
        return None

    payload     = raw[8 : 8 + payload_len]
    crc_rx      = (raw[8 + payload_len] << 8) | raw[8 + payload_len + 1]

    crc_data    = raw[1 : 1 + 7 + payload_len]
    crc_calc    = crc16_ccitt(crc_data)
    crc_ok      = (crc_calc == crc_rx)

    return {
        "version":     version,
        "msg_type":    msg_type,
        "flags":       flags,
        "request_id":  request_id,
        "payload_len": payload_len,
        "payload":     bytes(payload),
        "crc_ok":      crc_ok,
    }


def parse_mcu_payload(pkt: dict) -> dict:
    """Interpret an MCU packet's payload into human-readable fields."""
    t = pkt["msg_type"]
    p = pkt["payload"]
    info: dict = {"msg_name": MSG_NAMES.get(t, f"0x{t:02X}")}

    if t == MSG_PASS_RESULT and p:
        info["result"] = RESULT_NAMES.get(p[0], f"0x{p[0]:02X}")
        info["result_code"] = p[0]
    elif t == MSG_STATUS_UPDATE and p:
        info["state"] = STATE_NAMES.get(p[0], f"0x{p[0]:02X}")
        info["state_code"] = p[0]
    elif t == MSG_NONCE_ISSUED:
        info["nonce_hex"] = p.hex()
    elif t == MSG_LOCKOUT_NOTICE and p:
        info["remaining_seconds"] = p[0]
    elif t == MSG_ERROR and p:
        info["error"] = ERROR_NAMES.get(p[0], f"0x{p[0]:02X}")
        info["error_code"] = p[0]

    return info
