"""
fac_broker.py — FAC middleware broker.

Exclusively owns the serial port to the NUCLEO-G474RE and exposes a
WebSocket server for GUI clients (Visitor + Admin).

Usage:
  python fac_broker.py COM4
  python fac_broker.py COM4 --ws-port 8765 --log-file fac_audit.log --verbose
"""

import argparse
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime

import serial
import websockets

from fac_protocol import (
    START, END,
    MSG_PASS_TRY, MSG_PASS_RESULT, MSG_REQUEST_ADMIN, MSG_NONCE_ISSUED,
    MSG_ADMIN_APPROVE, MSG_ADMIN_DENY, MSG_STATUS_UPDATE, MSG_ERROR,
    MSG_LOCKOUT_NOTICE, MSG_PING, MSG_PONG,
    MSG_NAMES, STATE_NAMES,
    encode_packet, decode_packet, parse_mcu_payload,
)

log = logging.getLogger("fac_broker")

# ── Broker state ─────────────────────────────────────────────────────────────

@dataclass
class BrokerState:
    fsm_state: str = "LOCKED_IDLE"
    fsm_state_code: int = 0x10
    pending_nonce_hex: str | None = None
    pending_request_id: int | None = None
    serial_connected: bool = False
    last_request_id: int = 0

    def next_request_id(self) -> int:
        self.last_request_id = (self.last_request_id + 1) % 65536
        return self.last_request_id


state = BrokerState()

# ── Connected WebSocket clients ──────────────────────────────────────────────

CLIENTS: set = set()

# ── Serial port handle (set in main) ────────────────────────────────────────

_ser: serial.Serial | None = None

# ── Audit log file handle ────────────────────────────────────────────────────

_audit_file = None


def _ts() -> str:
    return datetime.now().isoformat(timespec="microseconds")


def audit(entry: dict) -> None:
    entry["ts"] = _ts()
    if _audit_file:
        _audit_file.write(json.dumps(entry) + "\n")
        _audit_file.flush()
    log.info("AUDIT %s", json.dumps(entry))


# ── Broadcast to all GUI clients ─────────────────────────────────────────────

async def broadcast(event: dict) -> None:
    if not CLIENTS:
        return
    msg = json.dumps(event)
    stale = set()
    for ws in CLIENTS:
        try:
            await ws.send(msg)
        except websockets.ConnectionClosed:
            stale.add(ws)
    CLIENTS.difference_update(stale)


async def send_to(ws, event: dict) -> None:
    try:
        await ws.send(json.dumps(event))
    except websockets.ConnectionClosed:
        pass


# ── Handle packets from MCU ──────────────────────────────────────────────────

async def handle_mcu_packet(pkt: dict) -> None:
    if not pkt["crc_ok"]:
        log.warning("CRC mismatch on received packet, ignoring")
        return

    info = parse_mcu_payload(pkt)
    msg_name = info["msg_name"]
    req_id = pkt["request_id"]
    timestamp = _ts()

    t = pkt["msg_type"]

    if t == MSG_STATUS_UPDATE:
        state.fsm_state = info.get("state", state.fsm_state)
        state.fsm_state_code = info.get("state_code", state.fsm_state_code)
        await broadcast({
            "event": "state_update",
            "state": info["state"],
            "state_code": info["state_code"],
            "request_id": req_id,
            "timestamp": timestamp,
        })
        audit({"dir": "mcu->gui", "type": msg_name, "req_id": req_id,
               "state": info["state"]})

    elif t == MSG_PASS_RESULT:
        await broadcast({
            "event": "pass_result",
            "result": info["result"],
            "result_code": info["result_code"],
            "request_id": req_id,
            "timestamp": timestamp,
        })
        audit({"dir": "mcu->gui", "type": msg_name, "req_id": req_id,
               "result": info["result"]})

    elif t == MSG_NONCE_ISSUED:
        state.pending_nonce_hex = info["nonce_hex"]
        state.pending_request_id = req_id
        await broadcast({
            "event": "nonce_issued",
            "nonce_hex": info["nonce_hex"],
            "request_id": req_id,
            "timestamp": timestamp,
        })
        audit({"dir": "mcu->gui", "type": msg_name, "req_id": req_id,
               "nonce_hex": info["nonce_hex"]})

    elif t == MSG_LOCKOUT_NOTICE:
        await broadcast({
            "event": "lockout_notice",
            "remaining_seconds": info.get("remaining_seconds", 0),
            "request_id": req_id,
            "timestamp": timestamp,
        })
        audit({"dir": "mcu->gui", "type": msg_name, "req_id": req_id,
               "remaining_seconds": info.get("remaining_seconds", 0)})

    elif t == MSG_ERROR:
        await broadcast({
            "event": "error",
            "error": info.get("error", "UNKNOWN"),
            "error_code": info.get("error_code", 0),
            "request_id": req_id,
            "timestamp": timestamp,
        })
        audit({"dir": "mcu->gui", "type": msg_name, "req_id": req_id,
               "error": info.get("error", "UNKNOWN")})

    elif t == MSG_PONG:
        await broadcast({
            "event": "pong",
            "request_id": req_id,
            "timestamp": timestamp,
        })

    else:
        log.debug("Unhandled MCU message: %s (0x%02X)", msg_name, t)


# ── Handle commands from GUI clients ─────────────────────────────────────────

VALID_COMMANDS = {"pass_try", "request_admin", "admin_approve", "admin_deny",
                  "ping", "get_state"}

CMD_TO_MSG = {
    "pass_try":       MSG_PASS_TRY,
    "request_admin":  MSG_REQUEST_ADMIN,
    "admin_approve":  MSG_ADMIN_APPROVE,
    "admin_deny":     MSG_ADMIN_DENY,
    "ping":           MSG_PING,
}


async def handle_gui_command(msg: dict, ws) -> None:
    cmd_type = msg.get("type")
    if cmd_type not in VALID_COMMANDS:
        await send_to(ws, {"event": "error", "error": f"unknown command: {cmd_type}",
                           "timestamp": _ts()})
        return

    # get_state is broker-local, no serial packet
    if cmd_type == "get_state":
        await send_to(ws, {
            "event": "state_snapshot",
            "state": state.fsm_state,
            "state_code": state.fsm_state_code,
            "serial_connected": state.serial_connected,
            "pending_nonce_hex": state.pending_nonce_hex,
            "pending_request_id": state.pending_request_id,
            "timestamp": _ts(),
        })
        return

    if not state.serial_connected:
        await send_to(ws, {"event": "error", "error": "serial_disconnected",
                           "timestamp": _ts()})
        return

    # Build payload
    payload = b''
    if cmd_type == "pass_try":
        passkey = msg.get("passkey", "")
        payload = passkey.encode("ascii")[:6]
    elif cmd_type == "admin_approve":
        token_hex = msg.get("token_hex", "")
        try:
            payload = bytes.fromhex(token_hex)
        except ValueError:
            await send_to(ws, {"event": "error", "error": "invalid token_hex",
                               "timestamp": _ts()})
            return

    req_id = state.next_request_id()
    frame = encode_packet(CMD_TO_MSG[cmd_type], payload, request_id=req_id)

    # Write to serial via executor (non-blocking)
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, _serial_write, frame)
    except Exception as e:
        log.error("Serial write error: %s", e)
        await send_to(ws, {"event": "error", "error": "serial_write_failed",
                           "timestamp": _ts()})
        return

    # Ack back to originating GUI
    await send_to(ws, {
        "event": "command_ack",
        "command_type": cmd_type,
        "request_id": req_id,
        "timestamp": _ts(),
    })

    # Audit (redact passkey)
    if cmd_type == "pass_try":
        audit({"dir": "gui->mcu", "type": cmd_type, "req_id": req_id,
               "note": "passkey attempt (value redacted)"})
    else:
        audit({"dir": "gui->mcu", "type": cmd_type, "req_id": req_id})

    log.debug("-> MCU: %s req_id=%d", cmd_type, req_id)


def _serial_write(data: bytes) -> None:
    if _ser and _ser.is_open:
        _ser.write(data)
        _ser.flush()


# ── Serial reader (async, runs in executor) ──────────────────────────────────

async def serial_reader() -> None:
    loop = asyncio.get_running_loop()
    buf = bytearray()
    in_frame = False

    while True:
        try:
            data = await loop.run_in_executor(None, _serial_read_byte)
        except serial.SerialException:
            log.error("Serial port lost, attempting reconnect...")
            state.serial_connected = False
            await broadcast({"event": "serial_status", "connected": False,
                             "timestamp": _ts()})
            audit({"dir": "system", "type": "serial_disconnect"})
            await _reconnect_serial()
            buf = bytearray()
            in_frame = False
            continue

        if not data:
            continue

        byte = data[0]
        if not in_frame:
            if byte == START:
                buf = bytearray([START])
                in_frame = True
        else:
            buf.append(byte)
            if byte == END:
                pkt = decode_packet(bytes(buf))
                if pkt is not None:
                    await handle_mcu_packet(pkt)
                in_frame = False
                buf = bytearray()


def _serial_read_byte() -> bytes:
    if _ser and _ser.is_open:
        return _ser.read(1)
    raise serial.SerialException("port not open")


async def _reconnect_serial() -> None:
    global _ser
    while True:
        await asyncio.sleep(2)
        try:
            if _ser:
                try:
                    _ser.close()
                except Exception:
                    pass
            _ser = serial.Serial(_ser_port, _ser_baud, timeout=0.1)
            state.serial_connected = True
            log.info("Serial reconnected on %s", _ser_port)
            await broadcast({"event": "serial_status", "connected": True,
                             "timestamp": _ts()})
            audit({"dir": "system", "type": "serial_reconnect"})
            return
        except serial.SerialException as e:
            log.warning("Reconnect failed: %s, retrying in 2s...", e)


# ── WebSocket handler ────────────────────────────────────────────────────────

async def ws_handler(ws) -> None:
    CLIENTS.add(ws)
    remote = ws.remote_address
    log.info("GUI connected: %s", remote)
    audit({"dir": "system", "type": "gui_connect", "remote": str(remote)})

    # Send current state on connect
    await send_to(ws, {
        "event": "state_snapshot",
        "state": state.fsm_state,
        "state_code": state.fsm_state_code,
        "serial_connected": state.serial_connected,
        "pending_nonce_hex": state.pending_nonce_hex,
        "pending_request_id": state.pending_request_id,
        "timestamp": _ts(),
    })

    try:
        async for raw_msg in ws:
            try:
                msg = json.loads(raw_msg)
            except json.JSONDecodeError:
                await send_to(ws, {"event": "error", "error": "invalid JSON",
                                   "timestamp": _ts()})
                continue
            await handle_gui_command(msg, ws)
    except websockets.ConnectionClosed:
        pass
    finally:
        CLIENTS.discard(ws)
        log.info("GUI disconnected: %s", remote)
        audit({"dir": "system", "type": "gui_disconnect", "remote": str(remote)})


# ── Main ─────────────────────────────────────────────────────────────────────

_ser_port: str = ""
_ser_baud: int = 115200


async def main(port: str, baud: int, ws_port: int, log_file: str) -> None:
    global _ser, _ser_port, _ser_baud, _audit_file

    _ser_port = port
    _ser_baud = baud

    # Open audit log
    _audit_file = open(log_file, "a", encoding="utf-8")
    audit({"dir": "system", "type": "broker_start",
           "port": port, "baud": baud, "ws_port": ws_port})

    # Open serial port
    log.info("Opening %s at %d baud...", port, baud)
    try:
        _ser = serial.Serial(port, baud, timeout=0.1)
        state.serial_connected = True
        log.info("Serial connected.")
    except serial.SerialException as e:
        log.error("Could not open %s: %s", port, e)
        state.serial_connected = False

    # Start WebSocket server
    log.info("Starting WebSocket server on ws://localhost:%d", ws_port)
    async with websockets.serve(ws_handler, "localhost", ws_port):
        log.info("Broker ready. Waiting for GUI connections...")
        await serial_reader()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FAC middleware broker")
    parser.add_argument("port", help="Serial port (e.g. COM4)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--ws-port", type=int, default=8765,
                        help="WebSocket server port (default: 8765)")
    parser.add_argument("--log-file", default="fac_audit.log",
                        help="Audit log file (default: fac_audit.log)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        asyncio.run(main(args.port, args.baud, args.ws_port, args.log_file))
    except KeyboardInterrupt:
        log.info("Broker stopped.")
