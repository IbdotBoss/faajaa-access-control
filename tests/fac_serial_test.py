"""
fac_serial_test.py — pyserial test script for FAC firmware (NUCLEO-G474RE).

Packet wire format (from packet_spec.md / packet_codec.c):
  0x7E | VERSION(1) | TYPE(1) | FLAGS(1) | REQID(2 BE) | LEN(2 BE) | PAYLOAD(N)
       | CRC16(2 BE) | 0x7F

CRC-16/CCITT-FALSE  poly=0x1021  init=0xFFFF  over VERSION..end-of-PAYLOAD.

Usage:
  python fac_serial_test.py COM3          # run all tests
  python fac_serial_test.py COM3 --port   # just list available ports
"""

import sys
import time
import struct
import serial
import serial.tools.list_ports

# ── Protocol constants (mirror app_config.h) ─────────────────────────────────
START           = 0x7E
END             = 0x7F
PROTO_VERSION   = 0x01

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

RESULT_DENIED           = 0x00
RESULT_GRANTED          = 0x01
RESULT_LOCKOUT_ACTIVE   = 0x02

STATE_LOCKED_IDLE   = 0x10
STATE_VALIDATING    = 0x11
STATE_PENDING_ADMIN = 0x12
STATE_UNLOCKED      = 0x13
STATE_DENIED        = 0x14
STATE_LOCKOUT       = 0x15
STATE_FAULT         = 0x16

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

# ── CRC-16/CCITT-FALSE lookup table (poly=0x1021, init=0xFFFF) ───────────────
_CRC_TABLE = [0] * 256
for _i in range(256):
    _crc = _i << 8
    for _ in range(8):
        _crc = ((_crc << 1) ^ 0x1021) if (_crc & 0x8000) else (_crc << 1)
        _crc &= 0xFFFF
    _CRC_TABLE[_i] = _crc & 0xFFFF


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        idx = ((crc >> 8) ^ b) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFF
    return crc


# ── Packet encode / decode ────────────────────────────────────────────────────

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
    Returns None if the frame is malformed (wrong delimiters / too short).
    """
    if len(raw) < 12 or raw[0] != START or raw[-1] != END:
        return None

    version     = raw[1]
    msg_type    = raw[2]
    flags       = raw[3]
    request_id  = (raw[4] << 8) | raw[5]
    payload_len = (raw[6] << 8) | raw[7]

    if len(raw) != 1 + 7 + payload_len + 2 + 1:
        return None  # length field does not match actual frame

    payload     = raw[8 : 8 + payload_len]
    crc_rx      = (raw[8 + payload_len] << 8) | raw[8 + payload_len + 1]

    # CRC over VERSION..end-of-PAYLOAD (7 header bytes + N payload bytes)
    crc_data    = raw[1 : 1 + 7 + payload_len]
    crc_calc    = crc16_ccitt(crc_data)
    crc_ok      = (crc_calc == crc_rx)

    if not crc_ok:
        hex_frame = ' '.join(f'{b:02X}' for b in raw)
        hex_crc_data = ' '.join(f'{b:02X}' for b in crc_data)
        print(f"    [CRC DEBUG] frame: {hex_frame}")
        print(f"    [CRC DEBUG] crc_data ({len(crc_data)} bytes): {hex_crc_data}")
        print(f"    [CRC DEBUG] crc_rx=0x{crc_rx:04X}  crc_calc=0x{crc_calc:04X}")

    return {
        "version":    version,
        "msg_type":   msg_type,
        "flags":      flags,
        "request_id": request_id,
        "payload_len": payload_len,
        "payload":    bytes(payload),
        "crc_ok":     crc_ok,
    }


def pretty(pkt: dict) -> str:
    name = MSG_NAMES.get(pkt["msg_type"], f"0x{pkt['msg_type']:02X}")
    crc_tag = "" if pkt["crc_ok"] else " [CRC MISMATCH]"
    extra = ""
    t = pkt["msg_type"]
    if t == MSG_PASS_RESULT and pkt["payload"]:
        extra = f"  result={RESULT_NAMES.get(pkt['payload'][0], hex(pkt['payload'][0]))}"
    elif t == MSG_STATUS_UPDATE and pkt["payload"]:
        extra = f"  state={STATE_NAMES.get(pkt['payload'][0], hex(pkt['payload'][0]))}"
    elif t == MSG_NONCE_ISSUED:
        extra = f"  nonce={pkt['payload'].hex()}"
    elif t == MSG_LOCKOUT_NOTICE and pkt["payload"]:
        extra = f"  remaining={pkt['payload'][0]}s"
    elif t == MSG_ERROR and pkt["payload"]:
        extra = f"  code=0x{pkt['payload'][0]:02X}"
    elif pkt["payload"]:
        extra = f"  payload={pkt['payload'].hex()}"
    return f"  ← {name} (req={pkt['request_id']}){extra}{crc_tag}"


# ── Serial I/O helpers ────────────────────────────────────────────────────────

def read_packet(ser: serial.Serial, timeout: float = 2.0) -> dict | None:
    """
    Block until a complete framed packet arrives or timeout expires.
    Implements the same state machine as the firmware's parser_feed_byte().
    """
    deadline = time.monotonic() + timeout
    buf = bytearray()
    in_frame = False

    while time.monotonic() < deadline:
        ser.timeout = max(0.05, deadline - time.monotonic())
        b = ser.read(1)
        if not b:
            continue
        byte = b[0]

        if not in_frame:
            if byte == START:
                buf = bytearray([START])
                in_frame = True
        else:
            buf.append(byte)
            if byte == END:
                pkt = decode_packet(bytes(buf))
                if pkt is not None:
                    return pkt
                # malformed — resync
                in_frame = False
                buf = bytearray()

    return None


def send(ser: serial.Serial, msg_type: int, payload: bytes = b'',
         request_id: int = 0) -> None:
    frame = encode_packet(msg_type, payload, request_id=request_id)
    name = MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
    print(f"  → {name} (req={request_id})"
          + (f"  payload={payload.hex()}" if payload else ""))
    ser.write(frame)
    ser.flush()  # ensure bytes go out immediately


# ── Individual test helpers ───────────────────────────────────────────────────

def expect(ser: serial.Serial, expected_type: int,
           timeout: float = 3.0) -> dict | None:
    """
    Read packets until one with expected_type arrives or timeout.
    Prints any intermediate packets (e.g. STATUS_UPDATE) received en route.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        pkt = read_packet(ser, timeout=max(0.1, remaining))
        if pkt is None:
            return None
        print(pretty(pkt))
        if pkt["msg_type"] == expected_type:
            return pkt
    return None


# ── Test cases ────────────────────────────────────────────────────────────────

def test_ping(ser: serial.Serial) -> bool:
    print("\n[TEST 1] PING → PONG")
    send(ser, MSG_PING, request_id=1)
    pkt = expect(ser, MSG_PONG, timeout=3.0)
    if pkt and pkt["crc_ok"]:
        print("  PASS")
        return True
    print("  FAIL — no PONG received")
    return False


def test_pass_granted(ser: serial.Serial) -> bool:
    print("\n[TEST 2] PASS_TRY('1234') → PASS_RESULT(GRANTED)")
    send(ser, MSG_PASS_TRY, payload=b"1234", request_id=2)
    pkt = expect(ser, MSG_PASS_RESULT, timeout=5.0)
    if pkt and pkt["payload"] and pkt["payload"][0] == RESULT_GRANTED:
        print("  PASS")
        return True
    print("  FAIL — expected GRANTED")
    return False


def test_lockout(ser: serial.Serial) -> bool:
    print("\n[TEST 3] PASS_TRY('wrong') × 3 → LOCKOUT_NOTICE")
    # Wait for device to return to LOCKED_IDLE after previous test (unlock lasts 5s)
    print("  (waiting 6s for unlock timeout…)")
    time.sleep(6)

    for attempt in range(1, 4):
        print(f"  attempt {attempt}/3:")
        send(ser, MSG_PASS_TRY, payload=b"9999", request_id=10 + attempt)
        pkt = expect(ser, MSG_PASS_RESULT, timeout=3.0)
        if pkt is None:
            print("  FAIL — no PASS_RESULT")
            return False

    # After 3rd denial the firmware sends LOCKOUT_NOTICE
    pkt = expect(ser, MSG_LOCKOUT_NOTICE, timeout=3.0)
    if pkt:
        print("  PASS")
        return True
    print("  FAIL — no LOCKOUT_NOTICE")
    return False


def test_request_admin(ser: serial.Serial) -> bool:
    print("\n[TEST 4] REQUEST_ADMIN → NONCE_ISSUED")
    # Wait for lockout to clear (60s) OR send REQUEST_ADMIN from LOCKED_IDLE
    # after a manual board reset. Prompt the user.
    print("  Waiting for LOCKED_IDLE state (press RESET on board if needed)…")
    pkt = expect(ser, MSG_STATUS_UPDATE, timeout=70.0)
    if pkt is None or (pkt["payload"] and pkt["payload"][0] != STATE_LOCKED_IDLE):
        print("  (skipping — could not confirm LOCKED_IDLE; reset board and re-run)")
        return False

    send(ser, MSG_REQUEST_ADMIN, request_id=20)
    pkt = expect(ser, MSG_NONCE_ISSUED, timeout=5.0)
    if pkt and len(pkt["payload"]) == 16:
        print(f"  nonce = {pkt['payload'].hex()}")
        print("  PASS")
        return True
    print("  FAIL — no valid NONCE_ISSUED (16 bytes)")
    return False


# ── Entry point ───────────────────────────────────────────────────────────────

def list_ports() -> None:
    print("Available serial ports:")
    for p in serial.tools.list_ports.comports():
        print(f"  {p.device:<12} {p.description}")


def preflight_check(ser: serial.Serial) -> bool:
    """
    Send a PING and dump raw RX to diagnose the RX path.
    Returns True if PONG received successfully.
    """
    print("\n── Pre-flight RX check ──────────────")
    # First, show what the board sent on boot (don't flush!)
    time.sleep(0.5)
    boot = ser.read(256)
    if boot:
        hex_part = ' '.join(f'{b:02X}' for b in boot)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in boot)
        print(f"  Boot data ({len(boot)} bytes): {hex_part}")
        print(f"  ASCII: {ascii_part}")
    else:
        print("  No boot data received (board may not have reset)")

    # Now send PING and watch for ANY response bytes
    ping_frame = encode_packet(MSG_PING, request_id=99)
    hex_sent = ' '.join(f'{b:02X}' for b in ping_frame)
    print(f"\n  Sending PING: {hex_sent}")
    ser.write(ping_frame)
    ser.flush()

    # Wait and read raw bytes for 3 seconds
    print("  Waiting 3s for response bytes…")
    deadline = time.monotonic() + 3.0
    total = 0
    got_pong = False
    while time.monotonic() < deadline:
        chunk = ser.read(256)
        if chunk:
            total += len(chunk)
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            print(f"  RX [{len(chunk):3d} bytes]: {hex_part}")
            if 0x0B in chunk:  # MSG_PONG byte present
                got_pong = True

    if total == 0:
        print("  ✗ ZERO bytes received after PING — RX path is broken!")
        print("    → Board doesn't see our bytes, or UartRxProcess is stuck")
        return False
    elif got_pong:
        print(f"  ✓ Got {total} bytes including PONG — RX path works!")
        return True
    else:
        print(f"  ? Got {total} bytes but no PONG — partial RX or parser issue")
        return False


def run_all_tests(port: str, baud: int = 115200) -> None:
    print(f"Opening {port} at {baud} baud…")
    try:
        ser = serial.Serial(port, baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # Run pre-flight diagnostic first
    rx_ok = preflight_check(ser)
    if not rx_ok:
        print("\n  ⚠ Pre-flight failed. Running tests anyway for completeness…")

    ser.reset_input_buffer()

    results = []
    results.append(("PING→PONG",           test_ping(ser)))
    results.append(("PASS_TRY granted",     test_pass_granted(ser)))
    results.append(("lockout after 3 bad",  test_lockout(ser)))
    results.append(("REQUEST_ADMIN→nonce",  test_request_admin(ser)))

    ser.close()

    print("\n── Results ──────────────────────────")
    passed = 0
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")
        if ok:
            passed += 1
    print(f"\n{passed}/{len(results)} tests passed")


def sniff(port: str, baud: int = 115200, duration: float = 10.0) -> None:
    """
    Raw byte sniffer — prints every byte received for `duration` seconds.
    Use this to diagnose whether the board sends ANYTHING at all.
    Press Ctrl-C to stop early.
    """
    print(f"Sniffing {port} at {baud} baud for {duration}s …")
    print("(Press RESET on the board now to see the FAC_BOOT banner)\n")
    try:
        ser = serial.Serial(port, baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    ser.reset_input_buffer()
    deadline = time.monotonic() + duration
    total = 0

    try:
        while time.monotonic() < deadline:
            chunk = ser.read(256)
            if chunk:
                total += len(chunk)
                # Print both hex and ASCII representation
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  [{len(chunk):3d} bytes] {hex_part}")
                print(f"           ASCII: {ascii_part}")
    except KeyboardInterrupt:
        print("\n  (stopped)")

    ser.close()
    print(f"\nTotal: {total} bytes received in {duration}s")
    if total == 0:
        print("  ⚠ Zero bytes — board may not be running or UART is misconfigured.")
        print("  Check: 1) Board powered?  2) Correct COM port?  3) Press RESET on board.")


def rxtest(port: str, baud: int = 115200) -> None:
    """
    RX hardware test — works with the ECHO/DONE window in main.c.
    The firmware polls LPUART1 RXNE directly (no ISR, no HAL_GetTick).
    Echoes received bytes wrapped in brackets: [H][E][L][L][O]
    """
    print(f"RX hardware test on {port} at {baud} baud")
    print("Press RESET on the board NOW, then wait…\n")
    try:
        ser = serial.Serial(port, baud, timeout=0.2)
    except serial.SerialException as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    ser.reset_input_buffer()

    # Wait for ECHO banner (up to 5 seconds)
    print("  Waiting for ECHO banner…")
    deadline = time.monotonic() + 5.0
    buf = b''
    found_echo = False
    while time.monotonic() < deadline:
        chunk = ser.read(64)
        if chunk:
            buf += chunk
            text = buf.decode('ascii', errors='replace')
            if 'ECHO' in text:
                print(f"  Got banner!")
                print(f"  ASCII: {text.strip()}")
                found_echo = True
                break

    if not found_echo:
        if buf:
            print(f"  Got {len(buf)} bytes but no ECHO: {buf.hex()}")
            print(f"  ASCII: {buf.decode('ascii', errors='replace')}")
        else:
            print("  No data at all — board may not have reset")
        ser.close()
        return

    # Send test bytes during the echo window
    time.sleep(0.1)  # small gap to let firmware enter poll loop
    test_bytes = b'ABCDE'
    print(f"\n  Sending test bytes: {test_bytes.hex()} ('{test_bytes.decode()}')")
    ser.write(test_bytes)
    ser.flush()

    # Read echo response — wait up to 8 seconds (firmware loop is ~5s)
    print("  Waiting for echo (up to 8s)…")
    deadline = time.monotonic() + 8.0
    response = b''
    while time.monotonic() < deadline:
        chunk = ser.read(256)
        if chunk:
            response += chunk
            # Print as we receive
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  RX [{len(chunk):3d} bytes]: {hex_part}")
            print(f"           ASCII: {ascii_part}")
            # If we see DONE, the echo window ended
            if b'DONE' in response:
                break

    if not response:
        print("  ✗ ZERO bytes — LPUART1 RX is completely broken!")
        print("    → The peripheral cannot receive. Check:")
        print("      1) PA3 alternate function (AF12 for LPUART1)")
        print("      2) NUCLEO solder bridges for VCP routing")
        print("      3) Try USART2 (AF7) instead of LPUART1 (AF12)")
    elif b'[' in response:
        # Count echoed brackets
        bracket_count = response.count(ord('['))
        print(f"\n  ✓ Got {bracket_count} echoed byte(s)! UART RX hardware works!")
        print("    → Problem is in RTOS/CSP layer, not UART hardware")
    elif b'DONE' in response:
        print(f"\n  ✗ Got DONE but no echoed bytes — RXNE never set!")
        print("    → LPUART1 receiver may not be enabled, or baud mismatch")
    else:
        hex_part = ' '.join(f'{b:02X}' for b in response)
        print(f"\n  ? Unexpected response: {hex_part}")

    ser.close()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--port":
        list_ports()
        sys.exit(0)

    # --sniff mode: raw byte listener
    if len(sys.argv) >= 3 and sys.argv[2] == "--sniff":
        dur = float(sys.argv[3]) if len(sys.argv) >= 4 else 10.0
        sniff(sys.argv[1], duration=dur)
        sys.exit(0)

    # --rxtest mode: hardware RX echo test
    if len(sys.argv) >= 3 and sys.argv[2] == "--rxtest":
        rxtest(sys.argv[1])
        sys.exit(0)

    run_all_tests(sys.argv[1])
