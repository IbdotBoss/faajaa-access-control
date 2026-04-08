# Faajaa Access Control (FAC)

Secure access control system built on the STM32 NUCLEO-G474RE. Combines embedded firmware, a Python serial broker, and desktop GUIs for two access paths: local passkey entry and remote administrator approval with nonce-based challenge-response.

## Architecture

```
Visitor GUI ──┐                    ┌── LED / Relay
              ├── Python Broker ── NUCLEO-G474RE
Admin GUI ────┘   (serial owner)   └── Button
```

- **Edge**: NUCLEO-G474RE running FreeRTOS + CSP4CMSIS (4 concurrent processes)
- **Middleware**: Python broker with exclusive serial port ownership
- **Clients**: Visitor keypad GUI, Admin approve/deny GUI

## Firmware

The firmware uses [CSP4CMSIS](https://github.com/OliverFaust/CSP4CMSIS-nucleo-g474re_v10_Interrupt) (Communicating Sequential Processes for CMSIS/FreeRTOS) to structure the application as four concurrent processes connected by rendezvous channels:

| Process | Role |
|---|---|
| UartRxProcess | Interrupt-driven UART ring buffer, byte-by-byte packet assembly |
| ButtonProcess | GPIO debounce with press-event output |
| FsmProcess | ALT-based selective wait on packet + button channels, runs the FSM |
| UartTxProcess | Packet encoding and UART transmission |

Communication uses a custom binary packet protocol over LPUART1 at 115200 baud with CRC-16/CCITT-FALSE integrity.

### CSP4CMSIS Library

The CSP4CMSIS library used in this project is based on the interrupt-capable variant by Oliver Faust:

- [CSP4CMSIS-nucleo-g474re_v10_Interrupt](https://github.com/OliverFaust/CSP4CMSIS-nucleo-g474re_v10_Interrupt) - Interrupt variant with `putFromISR()`, `BufferPolicy` support, and ISR-to-channel integration (used in this project)
- [CSP4CMSIS_for_NUCLEO-G474RE](https://github.com/OliverFaust/CSP4CMSIS_for_NUCLEO-G474RE) - Basic variant with rendezvous channels and ALT selection

Custom fixes applied to the library for this project:
- Static event group persistence in AltScheduler (prevents use-after-free across ALT cycles)
- Static timer persistence in TimerGuard (prevents async deletion races)

## Broker

The Python broker (`broker/fac_broker.py`) exclusively owns the serial port and exposes a WebSocket server for the GUI clients. It handles packet encoding/decoding, state tracking, serial reconnection, and JSONL audit logging.

```bash
pip install -r broker/requirements.txt
python broker/fac_broker.py COM4
```

Options: `--ws-port 8765`, `--log-file fac_audit.log`, `--verbose`

## GUIs

Both GUIs connect to the broker via WebSocket and auto-reconnect on disconnect.

```bash
pip install customtkinter websockets
```

### Visitor GUI

Numeric keypad interface for passkey entry with real-time status feedback.

```bash
python gui/visitor_gui.py
```

Features: 6-digit masked passkey input, color-coded status display (locked/unlocked/denied/lockout), Call Admin button, lockout countdown.

### Admin GUI

Dashboard for reviewing and responding to admin access requests.

```bash
python gui/admin_gui.py
```

Features: pending request panel with nonce display and 30s countdown, Approve/Deny buttons with HMAC-SHA256 token generation, scrollable event log, FSM state indicator.

Options: `--ws ws://localhost:8765`, `--secret FAC_ADMIN_SECRET_2026`

### Full Demo

#### Prerequisites

1. NUCLEO-G474RE connected via USB (appears as COM4 — check Device Manager)
2. Firmware flashed (see Build & Flash below)
3. Python dependencies installed:
   ```bash
   pip install pyserial websockets customtkinter
   ```

#### Start the system (3 terminals)

```bash
# Terminal 1: Start broker (must be first — owns the serial port)
python broker/fac_broker.py COM4 --verbose

# Terminal 2: Visitor GUI
python gui/visitor_gui.py

# Terminal 3: Admin GUI
python gui/admin_gui.py
```

Both GUIs should show "Connected" once the broker is running.

#### Demo walkthrough (matches PRD section 20)

1. **System boots into LOCKED state** — LED off, Visitor GUI shows "LOCKED", Admin event log shows state
2. **Correct passkey** — On Visitor GUI, type `1234` then press ENT. Status flashes "VALIDATING" then "ACCESS GRANTED". LED turns on for 5 seconds, then system returns to LOCKED
3. **Wrong passkey + denial** — Type `9999` and press ENT. Status shows "ACCESS DENIED" briefly
4. **Repeated failures -> lockout** — Enter 3 wrong passkeys in a row. After the 3rd, status shows "LOCKOUT" with a 60-second countdown. All further attempts are rejected until the lockout expires
5. **Admin request via GUI** — Once back in LOCKED, press "Call Admin" on the Visitor GUI. Status changes to "PENDING ADMIN". The Admin GUI receives the request with a nonce and 30-second countdown
6. **Admin approves** — Click "Approve" on the Admin GUI. The firmware verifies the HMAC-SHA256 token against the nonce. LED turns on, Visitor GUI shows "ACCESS GRANTED", system returns to LOCKED after 5 seconds
7. **Admin denies** — Repeat step 5, but click "Deny". System returns to LOCKED without unlocking
8. **Admin request via button** — Press the physical user button (B1) on the NUCLEO board. Same flow as step 5 — nonce appears in Admin GUI
9. **Audit log** — Check `broker/fac_audit.log` for the complete JSONL event trail (passkey attempts are redacted)

#### Stopping

- Close the GUI windows
- Press Ctrl+C in the broker terminal
- The board continues running (defaults to LOCKED)

## Security

- **Message integrity**: All serial packets use CRC-16/CCITT-FALSE to detect corruption
- **Anti-replay**: Admin approval uses a one-time nonce generated by hardware RNG (STM32G474RE RNG peripheral). The nonce expires after 30 seconds and is invalidated immediately on use
- **HMAC-SHA256 token verification**: Admin approval tokens are `HMAC-SHA256(shared_secret, nonce || 0x01)`, verified on the MCU with constant-time comparison
- **Brute-force protection**: 3 failed passkey attempts trigger a 60-second lockout
- **Fail-secure**: System defaults to LOCKED on boot, reset, or host disconnect
- **Hardware RNG**: Nonces generated from the STM32G474RE true random number generator (PLL-clocked at 48 MHz)

## Project Structure

```
firmware/           STM32 firmware (C/C++, FreeRTOS, CSP4CMSIS)
  Src/              Application source (fac_processes.cpp, packet_codec.c, etc.)
  Inc/              Application headers (app_config.h, etc.)
  lib/CSP4CMSIS/    CSP4CMSIS library (interrupt variant + ALT fixes)
  Drivers/          STM32 HAL drivers
  Middlewares/      FreeRTOS
  Debug/            Build output (.elf)
broker/             Python middleware broker
  fac_protocol.py   Shared protocol constants, CRC, encode/decode
  fac_broker.py     Async serial + WebSocket broker with audit logging
tests/              Serial test suite (Python)
gui/                Desktop GUI clients (CustomTkinter)
  visitor_gui.py    Visitor keypad interface
  admin_gui.py      Admin approval dashboard
kini/               Design specs (PRD, system_design.json)
```

## Testing

```bash
python tests/fac_serial_test.py COM4
```

Runs 4 tests against the board over serial:
1. PING -> PONG (connectivity)
2. PASS_TRY('1234') -> GRANTED (local passkey)
3. 3x wrong passkey -> LOCKOUT_NOTICE (brute-force protection)
4. REQUEST_ADMIN -> NONCE_ISSUED (admin override flow)

## Build & Flash

Requires STM32CubeIDE toolchain.

```bash
# Build
cd firmware/Debug && make -j4 all

# Flash via SWD
STM32_Programmer_CLI -c port=SWD reset=HWrst -w Debug/faajaa-access-control.elf -rst
```

## Hardware

- STM32 NUCLEO-G474RE
- LPUART1 VCP (PA2 TX / PA3 RX, AF12) at 115200 baud
- User LED for lock state indication
- User button (PC13) for admin request
