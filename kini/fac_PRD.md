# Faajaa Access Control (FAC)
## Product Requirements Document and System Design Specification

## 1. Overview

The Faajaa Access Control (FAC) system is a secure access management solution built around the STM32 NUCLEO-G474RE. The system combines embedded control, host-side middleware, and graphical user interfaces to provide two access paths:

- Local access through a visitor keypad interface
- Remote access through an administrator approval interface

The design goal is to produce a secure, realistic, and demonstrable embedded system that is more sophisticated than a basic password checker while remaining feasible for a university project. The NUCLEO-G474RE acts as the trusted embedded controller for lock-state management and hardware actions, while a host PC provides richer user interfaces, logging, and message brokering.

The system is designed to be fail-secure, event-driven, and resistant to accidental corruption and simple replay attacks. It is not presented as a production-grade commercial appliance, but as a hardened academic prototype with clear current mitigations and a realistic roadmap for future improvement.

## 2. Project Objectives

The system must:

- Demonstrate secure access control using the NUCLEO-G474RE
- Include both low-level hardware handling and high-level user interaction
- Support a visitor-facing access request flow
- Support an administrator override flow
- Use software architecture to address key real-world limitations of a simple one-door system
- Be suitable for demonstration in a 5-minute video
- Be defensible in terms of embedded design, security thinking, and software engineering value

## 3. Design Rationale

A direct high-resolution GUI does not belong on the microcontroller. Instead, the system uses a host-client architecture.

- The NUCLEO-G474RE is responsible for trusted embedded execution, GPIO control, state management, lockout timing, and verification of security-sensitive commands.
- The host PC is responsible for the visitor GUI, administrator GUI, audit logging, and coordination between multiple software clients.

This separation keeps the embedded device deterministic and lightweight while allowing a modern interface and more advanced software logic on the host side.

## 4. System Scope

### In scope

- One controlled access point
- One NUCLEO-G474RE board
- One host PC running middleware and GUIs
- Local passkey-based entry using a keypad GUI
- Remote manual approval by an administrator
- Event logging and status monitoring
- Timeout, lockout, and message integrity protection

### Out of scope

- Multi-door campus-scale deployments
- Biometric authentication
- Cloud identity integration
- Production physical tamper sensors
- End-to-end enterprise PKI deployment

## 5. Stakeholders and Users

### Visitor

The visitor is the person requesting entry. They interact only with the Visitor GUI. They may either:

- enter a valid passkey, or
- request administrator assistance

### Administrator

The administrator monitors remote requests, reviews the current system state, and approves or denies access requests through the Admin GUI.

### System Owner

The system owner is the operator or assessor reviewing the design. This person is interested in the architecture, security decisions, limitations, and extensibility of the solution.

## 6. System Architecture

The system follows a Host-Client-Edge architecture.

### 6.1 Edge Layer: NUCLEO-G474RE

The NUCLEO-G474RE is the trusted embedded device and source of truth for physical lock state.

Responsibilities:

- maintain the finite state machine
- receive and parse commands from the host
- validate local access credentials
- validate administrator approval tokens for remote override
- control LED or relay output representing lock state
- monitor local input such as a button for access request
- enforce lockout and timeout rules
- default to locked on startup or reset

### 6.2 Middleware Layer: Python Broker

The Python broker is the only software process allowed to open the serial connection to the NUCLEO. In the current implementation, the broker is local-only and does not depend on any cloud service.

Responsibilities:

- maintain exclusive serial communication with the board
- parse and forward messages between the NUCLEO and GUIs
- prevent serial port contention when multiple GUIs are active
- log security-relevant events with timestamps
- coordinate request lifecycles between visitor and admin interfaces
- handle disconnections and reconnects gracefully

### 6.3 Client Layer: GUIs

#### Visitor GUI

Responsibilities:

- display keypad-style passkey entry
- mask passkey input
- allow clear and submit actions
- provide status messages such as LOCKED, ACCESS GRANTED, ACCESS DENIED, LOCKOUT, or PENDING ADMIN
- provide a button to request administrator assistance

#### Admin GUI

Responsibilities:

- display incoming remote access requests
- show current lock state and recent events
- allow approve or deny decisions
- display timeout state for pending requests
- optionally display attempt counters and error messages

## 7. Access Paths

The system supports two independent access paths.

### 7.1 Local Access Path

The visitor enters a numeric passkey through the Visitor GUI.

Recommended implementation:

- the visitor enters a 4-digit to 6-digit numeric passkey
- the Visitor GUI sends the passkey attempt to the broker
- the broker forwards the attempt to the NUCLEO over serial
- the NUCLEO validates the passkey against a stored reference
- if valid, the NUCLEO unlocks for a short defined period
- if invalid, the NUCLEO increments the failure counter and may enter lockout

Important design note:

The local path should not rely on sending only a static hash of the passkey from the GUI, because a static hash can be captured and replayed. For a coursework prototype, it is more honest and technically defensible either to:

- validate the passkey directly on the NUCLEO after receiving the attempt over the trusted local serial link, or
- describe challenge-response protection for the local path as future work

### 7.2 Remote Admin Override Path

The visitor can request remote admission when local entry is not available.

Recommended flow:

- the visitor presses the physical request button or uses a Call Admin action in the Visitor GUI
- the NUCLEO creates a one-time random nonce and enters PENDING_ADMIN state
- the nonce is sent through the broker to the Admin GUI
- the administrator reviews the request and chooses Approve or Deny
- on approval, the Admin GUI creates a cryptographic response based on the nonce and a protected administrator secret
- the broker forwards the response to the NUCLEO
- the NUCLEO verifies that the response is valid, fresh, and still within timeout
- the NUCLEO unlocks if verification succeeds

This path is stronger than a simple FORCE_OPEN message because it prevents straightforward replay of a previously captured admin approval.

## 8. Security Design

The project should be described as security-aware and hardened for coursework, not as perfect or invulnerable.

### 8.1 Security Goals

- prevent unauthorized unlocking due to accidental serial corruption
- reduce replay risk for remote administrator approval
- ensure the system defaults to a locked state after reset
- limit brute-force passkey attempts through lockout logic
- maintain a record of access attempts and decisions

### 8.2 Message Integrity

All messages between host and NUCLEO should include framing and integrity checks.

Recommended approach:

- use framed packets rather than raw unstructured strings
- use COBS framing or a clear start-length-payload-checksum format
- use CRC-16 to detect accidental corruption on the serial channel

This does not provide full cryptographic security on its own, but it prevents malformed or noisy input from being mistaken as valid commands.

### 8.3 Anti-Replay Protection for Remote Approval

Remote approval should use a nonce-based challenge-response flow.

Recommended approach:

- NUCLEO generates a fresh random nonce for each admin request
- nonce is single-use
- nonce expires after a short period such as 30 seconds
- admin approval includes a cryptographic response tied to that exact nonce and action
- NUCLEO rejects reused, invalid, or expired responses

### 8.4 Brute-Force Mitigation

The local passkey path should include:

- failed-attempt counting
- short lockout after repeated failures
- visible denied status
- optional longer lockout after repeated lockout cycles

### 8.5 Fail-Secure Behavior

The NUCLEO must:

- default to LOCKED after power-on reset
- clear pending requests after reset
- not remain unlocked if the host disconnects unexpectedly
- return to LOCKED after the unlock timer expires

### 8.6 Secret Handling

For the coursework prototype:

- store local passkey reference securely in firmware-controlled memory
- store admin secret in protected firmware storage where possible
- avoid sending secret keys over the serial link

For realism, the report can mention that STM32G474RE hardware supports OTP and memory protection features, but those should be presented as hardening options rather than mandatory project requirements.

## 9. Functional Requirements

### FR1
The system shall remain in a LOCKED state by default.

### FR2
The system shall allow a visitor to enter a numeric passkey using the Visitor GUI.

### FR3
The system shall verify the passkey attempt and return GRANTED or DENIED.

### FR4
The system shall allow a visitor to request administrator assistance.

### FR5
The system shall notify the Admin GUI when a remote request is pending.

### FR6
The administrator shall be able to approve or deny a pending request.

### FR7
The system shall unlock only for a short defined interval after successful validation.

### FR8
The system shall log access attempts, approvals, denials, lockouts, and timeouts.

### FR9
The system shall enter lockout after repeated invalid passkey attempts.

### FR10
The system shall reject expired or replayed admin approval responses.

## 10. Non-Functional Requirements

### NFR1 Performance
The system should respond to valid local passkey entry within a short user-visible time, ideally under one second in normal operation.

### NFR2 Reliability
The NUCLEO firmware should be non-blocking and continue servicing inputs while waiting for timeouts or remote responses.

### NFR3 Maintainability
The system should be modular so that firmware, broker, and GUIs can be developed and tested independently.

### NFR4 Demonstrability
The architecture and system states should be easy to explain and demonstrate clearly in a short assessment video.

### NFR5 Safety
The system should fail secure. A crash, restart, or disconnected host should not leave the lock in an unlocked state.

## 11. State Machine Design

The NUCLEO firmware should use a non-blocking finite state machine.

### LOCKED_IDLE
Default state. Waiting for local passkey entry, button press, or admin-related requests.

### VALIDATING_LOCAL
The NUCLEO is validating a passkey attempt.

### PENDING_ADMIN
A remote approval request is active. A nonce has been issued and the timeout window is open.

### UNLOCKED
The lock output is active for a short fixed duration.

### DENIED
A failed attempt has occurred. The system may briefly indicate failure before returning to LOCKED_IDLE.

### LOCKOUT
The system temporarily ignores local attempts due to repeated failures.

### SYSTEM_FAULT
Optional state used if configuration or integrity checks fail at startup.

## 12. Priority Rules and Edge Cases

### 12.1 Concurrent Inputs

If a valid local passkey is accepted while an admin request is pending:

- local success takes priority
- the pending admin nonce is invalidated
- the system transitions to UNLOCKED once

This avoids stale approvals causing a second unintended unlock.

### 12.2 Stale Admin Approval

If an admin response arrives after the timeout window:

- the NUCLEO rejects it
- the nonce is cleared
- the system returns to LOCKED_IDLE

### 12.3 Host Disconnect

If the broker disconnects or serial communication fails:

- the NUCLEO remains or returns to LOCKED
- pending admin requests are cancelled
- the system records a communication error if logging is available

### 12.4 Reboot Behavior

On reset or power-up:

- the lock state must initialize to LOCKED
- failure counters may either reset or be restored depending on implementation scope
- all pending sessions must be cleared

## 13. Communication Design

The host and NUCLEO communicate over USB virtual serial.

### Recommended transport choices

- 115200 baud UART over ST-LINK virtual COM port
- framed binary or structured text messages
- checksum on every packet

### Recommended message types

- PASS_TRY
- PASS_RESULT
- REQUEST_ADMIN
- NONCE_ISSUED
- ADMIN_APPROVE
- ADMIN_DENY
- STATUS_UPDATE
- ERROR
- LOCKOUT

A packet-based approach is preferred over ad hoc strings because it scales better, improves parsing reliability, and supports cleaner debugging.

## 14. Middleware Design

The middleware broker exists because only one process should own the physical serial port.

### Broker responsibilities

- open the serial port once and keep it open
- forward visitor requests to the NUCLEO
- forward admin actions to the NUCLEO
- relay NUCLEO status changes to all connected GUIs
- maintain event logs
- isolate GUI failures from the device connection

### Suggested implementation technologies

- Python 3.x
- pyserial
- asyncio or threading
- Tkinter, CustomTkinter, PySide6, or PyQt for GUIs
- optional local socket or WebSocket layer for inter-process communication
- optional SQLite for local audit storage

## 15. Hardware and Software Components

### Hardware

- STM32 NUCLEO-G474RE
- user LED or external LED to indicate lock state
- optional relay module or lock simulation output
- one local button for request/doorbell behavior
- host PC connected by USB

### Software

- STM32 firmware in C using STM32CubeIDE or equivalent
- Python middleware broker
- Visitor GUI
- Admin GUI
- optional log viewer or audit file output

## 16. Limitations Addressed in the Current Solution

These are the limitations that the proposed design actively addresses.

### Limitation 1: No user-friendly secure interface in a basic embedded-only system

#### Risk
A simple board-only setup is difficult to use and hard to demonstrate clearly. It also limits the realism of the secure access workflow.

#### Approach used in this solution
A host-side GUI is introduced for visitor passkey entry and administrator monitoring. The NUCLEO remains responsible for trusted execution, while the PC provides an understandable and professional interface.

#### Result
The project becomes easier to use, more demonstrable, and more relevant to software engineering and embedded-system integration roles.

### Limitation 2: Serial contention when multiple interfaces try to reach one device

#### Risk
Two GUI applications cannot safely open the same serial port at the same time. This would cause communication failures or unstable behavior.

#### Approach used in this solution
A Python middleware broker owns the serial port and acts as the only communication bridge to the NUCLEO. Both GUIs communicate with the broker instead of opening the device directly.

#### Result
The architecture supports multiple software interfaces without breaking the hardware connection.

### Limitation 3: Replay risk for remote admin approval

#### Risk
If admin approval is sent as a simple static command such as OPEN, an attacker could capture the message and replay it later.

#### Approach used in this solution
Remote approval is bound to a one-time nonce generated by the NUCLEO. The admin response is only valid for that specific nonce and only within a short timeout period.

#### Result
Previously captured approval messages cannot be reused directly for later entry.

### Limitation 4: Brute-force attempts against a simple passkey system

#### Risk
A basic keypad design allows repeated guessing attempts.

#### Approach used in this solution
The NUCLEO tracks failed attempts and enters a temporary lockout state after repeated failures.

#### Result
The system becomes more resistant to basic brute-force behaviour.

### Limitation 5: Blocking firmware that misses concurrent events

#### Risk
If the firmware uses blocking delays, the device may become unresponsive while waiting for timeouts or remote input.

#### Approach used in this solution
The firmware is designed around a non-blocking finite state machine with interrupt-driven or event-driven input handling.

#### Result
The system remains responsive while handling local entry, remote approval, and timeout logic.

## 17. Future Limitations and Future Work

These are limitations acknowledged but intentionally left for future development.

### Future Limitation 1: Local passkey path is not fully challenge-response protected

#### Risk
If the local GUI path is compromised, passkey attempts may still be exposed depending on implementation details.

#### Future approach
Move to a stronger local authentication design such as challenge-response, a direct physical keypad, or a secure element-backed credential flow.

### Future Limitation 2: Secret provisioning and long-term key management are simplified

#### Risk
Managing secrets securely becomes difficult as the number of devices or administrators grows.

#### Future approach
Use protected flash, OTP, or a more formal key-management mechanism. For larger deployments, move toward asymmetric signatures and per-device identities.

### Future Limitation 3: Single-door architecture does not scale well

#### Risk
The design is suitable for one access point but does not yet address a building-wide deployment.

#### Future approach
Add a multi-device broker, central policy service, per-door identities, and a scalable audit architecture.

### Future Limitation 4: There is no cloud-based central audit service in the current version

#### Risk
The current implementation stores logs locally. This improves reliability and keeps the prototype simple, but it means there is no centralized dashboard, remote analytics, or automatic cross-site audit aggregation.

#### Future approach
Add a cloud synchronization layer that uploads logs from the broker to a managed database or API. The cloud layer should remain secondary so that loss of internet connectivity does not prevent local access control from functioning.

## 18. Implementation Approach

### Firmware

- C on STM32CubeIDE
- UART receive handling with interrupts or DMA
- finite state machine for access logic
- GPIO control for LED or relay
- hardware RNG if used for nonce generation

### Middleware

- Python broker using pyserial
- structured message parsing
- event forwarding to GUIs
- logging to file or SQLite

### GUIs

- Visitor keypad screen
- Admin dashboard for approval and denial
- live status display and recent events

## 19. Testing Strategy

### Functional tests

- correct passkey unlocks the system
- incorrect passkey denies access
- three failed attempts trigger lockout
- admin request creates pending state
- valid admin approval unlocks
- admin deny returns to locked state

### Security-oriented tests

- replay a previous admin approval and confirm rejection
- send malformed serial packets and confirm parser recovery
- test timeout expiry for pending admin requests
- test power reset and confirm fail-secure locked state

### Robustness tests

- disconnect and reconnect the broker
- send simultaneous visitor and admin actions
- verify that only one unlock action occurs per successful event

## 20. Demo Plan

A short demonstration can show:

- system booting into LOCKED state
- visitor entering wrong passkey and receiving denial
- repeated failures causing lockout
- visitor requesting admin assistance
- admin receiving request and approving it
- NUCLEO unlocking briefly and returning to locked state
- log output showing the complete event sequence

## 21. Conclusion

The Secure Multi-Track Access system is a realistic secure access prototype built on the STM32 NUCLEO-G474RE. It improves on a minimal embedded door-control model by combining embedded state management, multiple software interfaces, message validation, replay-resistant remote approval, and clear extensibility. The current implementation remains fully local, while cloud-based audit aggregation is reserved for future work. The design is strong for an academic embedded computing assessment because it demonstrates not only functionality, but also architectural reasoning, security awareness, and reflection on present and future limitations.
