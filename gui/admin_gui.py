"""
admin_gui.py — FAC Administrator dashboard.

Connects to the broker via WebSocket and provides:
  - Current lock state display
  - Pending admin request panel with Approve / Deny
  - Nonce timeout countdown
  - Scrollable event log
  - Serial connection status

Usage:
  python admin_gui.py
  python admin_gui.py --ws ws://localhost:8765 --secret myAdminSecret
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import threading
from datetime import datetime

import customtkinter as ctk
import websockets

# ── Appearance ───────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

NONCE_TIMEOUT_S = 30

STATE_COLORS = {
    "LOCKED_IDLE":   "#aaaaaa",
    "VALIDATING":    "#ffa500",
    "UNLOCKED":      "#00ff00",
    "DENIED":        "#ff4444",
    "LOCKOUT":       "#ff8800",
    "PENDING_ADMIN": "#44aaff",
    "SYSTEM_FAULT":  "#ff0000",
}


class AdminGUI(ctk.CTk):
    def __init__(self, ws_url: str, admin_secret: str):
        super().__init__()
        self.ws_url = ws_url
        self.admin_secret = admin_secret.encode("utf-8")
        self.ws = None
        self.connected = False
        self.pending_nonce: bytes | None = None
        self.pending_req_id: int | None = None
        self.nonce_timer_id = None
        self.nonce_countdown = 0

        self.title("FAC - Admin Dashboard")
        self.geometry("520x680")
        self.resizable(False, False)

        self._build_ui()
        self._start_ws_thread()

    # ── UI Layout ────────────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar: connection + state
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=15, pady=(10, 5))

        self.conn_label = ctk.CTkLabel(top, text="Disconnected",
                                       text_color="#ff4444", font=("", 12))
        self.conn_label.pack(side="left")

        self.state_label = ctk.CTkLabel(top, text="LOCKED_IDLE",
                                        text_color="#aaaaaa",
                                        font=("", 16, "bold"))
        self.state_label.pack(side="right")

        ctk.CTkLabel(top, text="State:", font=("", 14)).pack(side="right", padx=(0, 6))

        # Title
        ctk.CTkLabel(self, text="Admin Dashboard", font=("", 22, "bold")).pack(pady=(0, 8))

        # Pending request panel
        self.req_frame = ctk.CTkFrame(self, corner_radius=10)
        self.req_frame.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(self.req_frame, text="Pending Request",
                     font=("", 16, "bold")).pack(pady=(8, 4))

        self.nonce_label = ctk.CTkLabel(self.req_frame, text="No pending request",
                                        font=("Consolas", 12), text_color="#888888")
        self.nonce_label.pack(padx=10, pady=(0, 4))

        self.countdown_label = ctk.CTkLabel(self.req_frame, text="",
                                            font=("", 14, "bold"), text_color="#ffa500")
        self.countdown_label.pack()

        btn_frame = ctk.CTkFrame(self.req_frame, fg_color="transparent")
        btn_frame.pack(pady=(4, 10))

        self.approve_btn = ctk.CTkButton(btn_frame, text="Approve", width=140, height=40,
                                         font=("", 15, "bold"), fg_color="#006400",
                                         hover_color="#008000", state="disabled",
                                         command=self._on_approve)
        self.approve_btn.pack(side="left", padx=8)

        self.deny_btn = ctk.CTkButton(btn_frame, text="Deny", width=140, height=40,
                                      font=("", 15, "bold"), fg_color="#8B0000",
                                      hover_color="#a00000", state="disabled",
                                      command=self._on_deny)
        self.deny_btn.pack(side="left", padx=8)

        # Event log
        ctk.CTkLabel(self, text="Event Log", font=("", 16, "bold")).pack(
            anchor="w", padx=15, pady=(5, 2))

        self.log_box = ctk.CTkTextbox(self, height=300, font=("Consolas", 11),
                                      state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    # ── Actions ──────────────────────────────────────────────────────────

    def _on_approve(self):
        if self.pending_nonce is None:
            return
        # Compute HMAC-SHA256(secret, nonce || 0x01)
        token = hmac.new(self.admin_secret,
                         self.pending_nonce + b'\x01',
                         hashlib.sha256).digest()
        self._ws_send({"type": "admin_approve", "token_hex": token.hex()})
        self._clear_pending()
        self._log_event("ADMIN", "Approve sent")

    def _on_deny(self):
        self._ws_send({"type": "admin_deny"})
        self._clear_pending()
        self._log_event("ADMIN", "Deny sent")

    def _clear_pending(self):
        self.pending_nonce = None
        self.pending_req_id = None
        self.nonce_label.configure(text="No pending request", text_color="#888888")
        self.countdown_label.configure(text="")
        self.approve_btn.configure(state="disabled")
        self.deny_btn.configure(state="disabled")
        if self.nonce_timer_id:
            self.after_cancel(self.nonce_timer_id)
            self.nonce_timer_id = None

    def _set_pending(self, nonce_hex: str, req_id: int):
        self.pending_nonce = bytes.fromhex(nonce_hex)
        self.pending_req_id = req_id
        self.nonce_label.configure(
            text=f"Nonce: {nonce_hex[:16]}...\nRequest ID: {req_id}",
            text_color="#44aaff")
        self.approve_btn.configure(state="normal")
        self.deny_btn.configure(state="normal")
        self.nonce_countdown = NONCE_TIMEOUT_S
        self._tick_countdown()

    def _tick_countdown(self):
        if self.nonce_countdown <= 0:
            self.countdown_label.configure(text="EXPIRED", text_color="#ff4444")
            self._clear_pending()
            self._log_event("SYSTEM", "Admin nonce expired")
            return
        self.countdown_label.configure(
            text=f"Expires in {self.nonce_countdown}s",
            text_color="#ffa500" if self.nonce_countdown > 10 else "#ff4444")
        self.nonce_countdown -= 1
        self.nonce_timer_id = self.after(1000, self._tick_countdown)

    # ── Event log ────────────────────────────────────────────────────────

    def _log_event(self, category: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{category}] {message}\n"
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # ── Status updates ───────────────────────────────────────────────────

    def _update_state(self, state: str):
        color = STATE_COLORS.get(state, "#aaaaaa")
        self.state_label.configure(text=state, text_color=color)

    def _update_connection(self, connected: bool):
        self.connected = connected
        if connected:
            self.conn_label.configure(text="Connected", text_color="#00cc00")
        else:
            self.conn_label.configure(text="Disconnected", text_color="#ff4444")

    # ── WebSocket ────────────────────────────────────────────────────────

    def _ws_send(self, msg: dict):
        if self._ws_loop and self.ws:
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps(msg)), self._ws_loop)

    def _start_ws_thread(self):
        self._ws_loop = None
        t = threading.Thread(target=self._ws_thread, daemon=True)
        t.start()

    def _ws_thread(self):
        self._ws_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._ws_loop)
        self._ws_loop.run_until_complete(self._ws_connect_loop())

    async def _ws_connect_loop(self):
        while True:
            try:
                async with websockets.connect(self.ws_url) as ws:
                    self.ws = ws
                    self.after(0, self._update_connection, True)
                    async for raw in ws:
                        event = json.loads(raw)
                        self.after(0, self._handle_event, event)
            except (websockets.ConnectionClosed, ConnectionRefusedError, OSError):
                pass
            self.ws = None
            self.after(0, self._update_connection, False)
            await asyncio.sleep(2)

    def _handle_event(self, event: dict):
        ev = event.get("event")

        if ev == "state_snapshot":
            self._update_state(event.get("state", "LOCKED_IDLE"))
            self._log_event("SYSTEM", f"Connected. State: {event.get('state')}")
            if event.get("pending_nonce_hex"):
                self._set_pending(event["pending_nonce_hex"],
                                  event.get("pending_request_id", 0))

        elif ev == "state_update":
            state = event.get("state", "")
            self._update_state(state)
            self._log_event("STATE", state)
            # If state left PENDING_ADMIN without our action, clear pending
            if state != "PENDING_ADMIN" and self.pending_nonce:
                self._clear_pending()

        elif ev == "pass_result":
            result = event.get("result", "")
            req = event.get("request_id", "?")
            self._log_event("ACCESS", f"PASS_RESULT: {result} (req={req})")

        elif ev == "nonce_issued":
            nonce_hex = event.get("nonce_hex", "")
            req_id = event.get("request_id", 0)
            self._set_pending(nonce_hex, req_id)
            self._log_event("REQUEST", f"Admin request received (nonce: {nonce_hex[:16]}...)")

        elif ev == "lockout_notice":
            secs = event.get("remaining_seconds", 0)
            self._log_event("LOCKOUT", f"Lockout active: {secs}s remaining")

        elif ev == "error":
            err = event.get("error", "unknown")
            self._log_event("ERROR", err)

        elif ev == "serial_status":
            conn = event.get("connected", False)
            self._log_event("SERIAL", "Connected" if conn else "Disconnected")

        elif ev == "pong":
            pass  # silent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FAC Admin GUI")
    parser.add_argument("--ws", default="ws://localhost:8765",
                        help="Broker WebSocket URL")
    parser.add_argument("--secret", default="FAC_ADMIN_SECRET_2026",
                        help="Admin HMAC secret for approval tokens")
    args = parser.parse_args()

    app = AdminGUI(args.ws, args.secret)
    app.mainloop()
