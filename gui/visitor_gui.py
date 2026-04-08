"""
visitor_gui.py — FAC Visitor keypad interface.

Connects to the broker via WebSocket and provides:
  - Numeric keypad for passkey entry
  - Masked passkey display
  - Clear / Submit buttons
  - Call Admin button
  - Real-time status display

Usage:
  python visitor_gui.py
  python visitor_gui.py --ws ws://localhost:8765
"""

import argparse
import asyncio
import json
import threading

import customtkinter as ctk
import websockets

# ── Appearance ───────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

STATUS_COLORS = {
    "LOCKED_IDLE":   ("#2b2b2b", "#aaaaaa"),   # bg, fg
    "VALIDATING":    ("#2b2b2b", "#ffa500"),
    "UNLOCKED":      ("#1a4d1a", "#00ff00"),
    "DENIED":        ("#4d1a1a", "#ff4444"),
    "LOCKOUT":       ("#4d3a1a", "#ff8800"),
    "PENDING_ADMIN": ("#1a2d4d", "#44aaff"),
    "SYSTEM_FAULT":  ("#4d1a1a", "#ff0000"),
}

STATUS_TEXT = {
    "LOCKED_IDLE":   "LOCKED",
    "VALIDATING":    "VALIDATING...",
    "UNLOCKED":      "ACCESS GRANTED",
    "DENIED":        "ACCESS DENIED",
    "LOCKOUT":       "LOCKOUT",
    "PENDING_ADMIN": "PENDING ADMIN",
    "SYSTEM_FAULT":  "SYSTEM FAULT",
}


class VisitorGUI(ctk.CTk):
    def __init__(self, ws_url: str):
        super().__init__()
        self.ws_url = ws_url
        self.ws = None
        self.passkey = ""
        self.connected = False

        self.title("FAC - Visitor Access")
        self.geometry("380x620")
        self.resizable(False, False)

        self._build_ui()
        self._start_ws_thread()

    # ── UI Layout ────────────────────────────────────────────────────────

    def _build_ui(self):
        # Connection indicator
        self.conn_label = ctk.CTkLabel(self, text="Disconnected",
                                       text_color="#ff4444", font=("", 12))
        self.conn_label.pack(pady=(8, 0))

        # Title
        ctk.CTkLabel(self, text="Visitor Access", font=("", 22, "bold")).pack(pady=(4, 8))

        # Status display
        self.status_frame = ctk.CTkFrame(self, height=60, corner_radius=10)
        self.status_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.status_frame.pack_propagate(False)
        self.status_label = ctk.CTkLabel(self.status_frame, text="LOCKED",
                                         font=("", 24, "bold"), text_color="#aaaaaa")
        self.status_label.pack(expand=True)

        # Passkey display
        self.pass_display = ctk.CTkLabel(self, text="", font=("Consolas", 32),
                                         height=50)
        self.pass_display.pack(pady=(0, 10))

        # Keypad grid
        keypad_frame = ctk.CTkFrame(self, fg_color="transparent")
        keypad_frame.pack(padx=20)

        buttons = [
            ["1", "2", "3"],
            ["4", "5", "6"],
            ["7", "8", "9"],
            ["CLR", "0", "ENT"],
        ]
        for row_idx, row in enumerate(buttons):
            for col_idx, label in enumerate(row):
                if label == "CLR":
                    btn = ctk.CTkButton(keypad_frame, text=label, width=90, height=60,
                                        font=("", 18, "bold"), fg_color="#8B0000",
                                        hover_color="#a00000",
                                        command=self._on_clear)
                elif label == "ENT":
                    btn = ctk.CTkButton(keypad_frame, text=label, width=90, height=60,
                                        font=("", 18, "bold"), fg_color="#006400",
                                        hover_color="#008000",
                                        command=self._on_submit)
                else:
                    digit = label
                    btn = ctk.CTkButton(keypad_frame, text=label, width=90, height=60,
                                        font=("", 20),
                                        command=lambda d=digit: self._on_digit(d))
                btn.grid(row=row_idx, column=col_idx, padx=4, pady=4)

        # Call Admin button
        self.admin_btn = ctk.CTkButton(self, text="Call Admin", width=280, height=45,
                                       font=("", 16, "bold"), fg_color="#1a5276",
                                       hover_color="#1f6fa0",
                                       command=self._on_call_admin)
        self.admin_btn.pack(pady=(15, 10))

        # Lockout countdown
        self.lockout_label = ctk.CTkLabel(self, text="", font=("", 14),
                                          text_color="#ff8800")
        self.lockout_label.pack()

    # ── Keypad actions ───────────────────────────────────────────────────

    def _on_digit(self, d: str):
        if len(self.passkey) < 6:
            self.passkey += d
            self.pass_display.configure(text="*" * len(self.passkey))

    def _on_clear(self):
        self.passkey = ""
        self.pass_display.configure(text="")

    def _on_submit(self):
        if not self.passkey:
            return
        self._ws_send({"type": "pass_try", "passkey": self.passkey})
        self.passkey = ""
        self.pass_display.configure(text="")

    def _on_call_admin(self):
        self._ws_send({"type": "request_admin"})

    # ── Status updates ───────────────────────────────────────────────────

    def _update_status(self, state: str, extra: str = ""):
        text = STATUS_TEXT.get(state, state)
        if extra:
            text += f"\n{extra}"
        bg, fg = STATUS_COLORS.get(state, ("#2b2b2b", "#aaaaaa"))
        self.status_frame.configure(fg_color=bg)
        self.status_label.configure(text=text, text_color=fg)

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

        if ev == "state_snapshot" or ev == "state_update":
            state = event.get("state", "LOCKED_IDLE")
            self._update_status(state)
            if state != "LOCKOUT":
                self.lockout_label.configure(text="")

        elif ev == "pass_result":
            result = event.get("result", "")
            if result == "GRANTED":
                self._update_status("UNLOCKED")
            elif result == "LOCKOUT_ACTIVE":
                self._update_status("LOCKOUT")
            else:
                self._update_status("DENIED")

        elif ev == "lockout_notice":
            secs = event.get("remaining_seconds", 0)
            self._update_status("LOCKOUT", f"{secs}s remaining")
            self.lockout_label.configure(text=f"Retry in {secs}s")

        elif ev == "nonce_issued":
            self._update_status("PENDING_ADMIN", "Waiting for admin...")

        elif ev == "error":
            err = event.get("error", "Unknown error")
            self.lockout_label.configure(text=f"Error: {err}")

        elif ev == "serial_status":
            if not event.get("connected"):
                self._update_status("LOCKED_IDLE", "Board disconnected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FAC Visitor GUI")
    parser.add_argument("--ws", default="ws://localhost:8765",
                        help="Broker WebSocket URL")
    args = parser.parse_args()

    app = VisitorGUI(args.ws)
    app.mainloop()
