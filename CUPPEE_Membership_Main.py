import tkinter as tk
from tkinter import ttk, messagebox
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import os
import math
import traceback
from datetime import datetime, timedelta
import random

# ============================================================
# Shared Crypto + NTAG 424 DNA Class
# ============================================================

class NTAG424Crypto:
    def __init__(self):
        self.session_key_enc = None
        self.session_key_mac = None
        self.ti = None
        self.cmd_counter = 0

    @staticmethod
    def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = b'\x00'*16) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)

    @staticmethod
    def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = b'\x00'*16) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    @staticmethod
    def cmac(key: bytes, data: bytes) -> bytes:
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()

    def derive_session_keys(self, key: bytes, rnd_a: bytes, rnd_b: bytes):
        sv1 = b'\xA5\x5A\x00\x01\x00\x00' + rnd_a[:6] + rnd_b[-6:] + rnd_a[-6:] + rnd_b[:6]
        sv2 = b'\x5A\xA5\x00\x01\x00\x00' + rnd_a[:6] + rnd_b[-6:] + rnd_a[-6:] + rnd_b[:6]
        self.session_key_enc = self.cmac(key, sv1)[:16]
        self.session_key_mac = self.cmac(key, sv2)[:16]
        self.cmd_counter = 0

    def calculate_mac(self, data: bytes) -> bytes:
        """8-byte truncated MAC (even bytes)"""
        full_mac = self.cmac(self.session_key_mac, data)
        return bytes([full_mac[i] for i in range(0, 16, 2)])


class CUPPEENFC:
    APP_DF = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]

    def __init__(self):
        self.connection = None
        self.reader_name = None
        self.crypto = NTAG424Crypto()
        self.authenticated = False

    def list_readers(self):
        return readers()

    def connect(self, reader_index=0):
        r = readers()
        if not r:
            raise Exception("No NFC reader found. Check RF-IC02DQ connection.")
        self.reader_name = str(r[reader_index])
        self.connection = r[reader_index].createConnection()
        self.connection.connect()
        self.authenticated = False
        return self.reader_name

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except:
                pass
            self.connection = None
            self.authenticated = False

    def transmit(self, apdu):
        data, sw1, sw2 = self.connection.transmit(apdu)
        return data, sw1, sw2

    def select_application(self):
        apdu = [0x00, 0xA4, 0x04, 0x00, len(self.APP_DF)] + self.APP_DF + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 not in (0x90, 0x91):
            raise Exception(f"Select Application failed: {sw1:02X}{sw2:02X}")
        return data

    def get_version(self):
        data, sw1, sw2 = self.transmit([0x90, 0x60, 0x00, 0x00, 0x00])
        version = data[:]
        while sw2 == 0xAF:
            data, sw1, sw2 = self.transmit([0x90, 0xAF, 0x00, 0x00, 0x00])
            version.extend(data)
        return version

    def get_uid(self):
        try:
            version = self.get_version()
            if len(version) >= 14:
                return toHexString(version[7:14])
        except:
            pass
        data, sw1, sw2 = self.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if sw1 == 0x90:
            return toHexString(data)
        return "Unknown"

    def authenticate_ev2_first(self, key_no: int = 0, key: bytes = b'\x00' * 16):
        # Part 1
        apdu = [0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 != 0x91 or sw2 != 0xAF:
            raise Exception(f"Auth Part1 failed: {sw1:02X}{sw2:02X}")

        encrypted_rnd_b = bytes(data)
        rnd_b = self.crypto.aes_cbc_decrypt(key, encrypted_rnd_b)
        rnd_a = os.urandom(16)
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]
        encrypted = self.crypto.aes_cbc_encrypt(key, rnd_a + rnd_b_rot)

        # Part 2
        apdu = [0x90, 0xAF, 0x00, 0x00, 0x20] + list(encrypted) + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 != 0x91 or sw2 != 0x00:
            raise Exception(f"Auth Part2 failed: {sw1:02X}{sw2:02X}")

        decrypted = self.crypto.aes_cbc_decrypt(key, bytes(data[:16]))
        expected = rnd_a[1:] + rnd_a[:1]
        if decrypted != expected:
            raise Exception("RndA verification failed")

        self.crypto.derive_session_keys(key, rnd_a, rnd_b)
        self.authenticated = True
        return True

    def read_data(self, file_no=0x02, offset=0, length=80):
        offset_b = list(offset.to_bytes(3, 'big'))
        length_b = list(length.to_bytes(3, 'big'))
        apdu = [0x90, 0xBD, 0x00, 0x00, 0x07, file_no] + offset_b + length_b + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x91 and sw2 == 0x00:
            return bytes(data)
        raise Exception(f"Read failed: {sw1:02X}{sw2:02X}")

    def write_data(self, data: bytes, file_no=0x02, offset=0):
        """
        Authenticated Write (MAC mode)
        Requires successful AuthenticateEV2First first.
        """
        if not self.authenticated:
            raise Exception("Not authenticated. Call authenticate_ev2_first() first.")

        if len(data) > 200:
            raise Exception("Data too long for single write (max ~200 bytes recommended)")

        offset_b = list(offset.to_bytes(3, 'big'))
        length_b = list(len(data).to_bytes(3, 'big'))

        cmd_header = bytes([0x90, 0x8D, 0x00, 0x00])
        lc = 1 + 3 + 3 + len(data) + 8   # file + offset + length + data + MAC
        cmd_data = bytes([file_no]) + bytes(offset_b) + bytes(length_b) + data

        counter_bytes = self.crypto.cmd_counter.to_bytes(2, 'little')
        mac_input = counter_bytes + cmd_header + bytes([lc]) + cmd_data
        mac = self.crypto.calculate_mac(mac_input)

        apdu = list(cmd_header) + [lc] + list(cmd_data) + list(mac) + [0x00]
        resp, sw1, sw2 = self.transmit(apdu)

        if sw1 == 0x91 and sw2 == 0x00:
            self.crypto.cmd_counter += 1
            return True
        raise Exception(f"Write failed: {sw1:02X}{sw2:02X}")


# ============================================================
# Apple-style UI helpers
# ============================================================

def pick_font(*candidates):
    """Return the first installed family from candidates."""
    root = tk._default_root
    available = set(root.tk.call("font", "families")) if root else set()
    for name in candidates:
        if name in available:
            return name
    return "Segoe UI"


def rounded_rect(canvas, x1, y1, x2, y2, radius=18, steps=16, **kwargs):
    """Draw a complete rounded rectangle as one polygon; returns [id]."""
    r = min(float(radius), abs(x2 - x1) / 2.0, abs(y2 - y1) / 2.0)
    fill = kwargs.get("fill", "")
    outline = kwargs.get("outline", fill)
    width = kwargs.get("width", 0)

    # Clockwise corners (canvas y grows downward)
    corners = (
        (x1 + r, y1 + r, 180, 270),  # top-left
        (x2 - r, y1 + r, 270, 360),  # top-right
        (x2 - r, y2 - r, 0, 90),     # bottom-right
        (x1 + r, y2 - r, 90, 180),   # bottom-left
    )
    points = []
    for cx, cy, a0, a1 in corners:
        for i in range(steps + 1):
            ang = math.radians(a0 + (a1 - a0) * i / steps)
            points.append(cx + r * math.cos(ang))
            points.append(cy + r * math.sin(ang))

    item = canvas.create_polygon(
        points, smooth=False, splinesteps=1,
        fill=fill, outline=outline if width else fill, width=max(width, 0)
    )
    return [item]


def recolor_shape(canvas, ids, color):
    for item in ids:
        canvas.itemconfig(item, fill=color, outline=color)


class GlassPanel(tk.Canvas):
    """Frosted glass panel with rounded corners; grows with content."""

    def __init__(self, parent, width, height=120, radius=22, fill="#FFFFFF",
                 outline="#FFFFFF", bg="#E8EEF6", pad_x=28, pad_y=20, **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg,
                         highlightthickness=0, bd=0, **kwargs)
        self._panel_w = width
        self._radius = radius
        self._fill = fill
        self._outline = outline
        self._pad_x = pad_x
        self._pad_y = pad_y
        self._shape_ids = []
        self.inner = tk.Frame(self, bg=fill)
        self._window = self.create_window(
            width // 2, height // 2, window=self.inner, width=width - pad_x
        )
        self.inner.bind("<Configure>", self._on_inner_configure)
        self._redraw(height)

    def _redraw(self, height):
        for item in self._shape_ids:
            self.delete(item)
        self._shape_ids = rounded_rect(
            self, 2, 2, self._panel_w - 2, height - 2,
            radius=self._radius, fill=self._fill, outline=self._outline, width=1
        )
        self.configure(height=height)
        self.coords(self._window, self._panel_w // 2, height // 2)
        self.itemconfig(self._window, width=self._panel_w - self._pad_x)
        self.tag_raise(self._window)

    def _on_inner_configure(self, event=None):
        self.update_idletasks()
        needed = self.inner.winfo_reqheight() + self._pad_y
        needed = max(needed, 100)
        if abs(needed - int(self.cget("height"))) > 2:
            self._redraw(needed)

    def fit(self):
        """Force a resize pass after content updates."""
        self._on_inner_configure()


class PillButton(tk.Canvas):
    """Rounded pill button with hover feedback."""

    def __init__(self, parent, text, command, width=260, height=48,
                 bg_fill="#007AFF", fg="#FFFFFF", font=None,
                 hover="#0066D6", disabled_fill="#A8C7F0", canvas_bg="#E8EEF6"):
        super().__init__(parent, width=width, height=height, bg=canvas_bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self._command = command
        self._bg_fill = bg_fill
        self._hover = hover
        self._disabled_fill = disabled_fill
        self._enabled = True
        self._shape = rounded_rect(self, 1, 1, width - 1, height - 1,
                                   radius=height // 2, fill=bg_fill, outline=bg_fill)
        self._label = self.create_text(width // 2, height // 2, text=text,
                                       fill=fg, font=font)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.tag_bind(self._label, "<Button-1>", self._on_click)
        for item in self._shape:
            self.tag_bind(item, "<Button-1>", self._on_click)

    def _on_enter(self, _=None):
        if self._enabled:
            recolor_shape(self, self._shape, self._hover)

    def _on_leave(self, _=None):
        if self._enabled:
            recolor_shape(self, self._shape, self._bg_fill)

    def _on_click(self, _=None):
        if self._enabled and self._command:
            self._command()

    def set_enabled(self, enabled, text=None):
        self._enabled = enabled
        if text is not None:
            self.itemconfig(self._label, text=text)
        recolor_shape(self, self._shape, self._bg_fill if enabled else self._disabled_fill)
        self.configure(cursor="hand2" if enabled else "arrow")


class SoftButton(tk.Canvas):
    """Secondary translucent rounded button."""

    def __init__(self, parent, text, command, width=120, height=36,
                 bg_fill="#FFFFFF", fg="#1D1D1F", font=None, canvas_bg="#E8EEF6"):
        super().__init__(parent, width=width, height=height, bg=canvas_bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        shape = rounded_rect(self, 1, 1, width - 1, height - 1,
                             radius=height // 2, fill=bg_fill, outline="#C9AE9A", width=1)
        label = self.create_text(width // 2, height // 2, text=text, fill=fg, font=font)

        def click(_=None):
            if command:
                command()

        self.bind("<Button-1>", click)
        self.tag_bind(label, "<Button-1>", click)
        for item in shape:
            self.tag_bind(item, "<Button-1>", click)


# ============================================================
# Combined Application with Tabs
# ============================================================

class CUPPEEApp:
    WIN_W = 540
    WIN_H = 860

    def __init__(self, root):
        self.root = root
        self.root.title("CUPPEE Membership System")
        self.root.geometry(f"{self.WIN_W}x{self.WIN_H}")
        self.root.resizable(False, False)

        # Soft translucent Apple window feel
        try:
            self.root.attributes("-alpha", 0.97)
        except tk.TclError:
            pass

        self.nfc = CUPPEENFC()
        self.card_key = b'\x00' * 16          # ← Change to your real AES-128 key

        # Warm Apple-style palette (no background image)
        self.bg = "#F3EBE4"
        self.bg_deep = "#E5D5C8"
        self.glass = "#FAF6F2"
        self.glass_edge = "#FFFFFF"
        self.accent = "#A06C4A"
        self.accent_hover = "#845739"
        self.segment_color = "#D9C5B7"
        self.valid_color = "#34C759"
        self.expired_color = "#FF9F0A"
        self.error_color = "#FF3B30"
        self.text_dark = "#1D1D1F"
        self.text_secondary = "#3A3A3C"
        self.text_light = "#6E6E73"
        self.field_bg = "#FFFFFF"
        self.idle_glow = "#C9AE9A"
        self.scan_glow = "#FFD60A"
        self.orb_ring = "#F5EDE6"

        self.root.configure(bg=self.bg)

        self.font_display = pick_font("SF Pro Display", "Segoe UI Variable Display",
                                      "Bahnschrift", "Segoe UI")
        self.font_text = pick_font("SF Pro Text", "Segoe UI Variable Text",
                                   "Bahnschrift", "Segoe UI")

        self.active_tab = "check"
        self.create_ui()
        self.check_reader()

    def create_ui(self):
        self.shell = tk.Frame(self.root, bg=self.bg)
        self.shell.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Header
        header = tk.Frame(self.shell, bg=self.bg)
        header.pack(fill="x", pady=(28, 8))
        tk.Label(header, text="CUPPEE",
                 font=(self.font_display, 28, "bold"),
                 fg=self.text_dark, bg=self.bg).pack()
        tk.Label(header, text="Membership",
                 font=(self.font_text, 13),
                 fg=self.text_light, bg=self.bg).pack(pady=(2, 0))

        # Apple-style segmented control (inset so corners are not clipped)
        self.segment_host = tk.Frame(self.shell, bg=self.bg)
        self.segment_host.pack(pady=(14, 6))
        self.segment = tk.Canvas(self.segment_host, width=360, height=46,
                                 bg=self.bg, highlightthickness=0)
        self.segment.pack()
        rounded_rect(self.segment, 1, 1, 359, 45, radius=14,
                     fill=self.segment_color, outline=self.segment_color)
        self.seg_thumb_ids = []
        self.seg_check = self.segment.create_text(
            90, 23, text="Check", fill=self.text_dark,
            font=(self.font_text, 13, "bold"))
        self.seg_admin = self.segment.create_text(
            270, 23, text="Admin", fill=self.text_light,
            font=(self.font_text, 12))
        self._draw_seg_thumb(0)
        self.segment.bind("<Button-1>", self._on_segment_click)

        # Content pages
        self.content = tk.Frame(self.shell, bg=self.bg)
        self.content.pack(fill="both", expand=True, padx=28, pady=(10, 0))

        self.tab_check = tk.Frame(self.content, bg=self.bg)
        self.tab_admin = tk.Frame(self.content, bg=self.bg)
        self.build_check_tab()
        self.build_admin_tab()
        self.show_tab("check")

        tk.Label(self.shell,
                 text="CUPPEE  ·  NTAG 424 DNA  ·  Authenticated",
                 font=(self.font_text, 10), fg=self.text_light, bg=self.bg
                 ).pack(side="bottom", pady=14)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Glass.TCombobox",
                        fieldbackground=self.field_bg,
                        background=self.field_bg,
                        foreground=self.text_dark,
                        arrowcolor=self.text_light,
                        bordercolor=self.segment_color,
                        lightcolor=self.field_bg,
                        darkcolor=self.field_bg,
                        padding=6)
        style.map("Glass.TCombobox",
                  fieldbackground=[("readonly", self.field_bg)],
                  foreground=[("readonly", self.text_dark)])

    def _draw_seg_thumb(self, index):
        for item in self.seg_thumb_ids:
            self.segment.delete(item)
        x1 = 4 if index == 0 else 182
        x2 = 178 if index == 0 else 356
        self.seg_thumb_ids = rounded_rect(
            self.segment, x1, 4, x2, 42, radius=11,
            fill=self.glass_edge, outline=self.glass_edge)
        # Keep labels above thumb
        self.segment.tag_raise(self.seg_check)
        self.segment.tag_raise(self.seg_admin)

    def _on_segment_click(self, event):
        self.show_tab("check" if event.x < 180 else "admin")

    def show_tab(self, name):
        self.active_tab = name
        self.tab_check.pack_forget()
        self.tab_admin.pack_forget()
        if name == "check":
            self._draw_seg_thumb(0)
            self.segment.itemconfig(self.seg_check, fill=self.text_dark,
                                    font=(self.font_text, 13, "bold"))
            self.segment.itemconfig(self.seg_admin, fill=self.text_light,
                                    font=(self.font_text, 12))
            self.tab_check.pack(fill="both", expand=True)
        else:
            self._draw_seg_thumb(1)
            self.segment.itemconfig(self.seg_admin, fill=self.text_dark,
                                    font=(self.font_text, 13, "bold"))
            self.segment.itemconfig(self.seg_check, fill=self.text_light,
                                    font=(self.font_text, 12))
            self.tab_admin.pack(fill="both", expand=True)

    def _draw_nfc_orb(self, canvas, cx, cy, r_outer=72, r_inner=48):
        glow = canvas.create_oval(cx - r_outer + 8, cy - r_outer + 8,
                                  cx + r_outer - 8, cy + r_outer - 8,
                                  outline=self.idle_glow, width=5)
        canvas.create_oval(cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
                           fill=self.orb_ring, outline=self.glass_edge, width=2)
        canvas.create_oval(cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner,
                           fill=self.text_dark, outline="")
        canvas.create_text(cx, cy - 8, text="NFC", fill="#FFFFFF",
                           font=(self.font_display, 13, "bold"))
        canvas.create_text(cx, cy + 14, text="◉  〰", fill="#C4B4A6",
                           font=(self.font_text, 12))
        return glow

    # ----------------------------------------------------------
    # TAB 1 – Membership Check
    # ----------------------------------------------------------
    def build_check_tab(self):
        orb_wrap = tk.Frame(self.tab_check, bg=self.bg)
        orb_wrap.pack(pady=(6, 4))
        self.canvas_check = tk.Canvas(orb_wrap, width=180, height=180,
                                      bg=self.bg, highlightthickness=0)
        self.canvas_check.pack()
        self.glow_check = self._draw_nfc_orb(self.canvas_check, 90, 90)

        self.check_panel = GlassPanel(
            self.tab_check, width=460, height=160,
            radius=24, fill=self.glass, outline=self.glass_edge, bg=self.bg
        )
        self.check_panel.pack(pady=8)
        card = self.check_panel.inner

        self.status_label = tk.Label(card, text="Ready to Scan",
                                     font=(self.font_display, 26, "bold"),
                                     fg=self.text_dark, bg=self.glass,
                                     wraplength=400, justify="center")
        self.status_label.pack(pady=(6, 2), fill="x")

        self.detail_label = tk.Label(card, text="Place the CUPPEE cup on the reader",
                                     font=(self.font_text, 12),
                                     fg=self.text_light, bg=self.glass,
                                     wraplength=400, justify="center")
        self.detail_label.pack(fill="x", padx=8)

        self.info_frame = tk.Frame(card, bg=self.glass)
        self.info_frame.pack(pady=12, fill="x")

        self.uid_label = tk.Label(self.info_frame, text="", font=(self.font_text, 10),
                                  fg=self.text_light, bg=self.glass,
                                  wraplength=400, justify="center")
        self.uid_label.pack(fill="x")
        self.name_label = tk.Label(self.info_frame, text="",
                                   font=(self.font_display, 16, "bold"),
                                   fg=self.text_dark, bg=self.glass,
                                   wraplength=400, justify="center")
        self.name_label.pack(pady=(4, 0), fill="x")
        self.id_label = tk.Label(self.info_frame, text="", font=(self.font_text, 12),
                                 fg=self.text_secondary, bg=self.glass,
                                 wraplength=400, justify="center")
        self.id_label.pack(fill="x")
        self.points_label = tk.Label(self.info_frame, text="",
                                     font=(self.font_text, 13, "bold"),
                                     fg=self.accent, bg=self.glass,
                                     wraplength=400, justify="center")
        self.points_label.pack(pady=(4, 0), fill="x")
        self.expiry_label = tk.Label(self.info_frame, text="", font=(self.font_text, 11),
                                     fg=self.text_light, bg=self.glass,
                                     wraplength=400, justify="center")
        self.expiry_label.pack(fill="x")

        self.scan_btn = PillButton(
            self.tab_check, text="Scan Membership", command=self.scan_card,
            width=280, height=50, bg_fill=self.accent, hover=self.accent_hover,
            font=(self.font_text, 14, "bold"), canvas_bg=self.bg
        )
        self.scan_btn.pack(pady=(14, 8))

        self.reader_status = tk.Label(self.tab_check, text="",
                                      font=(self.font_text, 11),
                                      fg=self.text_light, bg=self.bg,
                                      wraplength=460, justify="center")
        self.reader_status.pack(fill="x", padx=12)

    # ----------------------------------------------------------
    # TAB 2 – Admin Writer
    # ----------------------------------------------------------
    def build_admin_tab(self):
        orb_wrap = tk.Frame(self.tab_admin, bg=self.bg)
        orb_wrap.pack(pady=(2, 2))
        self.canvas_admin = tk.Canvas(orb_wrap, width=130, height=130,
                                      bg=self.bg, highlightthickness=0)
        self.canvas_admin.pack()
        self.glow_admin = self._draw_nfc_orb(self.canvas_admin, 65, 65, r_outer=56, r_inner=36)

        self.admin_panel = GlassPanel(
            self.tab_admin, width=460, height=300,
            radius=24, fill=self.glass, outline=self.glass_edge, bg=self.bg
        )
        self.admin_panel.pack(pady=6)
        form = self.admin_panel.inner

        tk.Label(form, text="Write Membership Data",
                 font=(self.font_display, 15, "bold"),
                 fg=self.text_dark, bg=self.glass).pack(pady=(4, 10), anchor="w")

        def add_field(label, default=""):
            row = tk.Frame(form, bg=self.glass)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label, font=(self.font_text, 11),
                     fg=self.text_light, bg=self.glass, width=13, anchor="w").pack(side="left")
            e = tk.Entry(row, font=(self.font_text, 12), bg=self.field_bg,
                         fg=self.text_dark, insertbackground=self.text_dark,
                         relief="flat", highlightthickness=1,
                         highlightbackground="#D2D2D7", highlightcolor=self.accent)
            e.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 2))
            e.insert(0, default)
            return e

        self.entry_name = add_field("Member Name", "Alex Wong")
        self.entry_id = add_field("Member ID", "CP-2026-88421")
        self.entry_points = add_field("Loyalty Points", "1240")
        self.entry_expiry = add_field(
            "Expiry Date",
            (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
        )

        for label, attr, values, default in [
            ("Status", "status_var", ["Active", "Expired", "Suspended"], "Active"),
            ("Tier", "tier_var", ["Silver", "Gold", "Platinum"], "Gold"),
        ]:
            row = tk.Frame(form, bg=self.glass)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label, font=(self.font_text, 11),
                     fg=self.text_light, bg=self.glass, width=13, anchor="w").pack(side="left")
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            ttk.Combobox(row, textvariable=var, values=values, state="readonly",
                         style="Glass.TCombobox",
                         font=(self.font_text, 12)).pack(side="left", fill="x", expand=True)

        self.write_btn = PillButton(
            self.tab_admin, text="Authenticate & Write",
            command=self.write_to_card, width=300, height=50,
            bg_fill=self.accent, hover=self.accent_hover,
            font=(self.font_text, 14, "bold"), canvas_bg=self.bg
        )
        self.write_btn.pack(pady=(12, 8))

        sec = tk.Frame(self.tab_admin, bg=self.bg)
        sec.pack()
        SoftButton(sec, "Clear Form", self.clear_form, width=126, height=36,
                   font=(self.font_text, 11), canvas_bg=self.bg).pack(side="left", padx=5)
        SoftButton(sec, "Generate ID", self.generate_id, width=126, height=36,
                   font=(self.font_text, 11), canvas_bg=self.bg).pack(side="left", padx=5)

        self.admin_log = tk.Label(self.tab_admin, text="Ready. Place a card on the reader.",
                                  font=(self.font_text, 11), fg=self.text_light, bg=self.bg,
                                  wraplength=420, justify="center")
        self.admin_log.pack(pady=10, fill="x", padx=16)

    # ----------------------------------------------------------
    # Shared / Check / Admin actions
    # ----------------------------------------------------------
    def check_reader(self):
        try:
            r = self.nfc.list_readers()
            if r:
                name = self.nfc.connect()
                self.reader_status.config(
                    text=self._format_message(f"Reader ready · {name}", limit=90),
                    fg=self.valid_color
                )
                self.nfc.disconnect()
            else:
                self.reader_status.config(text="No NFC reader detected", fg=self.error_color)
        except Exception as e:
            self.reader_status.config(
                text=self._format_message(f"Reader error: {e}", limit=90),
                fg=self.error_color
            )

    def scan_card(self):
        self.scan_btn.set_enabled(False, "Scanning...")
        self.canvas_check.itemconfig(self.glow_check, outline=self.scan_glow)
        self.status_label.config(text="Scanning...", fg=self.text_dark)
        self.detail_label.config(text="Hold the cup steady on the reader")
        self.clear_info()
        self.root.update()

        try:
            self.nfc.connect()
            self.nfc.select_application()

            uid = self.nfc.get_uid()
            self.uid_label.config(text=f"UID  {uid}")

            self.nfc.authenticate_ev2_first(key_no=0, key=self.card_key)
            raw = self.nfc.read_data(file_no=0x02, length=80)
            text = raw.decode("utf-8", errors="ignore").strip("\x00").strip()

            if not text or "|" not in text:
                self.set_check_status("error", "No membership data found on card")
                return

            parts = text.split("|")
            if len(parts) < 5:
                self.set_check_status("error", "Invalid data format on card")
                return

            name, mid, points, expiry, status = parts[0], parts[1], parts[2], parts[3], parts[4]
            tier = parts[5] if len(parts) > 5 else ""

            try:
                is_expired = datetime.strptime(expiry, "%Y-%m-%d").date() < datetime.now().date()
            except Exception:
                is_expired = status.lower() == "expired"

            if is_expired or status.lower() == "expired":
                self.set_check_status("expired", name, mid, points, expiry, tier)
            else:
                self.set_check_status("valid", name, mid, points, expiry, tier)

        except NoCardException:
            self.set_check_status("error", "No card detected")
        except Exception as e:
            self.set_check_status("error", str(e))
            traceback.print_exc()
        finally:
            self.nfc.disconnect()
            self.scan_btn.set_enabled(True, "Scan Membership")

    def _format_message(self, text, limit=140):
        """Keep status text readable and inside the glass panel."""
        if text is None:
            return ""
        msg = " ".join(str(text).split())
        if len(msg) > limit:
            return msg[: limit - 1] + "…"
        return msg

    def set_check_status(self, status, name=None, mid=None, points=None, expiry=None, tier=None):
        if status == "valid":
            self.status_label.config(text="Valid", fg=self.valid_color)
            self.detail_label.config(text="Membership is active")
            self.name_label.config(text=name)
            self.id_label.config(text=f"ID  {mid}")
            self.points_label.config(text=f"{points} loyalty points")
            self.expiry_label.config(text=f"Expires {expiry}  ·  {tier}")
            self.canvas_check.itemconfig(self.glow_check, outline=self.valid_color)
        elif status == "expired":
            self.status_label.config(text="Expired", fg=self.expired_color)
            self.detail_label.config(text="Membership has expired")
            self.name_label.config(text=name)
            self.id_label.config(text=f"ID  {mid}")
            self.points_label.config(text=f"{points} loyalty points")
            self.expiry_label.config(text=f"Expired on {expiry}")
            self.canvas_check.itemconfig(self.glow_check, outline=self.expired_color)
        else:
            self.status_label.config(text="Error", fg=self.error_color)
            self.detail_label.config(text=self._format_message(name or "Unable to read card"))
            self.clear_info()
            self.canvas_check.itemconfig(self.glow_check, outline=self.error_color)
        self.root.after_idle(self.check_panel.fit)

    def clear_info(self):
        for lbl in (self.uid_label, self.name_label, self.id_label, self.points_label, self.expiry_label):
            lbl.config(text="")

    def write_to_card(self):
        name = self.entry_name.get().strip()
        mid = self.entry_id.get().strip()
        points = self.entry_points.get().strip()
        expiry = self.entry_expiry.get().strip()
        status = self.status_var.get()
        tier = self.tier_var.get()

        if not name or not mid:
            messagebox.showwarning("Missing Data", "Member Name and Member ID are required.")
            return

        payload = f"{name}|{mid}|{points}|{expiry}|{status}|{tier}".encode("utf-8")

        self.write_btn.set_enabled(False, "Writing...")
        self.canvas_admin.itemconfig(self.glow_admin, outline=self.scan_glow)
        self.admin_log.config(text="Authenticating and writing to card...", fg=self.text_secondary)
        self.root.update()

        try:
            self.nfc.connect()
            self.nfc.select_application()
            self.nfc.authenticate_ev2_first(key_no=0, key=self.card_key)
            self.nfc.write_data(payload, file_no=0x02, offset=0)

            self.canvas_admin.itemconfig(self.glow_admin, outline=self.valid_color)
            self.admin_log.config(
                text=self._format_message(f"Written · {name}  ·  {mid}  ·  {points} pts"),
                fg=self.valid_color
            )
            messagebox.showinfo("Success", "Membership data written and authenticated successfully!")

        except NoCardException:
            self.canvas_admin.itemconfig(self.glow_admin, outline=self.error_color)
            self.admin_log.config(text="No card detected. Place the card on the reader.",
                                  fg=self.error_color)
        except Exception as e:
            self.canvas_admin.itemconfig(self.glow_admin, outline=self.error_color)
            self.admin_log.config(
                text=self._format_message(f"Write failed: {e}"),
                fg=self.error_color
            )
            traceback.print_exc()
        finally:
            self.nfc.disconnect()
            self.write_btn.set_enabled(True, "Authenticate & Write")

    def clear_form(self):
        self.entry_name.delete(0, tk.END)
        self.entry_id.delete(0, tk.END)
        self.entry_points.delete(0, tk.END)
        self.entry_points.insert(0, "0")
        self.entry_expiry.delete(0, tk.END)
        self.entry_expiry.insert(0, (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"))
        self.status_var.set("Active")
        self.tier_var.set("Gold")
        self.admin_log.config(text="Form cleared.", fg=self.text_light)
        self.canvas_admin.itemconfig(self.glow_admin, outline=self.idle_glow)

    def generate_id(self):
        new_id = f"CP-{datetime.now().year}-{random.randint(10000, 99999)}"
        self.entry_id.delete(0, tk.END)
        self.entry_id.insert(0, new_id)


if __name__ == "__main__":
    root = tk.Tk()
    app = CUPPEEApp(root)
    root.mainloop()
