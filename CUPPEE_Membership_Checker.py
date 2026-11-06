import tkinter as tk
from tkinter import messagebox
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import os
import traceback
from datetime import datetime

# ============================================================
# Crypto + NTAG 424 DNA Class (same as Admin Writer)
# ============================================================

class NTAG424Crypto:
    def __init__(self):
        self.session_key_enc = None
        self.session_key_mac = None
        self.cmd_counter = 0

    @staticmethod
    def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = b'\x00'*16) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    @staticmethod
    def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = b'\x00'*16) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

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
        full = self.cmac(self.session_key_mac, data)
        return bytes([full[i] for i in range(0, 16, 2)])


class CUPPEENFC:
    APP_DF = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]

    def __init__(self):
        self.connection = None
        self.crypto = NTAG424Crypto()
        self.authenticated = False

    def list_readers(self):
        return readers()

    def connect(self, reader_index=0):
        r = readers()
        if not r:
            raise Exception("No NFC reader found")
        self.connection = r[reader_index].createConnection()
        self.connection.connect()
        self.authenticated = False
        return str(r[reader_index])

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except:
                pass
            self.connection = None
            self.authenticated = False

    def transmit(self, apdu):
        return self.connection.transmit(apdu)

    def select_application(self):
        apdu = [0x00, 0xA4, 0x04, 0x00, len(self.APP_DF)] + self.APP_DF + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 not in (0x90, 0x91):
            raise Exception(f"Select failed: {sw1:02X}{sw2:02X}")

    def get_uid(self):
        data, sw1, sw2 = self.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if sw1 == 0x90:
            return toHexString(data)
        return "Unknown"

    def authenticate_ev2_first(self, key_no=0, key=b'\x00'*16):
        # Part 1
        data, sw1, sw2 = self.transmit([0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00])
        if sw1 != 0x91 or sw2 != 0xAF:
            raise Exception(f"Auth Part1 failed: {sw1:02X}{sw2:02X}")

        rnd_b = self.crypto.aes_cbc_decrypt(key, bytes(data))
        rnd_a = os.urandom(16)
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]
        encrypted = self.crypto.aes_cbc_encrypt(key, rnd_a + rnd_b_rot)

        # Part 2
        data, sw1, sw2 = self.transmit([0x90, 0xAF, 0x00, 0x00, 0x20] + list(encrypted) + [0x00])
        if sw1 != 0x91 or sw2 != 0x00:
            raise Exception(f"Auth Part2 failed: {sw1:02X}{sw2:02X}")

        decrypted = self.crypto.aes_cbc_decrypt(key, bytes(data[:16]))
        if decrypted != rnd_a[1:] + rnd_a[:1]:
            raise Exception("RndA verification failed")

        self.crypto.derive_session_keys(key, rnd_a, rnd_b)
        self.authenticated = True

    def read_data(self, file_no=0x02, offset=0, length=64):
        offset_b = list(offset.to_bytes(3, 'big'))
        length_b = list(length.to_bytes(3, 'big'))
        apdu = [0x90, 0xBD, 0x00, 0x00, 0x07, file_no] + offset_b + length_b + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x91 and sw2 == 0x00:
            return bytes(data)
        raise Exception(f"Read failed: {sw1:02X}{sw2:02X}")


# ============================================================
# Membership Checking GUI
# ============================================================

class CUPPEEMembershipGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CUPPEE Membership Verification")
        self.root.geometry("480x780")
        self.root.configure(bg="#F7F5F2")
        self.root.resizable(False, False)

        self.nfc = CUPPEENFC()
        self.card_key = b'\x00' * 16          # ← Change to your real key

        # Colors
        self.bg = "#F7F5F2"
        self.card_bg = "#FFFFFF"
        self.accent = "#C48A5A"
        self.valid_color = "#2E7D32"
        self.expired_color = "#EF6C00"
        self.error_color = "#C62828"
        self.text_dark = "#2C2C2C"
        self.text_light = "#6B6B6B"

        self.create_widgets()
        self.check_reader()

    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg=self.bg)
        header.pack(fill="x", pady=(18, 5))
        tk.Label(header, text="CUPPEE", font=("Helvetica", 26, "bold"),
                 fg=self.accent, bg=self.bg).pack()
        tk.Label(header, text="Membership Verification",
                 font=("Helvetica", 12), fg=self.text_light, bg=self.bg).pack()

        # Reader visual
        reader_frame = tk.Frame(self.root, bg=self.bg)
        reader_frame.pack(pady=15)
        self.canvas = tk.Canvas(reader_frame, width=180, height=180, bg=self.bg, highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_oval(10, 10, 170, 170, fill="#E8D5B5", outline="#C9A86C", width=3)
        self.canvas.create_oval(38, 38, 142, 142, fill="#1A1A1A", outline="")
        self.canvas.create_text(90, 80, text="NFC", fill="white", font=("Helvetica", 13, "bold"))
        self.canvas.create_text(90, 105, text="◉ 〰", fill="#AAAAAA", font=("Helvetica", 15))
        self.glow = self.canvas.create_oval(25, 25, 155, 155, outline="#E8D5B5", width=5)

        # Status Card
        self.status_card = tk.Frame(self.root, bg=self.card_bg,
                                    highlightbackground="#E0E0E0", highlightthickness=1)
        self.status_card.pack(padx=35, fill="x", ipady=15)

        self.status_label = tk.Label(self.status_card, text="Ready to Scan",
                                     font=("Helvetica", 22, "bold"),
                                     fg=self.text_dark, bg=self.card_bg)
        self.status_label.pack(pady=(10, 4))

        self.detail_label = tk.Label(self.status_card, text="Place the CUPPEE cup on the reader",
                                     font=("Helvetica", 10), fg=self.text_light, bg=self.card_bg)
        self.detail_label.pack()

        # Member info
        self.info_frame = tk.Frame(self.status_card, bg=self.card_bg)
        self.info_frame.pack(pady=10)

        self.uid_label = tk.Label(self.info_frame, text="", font=("Helvetica", 9),
                                  fg=self.text_light, bg=self.card_bg)
        self.uid_label.pack()
        self.name_label = tk.Label(self.info_frame, text="", font=("Helvetica", 13, "bold"),
                                   fg=self.text_dark, bg=self.card_bg)
        self.name_label.pack()
        self.id_label = tk.Label(self.info_frame, text="", font=("Helvetica", 10),
                                 fg=self.text_light, bg=self.card_bg)
        self.id_label.pack()
        self.points_label = tk.Label(self.info_frame, text="", font=("Helvetica", 11),
                                     fg=self.accent, bg=self.card_bg)
        self.points_label.pack(pady=(2, 0))
        self.expiry_label = tk.Label(self.info_frame, text="", font=("Helvetica", 10),
                                     fg=self.text_light, bg=self.card_bg)
        self.expiry_label.pack()

        # Scan button
        btn_frame = tk.Frame(self.root, bg=self.bg)
        btn_frame.pack(pady=22)

        self.scan_btn = tk.Button(
            btn_frame, text="Scan Membership",
            font=("Helvetica", 13, "bold"),
            bg=self.accent, fg="white",
            activebackground="#A87545", activeforeground="white",
            relief="flat", width=22, height=2, cursor="hand2",
            command=self.scan_card
        )
        self.scan_btn.pack()

        # Reader status
        self.reader_status = tk.Label(self.root, text="Checking reader...",
                                      font=("Helvetica", 9), fg=self.text_light, bg=self.bg)
        self.reader_status.pack(pady=6)

        tk.Label(self.root, text="CUPPEE  ·  NTAG 424 DNA  ·  Authenticated Read",
                 font=("Helvetica", 9), fg="#A0A0A0", bg=self.bg).pack(side="bottom", pady=12)

    def check_reader(self):
        try:
            r = self.nfc.list_readers()
            if r:
                name = self.nfc.connect()
                self.reader_status.config(text=f"Reader ready: {name}", fg=self.valid_color)
                self.nfc.disconnect()
            else:
                self.reader_status.config(text="No NFC reader detected", fg=self.error_color)
        except Exception as e:
            self.reader_status.config(text=f"Reader error: {e}", fg=self.error_color)

    def scan_card(self):
        self.scan_btn.config(state="disabled", text="Scanning...")
        self.canvas.itemconfig(self.glow, outline="#FFD54F")
        self.status_label.config(text="Scanning...", fg=self.text_dark)
        self.detail_label.config(text="Hold the cup steady on the reader")
        self.clear_info()
        self.root.update()

        try:
            self.nfc.connect()
            self.nfc.select_application()

            uid = self.nfc.get_uid()
            self.uid_label.config(text=f"UID: {uid}")

            # Authenticate
            self.nfc.authenticate_ev2_first(key_no=0, key=self.card_key)

            # Read membership data
            raw = self.nfc.read_data(file_no=0x02, length=80)
            text = raw.decode("utf-8", errors="ignore").strip("\x00").strip()

            if not text or "|" not in text:
                self.set_status("error", "No membership data found on card")
                return

            # Parse: name|id|points|expiry|status|tier
            parts = text.split("|")
            if len(parts) < 5:
                self.set_status("error", "Invalid data format on card")
                return

            name, mid, points, expiry, status = parts[0], parts[1], parts[2], parts[3], parts[4]
            tier = parts[5] if len(parts) > 5 else ""

            # Check expiry
            try:
                exp_date = datetime.strptime(expiry, "%Y-%m-%d")
                is_expired = exp_date.date() < datetime.now().date()
            except:
                is_expired = status.lower() == "expired"

            if is_expired or status.lower() == "expired":
                self.set_status("expired", name, mid, points, expiry, tier)
            else:
                self.set_status("valid", name, mid, points, expiry, tier)

        except NoCardException:
            self.set_status("error", "No card detected")
        except Exception as e:
            self.set_status("error", str(e))
            traceback.print_exc()
        finally:
            self.nfc.disconnect()
            self.scan_btn.config(state="normal", text="Scan Membership")

    def clear_info(self):
        self.uid_label.config(text="")
        self.name_label.config(text="")
        self.id_label.config(text="")
        self.points_label.config(text="")
        self.expiry_label.config(text="")

    def set_status(self, status, name=None, mid=None, points=None, expiry=None, tier=None):
        if status == "valid":
            self.status_label.config(text="VALID", fg=self.valid_color)
            self.detail_label.config(text="Membership is active")
            self.name_label.config(text=name)
            self.id_label.config(text=f"ID: {mid}")
            self.points_label.config(text=f"Loyalty Points: {points}")
            self.expiry_label.config(text=f"Expires: {expiry}  ·  {tier}")
            self.canvas.itemconfig(self.glow, outline=self.valid_color)

        elif status == "expired":
            self.status_label.config(text="EXPIRED", fg=self.expired_color)
            self.detail_label.config(text="Membership has expired")
            self.name_label.config(text=name)
            self.id_label.config(text=f"ID: {mid}")
            self.points_label.config(text=f"Loyalty Points: {points}")
            self.expiry_label.config(text=f"Expired on: {expiry}")
            self.canvas.itemconfig(self.glow, outline=self.expired_color)

        else:  # error
            self.status_label.config(text="ERROR", fg=self.error_color)
            self.detail_label.config(text=name or "Unable to read card")
            self.canvas.itemconfig(self.glow, outline=self.error_color)


if __name__ == "__main__":
    root = tk.Tk()
    app = CUPPEEMembershipGUI(root)
    root.mainloop()