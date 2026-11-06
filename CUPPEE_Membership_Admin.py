import tkinter as tk
from tkinter import ttk, messagebox
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import os
import traceback
from datetime import datetime, timedelta
import random

# ============================================================
# Crypto Helper
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


# ============================================================
# NTAG 424 DNA Class with Authenticated Read + Write
# ============================================================

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

    def read_data(self, file_no=0x02, offset=0, length=32):
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

        # Command header for MAC calculation
        # CLA INS P1 P2 Lc  +  FileNo + Offset + Length + Data
        cmd_header = bytes([0x90, 0x8D, 0x00, 0x00])
        lc = 1 + 3 + 3 + len(data) + 8   # file + offset + length + data + MAC
        cmd_data = bytes([file_no]) + bytes(offset_b) + bytes(length_b) + data

        # Build MAC input: CmdCounter (2B LE) + CmdHeader + CmdData
        counter_bytes = self.crypto.cmd_counter.to_bytes(2, 'little')
        mac_input = counter_bytes + cmd_header + bytes([lc]) + cmd_data
        mac = self.crypto.calculate_mac(mac_input)

        # Full APDU
        apdu = list(cmd_header) + [lc] + list(cmd_data) + list(mac) + [0x00]

        resp, sw1, sw2 = self.transmit(apdu)

        if sw1 == 0x91 and sw2 == 0x00:
            self.crypto.cmd_counter += 1
            return True
        else:
            raise Exception(f"Write failed: {sw1:02X}{sw2:02X}")


# ============================================================
# Admin Writer GUI with Authenticated Write
# ============================================================

class CUPPEEAdminWriter:
    def __init__(self, root):
        self.root = root
        self.root.title("CUPPEE Admin – Authenticated Card Writer")
        self.root.geometry("520x820")
        self.root.configure(bg="#F7F5F2")
        self.root.resizable(False, False)

        self.nfc = CUPPEENFC()
        self.card_key = b'\x00' * 16          # ← Change to your real AES-128 key

        self.bg = "#F7F5F2"
        self.card_bg = "#FFFFFF"
        self.accent = "#C48A5A"
        self.success = "#2E7D32"
        self.error = "#C62828"
        self.text_dark = "#2C2C2C"
        self.text_light = "#6B6B6B"

        self.create_widgets()
        self.check_reader()

    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg=self.bg)
        header.pack(fill="x", pady=(16, 4))
        tk.Label(header, text="CUPPEE", font=("Helvetica", 26, "bold"),
                 fg=self.accent, bg=self.bg).pack()
        tk.Label(header, text="Admin  ·  Authenticated Membership Writer",
                 font=("Helvetica", 11), fg=self.text_light, bg=self.bg).pack()

        # Reader visual
        reader_frame = tk.Frame(self.root, bg=self.bg)
        reader_frame.pack(pady=10)
        self.canvas = tk.Canvas(reader_frame, width=150, height=150, bg=self.bg, highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_oval(8, 8, 142, 142, fill="#E8D5B5", outline="#C9A86C", width=3)
        self.canvas.create_oval(30, 30, 120, 120, fill="#1A1A1A", outline="")
        self.canvas.create_text(75, 65, text="NFC", fill="white", font=("Helvetica", 12, "bold"))
        self.canvas.create_text(75, 88, text="◉ 〰", fill="#AAAAAA", font=("Helvetica", 13))
        self.glow = self.canvas.create_oval(20, 20, 130, 130, outline="#E8D5B5", width=5)

        # Form
        form = tk.Frame(self.root, bg=self.card_bg, highlightbackground="#E0E0E0", highlightthickness=1)
        form.pack(padx=35, fill="x", ipady=6)

        tk.Label(form, text="Membership Data", font=("Helvetica", 12, "bold"),
                 fg=self.text_dark, bg=self.card_bg).pack(pady=(10, 8))

        def add_field(label, default=""):
            f = tk.Frame(form, bg=self.card_bg)
            f.pack(fill="x", padx=22, pady=3)
            tk.Label(f, text=label, font=("Helvetica", 10), fg=self.text_light,
                     bg=self.card_bg, width=13, anchor="w").pack(side="left")
            e = tk.Entry(f, font=("Helvetica", 11), bg="#FAFAFA", relief="solid", bd=1)
            e.pack(side="left", fill="x", expand=True, ipady=3)
            e.insert(0, default)
            return e

        self.entry_name   = add_field("Member Name", "Alex Wong")
        self.entry_id     = add_field("Member ID", "CP-2026-88421")
        self.entry_points = add_field("Loyalty Points", "1240")
        self.entry_expiry = add_field("Expiry Date",
                                      (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"))

        # Status & Tier
        for label, var_name, values, default in [
            ("Status", "status_var", ["Active", "Expired", "Suspended"], "Active"),
            ("Tier", "tier_var", ["Silver", "Gold", "Platinum"], "Gold")
        ]:
            f = tk.Frame(form, bg=self.card_bg)
            f.pack(fill="x", padx=22, pady=3)
            tk.Label(f, text=label, font=("Helvetica", 10), fg=self.text_light,
                     bg=self.card_bg, width=13, anchor="w").pack(side="left")
            var = tk.StringVar(value=default)
            setattr(self, var_name, var)
            ttk.Combobox(f, textvariable=var, values=values, state="readonly",
                         font=("Helvetica", 11), width=18).pack(side="left", fill="x", expand=True)

        tk.Frame(form, bg=self.card_bg, height=6).pack()

        # Buttons
        btn_frame = tk.Frame(self.root, bg=self.bg)
        btn_frame.pack(pady=14)

        self.write_btn = tk.Button(
            btn_frame, text="Authenticate & Write to Card",
            font=("Helvetica", 13, "bold"),
            bg=self.accent, fg="white",
            activebackground="#A87545", activeforeground="white",
            relief="flat", width=26, height=2, cursor="hand2",
            command=self.write_to_card
        )
        self.write_btn.pack()

        sec = tk.Frame(self.root, bg=self.bg)
        sec.pack()
        tk.Button(sec, text="Clear Form", font=("Helvetica", 10),
                  bg="#E0E0E0", relief="flat", width=12, command=self.clear_form).pack(side="left", padx=5)
        tk.Button(sec, text="Generate ID", font=("Helvetica", 10),
                  bg="#E0E0E0", relief="flat", width=12, command=self.generate_id).pack(side="left", padx=5)

        # Log
        self.log_label = tk.Label(self.root, text="Ready. Place a CUPPEE card on the reader.",
                                  font=("Helvetica", 10), fg=self.text_light, bg=self.bg,
                                  wraplength=440, justify="center")
        self.log_label.pack(pady=10)

        self.reader_status = tk.Label(self.root, text="", font=("Helvetica", 9),
                                      fg=self.text_light, bg=self.bg)
        self.reader_status.pack()

        tk.Label(self.root, text="CUPPEE Admin  ·  NTAG 424 DNA  ·  Authenticated Write",
                 font=("Helvetica", 9), fg="#A0A0A0", bg=self.bg).pack(side="bottom", pady=10)

    def check_reader(self):
        try:
            r = self.nfc.list_readers()
            if r:
                name = self.nfc.connect()
                self.reader_status.config(text=f"Reader ready: {name}", fg=self.success)
                self.nfc.disconnect()
            else:
                self.reader_status.config(text="No NFC reader detected", fg=self.error)
        except Exception as e:
            self.reader_status.config(text=f"Reader error: {e}", fg=self.error)

    def generate_id(self):
        new_id = f"CP-{datetime.now().year}-{random.randint(10000,99999)}"
        self.entry_id.delete(0, tk.END)
        self.entry_id.insert(0, new_id)

    def clear_form(self):
        self.entry_name.delete(0, tk.END)
        self.entry_id.delete(0, tk.END)
        self.entry_points.delete(0, tk.END)
        self.entry_points.insert(0, "0")
        self.entry_expiry.delete(0, tk.END)
        self.entry_expiry.insert(0, (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"))
        self.status_var.set("Active")
        self.tier_var.set("Gold")
        self.log_label.config(text="Form cleared.", fg=self.text_light)
        self.canvas.itemconfig(self.glow, outline="#E8D5B5")

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

        # Build data string (simple format – you can change to JSON or NDEF later)
        payload = f"{name}|{mid}|{points}|{expiry}|{status}|{tier}".encode("utf-8")

        self.write_btn.config(state="disabled", text="Writing...")
        self.canvas.itemconfig(self.glow, outline="#FFD54F")
        self.log_label.config(text="Authenticating and writing to card...", fg=self.text_dark)
        self.root.update()

        try:
            self.nfc.connect()
            self.nfc.select_application()

            # Authenticate
            self.nfc.authenticate_ev2_first(key_no=0, key=self.card_key)

            # Write
            self.nfc.write_data(payload, file_no=0x02, offset=0)

            self.canvas.itemconfig(self.glow, outline=self.success)
            self.log_label.config(
                text=f"Successfully written!\n{name}  |  {mid}  |  {points} pts  |  {status}",
                fg=self.success
            )
            messagebox.showinfo("Success", "Membership data written and authenticated successfully!")

        except NoCardException:
            self.canvas.itemconfig(self.glow, outline=self.error)
            self.log_label.config(text="No card detected. Place the card on the reader.", fg=self.error)
        except Exception as e:
            self.canvas.itemconfig(self.glow, outline=self.error)
            self.log_label.config(text=f"Write failed: {str(e)}", fg=self.error)
            traceback.print_exc()
        finally:
            self.nfc.disconnect()
            self.write_btn.config(state="normal", text="Authenticate & Write to Card")


if __name__ == "__main__":
    root = tk.Tk()
    app = CUPPEEAdminWriter(root)
    root.mainloop()