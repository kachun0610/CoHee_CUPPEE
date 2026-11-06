"""NTAG 424 DNA NFC service for CUPPEE (PC/SC via pyscard).

Reuses the authenticated EV2 read/write flow from the desktop demo.
Falls back to an in-memory simulator when no reader is available.
"""

from __future__ import annotations

import os
import random
import threading
from datetime import datetime, timedelta
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
    from smartcard.Exceptions import NoCardException, CardConnectionException
except Exception:  # pragma: no cover
    readers = None
    toHexString = None
    NoCardException = Exception
    CardConnectionException = Exception

from config import ALLOW_NFC_SIMULATION, NTAG_AUTH_KEY
from crypto_util import decrypt_card_payload, encrypt_card_payload


class NTAG424Crypto:
    def __init__(self):
        self.session_key_enc = None
        self.session_key_mac = None
        self.cmd_counter = 0

    @staticmethod
    def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 16) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    @staticmethod
    def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 16) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    @staticmethod
    def cmac(key: bytes, data: bytes) -> bytes:
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()

    def derive_session_keys(self, key: bytes, rnd_a: bytes, rnd_b: bytes):
        sv1 = b"\xA5\x5A\x00\x01\x00\x00" + rnd_a[:6] + rnd_b[-6:] + rnd_a[-6:] + rnd_b[:6]
        sv2 = b"\x5A\xA5\x00\x01\x00\x00" + rnd_a[:6] + rnd_b[-6:] + rnd_a[-6:] + rnd_b[:6]
        self.session_key_enc = self.cmac(key, sv1)[:16]
        self.session_key_mac = self.cmac(key, sv2)[:16]
        self.cmd_counter = 0

    def calculate_mac(self, data: bytes) -> bytes:
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
        if readers is None:
            return []
        return readers()

    def connect(self, reader_index: int = 0):
        r = self.list_readers()
        if not r:
            raise RuntimeError("No NFC reader found. Check RF-IC02 connection.")
        self.reader_name = str(r[reader_index])
        self.connection = r[reader_index].createConnection()
        self.connection.connect()
        self.authenticated = False
        return self.reader_name

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
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
            raise RuntimeError(f"Select Application failed: {sw1:02X}{sw2:02X}")
        return data

    def get_version(self):
        data, sw1, sw2 = self.transmit([0x90, 0x60, 0x00, 0x00, 0x00])
        version = data[:]
        while sw2 == 0xAF:
            data, sw1, sw2 = self.transmit([0x90, 0xAF, 0x00, 0x00, 0x00])
            version.extend(data)
        return version

    def get_uid(self) -> str:
        try:
            version = self.get_version()
            if len(version) >= 14 and toHexString:
                return toHexString(version[7:14])
        except Exception:
            pass
        data, sw1, sw2 = self.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if sw1 == 0x90 and toHexString:
            return toHexString(data)
        return "Unknown"

    def authenticate_ev2_first(self, key_no: int = 0, key: bytes = b"\x00" * 16):
        apdu = [0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 != 0x91 or sw2 != 0xAF:
            raise RuntimeError(f"Auth Part1 failed: {sw1:02X}{sw2:02X}")

        encrypted_rnd_b = bytes(data)
        rnd_b = self.crypto.aes_cbc_decrypt(key, encrypted_rnd_b)
        rnd_a = os.urandom(16)
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]
        encrypted = self.crypto.aes_cbc_encrypt(key, rnd_a + rnd_b_rot)

        apdu = [0x90, 0xAF, 0x00, 0x00, 0x20] + list(encrypted) + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 != 0x91 or sw2 != 0x00:
            raise RuntimeError(f"Auth Part2 failed: {sw1:02X}{sw2:02X}")

        decrypted = self.crypto.aes_cbc_decrypt(key, bytes(data[:16]))
        if decrypted != rnd_a[1:] + rnd_a[:1]:
            raise RuntimeError("RndA verification failed")

        self.crypto.derive_session_keys(key, rnd_a, rnd_b)
        self.authenticated = True
        return True

    def read_data(self, file_no: int = 0x02, offset: int = 0, length: int = 128):
        offset_b = list(offset.to_bytes(3, "big"))
        length_b = list(length.to_bytes(3, "big"))
        apdu = [0x90, 0xBD, 0x00, 0x00, 0x07, file_no] + offset_b + length_b + [0x00]
        data, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x91 and sw2 == 0x00:
            return bytes(data)
        raise RuntimeError(f"Read failed: {sw1:02X}{sw2:02X}")

    def write_data(self, data: bytes, file_no: int = 0x02, offset: int = 0):
        if not self.authenticated:
            raise RuntimeError("Not authenticated. Call authenticate_ev2_first() first.")
        if len(data) > 200:
            raise RuntimeError("Data too long for single write (max ~200 bytes)")

        offset_b = list(offset.to_bytes(3, "big"))
        length_b = list(len(data).to_bytes(3, "big"))
        cmd_header = bytes([0x90, 0x8D, 0x00, 0x00])
        lc = 1 + 3 + 3 + len(data) + 8
        cmd_data = bytes([file_no]) + bytes(offset_b) + bytes(length_b) + data

        counter_bytes = self.crypto.cmd_counter.to_bytes(2, "little")
        mac_input = counter_bytes + cmd_header + bytes([lc]) + cmd_data
        mac = self.crypto.calculate_mac(mac_input)

        apdu = list(cmd_header) + [lc] + list(cmd_data) + list(mac) + [0x00]
        _resp, sw1, sw2 = self.transmit(apdu)
        if sw1 == 0x91 and sw2 == 0x00:
            self.crypto.cmd_counter += 1
            return True
        raise RuntimeError(f"Write failed: {sw1:02X}{sw2:02X}")


class SimulatedCardStore:
    """In-memory card file for demo when hardware is unavailable."""

    def __init__(self):
        self.uid = "SIM-DEADBEEF"
        self.file02 = b""

    def clear(self):
        self.file02 = b""


_SIM_FIRST = [
    "Alex", "Jamie", "Sam", "Chris", "Taylor", "Jordan", "Casey", "Morgan",
    "Riley", "Avery", "Quinn", "Harper", "Kai", "Nova", "Ellis", "Reese",
]
_SIM_LAST = [
    "Wong", "Chan", "Lee", "Cheung", "Lam", "Ho", "Ng", "Cheng",
    "Leung", "Lau", "Yip", "Tang", "Mak", "Kwok", "Tsang", "Fung",
]
_SIM_TIERS = ["Silver", "Gold", "Platinum"]
_SIM_STATUSES = ["Active", "Active", "Active", "Expired", "Suspended"]


def _random_sim_member() -> dict:
    """Generate demo membership data for simulation scans."""
    name = f"{random.choice(_SIM_FIRST)} {random.choice(_SIM_LAST)}"
    member_id = f"CP-{datetime.now().year}-{random.randint(10000, 99999)}"
    start = datetime.now().date() - timedelta(days=random.randint(0, 400))
    end = start + timedelta(days=365)
    status = random.choice(_SIM_STATUSES)
    if status == "Expired":
        end = datetime.now().date() - timedelta(days=random.randint(1, 90))
        start = end - timedelta(days=365)
    return {
        "name": name,
        "member_id": member_id,
        "loyalty_points": random.randint(0, 2500),
        "start_date": start.strftime("%Y-%m-%d"),
        "end_date": end.strftime("%Y-%m-%d"),
        "status": status,
        "tier": random.choice(_SIM_TIERS),
    }


def _random_sim_uid() -> str:
    return "SIM-" + "".join(f"{random.randint(0, 255):02X}" for _ in range(4))


_sim_store = SimulatedCardStore()
_nfc_lock = threading.Lock()


def reader_status() -> dict:
    """Return whether a physical reader is available."""
    nfc = CUPPEENFC()
    try:
        r = nfc.list_readers()
        if r:
            name = str(r[0])
            return {"ok": True, "mode": "hardware", "reader": name}
        if ALLOW_NFC_SIMULATION:
            return {
                "ok": True,
                "mode": "simulation",
                "reader": "Simulation (no hardware)",
            }
        return {"ok": False, "mode": "none", "reader": None, "error": "No NFC reader"}
    except Exception as exc:
        if ALLOW_NFC_SIMULATION:
            return {
                "ok": True,
                "mode": "simulation",
                "reader": f"Simulation ({exc})",
            }
        return {"ok": False, "mode": "none", "reader": None, "error": str(exc)}


def _use_simulation() -> bool:
    status = reader_status()
    return status.get("mode") == "simulation"


def read_membership(
    card_aes_key: bytes,
    auth_key: Optional[bytes] = None,
    *,
    sim_random: bool = True,
) -> dict:
    """Authenticate, read file 02, decrypt membership payload.

    In simulation mode, each scan mints a random customer by default so the
    Check / Admin scan buttons work without writing a card first.
    """
    auth_key = auth_key or NTAG_AUTH_KEY
    with _nfc_lock:
        if _use_simulation():
            if sim_random or not _sim_store.file02:
                member = _random_sim_member()
                _sim_store.uid = _random_sim_uid()
                _sim_store.file02 = encrypt_card_payload(card_aes_key, member)
            else:
                member = decrypt_card_payload(card_aes_key, _sim_store.file02)
            return {"uid": _sim_store.uid, "member": member, "mode": "simulation"}

        nfc = CUPPEENFC()
        try:
            nfc.connect()
            nfc.select_application()
            uid = nfc.get_uid()
            nfc.authenticate_ev2_first(key_no=0, key=auth_key)
            raw = nfc.read_data(file_no=0x02, length=160)
            member = decrypt_card_payload(card_aes_key, raw)
            return {"uid": uid, "member": member, "mode": "hardware"}
        except NoCardException:
            raise RuntimeError("No card detected. Place the CUPPEE card on the reader.")
        finally:
            nfc.disconnect()


def write_membership(
    card_aes_key: bytes,
    member_data: dict,
    auth_key: Optional[bytes] = None,
) -> dict:
    """Encrypt membership, authenticate, write to file 02."""
    auth_key = auth_key or NTAG_AUTH_KEY
    payload = encrypt_card_payload(card_aes_key, member_data)

    with _nfc_lock:
        if _use_simulation():
            _sim_store.file02 = payload
            return {
                "uid": _sim_store.uid,
                "member": member_data,
                "bytes_written": len(payload),
                "mode": "simulation",
            }

        nfc = CUPPEENFC()
        try:
            nfc.connect()
            nfc.select_application()
            uid = nfc.get_uid()
            nfc.authenticate_ev2_first(key_no=0, key=auth_key)
            nfc.write_data(payload, file_no=0x02, offset=0)
            return {
                "uid": uid,
                "member": member_data,
                "bytes_written": len(payload),
                "mode": "hardware",
            }
        except NoCardException:
            raise RuntimeError("No card detected. Place the CUPPEE card on the reader.")
        finally:
            nfc.disconnect()


def update_card_points(
    card_aes_key: bytes,
    new_points: int,
    auth_key: Optional[bytes] = None,
) -> dict:
    """Read card, update loyalty points, write back (encrypted).

    Simulation uses the last tapped card (no new random member).
    """
    auth_key = auth_key or NTAG_AUTH_KEY
    with _nfc_lock:
        if _use_simulation():
            if not _sim_store.file02:
                raise RuntimeError("No simulated card data. Scan a membership first.")
            member = decrypt_card_payload(card_aes_key, _sim_store.file02)
            member["loyalty_points"] = int(new_points)
            _sim_store.file02 = encrypt_card_payload(card_aes_key, member)
            return {
                "uid": _sim_store.uid,
                "member": member,
                "bytes_written": len(_sim_store.file02),
                "mode": "simulation",
            }

    result = read_membership(card_aes_key, auth_key=auth_key, sim_random=False)
    member = dict(result["member"])
    member["loyalty_points"] = int(new_points)
    return write_membership(card_aes_key, member, auth_key=auth_key)
