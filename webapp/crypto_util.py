"""AES-128 helpers for CUPPEE card payloads and database field encryption."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def _require_aes128(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    return bytes(key)


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """AES-128-CBC encrypt with random IV prepended to ciphertext."""
    key = _require_aes128(key)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES.block_size))


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    """Decrypt AES-128-CBC blob produced by encrypt_bytes."""
    key = _require_aes128(key)
    if len(blob) < 32 or len(blob) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    iv, ct = blob[:16], blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def encrypt_text(key: bytes, text: str) -> str:
    """Encrypt UTF-8 text → URL-safe base64 string for storage / transport."""
    return base64.urlsafe_b64encode(encrypt_bytes(key, text.encode("utf-8"))).decode("ascii")


def decrypt_text(key: bytes, token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    return decrypt_bytes(key, raw).decode("utf-8")


def encrypt_json(key: bytes, obj: Any) -> str:
    return encrypt_text(key, json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def decrypt_json(key: bytes, token: str) -> Any:
    return json.loads(decrypt_text(key, token))


# ---------------------------------------------------------------------------
# Card payload: name | id | points | start | end | status | tier
# Stored on NTAG as AES-128 encrypted bytes (IV + ciphertext).
# ---------------------------------------------------------------------------

CARD_FIELDS = ("name", "member_id", "loyalty_points", "start_date", "end_date", "status", "tier")


def pack_membership_plaintext(data: dict) -> bytes:
    parts = [
        str(data.get("name", "")).strip(),
        str(data.get("member_id", "")).strip(),
        str(data.get("loyalty_points", 0)).strip(),
        str(data.get("start_date", "")).strip(),
        str(data.get("end_date", "")).strip(),
        str(data.get("status", "Active")).strip(),
        str(data.get("tier", "Gold")).strip(),
    ]
    return "|".join(parts).encode("utf-8")


def unpack_membership_plaintext(raw: bytes) -> dict:
    text = raw.decode("utf-8", errors="ignore").strip("\x00").strip()
    if not text or "|" not in text:
        raise ValueError("No membership data found")
    parts = text.split("|")
    if len(parts) < 5:
        raise ValueError("Invalid membership data format")

    # Backward compatible with older cards: name|id|points|expiry|status|tier
    if len(parts) >= 7:
        name, mid, points, start, end, status = parts[:6]
        tier = parts[6] if len(parts) > 6 else ""
    else:
        name, mid, points, end, status = parts[:5]
        start = ""
        tier = parts[5] if len(parts) > 5 else ""

    return {
        "name": name,
        "member_id": mid,
        "loyalty_points": int(points) if str(points).isdigit() else points,
        "start_date": start,
        "end_date": end,
        "status": status,
        "tier": tier,
    }


# Card file framing: b"CP1\0" + uint16 BE length + AES-128-CBC(IV||ciphertext)
_CARD_MAGIC = b"CP1\0"


def encrypt_card_payload(key: bytes, data: dict) -> bytes:
    """Produce framed AES-128 encrypted bytes to write onto the NFC card file."""
    body = encrypt_bytes(key, pack_membership_plaintext(data))
    return _CARD_MAGIC + len(body).to_bytes(2, "big") + body


def decrypt_card_payload(key: bytes, blob: bytes) -> dict:
    """
    Decrypt card file contents.
    Tries framed AES-128 first, then raw AES blob, then legacy plaintext.
    """
    raw = bytes(blob)
    try:
        if raw.startswith(_CARD_MAGIC) and len(raw) >= 6:
            length = int.from_bytes(raw[4:6], "big")
            body = raw[6 : 6 + length]
            plain = decrypt_bytes(key, body)
            return unpack_membership_plaintext(plain)
    except Exception:
        pass

    # Unframed AES attempt (trim only after failed framed parse)
    try:
        trimmed = raw.rstrip(b"\x00")
        plain = decrypt_bytes(key, trimmed)
        return unpack_membership_plaintext(plain)
    except Exception:
        return unpack_membership_plaintext(raw.rstrip(b"\x00"))
