"""CUPPEE web app configuration."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Flask
SECRET_KEY = os.environ.get("CUPPEE_SECRET_KEY", "cohee-cuppee-demo-change-me")
ADMIN_PASSWORD = os.environ.get("CUPPEE_ADMIN_PASSWORD", "cohee2026")

# AES-128 keys (16 bytes). Override via env for production.
# Membership payload on NFC cards and sensitive DB fields use these keys.
CARD_AES_KEY = os.environ.get(
    "CUPPEE_CARD_AES_KEY",
    "CoHeeCUPPEEKey!!",  # exactly 16 chars → 16 bytes AES-128
).encode("utf-8")[:16].ljust(16, b"\0")

DB_AES_KEY = os.environ.get(
    "CUPPEE_DB_AES_KEY",
    "CoHeeDBSecretKey",  # exactly 16 chars
).encode("utf-8")[:16].ljust(16, b"\0")

# NTAG 424 DNA authentication key (default factory key — change for production)
NTAG_AUTH_KEY = bytes.fromhex(
    os.environ.get("CUPPEE_NTAG_AUTH_KEY", "00" * 16)
)

DATABASE_PATH = DATA_DIR / "cuppee.db"

# Points earned per HKD spent (demo default)
POINTS_PER_DOLLAR = float(os.environ.get("CUPPEE_POINTS_PER_DOLLAR", "1"))

# Allow simulated NFC when no reader is present (dev / demo)
ALLOW_NFC_SIMULATION = os.environ.get("CUPPEE_ALLOW_NFC_SIM", "1") == "1"
