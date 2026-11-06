"""Encrypted SQLite store for CUPPEE memberships and purchases."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import DATABASE_PATH, DB_AES_KEY
from crypto_util import decrypt_json, encrypt_json


def _connect(path: Path = DATABASE_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db(path: Path = DATABASE_PATH):
    conn = _connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Path = DATABASE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with get_db(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS members (
                member_id   TEXT PRIMARY KEY,
                card_uid    TEXT,
                payload_enc TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS purchases (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id     TEXT NOT NULL,
                items_enc     TEXT NOT NULL,
                amount        REAL NOT NULL DEFAULT 0,
                points_earned INTEGER NOT NULL DEFAULT 0,
                purchased_at  TEXT NOT NULL,
                FOREIGN KEY (member_id) REFERENCES members(member_id)
            );

            CREATE INDEX IF NOT EXISTS idx_purchases_member
                ON purchases(member_id);
            """
        )


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _encrypt_member(member: dict) -> str:
    return encrypt_json(DB_AES_KEY, member)


def _decrypt_member(token: str) -> dict:
    return decrypt_json(DB_AES_KEY, token)


def upsert_member(member: dict, card_uid: Optional[str] = None) -> dict:
    """Insert or update a member. Sensitive fields stored AES-128 encrypted."""
    member_id = str(member["member_id"]).strip()
    if not member_id:
        raise ValueError("member_id is required")

    payload = {
        "name": member.get("name", ""),
        "member_id": member_id,
        "loyalty_points": int(member.get("loyalty_points", 0) or 0),
        "start_date": member.get("start_date", ""),
        "end_date": member.get("end_date", ""),
        "status": member.get("status", "Active"),
        "tier": member.get("tier", "Gold"),
    }
    enc = _encrypt_member(payload)
    now = _now()

    with get_db() as conn:
        row = conn.execute(
            "SELECT member_id FROM members WHERE member_id = ?", (member_id,)
        ).fetchone()
        if row:
            conn.execute(
                """
                UPDATE members
                   SET card_uid = COALESCE(?, card_uid),
                       payload_enc = ?,
                       updated_at = ?
                 WHERE member_id = ?
                """,
                (card_uid, enc, now, member_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO members (member_id, card_uid, payload_enc, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (member_id, card_uid, enc, now, now),
            )
    return payload


def get_member(member_id: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM members WHERE member_id = ?", (member_id,)
        ).fetchone()
    if not row:
        return None
    data = _decrypt_member(row["payload_enc"])
    data["card_uid"] = row["card_uid"]
    data["created_at"] = row["created_at"]
    data["updated_at"] = row["updated_at"]
    return data


def list_members() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM members ORDER BY updated_at DESC"
        ).fetchall()
    result = []
    for row in rows:
        data = _decrypt_member(row["payload_enc"])
        data["card_uid"] = row["card_uid"]
        data["created_at"] = row["created_at"]
        data["updated_at"] = row["updated_at"]
        result.append(data)
    return result


def search_members(query: str = "") -> list[dict]:
    """Return members matching query across decrypted fields (case-insensitive)."""
    members = list_members()
    q = (query or "").strip().lower()
    if not q:
        return members

    def matches(m: dict) -> bool:
        haystack = " ".join(
            str(m.get(k) or "")
            for k in (
                "name",
                "member_id",
                "loyalty_points",
                "start_date",
                "end_date",
                "status",
                "tier",
                "card_uid",
            )
        ).lower()
        return q in haystack

    return [m for m in members if matches(m)]


def update_member_points(member_id: str, loyalty_points: int) -> Optional[dict]:
    member = get_member(member_id)
    if not member:
        return None
    member["loyalty_points"] = int(loyalty_points)
    return upsert_member(member, card_uid=member.get("card_uid"))


def add_purchase(
    member_id: str,
    items: list[dict] | str,
    amount: float,
    points_earned: int = 0,
) -> dict:
    """Store a purchase. Item details are AES-128 encrypted at rest."""
    if isinstance(items, str):
        items_obj: Any = {"note": items}
    else:
        items_obj = items

    enc = encrypt_json(DB_AES_KEY, items_obj)
    now = _now()
    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO purchases (member_id, items_enc, amount, points_earned, purchased_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (member_id, enc, float(amount), int(points_earned), now),
        )
        purchase_id = cur.lastrowid

    return {
        "id": purchase_id,
        "member_id": member_id,
        "items": items_obj,
        "amount": float(amount),
        "points_earned": int(points_earned),
        "purchased_at": now,
    }


def list_purchases(member_id: Optional[str] = None, limit: int = 50) -> list[dict]:
    with get_db() as conn:
        if member_id:
            rows = conn.execute(
                """
                SELECT * FROM purchases
                 WHERE member_id = ?
                 ORDER BY purchased_at DESC
                 LIMIT ?
                """,
                (member_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM purchases
                 ORDER BY purchased_at DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()

    result = []
    for row in rows:
        try:
            items = decrypt_json(DB_AES_KEY, row["items_enc"])
        except Exception:
            items = {"raw": row["items_enc"]}
        result.append(
            {
                "id": row["id"],
                "member_id": row["member_id"],
                "items": items,
                "amount": row["amount"],
                "points_earned": row["points_earned"],
                "purchased_at": row["purchased_at"],
            }
        )
    return result
