"""CoHee CUPPEE Membership — Flask web application."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    session,
)

from config import (
    ADMIN_PASSWORD,
    CARD_AES_KEY,
    POINTS_PER_DOLLAR,
    SECRET_KEY,
)
import database as db
import nfc_service

app = Flask(__name__)
app.secret_key = SECRET_KEY

db.init_db()

# Common CoHee menu items (HKD) for the Check page purchase dropdown
MENU_ITEMS = [
    {"id": "americano", "name": "Americano", "price": 32},
    {"id": "latte", "name": "Latte", "price": 38},
    {"id": "cappuccino", "name": "Cappuccino", "price": 38},
    {"id": "flat_white", "name": "Flat White", "price": 40},
    {"id": "mocha", "name": "Mocha", "price": 42},
    {"id": "espresso", "name": "Espresso", "price": 28},
    {"id": "cold_brew", "name": "Cold Brew", "price": 42},
    {"id": "matcha_latte", "name": "Matcha Latte", "price": 42},
    {"id": "hot_chocolate", "name": "Hot Chocolate", "price": 36},
    {"id": "croissant", "name": "Butter Croissant", "price": 28},
    {"id": "pain_chocolat", "name": "Pain au Chocolat", "price": 30},
    {"id": "banana_bread", "name": "Banana Bread", "price": 32},
    {"id": "cookie", "name": "Cookie", "price": 18},
    {"id": "sandwich", "name": "Ham & Cheese Sandwich", "price": 48},
]


def _menu_by_id(item_id: str) -> dict | None:
    for item in MENU_ITEMS:
        if item["id"] == item_id:
            return item
    return None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_ok"):
            return jsonify({"ok": False, "error": "Admin authentication required"}), 401
        return fn(*args, **kwargs)

    return wrapper


def db_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("db_ok"):
            return jsonify({"ok": False, "error": "Database authentication required"}), 401
        return fn(*args, **kwargs)

    return wrapper


def _parse_member_from_form(data: dict) -> dict:
    return {
        "name": (data.get("name") or "").strip(),
        "member_id": (data.get("member_id") or "").strip(),
        "loyalty_points": int(data.get("loyalty_points") or 0),
        "start_date": (data.get("start_date") or "").strip(),
        "end_date": (data.get("end_date") or "").strip(),
        "status": (data.get("status") or "Active").strip(),
        "tier": (data.get("tier") or "Gold").strip(),
    }


def _membership_availability(member: dict) -> dict:
    status = str(member.get("status", "")).lower()
    end = member.get("end_date") or ""
    is_expired = status == "expired"
    try:
        if end:
            is_expired = is_expired or (
                datetime.strptime(end, "%Y-%m-%d").date() < datetime.now().date()
            )
    except ValueError:
        pass

    if status == "suspended":
        state = "suspended"
        label = "Suspended"
    elif is_expired:
        state = "expired"
        label = "Expired"
    else:
        state = "valid"
        label = "Valid"

    return {"state": state, "label": label, "is_active": state == "valid"}


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if password == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Incorrect password"}), 401


@app.post("/api/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return jsonify({"ok": True})


@app.get("/api/admin/session")
def admin_session():
    return jsonify({"ok": True, "authenticated": bool(session.get("admin_ok"))})


@app.post("/api/db/login")
def db_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if password == ADMIN_PASSWORD:
        session["db_ok"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Incorrect password"}), 401


@app.post("/api/db/logout")
def db_logout():
    session.pop("db_ok", None)
    return jsonify({"ok": True})


@app.get("/api/db/session")
def db_session():
    return jsonify({"ok": True, "authenticated": bool(session.get("db_ok"))})


@app.get("/api/db/members")
@db_required
def api_db_members():
    query = (request.args.get("q") or "").strip()
    members = db.search_members(query)
    return jsonify({"ok": True, "members": members, "count": len(members), "query": query})


# ---------------------------------------------------------------------------
# NFC / reader
# ---------------------------------------------------------------------------

@app.get("/api/reader")
def api_reader():
    return jsonify({"ok": True, **nfc_service.reader_status()})


@app.post("/api/check/scan")
def api_check_scan():
    try:
        result = nfc_service.read_membership(CARD_AES_KEY)
        member = result["member"]
        availability = _membership_availability(member)

        # Sync DB from card when possible
        try:
            db.upsert_member(member, card_uid=result.get("uid"))
        except Exception:
            pass

        purchases = db.list_purchases(member_id=member.get("member_id"), limit=10)
        return jsonify(
            {
                "ok": True,
                "uid": result.get("uid"),
                "mode": result.get("mode"),
                "member": member,
                "availability": availability,
                "purchases": purchases,
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/check/purchase")
def api_check_purchase():
    data = request.get_json(silent=True) or {}
    member_id = (data.get("member_id") or "").strip()
    menu_item_id = (data.get("menu_item_id") or "").strip()
    update_card = bool(data.get("update_card", True))

    if not member_id:
        return jsonify({"ok": False, "error": "member_id is required"}), 400

    menu_item = _menu_by_id(menu_item_id)
    if not menu_item:
        return jsonify({"ok": False, "error": "Select a menu item"}), 400

    amount = float(menu_item["price"])
    purchase_items = {
        "id": menu_item["id"],
        "name": menu_item["name"],
        "price": menu_item["price"],
    }
    points_earned = int(round(amount * POINTS_PER_DOLLAR))

    member = db.get_member(member_id)
    if not member:
        # Allow purchase logging if card was just scanned but not yet in DB
        member = {
            "name": data.get("name") or "",
            "member_id": member_id,
            "loyalty_points": int(data.get("loyalty_points") or 0),
            "start_date": data.get("start_date") or "",
            "end_date": data.get("end_date") or "",
            "status": data.get("status") or "Active",
            "tier": data.get("tier") or "Gold",
        }
        db.upsert_member(member)

    new_points = int(member.get("loyalty_points") or 0) + points_earned
    purchase = db.add_purchase(member_id, purchase_items, amount, points_earned)
    db.update_member_points(member_id, new_points)

    card_result = None
    card_error = None
    if update_card:
        try:
            card_result = nfc_service.update_card_points(CARD_AES_KEY, new_points)
        except Exception as exc:
            card_error = str(exc)

    return jsonify(
        {
            "ok": True,
            "purchase": purchase,
            "loyalty_points": new_points,
            "points_earned": points_earned,
            "card_updated": card_result is not None,
            "card_error": card_error,
            "card": card_result,
        }
    )


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.post("/api/admin/generate-id")
@admin_required
def api_generate_id():
    new_id = f"CP-{datetime.now().year}-{random.randint(10000, 99999)}"
    return jsonify({"ok": True, "member_id": new_id})


@app.post("/api/admin/scan")
@admin_required
def api_admin_scan():
    """Read membership from NFC card and return fields for the admin form."""
    try:
        result = nfc_service.read_membership(CARD_AES_KEY)
        member = result["member"]
        try:
            db.upsert_member(member, card_uid=result.get("uid"))
        except Exception:
            pass
        return jsonify(
            {
                "ok": True,
                "uid": result.get("uid"),
                "mode": result.get("mode"),
                "member": member,
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/admin/create")
@admin_required
def api_admin_create():
    data = request.get_json(silent=True) or {}
    member = _parse_member_from_form(data)

    if not member["name"] or not member["member_id"]:
        return jsonify({"ok": False, "error": "Name and Member ID are required"}), 400

    if not member["start_date"]:
        member["start_date"] = datetime.now().strftime("%Y-%m-%d")
    if not member["end_date"]:
        member["end_date"] = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")

    write_card = bool(data.get("write_card", True))

    try:
        card_result = None
        if write_card:
            card_result = nfc_service.write_membership(CARD_AES_KEY, member)
            uid = card_result.get("uid")
        else:
            uid = data.get("card_uid")

        saved = db.upsert_member(member, card_uid=uid)
        return jsonify(
            {
                "ok": True,
                "member": saved,
                "card": card_result,
                "mode": (card_result or {}).get("mode"),
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/admin/members")
@admin_required
def api_admin_members():
    return jsonify({"ok": True, "members": db.list_members()})


@app.get("/api/admin/purchases")
@admin_required
def api_admin_purchases():
    member_id = request.args.get("member_id")
    return jsonify({"ok": True, "purchases": db.list_purchases(member_id=member_id)})


@app.get("/api/defaults")
def api_defaults():
    today = datetime.now().strftime("%Y-%m-%d")
    end = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
    return jsonify(
        {
            "ok": True,
            "defaults": {
                "start_date": today,
                "end_date": end,
                "loyalty_points": 0,
                "status": "Active",
                "tier": "Gold",
                "points_per_dollar": POINTS_PER_DOLLAR,
            },
            "menu": MENU_ITEMS,
        }
    )


@app.get("/api/menu")
def api_menu():
    return jsonify({"ok": True, "menu": MENU_ITEMS})


if __name__ == "__main__":
    print("CoHee CUPPEE Membership — http://127.0.0.1:5050")
    print(f"Admin password: (set CUPPEE_ADMIN_PASSWORD or default 'cohee2026')")
    app.run(host="0.0.0.0", port=5050, debug=True)
