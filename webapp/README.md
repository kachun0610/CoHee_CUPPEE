# CoHee · CUPPEE Membership Web App

Shop-side web app for the **CUPPEE** membership program at **CoHee**.

## Features

| Tab | Purpose |
|-----|---------|
| **Check** | Scan NFC card, show membership availability, record this visit’s purchase |
| **Admin** | Password-protected: create membership, AES-128 encrypt & write to NFC card |

### Card data (AES-128 encrypted)

- Name  
- Member ID  
- Loyalty points  
- Membership start date  
- Membership end date  
- Status & tier  

### Database

SQLite at `data/cuppee.db`:

- **members** — card fields stored as AES-128 encrypted JSON  
- **purchases** — visit items encrypted; amount & points in clear for reporting  

## Requirements

- Python 3.10+
- NFC reader (e.g. RF-IC02) + NTAG 424 DNA cards via PC/SC (`pyscard`)
- Without a reader, the app runs in **simulation mode** (demo write/read in memory)

## Setup

```bash
cd webapp
python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5050**

### Default admin password

`cohee2026`

Override with environment variables:

| Variable | Meaning |
|----------|---------|
| `CUPPEE_ADMIN_PASSWORD` | Admin tab password |
| `CUPPEE_CARD_AES_KEY` | 16-char AES-128 key for card payloads |
| `CUPPEE_DB_AES_KEY` | 16-char AES-128 key for DB fields |
| `CUPPEE_NTAG_AUTH_KEY` | 32 hex chars — NTAG 424 auth key (default all zeros) |
| `CUPPEE_SECRET_KEY` | Flask session secret |
| `CUPPEE_ALLOW_NFC_SIM` | `1` = allow simulation when no reader |

## Typical shop flow

1. **Admin** → unlock → fill member → *Create & write card* (cup on reader)  
2. **Check** → *Scan membership* → enter purchase → *Save purchase* (points update on card + DB)

## Note on Web NFC

Browsers cannot talk to desktop PC/SC readers. This app’s **Flask backend** drives the reader (same approach as the existing Tkinter demo). The browser UI only calls HTTP APIs.
