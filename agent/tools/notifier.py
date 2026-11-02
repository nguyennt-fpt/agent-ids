import json
import os
import sqlite3
from datetime import datetime

import httpx

WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
DB_PATH = os.getenv("DASHBOARD_DB", "/app/data/events.db")

_db_ready = False


# columns added after the initial release (safe incremental migration).
# grounded: "1"/"0" = the model's cited evidence was / was not in the event, NULL = not checked
_EXTRA_COLUMNS = ("mode", "eid", "mitre", "severity", "note", "confidence", "grounded")


def _ensure_db() -> None:
    global _db_ready
    if _db_ready:
        return
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            src_ip    TEXT,
            attack    TEXT,
            action    TEXT,
            detail    TEXT,
            mode      TEXT,
            eid       TEXT,
            mitre     TEXT,
            severity  TEXT,
            note      TEXT,
            confidence TEXT,
            grounded  TEXT
        )
    """)
    # migrate older DBs that predate the extra columns
    existing = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    for col in _EXTRA_COLUMNS:
        if col not in existing:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    conn.commit()
    conn.close()
    _db_ready = True


def send_alert(message: str, src_ip: str = "", attack_type: str = "", action: str = "",
               eid: str = "", mode: str = "", mitre: str = "", severity: str = "",
               note: str = "", confidence: float | None = None,
               grounded: str | None = None) -> dict:
    """Log event to SQLite and optionally send to webhook."""
    _ensure_db()
    ts = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO events (ts, src_ip, attack, action, detail, mode, eid, "
        "mitre, severity, note, confidence, grounded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, src_ip, attack_type, action, message, mode, eid, mitre, severity, note,
         confidence, grounded),
    )
    conn.commit()
    conn.close()

    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json={"text": message, "ts": ts}, timeout=5)
        except Exception:
            pass

    print(f"[ALERT] {ts} | {src_ip} | {attack_type} | {action} | {message}")
    return {"status": "sent", "ts": ts}
