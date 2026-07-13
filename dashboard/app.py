import os
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, render_template

DB_PATH = os.getenv("DB_PATH", "/app/data/events.db")

app = Flask(__name__)


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_table() -> None:
    try:
        conn = _get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                src_ip TEXT,
                attack TEXT,
                action TEXT,
                detail TEXT,
                mode TEXT,
                eid TEXT,
                mitre TEXT,
                severity TEXT,
                note TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    _ensure_table()
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/rules")
def api_rules():
    """Self-evolving rule audit trail (Trụ 4B)."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT ts, rule, status, precision, recall, f1_before, f1_after, epoch, reason "
            "FROM rules ORDER BY id DESC LIMIT 100"
        ).fetchall()
        out = [dict(r) for r in rows]
    except sqlite3.OperationalError:
        out = []  # rules table not created yet
    conn.close()
    return jsonify(out)


@app.route("/api/stats")
def api_stats():
    _ensure_table()
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action='block'").fetchone()[0]
    by_attack = conn.execute(
        "SELECT attack, COUNT(*) as cnt FROM events GROUP BY attack ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    by_ip = conn.execute(
        "SELECT src_ip, COUNT(*) as cnt FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    by_mitre = conn.execute(
        "SELECT mitre, COUNT(*) as cnt FROM events "
        "WHERE mitre IS NOT NULL AND mitre <> '' GROUP BY mitre ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM events "
        "WHERE severity IS NOT NULL AND severity <> '' GROUP BY severity ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return jsonify({
        "total_events": total,
        "total_blocked": blocked,
        "by_attack_type": [dict(r) for r in by_attack],
        "top_attacker_ips": [dict(r) for r in by_ip],
        "by_mitre": [dict(r) for r in by_mitre],
        "by_severity": [dict(r) for r in by_severity],
    })


if __name__ == "__main__":
    _ensure_table()
    app.run(host="0.0.0.0", port=5000, debug=False)
