import hmac
import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request

DB_PATH = os.getenv("DB_PATH", "/app/data/events.db")
# The dashboard is read-only except for answering escalated blocks (G5), and
# that needs this token; unset = approvals disabled (no open write endpoint).
APPROVAL_TOKEN = os.getenv("APPROVAL_TOKEN", "")
ANSWERS = ("approve", "warn", "benign")       # same as agent/approvals.py

app = Flask(__name__)


def _get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)    # the agent writes the same file
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


@app.route("/api/approvals")
def api_approvals():
    """Blocks the HITL gate escalated that still wait for a human (G5). The
    `approvals` table belongs to agent/approvals.py."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT eid, ts, src_ip, attack_type, confidence, note FROM approvals "
            "WHERE answer IS NULL AND resumed = 0 ORDER BY id").fetchall()
        pending = [dict(r) for r in rows]
    except sqlite3.OperationalError:
        pending = []          # the agent creates the table on its first escalation
    conn.close()
    return jsonify({"enabled": bool(APPROVAL_TOKEN), "now": time.time(), "pending": pending})


@app.route("/api/approvals/<eid>", methods=["POST"])
def api_answer(eid):
    """Answer one escalated block — the dashboard's only write. The token comes
    in a custom header, which a cross-site form cannot set (no CSRF)."""
    token = request.headers.get("X-Approval-Token", "")
    if not APPROVAL_TOKEN or not hmac.compare_digest(token.encode(), APPROVAL_TOKEN.encode()):
        return jsonify({"error": "approval token missing or wrong"}), 403
    answer = (request.get_json(silent=True) or {}).get("answer")
    if answer not in ANSWERS:
        return jsonify({"error": f"answer must be one of {', '.join(ANSWERS)}"}), 400
    conn = _get_db()
    try:
        cur = conn.execute("UPDATE approvals SET answer = ?, answered_ts = ? "
                           "WHERE eid = ? AND answer IS NULL AND resumed = 0",
                           (answer, time.time(), eid))
        conn.commit()
        changed = cur.rowcount
    except sqlite3.OperationalError:
        changed = 0
    conn.close()
    if not changed:
        return jsonify({"error": "no open approval for this eid"}), 404
    return jsonify({"eid": eid, "answer": answer})


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
