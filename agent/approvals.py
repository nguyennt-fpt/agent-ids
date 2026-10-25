"""Approval queue for the human-in-the-loop gate outside the demo (G5).

With AUTO_APPROVE=false, a block the risk gate escalates pauses its batch's
graph run (LangGraph interrupt; state kept by a SQLite checkpointer, so it
survives an agent restart). The escalated items land here; an analyst answers
with `python approve.py` inside the agent container; the main loop resumes the
paused run once every item of that run is answered.

Answers: approve (block), warn (attack, but don't firewall), benign (false
positive -> log). An item left unanswered for HITL_TIMEOUT_S counts as warn —
never an unreviewed block. The dashboard stays read-only (CLAUDE.md).
"""

import os
import sqlite3
import time

DB_PATH = os.getenv("DASHBOARD_DB", "/app/data/events.db")
TIMEOUT_S = int(os.getenv("HITL_TIMEOUT_S", "900"))
ANSWERS = ("approve", "warn", "benign")


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.execute("""
        CREATE TABLE IF NOT EXISTS approvals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL,
            thread_id   TEXT,
            eid         TEXT,
            src_ip      TEXT,
            attack_type TEXT,
            confidence  REAL,
            note        TEXT,
            answer      TEXT,
            answered_ts REAL,
            resumed     INTEGER DEFAULT 0
        )
    """)
    return c


def add_pending(thread_id: str, items: list[dict]) -> None:
    """items: the interrupt payload's `pending` list (eid, src_ip, attack_type, ...)."""
    c = _conn()
    c.executemany(
        "INSERT INTO approvals (ts, thread_id, eid, src_ip, attack_type, confidence, note) "
        "VALUES (?,?,?,?,?,?,?)",
        [(time.time(), thread_id, i.get("eid", ""), i.get("src_ip", ""), i.get("attack_type", ""),
          i.get("confidence"), i.get("analyst_note", "")) for i in items])
    c.commit()
    c.close()


def pending() -> list[dict]:
    """Unanswered items of runs not resumed yet, oldest first."""
    c = _conn()
    c.row_factory = sqlite3.Row
    rows = c.execute("SELECT * FROM approvals WHERE answer IS NULL AND resumed = 0 "
                     "ORDER BY id").fetchall()
    c.close()
    return [dict(r) for r in rows]


def answer(eid: str, value: str) -> bool:
    """Answer the open item for `eid`; False if there is none (or a bad value)."""
    if value not in ANSWERS:
        return False
    c = _conn()
    cur = c.execute("UPDATE approvals SET answer = ?, answered_ts = ? "
                    "WHERE eid = ? AND answer IS NULL AND resumed = 0", (value, time.time(), eid))
    c.commit()
    c.close()
    return cur.rowcount > 0


def ready_threads(now: float | None = None) -> dict[str, dict[str, str]]:
    """thread_id -> {eid: answer} for paused runs whose every item is answered
    or has expired (expired -> "warn")."""
    now = time.time() if now is None else now
    c = _conn()
    rows = c.execute("SELECT thread_id, eid, answer, ts FROM approvals WHERE resumed = 0").fetchall()
    c.close()
    threads: dict[str, dict] = {}
    for thread_id, eid, ans, ts in rows:
        if ans is None and now - ts >= TIMEOUT_S:
            ans = "warn"
        threads.setdefault(thread_id, {})[eid] = ans
    return {t: a for t, a in threads.items() if all(v is not None for v in a.values())}


def items(thread_id: str) -> list[dict]:
    """The escalated items of one paused run (eid, attack_type the model proposed)."""
    c = _conn()
    rows = c.execute("SELECT eid, attack_type FROM approvals WHERE thread_id = ? ORDER BY id",
                     (thread_id,)).fetchall()
    c.close()
    return [{"eid": e, "attack_type": a} for e, a in rows]


def mark_resumed(thread_id: str) -> None:
    c = _conn()
    c.execute("UPDATE approvals SET resumed = 1 WHERE thread_id = ?", (thread_id,))
    c.commit()
    c.close()
