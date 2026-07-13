"""Experience memory for the agent (Trụ 4A).

Stores past decisions + ground-truth feedback, retrieves similar past cases
(prioritizing mistakes) to inject as few-shot lessons. Embeddings via Ollama
`nomic-embed-text`; if unavailable, falls back to token-overlap similarity so
the logic still works (and is testable offline).
"""

import json
import math
import os
import sqlite3
from datetime import datetime

import httpx

DB_PATH = os.getenv("MEMORY_DB", os.getenv("DASHBOARD_DB", "/app/data/events.db"))
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")

_ready = False


def _conn():
    return sqlite3.connect(DB_PATH)


def _ensure() -> None:
    global _ready
    if _ready:
        return
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = _conn()
    c.execute("""
        CREATE TABLE IF NOT EXISTS experience (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            eid          TEXT,
            signature    TEXT,
            payload      TEXT,
            attack_type  TEXT,
            decision     TEXT,
            ground_truth TEXT,
            was_correct  INTEGER,
            lesson       TEXT,
            epoch        INTEGER,
            ts           TEXT,
            embedding    TEXT
        )
    """)
    c.commit()
    c.close()
    _ready = True


# ─── embedding / similarity ───────────────────────────────────────────────────

def _embed(text: str) -> list[float] | None:
    try:
        r = httpx.post(f"{OLLAMA_HOST}/api/embeddings",
                       json={"model": EMBED_MODEL, "prompt": text}, timeout=30)
        r.raise_for_status()
        emb = r.json().get("embedding")
        return emb if isinstance(emb, list) and emb else None
    except Exception:
        return None


def _tokens(text: str) -> set[str]:
    return set("".join(ch.lower() if ch.isalnum() else " " for ch in text).split())


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# ─── public API ───────────────────────────────────────────────────────────────

def add_experience(eid: str, signature: str, payload: str, attack_type: str,
                   decision: str, epoch: int = 0) -> None:
    _ensure()
    emb = _embed(f"{signature} {payload}")
    c = _conn()
    c.execute(
        "INSERT INTO experience (eid, signature, payload, attack_type, decision, "
        "ground_truth, was_correct, lesson, epoch, ts, embedding) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (eid, signature, payload, attack_type, decision, "", None, "", epoch,
         datetime.utcnow().isoformat(), json.dumps(emb) if emb else None),
    )
    c.commit()
    c.close()


def make_lesson(attack_type: str, predicted: str, truth: str, payload: str) -> str:
    """Template reflection — what went wrong and how to fix it next time."""
    snippet = (payload or "")[:80]
    if truth == "malicious" and predicted in ("log", "", "none"):
        return (f"MISSED a {attack_type} attack (predicted benign). Payload like "
                f"`{snippet}` IS an attack — flag similar patterns as malicious.")
    if truth == "benign" and predicted in ("block", "warn"):
        return (f"FALSE POSITIVE: blocked benign traffic as {attack_type}. Content like "
                f"`{snippet}` is benign — do not block on keyword resemblance alone.")
    return ""


def record_feedback(eid: str, ground_truth: str, predicted: str, attack_type: str,
                    payload: str) -> bool:
    """Mark whether the past decision was correct + attach a lesson if wrong."""
    _ensure()
    pred_mal = predicted in ("block", "warn")
    correct = (ground_truth == "malicious") == pred_mal
    lesson = "" if correct else make_lesson(attack_type, predicted, ground_truth, payload)
    c = _conn()
    c.execute(
        "UPDATE experience SET ground_truth=?, was_correct=?, lesson=? WHERE eid=?",
        (ground_truth, int(correct), lesson, eid),
    )
    c.commit()
    c.close()
    return correct


def retrieve_similar(query_text: str, k: int = 3, prefer_mistakes: bool = True) -> list[dict]:
    """Return the k most relevant *learned* past cases (those with feedback)."""
    _ensure()
    c = _conn()
    rows = c.execute(
        "SELECT signature, payload, attack_type, ground_truth, was_correct, lesson, embedding "
        "FROM experience WHERE was_correct IS NOT NULL"
    ).fetchall()
    c.close()
    if not rows:
        return []

    q_emb = _embed(query_text)
    scored = []
    for sig, payload, atk, truth, correct, lesson, emb_json in rows:
        case_text = f"{sig} {payload}"
        if q_emb and emb_json:
            sim = _cosine(q_emb, json.loads(emb_json))
        else:
            sim = _jaccard(query_text, case_text)
        if prefer_mistakes and not correct:
            sim += 0.15            # boost lessons learned from mistakes
        scored.append((sim, {"attack_type": atk, "ground_truth": truth,
                             "was_correct": bool(correct), "lesson": lesson,
                             "payload": payload[:120]}))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:k]]


def format_for_prompt(cases: list[dict]) -> str:
    if not cases:
        return ""
    lines = ["## Lessons from past cases (learn from these):"]
    for i, c in enumerate(cases, 1):
        verdict = "CORRECT" if c["was_correct"] else "MISTAKE"
        note = c["lesson"] or f"{c['ground_truth']} ({c['attack_type']})"
        lines.append(f"{i}. [{verdict}] {note}")
    return "\n".join(lines)
