"""Validation pipeline for agent-proposed Suricata rules (Trụ 4B).

Four gates ensure a self-generated rule is correct AND improves the system
(monotonic improvement), never degrades it:

  Gate 1 Syntax    — structural check (+ real `suricata -T` if SURICATA_BIN set)
  Gate 2 Shadow    — precision/recall of the rule on a held-out set; promote only if precision >= 0.95
  Gate 3 Regression— F1 on a fixed golden set must NOT drop vs the active rule set
  Gate 4 Runtime   — (recorded for monitoring) audit trail; runtime FP -> auto-disable

NOTE: gates 2/3 approximate Suricata detection by evaluating the rule's
`content`/`pcre` matchers against request text — enough to prove the pipeline +
learning curve offline. Set SURICATA_BIN to add a real `suricata -T` syntax gate.
"""

import os
import re
import sqlite3
import subprocess
from datetime import datetime

DB_PATH = os.getenv("MEMORY_DB", os.getenv("DASHBOARD_DB", "/app/data/events.db"))
SURICATA_BIN = os.getenv("SURICATA_BIN", "")
MIN_PRECISION = float(os.getenv("RULE_MIN_PRECISION", "0.95"))

_RULE_RE = re.compile(
    r"^\s*(alert|drop|reject|pass)\s+\S+\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s*\((.*)\)\s*$"
)
_CONTENT_RE = re.compile(r'content:\s*"((?:[^"\\]|\\.)*)"', re.I)
_PCRE_RE = re.compile(r'pcre:\s*"/((?:[^"/\\]|\\.)*)/[a-zA-Z]*"', re.I)


# ─── rule parsing / simulated matching ────────────────────────────────────────

def extract_matchers(rule: str) -> tuple[list[str], list[str]]:
    contents = [m.replace('\\"', '"') for m in _CONTENT_RE.findall(rule)]
    pcres = _PCRE_RE.findall(rule)
    return contents, pcres


def rule_matches(rule: str, text: str) -> bool:
    """Approximate Suricata match: all `content` present AND all `pcre` match."""
    contents, pcres = extract_matchers(rule)
    if not contents and not pcres:
        return False
    low = text.lower()
    for c in contents:
        if c.lower() not in low:
            return False
    for p in pcres:
        try:
            if not re.search(p, text, re.I):
                return False
        except re.error:
            return False
    return True


def _prf(rules: list[str], dataset: list[dict]) -> tuple[float, float, float]:
    """Precision/Recall/F1 of a rule SET over dataset [{text,label}]."""
    tp = fp = fn = tn = 0
    for s in dataset:
        pred_mal = any(rule_matches(r, s["text"]) for r in rules)
        gt_mal = s["label"] == "malicious"
        if gt_mal and pred_mal:
            tp += 1
        elif gt_mal:
            fn += 1
        elif pred_mal:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


# ─── gates ────────────────────────────────────────────────────────────────────

def gate1_syntax(rule: str) -> tuple[bool, str]:
    rule = rule.strip()
    if not _RULE_RE.match(rule):
        return False, "structural syntax invalid (header/options)"
    if "sid:" not in rule:
        return False, "missing sid"
    if "msg:" not in rule:
        return False, "missing msg"
    if SURICATA_BIN and os.path.exists(SURICATA_BIN):
        try:
            import tempfile
            with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False) as f:
                f.write(rule + "\n")
                path = f.name
            res = subprocess.run([SURICATA_BIN, "-T", "-S", path],
                                 capture_output=True, text=True, timeout=30)
            os.unlink(path)
            if res.returncode != 0:
                return False, f"suricata -T failed: {res.stderr.strip()[:120]}"
        except Exception as e:
            return False, f"suricata -T error: {e}"
    return True, "ok"


def gate2_shadow(rule: str, holdout: list[dict]) -> tuple[bool, float, float]:
    p, r, _ = _prf([rule], holdout)
    return p >= MIN_PRECISION, p, r


def gate3_regression(active_rules: list[str], candidate: str,
                     golden: list[dict]) -> tuple[bool, float, float]:
    _, _, f1_before = _prf(active_rules, golden)
    _, _, f1_after = _prf(active_rules + [candidate], golden)
    return f1_after >= f1_before - 1e-9, f1_before, f1_after


# ─── audit storage ────────────────────────────────────────────────────────────

def _ensure_rules_table() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT,
            rule      TEXT,
            status    TEXT,
            precision REAL,
            recall    REAL,
            f1_before REAL,
            f1_after  REAL,
            epoch     INTEGER,
            reason    TEXT
        )
    """)
    c.commit()
    c.close()


def record_rule(rule: str, status: str, precision: float = 0.0, recall: float = 0.0,
                f1_before: float = 0.0, f1_after: float = 0.0, epoch: int = 0,
                reason: str = "") -> None:
    _ensure_rules_table()
    c = sqlite3.connect(DB_PATH)
    c.execute(
        "INSERT INTO rules (ts, rule, status, precision, recall, f1_before, f1_after, "
        "epoch, reason) VALUES (?,?,?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), rule, status, precision, recall,
         f1_before, f1_after, epoch, reason),
    )
    c.commit()
    c.close()


def validate_rule(rule: str, holdout: list[dict], golden: list[dict],
                  active_rules: list[str], epoch: int = 0) -> dict:
    """Run the 4-gate pipeline. Returns a verdict and records it for audit."""
    ok, msg = gate1_syntax(rule)
    if not ok:
        record_rule(rule, "rejected", epoch=epoch, reason=f"gate1: {msg}")
        return {"status": "rejected", "gate": 1, "reason": msg}

    promote, precision, recall = gate2_shadow(rule, holdout)
    if not promote:
        record_rule(rule, "pending", precision=precision, recall=recall, epoch=epoch,
                    reason=f"gate2: precision {precision:.2f} < {MIN_PRECISION}")
        return {"status": "pending", "gate": 2, "precision": precision, "recall": recall}

    keep, f1_before, f1_after = gate3_regression(active_rules, rule, golden)
    if not keep:
        record_rule(rule, "rejected", precision=precision, recall=recall,
                    f1_before=f1_before, f1_after=f1_after, epoch=epoch,
                    reason=f"gate3: F1 {f1_before:.3f}->{f1_after:.3f} regression")
        return {"status": "rejected", "gate": 3, "f1_before": f1_before, "f1_after": f1_after}

    record_rule(rule, "active", precision=precision, recall=recall,
                f1_before=f1_before, f1_after=f1_after, epoch=epoch, reason="passed all gates")
    return {"status": "active", "gate": 4, "precision": precision, "recall": recall,
            "f1_before": f1_before, "f1_after": f1_after}
