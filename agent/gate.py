"""Risk tiering + human-in-the-loop gate (bài 06 — Trustworthy Agents).

Mirrors the course's demo_human_in_the_loop.py: an action is classified into a
risk tier, and the high tier requires oversight. For an IDS responder the
disruptive, hard-to-reverse action is *blocking a source IP* (it can cut off a
legitimate user), so that is the high tier; warn is medium; log is benign.

The actual interrupt()/approval wiring lives in graph.py (Phase 2b); this module
just holds the tiering so it can be reused and unit-tested on its own.
"""

import os
import re

# lowest confidence at which a high-risk action may be auto-approved without a
# human, when AUTO_APPROVE is off (kept here so tests and the gate agree).
HIGH_RISK_AUTO_CONF = 0.90
# strict policy: every block needs a human, whatever the model's confidence.
# demo_hitl.py turns it on — a clear SQLi is (rightly) >= 0.90 and would
# otherwise never reach the human.
HITL_ALL_BLOCKS = os.getenv("HITL_ALL_BLOCKS", "false").lower() == "true"


def classify_risk(action: str) -> str:
    a = str(action).lower().strip()
    if a == "block":
        return "high"     # contains a source IP — disruptive, needs oversight
    if a == "warn":
        return "medium"
    return "low"          # log / benign / informational


def needs_human(action: str, confidence: float, grounded: bool = True) -> bool:
    """High-risk action below the auto-approve confidence, or whose stated
    evidence is not in the event (or any high-risk action under
    HITL_ALL_BLOCKS) → escalate to a human."""
    if classify_risk(action) != "high":
        return False
    return HITL_ALL_BLOCKS or not grounded or float(confidence or 0.0) < HIGH_RISK_AUTO_CONF


# What only an IDS alert could have told the model. On the 2026-11-01 test set,
# 3 false positives on web-only events gave "IDS severity 1/2" as the reason (the
# phrase was in the prompt's example until v4) although no alert had fired.
_IDS_CLAIM = re.compile(r"\b(ids|suricata|snort|sid\s*\d+)\b", re.I)
_SEV_CLAIM = re.compile(r"\bseverity\s*(?:level\s*)?[:=]?\s*([1-4])\b", re.I)
_ENC_CLAIM = re.compile(r"\b(encoded|encoding|obfuscat\w*|base64)\b", re.I)
_ENCODED = re.compile(r"%[0-9a-f]{2}|\\x[0-9a-f]{2}|&#\d+|\b0x[0-9a-f]{2,}|[A-Za-z0-9+/]{16,}={1,2}",
                      re.I)


def check_grounding(event: dict, decision: dict) -> str:
    """Why the evidence the model's reason/note cites is not in the event, or
    "" when nothing checkable is wrong. The flagged decision itself stands."""
    text = f"{decision.get('reason', '')} {decision.get('analyst_note', '')}"
    sev = _SEV_CLAIM.search(text)
    if event.get("source") == "web" and (sev or _IDS_CLAIM.search(text)):
        return "cites IDS evidence, but no IDS alert fired"
    if event.get("source") == "ids" and sev and str(event.get("severity")) != sev.group(1):
        return f"cites IDS severity {sev.group(1)}, the alert has {event.get('severity')}"
    if _ENC_CLAIM.search(text) and not _ENCODED.search(
            f"{event.get('url', '')} {event.get('payload', '')}"):
        return "claims an encoding the request does not contain"
    return ""
