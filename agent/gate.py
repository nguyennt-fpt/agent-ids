"""Risk tiering + human-in-the-loop gate (bài 06 — Trustworthy Agents).

Mirrors the course's demo_human_in_the_loop.py: an action is classified into a
risk tier, and the high tier requires oversight. For an IDS responder the
disruptive, hard-to-reverse action is *blocking a source IP* (it can cut off a
legitimate user), so that is the high tier; warn is medium; log is benign.

The actual interrupt()/approval wiring lives in graph.py (Phase 2b); this module
just holds the tiering so it can be reused and unit-tested on its own.
"""

# lowest confidence at which a high-risk action may be auto-approved without a
# human, when AUTO_APPROVE is off (kept here so tests and the gate agree).
HIGH_RISK_AUTO_CONF = 0.90


def classify_risk(action: str) -> str:
    a = str(action).lower().strip()
    if a == "block":
        return "high"     # contains a source IP — disruptive, needs oversight
    if a == "warn":
        return "medium"
    return "low"          # log / benign / informational


def needs_human(action: str, confidence: float) -> bool:
    """High-risk action below the auto-approve confidence → escalate to a human."""
    return classify_risk(action) == "high" and float(confidence or 0.0) < HIGH_RISK_AUTO_CONF
