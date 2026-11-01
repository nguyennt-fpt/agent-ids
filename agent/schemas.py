"""Structured-output contract for the LangGraph agent (bài 07 — Planning /
Structured Output).

Pydantic + a fixed `Action` enum stop the model inventing actions or extra
fields: the graph consumes validated objects, and the `eid`-keyed shape stays
byte-identical to what the benchmark harness (`score.py`) already joins on — so
the evaluation harness never has to change.
"""

import json
from enum import Enum

from pydantic import BaseModel, Field, ValidationError, field_validator


class Action(str, Enum):
    block = "block"   # attack, contain the source
    warn = "warn"     # attack, flag but don't firewall
    log = "log"       # benign / informational


class Decision(BaseModel):
    eid: str = Field(description="Event id this decision is for — copied verbatim from the event.")
    action: Action = Field(description="block/warn for attacks, log for benign.")
    attack_type: str = Field(
        default="none",
        description="sqli / xss / cmdi / lfi / rfi / bruteforce / scan / none",
    )
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Probability that the event is an attack: 0 = certainly benign, "
                    "1 = certainly an attack. One scale for every action, log included.",
    )
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique id, e.g. T1190")
    severity: str = Field(default="", description="low / medium / high / critical")
    analyst_note: str = Field(default="", description="1–2 sentence SOC L1 note (what/why/action)")
    reason: str = Field(default="", description="Short technical justification.")

    @field_validator("action", mode="before")
    @classmethod
    def _unknown_action_is_warn(cls, v: object) -> str:
        """Fail closed per item: an action outside the enum (e.g. "alert") is
        treated as a flagged attack, never silently benign."""
        a = (v.value if isinstance(v, Action) else str(v)).strip().lower()
        return a if a in {x.value for x in Action} else Action.warn.value

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: object) -> float:
        try:
            return max(0.0, min(1.0, float(v)))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0.0


class DecisionList(BaseModel):
    """Top-level object the model returns: {"decisions": [Decision, ...]}."""

    decisions: list[Decision] = Field(default_factory=list)


def _complete_items(text: str) -> list:
    """Items of the `decisions` array, or — if the JSON was cut off mid-array
    (num_predict hit) — every item that was fully written before the cut."""
    try:
        obj = json.loads(text)
        items = obj.get("decisions", []) if isinstance(obj, dict) else obj
        return items if isinstance(items, list) else []
    except json.JSONDecodeError:
        pass
    i = text.find("[")
    if i < 0:
        return []
    decoder, items, i = json.JSONDecoder(), [], i + 1
    while True:
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        if i >= len(text) or text[i] != "{":
            return items
        try:
            item, i = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            return items            # the truncated tail
        items.append(item)


def salvage_decisions(text: str) -> list[Decision]:
    """Recover the valid decisions from raw model output that failed to parse
    as a whole. Each item is validated on its own, so one bad item (or a
    truncated tail) no longer discards the whole batch."""
    out = []
    for item in _complete_items(text):
        try:
            out.append(Decision.model_validate(item))
        except ValidationError:
            continue
    return out
