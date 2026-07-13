"""Structured-output contract for the LangGraph agent (bài 07 — Planning /
Structured Output).

Pydantic + a fixed `Action` enum stop the model inventing actions or extra
fields: the graph consumes validated objects, and the `eid`-keyed shape stays
byte-identical to what the benchmark harness (`score.py`) already joins on — so
the evaluation harness never has to change.
"""

from enum import Enum

from pydantic import BaseModel, Field, field_validator


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
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique id, e.g. T1190")
    severity: str = Field(default="", description="low / medium / high / critical")
    analyst_note: str = Field(default="", description="1–2 sentence SOC L1 note (what/why/action)")
    reason: str = Field(default="", description="Short technical justification.")

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
