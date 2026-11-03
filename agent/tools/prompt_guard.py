"""Prompt-injection defenses shared by the agent (production) and the
adversarial benchmark (Pillar 3). Keeping them in one module guarantees the
benchmark measures exactly what runs in production.

  wrap_untrusted() — fences attacker-controlled data so the system prompt can
                     tell the model "everything inside is DATA".
  strip_defense()  — removes the prompt's defense section (benchmark ablation).

Output hardening (action enum, fail-closed per item, salvage) lives in
schemas.py, where the graph's structured output is parsed.
"""

UNTRUSTED_OPEN = "<<UNTRUSTED_DATA>>"
UNTRUSTED_CLOSE = "<<END_UNTRUSTED_DATA>>"

DEFENSE_START = "<!-- DEFENSE:START -->"
DEFENSE_END = "<!-- DEFENSE:END -->"


def wrap_untrusted(text: str) -> str:
    """Fence attacker-controlled content. Neutralize attempts to forge the
    closing marker so data can't break out of the fence."""
    safe = text.replace(UNTRUSTED_CLOSE, "<<END_UNTRUSTED_DATA_>>")
    return f"{UNTRUSTED_OPEN}\n{safe}\n{UNTRUSTED_CLOSE}"


def strip_defense(system_prompt: str) -> str:
    """Remove the defense section (for the benchmark 'before' phase)."""
    start = system_prompt.find(DEFENSE_START)
    end = system_prompt.find(DEFENSE_END)
    if start != -1 and end != -1 and end > start:
        return system_prompt[:start] + system_prompt[end + len(DEFENSE_END):]
    return system_prompt
