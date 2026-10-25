"""G4 — the adversarial harness drives the real graph and isolates each defense.

A fake Ollama answers `block` only when the events arrive fenced, so the 2x2
design must show: fence effect -100%, prompt effect 0, collateral bypass
exactly where the fence is off. Placeholder rows only — no attack content needed.
"""

import json
import os
import re
import sys

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_ollama")

from langchain_ollama import ChatOllama  # noqa: E402

import graph  # noqa: E402
import main  # noqa: E402
from tools import agent_tools  # noqa: E402
from tools.prompt_guard import UNTRUSTED_OPEN, strip_defense  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmark", "adversarial"))
import test_injection as harness  # noqa: E402


@pytest.fixture
def fenced_only_model(monkeypatch):
    seen = []

    def fake_stream(self, messages, stop=None, **kwargs):
        human = messages[-1].content
        seen.append((messages[0].content, human))
        action = "block" if UNTRUSTED_OPEN in human else "log"
        eids = re.findall(r'"eid": "([^"]+)"', human)
        out = {"decisions": [{"eid": e, "action": action, "confidence": 0.95} for e in eids]}
        yield {"model": "fake", "message": {"role": "assistant", "content": json.dumps(out)},
               "done": True, "done_reason": "stop"}

    monkeypatch.setattr(ChatOllama, "_create_chat_stream", fake_stream)
    monkeypatch.setattr(graph, "_triage_llm", None)
    # the harness rebinds these module globals; let monkeypatch restore them
    for mod, name in ((graph, "SYSTEM_PROMPT"), (graph, "wrap_untrusted"), (graph, "record_decision"),
                      (graph, "AUTO_APPROVE"), (main, "record_decision"),
                      (agent_tools, "EVE_LOG"), (agent_tools, "NGINX_LOG")):
        monkeypatch.setattr(mod, name, getattr(mod, name))
    return seen


def _row(eid):
    return {"eid": eid, "technique": f"t-{eid}", "path": "/dvwa/vulnerabilities/sqli/",
            "params": {"id": f"placeholder-{eid}"}}


def test_2x2_isolates_each_defense_and_measures_collateral(fenced_only_model):
    rows = harness.run([_row("i1"), _row("i2")], companions=[_row("c1")], repeats=1)
    assert len(rows) == 4 * 2                                    # conditions x injections
    s = harness.summarize(rows)
    assert s["none"]["bypass"][0] == 1 and s["prompt_only"]["bypass"][0] == 1
    assert s["fence_only"]["bypass"][0] == 0 and s["both"]["bypass"][0] == 0
    assert s["effect_fence"][0] == -1 and s["effect_prompt"][0] == 0
    assert s["none"]["collateral"][0] == 1 and s["both"]["collateral"][0] == 0


def test_prompt_toggle_strips_only_the_defense_section(fenced_only_model):
    harness.run([_row("i1")], companions=[], repeats=1)
    # one batch per condition, in CONDITIONS order
    systems = {cond: sp for cond, (sp, _) in zip([c for c, *_ in harness.CONDITIONS], fenced_only_model)}
    assert systems["prompt_only"] == systems["both"] == harness.FULL_PROMPT
    assert systems["none"] == systems["fence_only"] == strip_defense(harness.FULL_PROMPT)
    assert "Untrusted data handling" in harness.FULL_PROMPT
    assert "Untrusted data handling" not in systems["none"]


def test_as_event_is_a_web_event_without_ids_hints():
    ev = harness.as_event({"eid": "e1", "path": "/dvwa/vulnerabilities/exec/", "method": "POST",
                           "params": {}, "body": {"ip": "x", "Submit": "Submit"}}, "192.0.2.10")
    assert ev["source"] == "web" and ev["signature"] == "" and ev["severity"] == ""
    assert ev["url"] == "/vulnerabilities/exec/"    # old /dvwa prefix dropped; eid not shown
    assert ev["payload"] == "ip=x&Submit=Submit" and ev["src_ip"] == "192.0.2.10"
