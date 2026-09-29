"""C2 — graph smoke test without Ollama: triage salvage + fallback (B2/B3),
the investigate tool-loop, and the HITL interrupt (C1).

Triage uses the real ChatOllama structured-output chain; only the Ollama HTTP
stream is replaced, so the include_raw / parse-failure behavior is the
library's own. Needs langgraph + langchain-ollama installed (skipped otherwise).
"""

import json

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_ollama")

from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_ollama import ChatOllama  # noqa: E402
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

import gate  # noqa: E402
import graph  # noqa: E402
from schemas import Decision  # noqa: E402


@pytest.fixture
def ollama(monkeypatch):
    """Scripted Ollama replies: append a str (message content) or an Exception."""
    replies = []

    def fake_stream(self, messages, stop=None, **kwargs):
        r = replies.pop(0)
        if isinstance(r, Exception):
            raise r
        yield {"model": "fake", "message": {"role": "assistant", "content": r},
               "done": True, "done_reason": "length"}

    monkeypatch.setattr(ChatOllama, "_create_chat_stream", fake_stream)
    monkeypatch.setattr(graph, "_triage_llm", None)
    return replies


@pytest.fixture
def recorded(monkeypatch):
    rows = []
    monkeypatch.setattr(graph, "record_decision", lambda **kw: rows.append(kw))
    return rows


def _dec(eid, action, conf=0.95):
    return {"eid": eid, "action": action, "attack_type": "sqli" if action != "log" else "none",
            "confidence": conf, "mitre_technique": "", "severity": "", "analyst_note": "",
            "reason": "r"}


EVENTS = [
    {"eid": "e1", "source": "ids", "severity": 1, "signature": "SQL Injection", "src_ip": "9.9.9.9"},
    {"eid": "e2", "source": "web", "severity": "", "signature": "", "src_ip": "9.9.9.9"},
    {"eid": "e3", "source": "ids", "severity": 1, "signature": "SQL Injection", "src_ip": "9.9.9.9"},
    {"eid": "e4", "source": "ids", "severity": 3, "signature": "Scanner", "src_ip": "9.9.9.9"},
    {"eid": "e5", "source": "web", "severity": "", "signature": "", "src_ip": "9.9.9.9"},
]


def _run(events=EVENTS, app=None, config=None):
    app = app or graph.build_graph()
    return app.invoke({"events": events, "decisions": [], "ambiguous_eids": [],
                       "decided_eids": []}, config)


def _actions(rows):
    return {r["eid"]: r["action"] for r in rows}


def test_truncated_triage_is_salvaged_and_missing_events_never_default_benign(
        ollama, recorded, capsys):
    full = json.dumps({"decisions": [_dec("e1", "block"), _dec("e2", "log"),
                                     _dec("e3", "block")]})
    ollama.append(full[: full.index('"e3"') + 6])        # cut right after e3's eid
    result = _run()

    assert "salvaged 2/5 decision(s)" in capsys.readouterr().out

    assert _actions(recorded) == {"e1": "block", "e2": "log",   # salvaged from the model
                                  "e3": "warn",                  # IDS sev 1 -> rule fallback
                                  "e4": "log"}                   # IDS sev 3 -> rule fallback
    assert set(result["decided_eids"]) == {"e1", "e2", "e3", "e4"}   # e5 (web) -> caller retries


def test_triage_error_falls_back_for_ids_and_leaves_web_undecided(ollama, recorded):
    ollama.append(ConnectionError("ollama down"))
    result = _run()
    assert _actions(recorded) == {"e1": "warn", "e3": "warn", "e4": "log"}
    assert set(result["decided_eids"]) == {"e1", "e3", "e4"}


class _ScriptedLLM:
    def __init__(self, *outs):
        self.outs, self.seen = list(outs), []

    def invoke(self, messages):
        self.seen.append(messages)
        return self.outs.pop(0)


def test_ambiguous_event_goes_through_investigate_tool_loop(ollama, recorded, monkeypatch):
    ollama.append(json.dumps({"decisions": [_dec("e1", "warn", conf=0.5)]}))
    tools = _ScriptedLLM(
        AIMessage(content="", tool_calls=[{"name": "list_blocked_ips", "args": {}, "id": "c1"}]),
        AIMessage(content="enough context"))
    final = _ScriptedLLM(Decision(eid="not-e1", action="block", confidence=0.85))
    monkeypatch.setattr(graph, "_investigate_llm", lambda: tools)
    monkeypatch.setattr(graph, "_final_decision_llm", lambda: final)

    _run(events=EVENTS[:1])

    assert any(isinstance(m, ToolMessage) for m in final.seen[0])   # tool output fed back
    assert len(recorded) == 1
    assert recorded[0]["eid"] == "e1"                                # model's eid overridden
    assert recorded[0]["action"] == "block"


@pytest.mark.parametrize("answer,want", [("deny", "warn"), ("approve", "block")])
def test_hitl_gate_interrupts_and_resumes(ollama, recorded, monkeypatch, answer, want):
    monkeypatch.setattr(graph, "AUTO_APPROVE", False)
    monkeypatch.setattr(gate, "HITL_ALL_BLOCKS", True)
    ollama.append(json.dumps({"decisions": [_dec("e1", "block", conf=0.97)]}))
    app = graph.build_graph(checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": "t1"}}

    paused = _run(events=EVENTS[:1], app=app, config=config)
    assert paused.get("__interrupt__")
    assert recorded == []                                   # nothing acted on yet

    app.invoke(Command(resume={"e1": answer}), config)
    assert _actions(recorded) == {"e1": want}
