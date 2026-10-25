"""G5 — HITL outside the demo: the main loop pauses an escalated batch in a
checkpointed thread, keeps going, and resumes it from the approval queue."""

import json
import re
import sqlite3

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_ollama")
pytest.importorskip("langgraph.checkpoint.sqlite")

from langchain_ollama import ChatOllama  # noqa: E402
from langgraph.checkpoint.sqlite import SqliteSaver  # noqa: E402

import approvals  # noqa: E402
import graph  # noqa: E402
import main  # noqa: E402

EVENTS = [{"eid": "e1", "source": "ids", "severity": 1, "signature": "SQLi", "src_ip": "198.51.100.7"},
          {"eid": "e2", "source": "web", "severity": "", "signature": "", "src_ip": "198.51.100.8"}]


@pytest.fixture
def hitl(monkeypatch, tmp_path):
    """Fake model: e1 = low-confidence block (escalated), others benign."""
    def fake_stream(self, messages, stop=None, **kwargs):
        eids = re.findall(r'"eid": "([^"]+)"', messages[-1].content)
        out = {"decisions": [{"eid": e, "action": "block" if e == "e1" else "log",
                              "attack_type": "sqli" if e == "e1" else "none",
                              "confidence": 0.85 if e == "e1" else 0.95} for e in eids]}
        yield {"model": "fake", "message": {"role": "assistant", "content": json.dumps(out)},
               "done": True, "done_reason": "stop"}

    monkeypatch.setattr(ChatOllama, "_create_chat_stream", fake_stream)
    monkeypatch.setattr(graph, "_triage_llm", None)
    monkeypatch.setattr(graph, "AUTO_APPROVE", False)
    monkeypatch.setattr(approvals, "DB_PATH", str(tmp_path / "events.db"))
    rows, fed = [], []
    monkeypatch.setattr(graph, "record_decision", lambda **kw: rows.append(kw))
    monkeypatch.setattr(main, "record_decision", lambda **kw: rows.append(kw))
    import tools.memory
    monkeypatch.setattr(tools.memory, "record_feedback", lambda *a: fed.append(a))
    saver = SqliteSaver(sqlite3.connect(tmp_path / "ckpt.db", check_same_thread=False))
    return graph.build_graph(saver), rows, fed


def _actions(rows):
    return {r["eid"]: r["action"] for r in rows}


@pytest.mark.parametrize("batch,acted", [(15, {}), (1, {"e2": "log"})])
def test_escalated_batch_waits_without_blocking_the_loop(hitl, monkeypatch, batch, acted):
    monkeypatch.setattr(main, "TRIAGE_BATCH", batch)
    app, rows, _ = hitl
    decided, retries, paused = set(), {}, {}
    main.process_agent_events(app, list(EVENTS), decided, retries, paused)
    # the escalated batch waits whole, nothing retried; one event per call: only e1 waits
    assert _actions(rows) == acted and decided == set(acted) and retries == {}
    assert len(paused) == 1 and [p["eid"] for p in approvals.pending()] == ["e1"]
    main.resume_approved(app, decided, retries, paused)          # not answered yet: still waits
    assert _actions(rows) == acted and len(paused) == 1


@pytest.mark.parametrize("answer,want,truth", [("approve", "block", "malicious"),
                                               ("warn", "warn", "malicious"),
                                               ("benign", "log", "benign")])
def test_answer_resumes_the_run_and_feeds_memory(hitl, answer, want, truth):
    app, rows, fed = hitl
    decided, retries, paused = set(), {}, {}
    main.process_agent_events(app, list(EVENTS), decided, retries, paused)
    assert approvals.answer("e1", answer)
    main.resume_approved(app, decided, retries, paused, memory=True)
    assert _actions(rows) == {"e1": want, "e2": "log"}
    assert decided == {"e1", "e2"} and paused == {} and approvals.pending() == []
    assert [(f[0], f[1], f[2]) for f in fed] == [("e1", truth, "block")]   # model proposed block


def test_expired_approval_becomes_warn(hitl, monkeypatch):
    app, rows, _ = hitl
    decided, retries, paused = set(), {}, {}
    main.process_agent_events(app, list(EVENTS), decided, retries, paused)
    monkeypatch.setattr(approvals, "TIMEOUT_S", 0)
    main.resume_approved(app, decided, retries, paused)
    assert _actions(rows)["e1"] == "warn"


def test_paused_run_survives_an_agent_restart(hitl):
    app, rows, _ = hitl
    main.process_agent_events(app, list(EVENTS), set(), {}, {})
    approvals.answer("e1", "approve")
    decided = set()
    main.resume_approved(app, decided, {}, paused={})           # new process: no in-memory batch
    assert _actions(rows)["e1"] == "block" and "e1" in decided
