"""A4 — triage batches are chunked so one structured call can't overflow num_predict.
B4 — web-only events with no decision are retried alone, bounded, then fail closed."""

import pytest

import main


class FakeApp:
    """Stands in for the compiled graph: decides every event it is given,
    except the eids in `drop` (as if the model's output left them out)."""

    def __init__(self, drop=()):
        self.drop = set(drop)
        self.batches = []

    def invoke(self, state):
        eids = [e["eid"] for e in state["events"]]
        self.batches.append(eids)
        return {"decided_eids": [e for e in eids if e not in self.drop]}


@pytest.fixture
def recorded(monkeypatch):
    rows = []
    monkeypatch.setattr(main, "record_decision", lambda **kw: rows.append(kw))
    return rows


def _events(n, source="web"):
    return [{"eid": f"e{i}", "source": source, "src_ip": "1.2.3.4", "severity": ""}
            for i in range(n)]


def test_todo_is_split_into_triage_batches(monkeypatch, recorded):
    monkeypatch.setattr(main, "TRIAGE_BATCH", 15)
    app, decided, retries = FakeApp(), set(), {}
    main.process_agent_events(app, _events(40), decided, retries)
    assert [len(b) for b in app.batches] == [15, 15, 10]
    assert decided == {f"e{i}" for i in range(40)}
    assert retries == {} and recorded == []


def test_undecided_web_event_is_retried_alone_then_fails_closed(monkeypatch, recorded):
    monkeypatch.setattr(main, "MAX_RETRIES", 2)
    monkeypatch.setattr(main, "TRIAGE_BATCH", 15)                     # e1 first comes in a batch of 3
    app, decided, retries = FakeApp(drop={"e1"}), set(), {}

    main.process_agent_events(app, _events(3), decided, retries)      # attempt 1
    assert decided == {"e0", "e2"} and set(retries) == {"e1"}

    main.process_agent_events(app, [], decided, retries)              # attempt 2
    main.process_agent_events(app, [], decided, retries)              # attempt 3
    assert app.batches[1:] == [["e1"], ["e1"]]                        # alone each time
    assert "e1" in decided and retries == {}
    assert len(recorded) == 1
    assert recorded[0]["eid"] == "e1" and recorded[0]["action"] == "warn"

    main.process_agent_events(app, [], decided, retries)              # nothing left
    assert len(app.batches) == 3


def test_retry_succeeds_without_fail_closed_record(monkeypatch, recorded):
    app, decided, retries = FakeApp(drop={"e0"}), set(), {}
    main.process_agent_events(app, _events(1), decided, retries)
    app.drop.clear()                                                  # model recovers
    main.process_agent_events(app, [], decided, retries)
    assert decided == {"e0"} and retries == {} and recorded == []


def test_fresh_copy_of_a_retried_eid_replaces_the_retry(monkeypatch, recorded):
    app, decided, retries = FakeApp(drop={"e0"}), set(), {}
    main.process_agent_events(app, _events(1), decided, retries)
    app.drop.clear()
    ids_copy = [{"eid": "e0", "source": "ids", "src_ip": "1.2.3.4", "severity": 1}]
    main.process_agent_events(app, ids_copy, decided, retries)
    assert app.batches[1:] == [["e0"]]                                # processed once
    assert decided == {"e0"} and retries == {}
