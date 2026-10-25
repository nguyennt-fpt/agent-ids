"""G5 — the approval queue behind the HITL gate (approvals.py, approve.py)."""

import pytest

import approvals
import approve


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(approvals, "DB_PATH", str(tmp_path / "events.db"))


ITEMS = [{"eid": "e1", "src_ip": "198.51.100.7", "attack_type": "sqli", "confidence": 0.8,
          "analyst_note": "n1"},
         {"eid": "e2", "src_ip": "198.51.100.8", "attack_type": "xss", "confidence": 0.7,
          "analyst_note": "n2"}]


def test_run_is_ready_only_when_every_item_is_answered():
    approvals.add_pending("t1", ITEMS)
    assert [p["eid"] for p in approvals.pending()] == ["e1", "e2"]
    assert approvals.answer("e1", "approve")
    assert approvals.ready_threads() == {}                    # e2 still open
    assert approvals.answer("e2", "benign")
    assert approvals.ready_threads() == {"t1": {"e1": "approve", "e2": "benign"}}
    assert [i["attack_type"] for i in approvals.items("t1")] == ["sqli", "xss"]


def test_unanswered_items_expire_as_warn_never_block(monkeypatch):
    approvals.add_pending("t1", ITEMS[:1])
    monkeypatch.setattr(approvals, "TIMEOUT_S", 60)
    assert approvals.ready_threads() == {}
    later = approvals.pending()[0]["ts"] + 61
    assert approvals.ready_threads(now=later) == {"t1": {"e1": "warn"}}


def test_resumed_runs_are_done_and_bad_answers_refused():
    approvals.add_pending("t1", ITEMS[:1])
    assert not approvals.answer("e1", "block")                # not one of approve/warn/benign
    assert not approvals.answer("nope", "approve")
    approvals.answer("e1", "warn")
    approvals.mark_resumed("t1")
    assert approvals.ready_threads() == {} and approvals.pending() == []
    assert not approvals.answer("e1", "approve")              # already resumed


def test_cli(capsys):
    approvals.add_pending("t1", ITEMS[:1])
    assert approve.main(["approve.py"]) == 0
    assert "e1" in capsys.readouterr().out
    assert approve.main(["approve.py", "e1", "benign"]) == 0
    assert approve.main(["approve.py", "e1", "approve"]) == 1   # no open item any more
    assert approve.main(["approve.py", "e1", "nonsense"]) == 2
