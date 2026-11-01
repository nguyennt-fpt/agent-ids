"""A3 — per-mode wait before scoring (review bug C); A5 — MITRE id normalization."""

import json
import sqlite3
import time

import pytest

from alerted_eids import alerted_eids
from score import mitre_id, p95, wait_for_decisions


def _db(tmp_path, rows):
    db = str(tmp_path / "events.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, "
              "mode TEXT, eid TEXT, mitre TEXT)")
    c.executemany("INSERT INTO events (ts, action, mode, eid) VALUES ('t', 'log', ?, ?)", rows)
    c.commit()
    c.close()
    return db


SENT = {"e1": {"status": 200}, "e2": {"status": 404}, "e3": {"status": "error:timeout"}}


def test_agent_returns_once_every_answered_request_has_a_decision(tmp_path):
    # e3 never reached nginx (replay error) -> not expected
    db = _db(tmp_path, [("agent", "e1"), ("agent", "e2")])
    t0 = time.time()
    assert wait_for_decisions(db, "agent", SENT, settle_s=15, timeout_s=30) == 0
    assert time.time() - t0 < 1


def test_agent_waits_past_settle_window_then_times_out_and_reports(tmp_path, capsys):
    db = _db(tmp_path, [("agent", "e1"), ("rule_based", "e2")])   # other mode doesn't count
    t0 = time.time()
    assert wait_for_decisions(db, "agent", SENT, settle_s=0, timeout_s=3) == 1   # -> `undecided`
    assert time.time() - t0 >= 3          # did not stop on "stable count"
    assert "1/2 eids have no agent decision" in capsys.readouterr().out


def test_alerted_mode_waits_for_every_alerted_eid_not_a_quiet_db(tmp_path, capsys):
    db = _db(tmp_path, [("agent_ids", "e1")])
    t0 = time.time()
    wait_for_decisions(db, "agent_ids", SENT, settle_s=0, timeout_s=3, alerted={"e1", "e2"})
    assert time.time() - t0 >= 3                       # an LLM batch may still be running
    assert "1/2 eids have no agent_ids decision" in capsys.readouterr().out
    t0 = time.time()
    wait_for_decisions(db, "agent_ids", SENT, settle_s=15, timeout_s=30, alerted={"e1"})
    assert time.time() - t0 < 1


def _alert_line(eid, ts):
    return json.dumps({"event_type": "alert", "timestamp": ts,
                       "http": {"url": f"/vulnerabilities/sqli/?id=1&eid={eid}"}})


def test_alerted_eids_keeps_this_runs_alerts_only():
    sent = {"e1": {"ts_sent": 1_790_000_000.0}, "e2": {"ts_sent": 1_790_000_005.0}}
    lines = [
        _alert_line("e1", "2026-09-21T10:00:00.000000+0000"),   # earlier run, same eid
        _alert_line("e1", "2026-09-21T14:13:21.000000+0000"),   # this run (1_790_000_001)
        _alert_line("zz", "2026-09-21T14:13:22.000000+0000"),   # not replayed
        json.dumps({"event_type": "http", "http": {"url": "/?eid=e2"}}),
        "not json",
    ]
    assert alerted_eids(lines, sent) == ["e1"]


def test_rule_mode_returns_when_row_count_is_stable(tmp_path):
    db = _db(tmp_path, [("naive", "e1")])
    t0 = time.time()
    wait_for_decisions(db, "naive", SENT, settle_s=1, timeout_s=30)
    assert time.time() - t0 < 6


@pytest.mark.parametrize("raw,want", [
    ("T1190", "T1190"),
    ("T1190 (Exploit Public-Facing Application)", "T1190"),
    ("t1059.004", "T1059.004"),
    ("MITRE: T1059.007 JavaScript", "T1059.007"),
    ("", ""),
    ("none", ""),
])
def test_mitre_id(raw, want):
    assert mitre_id(raw) == want


def test_p95_is_nearest_rank():
    assert p95([]) == 0.0
    assert p95([5.0]) == 5.0
    assert p95([float(i) for i in range(1, 21)]) == 19.0      # 20 values: rank ceil(19) = 19
    assert p95([1.0, 2.0, 100.0]) == 100.0                    # a slow tail is not averaged away
