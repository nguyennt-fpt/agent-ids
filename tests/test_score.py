"""A3 — per-mode wait before scoring (review bug C); A5 — MITRE id normalization."""

import sqlite3
import time

import pytest

from score import mitre_id, wait_for_decisions


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
    wait_for_decisions(db, "agent", SENT, settle_s=15, timeout_s=30)
    assert time.time() - t0 < 1


def test_agent_waits_past_settle_window_then_times_out_and_reports(tmp_path, capsys):
    db = _db(tmp_path, [("agent", "e1"), ("rule_based", "e2")])   # other mode doesn't count
    t0 = time.time()
    wait_for_decisions(db, "agent", SENT, settle_s=0, timeout_s=3)
    assert time.time() - t0 >= 3          # did not stop on "stable count"
    assert "1/2 eids have no agent decision" in capsys.readouterr().out


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
