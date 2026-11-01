"""Phase F — confidence is stored per decision and its calibration measured."""

import json
import math
import sqlite3

from calibration import calibration
from score import fetch_decisions


def _p(conf, attack, mode="agent"):
    return {"mode": mode, "label": "malicious" if attack else "benign", "pred": attack,
            "confidence": conf}


def test_ece_and_bins():
    preds = ([_p(0.95, i < 9) for i in range(10)]          # top bin: 90% attacks vs conf 0.95
             + [_p(0.55, i < 3) for i in range(10)]        # low bin: 30% attacks vs conf 0.55
             + [_p(None, True), _p(0.9, False, mode="rule_based")])   # skipped
    bins, ece, n = calibration(preds, "agent")
    assert n == 20
    assert [(b["bin"], b["n"]) for b in bins] == [("[0.5, 0.6)", 10), ("[0.9, 1.0]", 10)]
    assert math.isclose(ece, 0.5 * 0.05 + 0.5 * 0.25)


def test_confidence_one_lands_in_the_top_bin():
    bins, _, _ = calibration([_p(1.0, True)], "agent")
    assert bins[0]["bin"] == "[0.9, 1.0]"


def test_confidence_is_attack_probability_so_a_sure_benign_log_is_calibrated():
    # 0.05 on benign requests = "5% attack": right, not "5% sure" (read so before 2026-11 -> ECE 0.95)
    bins, ece, _ = calibration([_p(0.05, False) for _ in range(10)], "agent")
    assert bins[0]["attack_rate"] == 0.0
    assert math.isclose(ece, 0.05)


def _db(tmp_path, with_confidence: bool):
    db = tmp_path / "events.db"
    c = sqlite3.connect(db)
    extra = ", confidence TEXT" if with_confidence else ""
    c.execute(f"CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, mode TEXT, "
              f"eid TEXT, mitre TEXT{extra})")
    rows = [("log", "e1", "0.4"), ("warn", "e1", "0.7"), ("block", "e1", "0.9"), ("log", "e2", "0.8")]
    for action, eid, conf in rows:
        if with_confidence:
            c.execute("INSERT INTO events (ts, action, mode, eid, mitre, confidence) "
                      "VALUES ('2026-10-25T00:00:00', ?, 'agent', ?, '', ?)", (action, eid, conf))
        else:
            c.execute("INSERT INTO events (ts, action, mode, eid, mitre) "
                      "VALUES ('2026-10-25T00:00:00', ?, 'agent', ?, '')", (action, eid))
    c.commit()
    c.close()
    return str(db)


def test_deciding_rows_confidence_is_kept(tmp_path):
    dec = fetch_decisions(_db(tmp_path, with_confidence=True), "agent")
    assert dec["e1"]["pred_malicious"] and dec["e1"]["confidence"] == 0.7   # first block/warn
    assert not dec["e2"]["pred_malicious"] and dec["e2"]["confidence"] == 0.8


def test_db_without_the_column_still_scores(tmp_path):
    dec = fetch_decisions(_db(tmp_path, with_confidence=False), "agent")
    assert dec["e1"]["pred_malicious"] and dec["e1"]["confidence"] is None


def test_notifier_migrates_and_stores_confidence(tmp_path, monkeypatch):
    from tools import notifier
    db = tmp_path / "events.db"
    c = sqlite3.connect(db)                                     # a DB from before the column
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
              "src_ip TEXT, attack TEXT, action TEXT, detail TEXT)")
    c.commit()
    c.close()
    monkeypatch.setattr(notifier, "DB_PATH", str(db))
    monkeypatch.setattr(notifier, "_db_ready", False)
    notifier.send_alert("m", eid="e1", action="warn", mode="agent", confidence=0.85)
    assert fetch_decisions(str(db), "agent")["e1"]["confidence"] == 0.85
    assert json.dumps(fetch_decisions(str(db), "agent"))           # plain types
