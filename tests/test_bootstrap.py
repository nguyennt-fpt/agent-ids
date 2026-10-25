"""Phase F — paired bootstrap CIs over requests (bootstrap_ci.py)."""

import json
import math
import sqlite3
import sys

import score
from bootstrap_ci import bootstrap, load_preds, metrics


def _preds(path, modes):
    """modes: {mode: predicate(i) -> predicted malicious}; eids 0-9 malicious, 10-19 benign; 2 runs."""
    with open(path, "w", encoding="utf-8") as f:
        for mode, pred in modes.items():
            for run in (1, 2):
                for i in range(20):
                    f.write(json.dumps({"mode": mode, "run": run, "eid": f"e{i}", "group": "g",
                                        "label": "malicious" if i < 10 else "benign",
                                        "pred": pred(i)}) + "\n")
    return load_preds(path)


def _row(rows, mode, metric):
    return next(r for r in rows if r["mode"] == mode and r["metric"] == metric)


def test_paired_difference_and_identical_modes(tmp_path):
    preds = _preds(tmp_path / "p.jsonl", {
        "rule_based": lambda i: i < 5,                 # catches half the attacks, no FP
        "naive": lambda i: i < 5,                      # identical to the baseline
        "agent": lambda i: i < 10 or i in (10, 11),    # catches all, 2 FP
    })
    rows = bootstrap(preds, "rule_based", b=300, seed=1)

    d_recall = _row(rows, "agent - rule_based", "recall")
    assert d_recall["point"] == 0.5 and d_recall["lo"] > 0          # survives resampling
    d_fpr = _row(rows, "agent - rule_based", "fpr")
    assert math.isclose(d_fpr["point"], 0.2) and d_fpr["lo"] >= 0
    same = _row(rows, "naive - rule_based", "f1")
    assert (same["point"], same["lo"], same["hi"]) == (0, 0, 0)     # paired: no spurious gap
    assert _row(rows, "agent", "recall")["n_eids"] == 20
    assert rows == bootstrap(preds, "rule_based", b=300, seed=1)    # deterministic


def test_undefined_metrics_are_nan_not_zero():
    m = metrics([(False, False), (False, False)])                   # no attacks, no alerts
    assert math.isnan(m["recall"]) and math.isnan(m["precision"]) and m["fpr"] == 0


def test_score_writes_per_eid_predictions(tmp_path, monkeypatch):
    db = tmp_path / "events.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, "
              "mode TEXT, eid TEXT, mitre TEXT)")
    c.execute("INSERT INTO events (ts, action, mode, eid, mitre) "
              "VALUES ('2026-10-25T04:00:00', 'block', 'rule_based', 'e1', '')")
    c.commit()
    c.close()
    sent = tmp_path / "sent.jsonl"
    sent.write_text("\n".join(json.dumps({"eid": e, "ts_sent": 0.0, "label": lab, "group": "g",
                                          "status": 200, "split": "dev"})
                              for e, lab in (("e1", "malicious"), ("e2", "benign"))) + "\n")
    preds = tmp_path / "preds.jsonl"
    monkeypatch.setattr(sys, "argv", [
        "score.py", "--mode", "rule_based", "--run", "3", "--db", str(db), "--sent", str(sent),
        "--out", str(tmp_path / "raw.csv"), "--preds", str(preds), "--settle", "0", "--timeout", "1"])
    score.main()
    got = sorted((p["eid"], p["pred"], p["run"]) for p in map(json.loads, preds.read_text().splitlines()))
    assert got == [("e1", True, 3), ("e2", False, 3)]
