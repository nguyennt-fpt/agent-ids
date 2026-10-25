"""WAF baseline (OWASP CRS, DetectionOnly): ModSecurity audit log -> decisions."""

import json
import time

import main
from bootstrap_ci import bootstrap
from score import wait_for_decisions


def _tx(uri, rule_ids=(), tags=(), xff="198.51.100.7, 198.51.100.7"):
    msgs = [{"message": "m", "details": {"ruleId": r, "tags": list(tags)}} for r in rule_ids]
    return json.dumps({"transaction": {
        "client_ip": "172.18.0.5",
        "request": {"method": "GET", "uri": uri, "headers": {"X-Forwarded-For": xff}},
        "messages": msgs}})


def test_audit_log_becomes_one_decision_per_request(tmp_path, monkeypatch):
    log = tmp_path / "audit.json"
    log.write_text("\n".join([
        _tx("/vulnerabilities/sqli/?id=x&eid=e1", ["942100", "949110"], ["attack-sqli", "paranoia-level/1"]),
        _tx("/vulnerabilities/xss_r/?name=Alice&eid=e2"),                        # nothing matched
        _tx("/search?q=x&eid=e3", ["920350"], ["attack-protocol"]),              # below threshold
        _tx("/login.php"),                                                       # redirect, no eid
        _tx("/vulnerabilities/sqli/?id=x&eid=e1", ["949110"]),                   # same eid again
        "not json", "[1, 2]",
    ]) + "\n")
    monkeypatch.setattr(main, "WAF_LOG", str(log))
    rows = []
    monkeypatch.setattr(main, "record_decision", lambda **kw: rows.append(kw))
    main.handle_waf(decided=set())

    got = {r["eid"]: (r["action"], r["attack"], r["src_ip"], r["mode"]) for r in rows}
    assert got == {"e1": ("block", "sqli", "198.51.100.7", "waf"),
                   "e2": ("log", "none", "198.51.100.7", "waf"),
                   "e3": ("log", "none", "198.51.100.7", "waf")}
    assert len(rows) == 3
    assert "942100" in rows[0]["reason"] and "949110" in rows[0]["reason"]


def test_waf_mode_waits_for_every_answered_request(tmp_path):
    import sqlite3
    db = tmp_path / "events.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, mode TEXT, eid TEXT)")
    c.execute("INSERT INTO events (ts, action, mode, eid) VALUES ('t', 'log', 'waf', 'e1')")
    c.commit()
    c.close()
    t0 = time.time()
    wait_for_decisions(str(db), "waf", {"e1": {"status": 200}, "e2": {"status": 200}},
                       settle_s=0, timeout_s=3)
    assert time.time() - t0 >= 3                     # e2 still missing: no early "stable" exit


def test_bootstrap_against_two_baselines(tmp_path):
    preds = {m: {1: {f"e{i}": (i < 5, p(i)) for i in range(10)}}
             for m, p in (("rule_based", lambda i: i < 2), ("waf", lambda i: i < 3),
                          ("agent", lambda i: i < 5))}
    names = {r["mode"] for r in bootstrap(preds, ["rule_based", "waf"], b=50, seed=0)}
    assert {"agent - rule_based", "agent - waf", "waf - rule_based"} <= names
    assert "rule_based - waf" not in names                 # each pair once
