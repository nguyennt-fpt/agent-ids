"""G2 — alerts without a benchmark eid (real traffic) still get a stable id;
D4 — late IDS alerts for web-triaged requests are detected;
G6 — stale agent-block rules from a previous run are cleaned up."""

import main
from tools import firewall
from tools.alert_reader import normalize_alert


def _eve(**kw):
    return {"event_type": "alert", "src_ip": "198.51.100.5", "src_port": 51000,
            "timestamp": "2026-10-25T04:30:00.000000+0000",
            "alert": {"signature": "x", "severity": 1},
            "http": {"url": "/vulnerabilities/sqli/?id=1"}, **kw}


def test_benchmark_eid_wins_over_auto_id():
    a = normalize_alert(_eve(flow_id=7, tx_id=0, http={"url": "/?id=1&eid=abc123"}))
    assert a["eid"] == "abc123"


def test_alerts_on_one_http_transaction_share_an_auto_id():
    first = normalize_alert(_eve(flow_id=123, tx_id=0, alert={"signature": "rule A", "severity": 1}))
    second = normalize_alert(_eve(flow_id=123, tx_id=0, alert={"signature": "rule B", "severity": 2}))
    next_request = normalize_alert(_eve(flow_id=123, tx_id=1))
    assert first["eid"] == second["eid"] == "auto-123-0"
    assert next_request["eid"] != first["eid"]


def test_auto_id_without_flow_id_is_stable_and_non_empty():
    a, b = normalize_alert(_eve()), normalize_alert(_eve())
    assert a["eid"] == b["eid"] and a["eid"].startswith("auto-") and len(a["eid"]) > 5
    assert normalize_alert(_eve(src_port=51001))["eid"] != a["eid"]


def test_rule_mode_decides_each_real_transaction_once(monkeypatch):
    rows = []
    monkeypatch.setattr(main, "record_decision", lambda **kw: rows.append(kw))
    alerts = [normalize_alert(_eve(flow_id=9, tx_id=0, alert={"signature": s, "severity": 1}))
              for s in ("rule A", "rule B")]
    main.handle_rule_based(alerts, "rule_based", decided=set())
    assert len(rows) == 1 and rows[0]["src_ip"] == "198.51.100.5" and rows[0]["action"] == "block"


def test_late_ids_alert_is_reported():
    alerts = [{"eid": "e1"}, {"eid": "e2"}, {"eid": ""}]
    assert main.late_ids_alerts(alerts, web_decided={"e2", "e9"}) == ["e2"]


def test_cleanup_removes_only_this_agents_rules(monkeypatch):
    calls = []
    listing = "\n".join([
        "-N DOCKER-USER",
        "-A DOCKER-USER -s 203.0.113.9/32 -m comment --comment agent-block-203.0.113.9 -j DROP",
        "-A DOCKER-USER -s 10.1.2.3/32 -j DROP",                       # someone else's rule
        "-A DOCKER-USER -s 203.0.113.9/32 -m comment --comment agent-block-203.0.113.9 -j DROP",
        "-A DOCKER-USER -j RETURN",
    ])

    def fake_run(cmd):
        calls.append(cmd)
        return (0, listing) if cmd[1] == "-S" else (0, "")

    monkeypatch.setattr(firewall, "_run", fake_run)
    assert firewall.cleanup_stale_blocks() == 2                        # duplicates both go
    deletes = [c for c in calls if c[1] == "-D"]
    assert deletes == [["iptables", "-D", "DOCKER-USER", "-s", "203.0.113.9/32", "-m", "comment",
                        "--comment", "agent-block-203.0.113.9", "-j", "DROP"]] * 2


def test_cleanup_is_a_noop_when_iptables_fails(monkeypatch):
    monkeypatch.setattr(firewall, "_run", lambda cmd: (1, "iptables: No chain/target/match"))
    assert firewall.cleanup_stale_blocks() == 0
