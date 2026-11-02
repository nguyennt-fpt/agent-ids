"""G2 for real traffic (no benchmark eid): an IDS alert and the nginx line of the
same request share one id, whichever source is read first; repeats of one source
+ signature are triaged once per window (the alert flood of 2026-10-27)."""

import json

import pytest

import main
from tools.alert_reader import normalize_alert, prime_position, web_eid

URI = "/vulnerabilities/sqli/?id=1&Submit=Submit"


@pytest.fixture
def web(tmp_path, monkeypatch):
    """A primed nginx log and clean join/dedup state; returns append(**fields)."""
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    monkeypatch.setattr(main, "WEB_UNTAGGED", True)
    monkeypatch.setattr(main, "_recent", {})
    monkeypatch.setattr(main, "_dedup_seen", {})
    open(log, "w").close()
    prime_position(log)

    def append(**kw):
        rec = {"remote_addr": "198.51.100.20", "remote_port": "40001", "method": "GET",
               "uri": URI, "request_id": "r1", **kw}
        with open(log, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return append


def _alert(port=40001, src="198.51.100.20", flow=1, sid=9000001, uri=URI):
    return normalize_alert({"event_type": "alert", "src_ip": src, "src_port": port,
                            "dest_ip": "10.0.0.5", "dest_port": 80, "flow_id": flow, "tx_id": 0,
                            "alert": {"signature": "DVWA SQL Injection", "signature_id": sid,
                                      "severity": 1},
                            "http": {"url": uri, "http_method": "GET"}})


def test_alert_keeps_the_client_port_and_rule_id():
    a = normalize_alert({"event_type": "alert", "direction": "to_client",
                         "src_ip": "10.0.0.5", "src_port": 80,
                         "dest_ip": "198.51.100.20", "dest_port": 40001,
                         "alert": {"signature": "x", "signature_id": 2013504, "severity": 3}})
    assert (a["src_ip"], a["src_port"], a["sid"]) == ("198.51.100.20", 40001, 2013504)


def test_web_line_id_is_the_request_id_or_a_stable_hash():
    assert web_eid({"request_id": "abc"}) == "web-abc"
    line = {"time": "t", "remote_addr": "198.51.100.20", "remote_port": "1", "uri": "/"}
    assert web_eid(line) == web_eid(dict(line)) and web_eid(line).startswith("web-")


def test_untagged_request_is_judged_under_its_own_id(web):
    web(uri="/index.php", request_id="r9")
    (ev,) = main.collect_agent_events([], decided=set())
    assert (ev["eid"], ev["source"], ev["src_ip"]) == ("web-r9", "web", "198.51.100.20")


def test_benchmark_runs_skip_untagged_requests(web, monkeypatch):
    monkeypatch.setattr(main, "WEB_UNTAGGED", False)
    web(uri="/login.php")                     # replay's redirect follow-up: no eid
    assert main.collect_agent_events([], decided=set()) == []


def test_alert_and_its_web_line_are_one_event(web):
    web()
    (ev,) = main.collect_agent_events([_alert()], decided=set())
    assert (ev["eid"], ev["source"]) == ("web-r1", "ids")


def test_alert_read_a_poll_after_its_line_is_not_triaged_again(web):
    web()
    decided = set()
    (ev,) = main.collect_agent_events([], decided)          # line first: judged from the web log
    decided.add(ev["eid"])
    alert = _alert()
    assert main.collect_agent_events([alert], decided) == []
    assert main.late_ids_alerts([alert], web_decided={ev["eid"]}) == [ev["eid"]]


def test_line_read_a_poll_after_its_alert_is_not_triaged_again(web):
    decided = set()
    (ev,) = main.collect_agent_events([_alert()], decided)
    assert ev["eid"].startswith("auto-")
    decided.add(ev["eid"])
    web()
    assert main.collect_agent_events([], decided) == []


def test_other_request_from_the_same_client_is_not_joined(web):
    web(uri="/index.php", request_id="r2")
    events = main.collect_agent_events([_alert()], decided=set())
    assert sorted(e["source"] for e in events) == ["ids", "web"]


def test_client_supplied_forwarded_for_does_not_pick_the_ip(web, capsys):
    web()                                                   # nginx: the TCP peer
    (ev,) = main.collect_agent_events([_alert(src="203.0.113.77")], decided=set())
    assert ev["src_ip"] == "198.51.100.20"
    assert "X-Forwarded-For" in capsys.readouterr().out


def test_repeated_alerts_are_triaged_once_per_window(web, monkeypatch, capsys):
    t = [1000.0]
    monkeypatch.setattr(main, "_clock", lambda: t[0])
    decided = set()
    burst = [_alert(port=41000 + i, flow=i) for i in range(5)]   # 5 requests, one source + rule
    assert len(main.collect_agent_events(burst, decided)) == 1
    assert len(decided) == 4                                       # the other 4: suppressed
    assert "suppressed 4 duplicate alert(s)" in capsys.readouterr().out
    t[0] += main.ALERT_DEDUP_WINDOW_S                              # window over: judged again
    assert len(main.collect_agent_events([_alert(port=42000, flow=99)], decided)) == 1


def test_suppressed_alerts_take_their_web_lines_with_them(web):
    for i in range(3):
        web(remote_port=str(43000 + i), request_id=f"q{i}")
    alerts = [_alert(port=43000 + i, flow=i) for i in range(3)]
    todo = main.collect_agent_events(alerts, decided=set())
    assert [(e["eid"], e["source"]) for e in todo] == [("web-q0", "ids")]


def test_benchmark_alerts_are_never_deduplicated(web):
    alerts = [normalize_alert({"event_type": "alert", "src_ip": "198.51.100.20",
                               "src_port": 44000 + i,
                               "alert": {"signature": "x", "signature_id": 1, "severity": 1},
                               "http": {"url": f"/?id=1&eid=b{i}", "http_method": "GET"}})
              for i in range(3)]
    assert [e["eid"] for e in main.collect_agent_events(alerts, decided=set())] == ["b0", "b1", "b2"]
