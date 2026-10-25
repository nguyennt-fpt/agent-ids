"""A1 — offset-based log reading (review bug B)."""

import json

import main
from tools.alert_reader import normalize_alert, prime_position, strip_eid, tail_new_lines


def _append(path, text):
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(text)


def test_prime_skips_backlog_and_each_line_returned_once(tmp_path):
    log = str(tmp_path / "a.log")
    _append(log, "old1\nold2\n")
    prime_position(log)
    assert tail_new_lines(log) == []
    _append(log, "new1\nnew2\n")
    assert tail_new_lines(log) == ["new1", "new2"]
    assert tail_new_lines(log) == []


def test_partial_line_held_until_complete(tmp_path):
    log = str(tmp_path / "a.log")
    prime_position(log)
    _append(log, '{"a":1}\n{"b":')
    assert tail_new_lines(log) == ['{"a":1}']
    _append(log, "2}\n")
    assert tail_new_lines(log) == ['{"b":2}']


def test_truncated_file_reread_from_start(tmp_path):
    log = str(tmp_path / "a.log")
    _append(log, "x" * 50 + "\n")
    prime_position(log)
    open(log, "w").close()
    _append(log, "fresh\n")
    assert tail_new_lines(log) == ["fresh"]


def _nginx_line(eid):
    return json.dumps({"remote_addr": "127.0.0.1", "method": "GET",
                       "uri": f"/dvwa/vulnerabilities/sqli/?id=1&eid={eid}",
                       "http_user_agent": "ua"}) + "\n"


def test_agent_ignores_prior_run_web_lines(tmp_path, monkeypatch):
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    _append(log, "".join(_nginx_line(f"old{i}") for i in range(150)))
    prime_position(log)                       # agent boot
    _append(log, _nginx_line("e1") + _nginx_line("e2"))

    todo = main.collect_agent_events([], decided=set())
    assert [e["eid"] for e in todo] == ["e1", "e2"]
    assert all(e["source"] == "web" for e in todo)
    assert main.collect_agent_events([], decided=set()) == []   # not re-read


def test_response_alert_attributes_the_client_not_the_server():
    eve = {"event_type": "alert", "direction": "to_client",
           "src_ip": "127.0.0.1", "dest_ip": "198.51.100.92",
           "alert": {"signature": "x", "severity": 3}, "http": {"url": "/?eid=e1"}}
    a = normalize_alert(eve)
    assert (a["src_ip"], a["dest_ip"]) == ("198.51.100.92", "127.0.0.1")
    eve.update(direction="to_server", src_ip="198.51.100.92", dest_ip="127.0.0.1")
    assert normalize_alert(eve)["src_ip"] == "198.51.100.92"


def test_ids_only_ablation_ignores_the_web_log(tmp_path, monkeypatch):
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    prime_position(log)
    _append(log, _nginx_line("e1"))
    alerts = [{"eid": "e2", "src_ip": "203.0.113.10", "signature": "SQLi", "severity": 1}]
    todo = main.collect_agent_events(alerts, decided=set(), include_web=False)
    assert [(e["eid"], e["source"]) for e in todo] == [("e2", "ids")]


def test_web_event_carries_logged_post_body(tmp_path, monkeypatch):
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    prime_position(log)
    _append(log, json.dumps({"remote_addr": "198.51.100.10", "method": "POST",
                             "uri": "/vulnerabilities/exec/?eid=e1",
                             "request_body": "ip=8.8.8.8&Submit=Submit"}) + "\n")
    (ev,) = main.collect_agent_events([], decided=set())
    assert ev["payload"] == "ip=8.8.8.8&Submit=Submit"
    assert ev["src_ip"] == "198.51.100.10"


def test_strip_eid_drops_only_the_eid_parameter():
    assert strip_eid("/p?a=1&eid=e1&b=2") == "/p?a=1&b=2"
    assert strip_eid("/p?eid=e1&b=2") == "/p?b=2"
    assert strip_eid("/p?a=1&eid=e1") == "/p?a=1"
    assert strip_eid("/p?eid=e1") == "/p"
    assert strip_eid("GET /p?id=1&eid=e1 HTTP/1.1 Host: x") == "GET /p?id=1 HTTP/1.1 Host: x"
    assert strip_eid("/p?xeid=1&id=2") == "/p?xeid=1&id=2"
    assert strip_eid("/p?id=1") == "/p?id=1"                    # real traffic: unchanged


def test_model_is_shown_events_without_the_eid(tmp_path, monkeypatch):
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    prime_position(log)
    _append(log, _nginx_line("e1"))
    alerts = [{"eid": "e2", "src_ip": "203.0.113.10", "signature": "SQLi", "severity": 1,
               "url": "/vulnerabilities/sqli/?id=1&eid=e2",
               "payload": "GET /vulnerabilities/sqli/?id=1&eid=e2 HTTP/1.1"}]
    todo = main.collect_agent_events(alerts, decided=set())
    assert [e["eid"] for e in todo] == ["e2", "e1"]               # still keyed by eid
    assert [e["url"] for e in todo] == ["/vulnerabilities/sqli/?id=1",
                                        "/dvwa/vulnerabilities/sqli/?id=1"]
    assert todo[0]["payload"] == "GET /vulnerabilities/sqli/?id=1 HTTP/1.1"


def test_web_line_dropped_when_ids_alert_has_same_eid(tmp_path, monkeypatch):
    log = str(tmp_path / "access.json.log")
    monkeypatch.setattr(main, "NGINX_LOG", log)
    prime_position(log)
    _append(log, _nginx_line("e1"))
    alerts = [{"eid": "e1", "src_ip": "127.0.0.1", "signature": "SQLi", "severity": 1}]
    todo = main.collect_agent_events(alerts, decided=set())
    assert [(e["eid"], e["source"]) for e in todo] == [("e1", "ids")]
