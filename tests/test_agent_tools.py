"""G2 — investigate tools only return context for the event's own source IP,
and only history since the agent started (no earlier benchmark runs)."""

import json
import time
from datetime import datetime, timezone

import pytest

pytest.importorskip("langchain_core")

from tools import agent_tools  # noqa: E402

NOW = time.time()


def _eve_ts(t):        # Suricata EVE: 2026-10-25T12:08:01.123456+0000
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _nginx_ts(t):      # nginx $time_iso8601: 2026-10-25T12:08:01+00:00
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _alert(ip, eid, t=NOW):
    return {"event_type": "alert", "src_ip": ip, "timestamp": _eve_ts(t),
            "alert": {"signature": "SQLi", "severity": 1},
            "http": {"url": f"/vulnerabilities/sqli/?id=1&eid={eid}"}}


@pytest.fixture
def logs(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_tools, "_STARTED", NOW - 60)        # agent started a minute ago
    eve = tmp_path / "eve.json"
    eve.write_text("\n".join([json.dumps(_alert("203.0.113.10", "old", t=NOW - 3600))]   # earlier run
                             + [json.dumps(_alert(ip, f"e{i}")) for i, ip in
                                enumerate(["203.0.113.10", "198.51.100.10", "203.0.113.10"])]) + "\n")
    web = tmp_path / "access.json.log"
    web.write_text("\n".join([json.dumps({"remote_addr": "198.51.100.10", "uri": "/old",
                                          "time": _nginx_ts(NOW - 3600)})]
                             + [json.dumps({"remote_addr": ip, "uri": f"/p{i}", "time": _nginx_ts(NOW)})
                                for i, ip in enumerate(["198.51.100.10", "203.0.113.10", "198.51.100.10"])]
                             + ['{"remote_addr": "198.51.100.10", "uri": "/no-time"}']) + "\n")
    monkeypatch.setattr(agent_tools, "EVE_LOG", str(eve))
    monkeypatch.setattr(agent_tools, "NGINX_LOG", str(web))


def test_alerts_are_filtered_to_the_source_ip_and_this_run(logs):
    got = json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "203.0.113.10"}))
    assert [a["eid"] for a in got] == ["e0", "e2"]                # "old" (before start) left out
    last = json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "203.0.113.10", "n": 1}))
    assert [a["eid"] for a in last] == ["e2"]
    assert json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "192.0.2.1"})) == []


def test_web_log_is_filtered_to_the_source_ip_and_this_run(logs):
    got = agent_tools.get_nginx_logs.invoke({"src_ip": "198.51.100.10"}).splitlines()
    assert [json.loads(line)["uri"] for line in got] == ["/p0", "/p2"]   # no /old, no /no-time


def test_window_caps_history_for_a_long_running_agent(logs, monkeypatch):
    monkeypatch.setattr(agent_tools, "_STARTED", NOW - 86400)     # agent up for a day
    monkeypatch.setattr(agent_tools, "WINDOW_S", 600)
    got = json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "203.0.113.10"}))
    assert [a["eid"] for a in got] == ["e0", "e2"]                # the hour-old alert is outside


def test_src_ip_is_required():
    assert "src_ip" in agent_tools.get_recent_alerts.args_schema.model_json_schema()["required"]
    assert "src_ip" in agent_tools.get_nginx_logs.args_schema.model_json_schema()["required"]
