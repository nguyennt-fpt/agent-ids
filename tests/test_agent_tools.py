"""G2 — investigate tools only return context for the event's own source IP."""

import json

import pytest

pytest.importorskip("langchain_core")

from tools import agent_tools  # noqa: E402


def _alert(ip, eid):
    return {"event_type": "alert", "src_ip": ip, "timestamp": "t",
            "alert": {"signature": "SQLi", "severity": 1},
            "http": {"url": f"/vulnerabilities/sqli/?id=1&eid={eid}"}}


@pytest.fixture
def logs(tmp_path, monkeypatch):
    eve = tmp_path / "eve.json"
    eve.write_text("\n".join(json.dumps(_alert(ip, f"e{i}")) for i, ip in
                             enumerate(["203.0.113.10", "198.51.100.10", "203.0.113.10"])) + "\n")
    web = tmp_path / "access.json.log"
    web.write_text("\n".join(json.dumps({"remote_addr": ip, "uri": f"/p{i}"}) for i, ip in
                             enumerate(["198.51.100.10", "203.0.113.10", "198.51.100.10"])) + "\n")
    monkeypatch.setattr(agent_tools, "EVE_LOG", str(eve))
    monkeypatch.setattr(agent_tools, "NGINX_LOG", str(web))


def test_alerts_are_filtered_to_the_source_ip(logs):
    got = json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "203.0.113.10"}))
    assert [a["eid"] for a in got] == ["e0", "e2"]
    last = json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "203.0.113.10", "n": 1}))
    assert [a["eid"] for a in last] == ["e2"]
    assert json.loads(agent_tools.get_recent_alerts.invoke({"src_ip": "192.0.2.1"})) == []


def test_web_log_is_filtered_to_the_source_ip(logs):
    got = agent_tools.get_nginx_logs.invoke({"src_ip": "198.51.100.10"}).splitlines()
    assert [json.loads(line)["uri"] for line in got] == ["/p0", "/p2"]


def test_src_ip_is_required():
    assert "src_ip" in agent_tools.get_recent_alerts.args_schema.model_json_schema()["required"]
    assert "src_ip" in agent_tools.get_nginx_logs.args_schema.model_json_schema()["required"]
