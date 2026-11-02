"""G2 — alerts without a benchmark eid (real traffic) still get a stable id;
D4 — late IDS alerts for web-triaged requests are detected;
G6 — blocks live in an ipset with kernel-side timeouts; per-IP rules left by
the older agent are cleaned up."""

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
        "-A DOCKER-USER -m set --match-set agent-block src -m comment --comment agent-block-set -j DROP",
        "-A DOCKER-USER -s 203.0.113.9/32 -m comment --comment \"agent-block-203.0.113.9\" -j DROP",  # as iptables prints it
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


class FakeKernel:
    """ipset/iptables stand-in: tracks set members and whether the set's DROP rule exists."""

    def __init__(self, rule=False, members=()):
        self.rule, self.members, self.calls = rule, dict.fromkeys(members, 3600), []

    def __call__(self, cmd):
        self.calls.append(cmd)
        tool, verb = cmd[0], cmd[1]
        if tool == "iptables":
            if verb == "-C":
                return (0 if self.rule else 1), ""
            self.rule = verb == "-I" or self.rule
            return 0, ""
        if verb == "test":
            return (0 if cmd[3] in self.members else 1), ""
        if verb == "add":
            self.members[cmd[3]] = int(cmd[5])
        elif verb == "del":
            self.members.pop(cmd[3], None)
        elif verb == "list":
            return 0, "\n".join([f"create {firewall.SET} hash:ip family inet timeout 3600"]
                                + [f"add {firewall.SET} {ip} timeout {t}" for ip, t in self.members.items()])
        return 0, ""


def test_block_adds_a_timed_set_entry_and_the_drop_rule_once(monkeypatch):
    k = FakeKernel()
    monkeypatch.setattr(firewall, "_run", k)
    assert firewall.block_ip("203.0.113.9", 600)["status"] == "blocked"
    assert firewall.block_ip("203.0.113.9")["status"] == "already_blocked"
    assert firewall.block_ip("203.0.113.10")["status"] == "blocked"
    assert k.members == {"203.0.113.9": 600, "203.0.113.10": 3600}
    assert sum(c[:2] == ["iptables", "-I"] for c in k.calls) == 1   # one rule for every IP
    assert ["ipset", "add", firewall.SET, "203.0.113.9", "timeout", "600", "-exist"] in k.calls


def test_blocked_ips_are_read_back_from_the_kernel_set(monkeypatch):
    monkeypatch.setattr(firewall, "_run", FakeKernel(rule=True, members=["198.51.100.1"]))
    (entry,) = firewall.get_blocked_ips()
    assert entry["ip"] == "198.51.100.1" and entry["remaining_s"] == 3600
    assert firewall.unblock_ip("198.51.100.1")["status"] == "unblocked"
    assert firewall.get_blocked_ips() == []


def test_block_reports_an_error_when_ipset_fails(monkeypatch):
    monkeypatch.setattr(firewall, "_run", lambda cmd: (1, "ipset: Kernel error"))
    res = firewall.block_ip("203.0.113.9")
    assert res["status"] == "error" and "Kernel" in res["detail"]
    assert firewall.get_blocked_ips() == []
