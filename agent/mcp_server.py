"""MCP server exposing security tools to the AI agent."""

import json
import os

from mcp.server.fastmcp import FastMCP

from tools.alert_reader import normalize_alert, read_new_alerts, read_recent_alerts
from tools.firewall import block_ip, get_blocked_ips, unblock_ip
from tools.ids_manager import append_rule, list_custom_rules
from tools.notifier import send_alert
from tools.rule_validator import validate_rule

EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")
GOLDEN_PATH = os.getenv("GOLDEN_PATH", "/app/data/golden.jsonl")
HOLDOUT_PATH = os.getenv("HOLDOUT_PATH", "/app/data/holdout.jsonl")


def _load_dataset(path: str) -> list[dict]:
    rows = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    rows.append({"text": r.get("text", ""), "label": r.get("label", "")})
    return rows

mcp = FastMCP("security-agent")


@mcp.tool()
def read_ids_alerts(limit: int = 30) -> str:
    """Return new IDS alerts (structured JSON, incl. `eid`) since last call."""
    alerts = read_new_alerts(EVE_LOG, limit=limit)
    if not alerts:
        return "no_new_alerts"
    return json.dumps([normalize_alert(a) for a in alerts], ensure_ascii=False)


@mcp.tool()
def get_recent_alerts(n: int = 20) -> str:
    """Return the last n alerts from the full EVE log (structured JSON)."""
    alerts = read_recent_alerts(EVE_LOG, n=n)
    return json.dumps([normalize_alert(a) for a in alerts], ensure_ascii=False)


@mcp.tool()
def block_attacker_ip(ip: str, ttl_seconds: int = 3600) -> str:
    """Block a source IP via iptables. Auto-expires after ttl_seconds (default 1h)."""
    result = block_ip(ip, ttl_seconds)
    return json.dumps(result)


@mcp.tool()
def unblock_attacker_ip(ip: str) -> str:
    """Remove a previously blocked IP from the firewall."""
    result = unblock_ip(ip)
    return json.dumps(result)


@mcp.tool()
def list_blocked_ips() -> str:
    """Return all currently blocked IPs with expiry info."""
    return json.dumps(get_blocked_ips())


@mcp.tool()
def get_nginx_logs(lines: int = 50) -> str:
    """Return the last N lines from the Nginx access log (JSON format)."""
    if not os.path.exists(NGINX_LOG):
        return "nginx_log_not_found"
    with open(NGINX_LOG, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    return "".join(all_lines[-lines:])


@mcp.tool()
def propose_rule(rule: str, epoch: int = 0) -> str:
    """Propose a Suricata rule. Runs the 4-gate validator; only rules that pass
    all gates are written to custom.rules (others recorded as pending/rejected)."""
    holdout = _load_dataset(HOLDOUT_PATH)
    golden = _load_dataset(GOLDEN_PATH)
    active = list_custom_rules()
    verdict = validate_rule(rule, holdout, golden, active, epoch=epoch)
    if verdict.get("status") == "active":
        verdict["append"] = append_rule(rule)
    return json.dumps(verdict)


@mcp.tool()
def add_ids_rule(rule: str) -> str:
    """[Deprecated — prefer propose_rule] Append a rule directly without gating."""
    result = append_rule(rule)
    return json.dumps(result)


@mcp.tool()
def get_ids_custom_rules() -> str:
    """Return all active custom Suricata rules."""
    rules = list_custom_rules()
    return json.dumps(rules)


@mcp.tool()
def alert_dashboard(message: str, src_ip: str = "", attack_type: str = "",
                    action: str = "", eid: str = "", mode: str = "",
                    mitre: str = "", severity: str = "", note: str = "") -> str:
    """Log a security event (incl. benchmark `eid`/`mode` and MITRE enrichment)."""
    result = send_alert(message, src_ip=src_ip, attack_type=attack_type,
                        action=action, eid=eid, mode=mode,
                        mitre=mitre, severity=severity, note=note)
    return json.dumps(result)


if __name__ == "__main__":
    mcp.run(transport="stdio")
