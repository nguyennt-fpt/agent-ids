"""Read-only enrichment tools the agent may call while investigating an
ambiguous event (bài 04 — Tool Use).

Least-privilege (bài 06): the LLM can only *look* — gather more context to make
a better call. Enforcement actions (block an IP, change IDS rules) are performed
by graph nodes behind the risk / human gate, never chosen directly by the model.
Tool `description`s matter more than names — the model routes on them (bài 04).
"""

import json
import os

from langchain_core.tools import tool

from tools.alert_reader import normalize_alert, read_recent_alerts
from tools.firewall import get_blocked_ips

EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")


@tool
def get_recent_alerts(n: int = 20) -> str:
    """Return the last n Suricata IDS alerts as JSON. Use this to check whether a
    source IP has *other* recent attack alerts — repeated alerts from one IP
    raise confidence that an ambiguous request is malicious."""
    alerts = read_recent_alerts(EVE_LOG, n=n)
    return json.dumps([normalize_alert(a) for a in alerts], ensure_ascii=False)


@tool
def get_nginx_logs(lines: int = 50) -> str:
    """Return the last N nginx access-log lines as JSON. Use this to see the
    request *sequence* from an IP: many fast requests, or probing lots of paths,
    signals scanning / brute force even when a single request looks benign."""
    if not os.path.exists(NGINX_LOG):
        return "nginx_log_not_found"
    with open(NGINX_LOG, "r", encoding="utf-8", errors="replace") as f:
        return "".join(f.readlines()[-lines:])


@tool
def list_blocked_ips() -> str:
    """Return the IPs currently blocked by the firewall as JSON. Use this to
    avoid re-deciding on a source that is already contained."""
    return json.dumps(get_blocked_ips())


# The read-only tool set handed to the investigate node's tool-calling loop.
READ_TOOLS = [get_recent_alerts, get_nginx_logs, list_blocked_ips]
