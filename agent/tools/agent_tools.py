"""Read-only enrichment tools the agent may call while investigating an
ambiguous event (bài 04 — Tool Use).

Least-privilege (bài 06): the LLM can only *look* — gather more context to make
a better call. Enforcement actions (block an IP, change IDS rules) are performed
by graph nodes behind the risk / human gate, never chosen directly by the model.
Tool `description`s matter more than names — the model routes on them (bài 04).
"""

import json
import os
import time
from datetime import datetime

from langchain_core.tools import tool

from tools.alert_reader import normalize_alert, read_recent_alerts
from tools.firewall import get_blocked_ips

EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")

# The tools show history only since this agent process started (like
# prime_position: the agent's view of traffic begins at its start) and within
# the last INVESTIGATE_WINDOW_S. Without it, benchmark reruns with deterministic
# actors showed the same IP sending the same requests in every earlier run, and
# the model read that as "repeated requests" -> false positives (EC2 2026-10-25).
_STARTED = time.time()
WINDOW_S = int(os.getenv("INVESTIGATE_WINDOW_S", "900"))


def _since() -> float:
    return max(_STARTED, time.time() - WINDOW_S)


def _epoch(ts: str) -> float:
    """EVE ('…:01.123456+0000') or nginx $time_iso8601 ('…:01+00:00') -> epoch;
    0 (= too old, left out) when unparsable."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt).timestamp()
        except (TypeError, ValueError):
            continue
    return 0.0


@tool
def get_recent_alerts(src_ip: str, n: int = 20) -> str:
    """Return the last n Suricata IDS alerts FROM src_ip as JSON (pass the
    event's src_ip). Use this to check whether that source has *other* recent
    attack alerts — repeated alerts from one IP raise confidence that an
    ambiguous request is malicious; none is evidence for benign."""
    since = _since()
    alerts = [normalize_alert(a) for a in read_recent_alerts(EVE_LOG, n=5000)]
    mine = [a for a in alerts if a["src_ip"] == src_ip and _epoch(a["timestamp"]) >= since][-n:]
    return json.dumps(mine, ensure_ascii=False)


@tool
def get_nginx_logs(src_ip: str, lines: int = 50) -> str:
    """Return the last N nginx access-log entries FROM src_ip as JSON lines
    (pass the event's src_ip). Use this to see that source's request
    *sequence*: many fast requests, or probing lots of paths, signals scanning /
    brute force even when a single request looks benign."""
    # isfile: the stock image's access.log is a symlink to /dev/stdout (blocks on open)
    if not os.path.isfile(NGINX_LOG):
        return "nginx_log_not_found"
    since, mine = _since(), []
    with open(NGINX_LOG, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("remote_addr") == src_ip and _epoch(rec.get("time", "")) >= since:
                mine.append(line.strip())
    return "\n".join(mine[-lines:])


@tool
def list_blocked_ips() -> str:
    """Return the IPs currently blocked by the firewall as JSON. Use this to
    avoid re-deciding on a source that is already contained."""
    return json.dumps(get_blocked_ips())


# The read-only tool set handed to the investigate node's tool-calling loop.
READ_TOOLS = [get_recent_alerts, get_nginx_logs, list_blocked_ips]
