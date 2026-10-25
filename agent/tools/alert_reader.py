import hashlib
import json
import os
import re
from urllib.parse import urlparse, parse_qs

_last_pos: dict[str, int] = {}
_EID_PARAM = re.compile(r"([?&])eid=[^&\s#]*(&?)")


def extract_eid(url: str) -> str:
    """Pull the benchmark eval-id (`eid`) out of a URL/URI query string."""
    if not url:
        return ""
    try:
        return parse_qs(urlparse(url).query).get("eid", [""])[0]
    except Exception:
        return ""


def strip_eid(text: str) -> str:
    """Drop the benchmark's `eid` query parameter from a URL or raw request —
    the model is shown events without it (the eid stays a separate field).
    Triaged alone, the model read the random hex token as an encoded payload
    and flagged plain requests (N1). Real traffic has no eid: no-op."""
    return _EID_PARAM.sub(lambda m: m.group(1) if m.group(2) else "", text or "")


def auto_eid(alert: dict) -> str:
    """Id for traffic without a benchmark eid (real traffic): one per HTTP
    transaction (flow_id + tx_id), so several alerts on one request are decided
    once — and act_node can find the event, i.e. its src_ip to block."""
    if alert.get("flow_id") is not None:
        return f"auto-{alert['flow_id']}-{alert.get('tx_id', '')}"
    key = "|".join(str(alert.get(k, "")) for k in ("timestamp", "src_ip", "src_port"))
    return "auto-" + hashlib.sha1(key.encode()).hexdigest()[:12]


def normalize_alert(alert: dict) -> dict:
    """Flatten an EVE alert dict into the structured fields the agent needs."""
    a = alert.get("alert", {})
    http = alert.get("http", {})
    url = http.get("url", "")
    # src_ip = the client (who would be blocked). EVE gives packet direction, so on
    # a response (to_client) alert the client is dest_ip — also where the XFF
    # overwrite puts the benchmark actor.
    to_client = alert.get("direction") == "to_client"
    return {
        "timestamp": alert.get("timestamp", ""),
        "src_ip": alert.get("dest_ip" if to_client else "src_ip", ""),
        "dest_ip": alert.get("src_ip" if to_client else "dest_ip", ""),
        "signature": a.get("signature", ""),
        "severity": a.get("severity", 3),
        "category": a.get("category", ""),
        "method": http.get("http_method", ""),
        "url": url,
        "user_agent": http.get("http_user_agent", ""),
        "eid": extract_eid(url) or auto_eid(alert),
        "payload": (alert.get("payload_printable", "") or "")[:300].replace("\n", " "),
    }


def prime_position(path: str) -> None:
    """Skip existing backlog: start reading only alerts appended after this call.

    Called once at agent startup. Between benchmark runs the agent is restarted
    but eve.json (on a named volume) is never cleared, so without this a fresh
    agent would reprocess a previous run's stale alerts as if they were new —
    corrupting recall and MTTB. Seeking to EOF at boot pins the read offset past
    the backlog so only the current run's traffic is processed.
    """
    _last_pos[path] = os.path.getsize(path) if os.path.exists(path) else 0


def tail_new_lines(path: str) -> list[str]:
    """Complete lines appended since the last call (offset-based, like `tail -f`).

    Each line is returned exactly once, so a trailing line the writer hasn't
    finished yet (no `\\n`) is left for the next call instead of being parsed
    half-written and lost.
    """
    if not os.path.exists(path):
        return []
    pos = _last_pos.get(path, 0)
    with open(path, "rb") as f:
        f.seek(0, 2)
        if f.tell() < pos:          # truncated / rotated -> start over
            pos = 0
        f.seek(pos)
        data = f.read()
    end = data.rfind(b"\n") + 1
    _last_pos[path] = pos + end
    return data[:end].decode("utf-8", errors="replace").split("\n")[:-1]


def read_new_alerts(eve_path: str, limit: int = 50) -> list[dict]:
    """Return new EVE JSON alert events since last call."""
    lines = tail_new_lines(eve_path)
    alerts = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            alerts.append(event)
    # Do NOT slice to the last `limit` here — dropping the oldest new alerts
    # silently loses eids. With prime_position() + a 5s poll the new-alert count
    # per call stays small; `limit` is enforced by the caller if needed.
    return alerts


def read_recent_alerts(eve_path: str, n: int = 20) -> list[dict]:
    """Return the last n alerts from the full eve.json (for context)."""
    if not os.path.exists(eve_path):
        return []
    alerts = []
    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts[-n:]


def format_alert_for_llm(alert: dict) -> str:
    """Flatten an EVE alert dict into a concise string for the LLM prompt."""
    a = alert.get("alert", {})
    http = alert.get("http", {})
    parts = [
        f"time={alert.get('timestamp', '')}",
        f"src={alert.get('src_ip', '?')}:{alert.get('src_port', '?')}",
        f"dst={alert.get('dest_ip', '?')}:{alert.get('dest_port', '?')}",
        f"signature=\"{a.get('signature', '')}\"",
        f"severity={a.get('severity', '?')}",
        f"category=\"{a.get('category', '')}\"",
    ]
    if http:
        parts.append(f"http_method={http.get('http_method', '')}")
        parts.append(f"url=\"{http.get('url', '')}\"")
        parts.append(f"user_agent=\"{http.get('http_user_agent', '')}\"")
    if alert.get("payload_printable"):
        payload = alert["payload_printable"][:200].replace("\n", " ")
        parts.append(f"payload=\"{payload}\"")
    return " | ".join(parts)
