import json
import os
from urllib.parse import urlparse, parse_qs

_last_pos: dict[str, int] = {}


def extract_eid(url: str) -> str:
    """Pull the benchmark eval-id (`eid`) out of a URL/URI query string."""
    if not url:
        return ""
    try:
        return parse_qs(urlparse(url).query).get("eid", [""])[0]
    except Exception:
        return ""


def normalize_alert(alert: dict) -> dict:
    """Flatten an EVE alert dict into the structured fields the agent needs."""
    a = alert.get("alert", {})
    http = alert.get("http", {})
    url = http.get("url", "")
    return {
        "timestamp": alert.get("timestamp", ""),
        "src_ip": alert.get("src_ip", ""),
        "dest_ip": alert.get("dest_ip", ""),
        "signature": a.get("signature", ""),
        "severity": a.get("severity", 3),
        "category": a.get("category", ""),
        "method": http.get("http_method", ""),
        "url": url,
        "user_agent": http.get("http_user_agent", ""),
        "eid": extract_eid(url),
        "payload": (alert.get("payload_printable", "") or "")[:300].replace("\n", " "),
    }


def _tail_new_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    pos = _last_pos.get(path, 0)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        size = f.tell()
        if size < pos:
            pos = 0
        f.seek(pos)
        lines = f.readlines()
        _last_pos[path] = f.tell()
    return lines


def read_new_alerts(eve_path: str, limit: int = 50) -> list[dict]:
    """Return new EVE JSON alert events since last call."""
    lines = _tail_new_lines(eve_path)
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
    return alerts[-limit:]


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
