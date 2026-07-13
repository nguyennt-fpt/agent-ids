"""AI Security Agent — polls IDS alerts and decides a response.

RESPONSE_MODE selects the decision engine (for A/B benchmarking):
  - rule_based : Suricata alerts only; block if severity <= 2 (IDS + auto-response)
  - naive      : Suricata alerts only; block on ANY alert (over-blocking baseline)
  - agent      : LangGraph engine (LLM + memory) over eve.json + nginx access.log

Tools are called in-process (no MCP hot path). The agent engine is a LangGraph
StateGraph; rule_based/naive stay pure Python and don't import LangChain.
"""

import json
import os
import time

import httpx

from actions import SEV_MAP, guess_attack, record_decision
from tools.alert_reader import (
    extract_eid, normalize_alert, prime_position, read_new_alerts,
)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "agent")
BLOCK_ENABLED = os.getenv("BLOCK_ENABLED", "true").lower() == "true"
EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")


# ─── Rule-based / naive engines (no LLM) ───────────────────────────────────────

def handle_rule_based(alerts: list[dict], mode: str, decided: set) -> None:
    for a in alerts:
        eid = a.get("eid", "")
        if eid and eid in decided:
            continue
        sev = a.get("severity", 3)
        sig = a.get("signature", "")
        if mode == "naive":
            action = "block"                          # block on any alert
        else:
            action = "block" if sev <= 2 else "log"   # rule_based: severity gate
        # rule-based IDS gives a Suricata severity but no semantic MITRE/notes
        record_decision(eid=eid, src_ip=a.get("src_ip", ""), attack=guess_attack(sig),
                        action=action, confidence=1.0,
                        reason=f"severity={sev} sig={sig}", mode=mode,
                        severity=SEV_MAP.get(sev, "low"))
        if eid:
            decided.add(eid)


# ─── Agent engine (2 sources -> LangGraph) ─────────────────────────────────────

def collect_agent_events(alerts: list[dict], decided: set) -> list[dict]:
    """Source 1: Suricata alerts. Source 2: nginx requests Suricata did NOT alert
    on. Returns the dedup'd todo list, skipping already-decided eids."""
    events: list[dict] = []
    alert_eids: set[str] = set()
    for a in alerts:
        eid = a.get("eid", "")
        if eid:
            alert_eids.add(eid)
        events.append({
            "eid": eid, "src_ip": a.get("src_ip", ""), "source": "ids",
            "signature": a.get("signature", ""), "severity": a.get("severity", ""),
            "method": a.get("method", ""), "url": a.get("url", ""),
            "user_agent": a.get("user_agent", ""), "payload": a.get("payload", ""),
        })

    if os.path.exists(NGINX_LOG):
        with open(NGINX_LOG, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-100:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            uri = rec.get("uri", "") or rec.get("request_uri", "")
            eid = extract_eid(uri)
            if not eid or eid in alert_eids:
                continue
            events.append({
                "eid": eid, "src_ip": rec.get("remote_addr", ""), "source": "web",
                "signature": "", "severity": "", "method": rec.get("method", ""),
                "url": uri, "user_agent": rec.get("http_user_agent", ""), "payload": "",
            })

    todo, seen = [], set()
    for e in events:
        eid = e["eid"]
        if eid and (eid in decided or eid in seen):
            continue
        if eid:
            seen.add(eid)
        todo.append(e)
    return todo


def wait_for_ollama() -> None:
    with httpx.Client() as c:
        for _ in range(60):
            try:
                c.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
                print("[AGENT] Ollama ready")
                return
            except Exception:
                time.sleep(5)


# ─── Main loop ────────────────────────────────────────────────────────────────

def run() -> None:
    print(f"[AGENT] Starting. mode={RESPONSE_MODE} poll={POLL_INTERVAL}s "
          f"block_enabled={BLOCK_ENABLED}")
    prime_position(EVE_LOG)          # skip a prior benchmark run's stale alerts
    decided: set[str] = set()

    app = None
    if RESPONSE_MODE == "agent":
        wait_for_ollama()
        from graph import build_graph   # imported here so rule modes skip LangChain
        app = build_graph()

    while True:
        alerts = [normalize_alert(a) for a in read_new_alerts(EVE_LOG, limit=50)]

        if RESPONSE_MODE in ("rule_based", "naive"):
            handle_rule_based(alerts, RESPONSE_MODE, decided)
        else:
            todo = collect_agent_events(alerts, decided)
            if todo:
                result = app.invoke({"events": todo, "decisions": [], "decided_eids": []})
                for eid in result.get("decided_eids", []):
                    decided.add(eid)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
