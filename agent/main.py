"""AI Security Agent — polls IDS alerts and decides a response.

RESPONSE_MODE selects the decision engine (for A/B benchmarking):
  - rule_based : Suricata alerts only; block if severity <= 2 (IDS + auto-response)
  - naive      : Suricata alerts only; block on ANY alert (over-blocking baseline)
  - agent      : LangGraph engine (LLM + memory) over eve.json + nginx access.log
  - agent_ids  : ablation — the same LangGraph engine over eve.json ONLY, to tell
                 "sees more (2nd source)" apart from "reasons better"

Tools are called in-process (no MCP hot path). The agent engine is a LangGraph
StateGraph; rule_based/naive stay pure Python and don't import LangChain.
"""

import json
import os
import time

import httpx

from actions import SEV_MAP, guess_attack, record_decision, rule_flags
from tools.alert_reader import (
    extract_eid, normalize_alert, prime_position, read_new_alerts, tail_new_lines,
)
from tools.firewall import cleanup_stale_blocks

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "agent")
BLOCK_ENABLED = os.getenv("BLOCK_ENABLED", "true").lower() == "true"
EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")
# events per triage call: output grows ~100 tokens/decision and past num_predict
# (4096) the JSON is cut off; input must also fit num_ctx (8192) with the prompt.
TRIAGE_BATCH = int(os.getenv("TRIAGE_BATCH", "15"))
# retries for a web-only event the model returned no decision for (then fail closed)
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))


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
            action = "block" if rule_flags(sev) else "log"   # rule_based: severity gate
        # rule-based IDS gives a Suricata severity but no semantic MITRE/notes
        record_decision(eid=eid, src_ip=a.get("src_ip", ""), attack=guess_attack(sig),
                        action=action, confidence=1.0,
                        reason=f"severity={sev} sig={sig}", mode=mode,
                        severity=SEV_MAP.get(sev, "low"))
        if eid:
            decided.add(eid)


# ─── Agent engine (2 sources -> LangGraph) ─────────────────────────────────────

def collect_agent_events(alerts: list[dict], decided: set,
                         include_web: bool = True) -> list[dict]:
    """Source 1: Suricata alerts. Source 2 (unless include_web=False, the
    agent_ids ablation): nginx requests Suricata did NOT alert on. Returns the
    dedup'd todo list, skipping already-decided eids."""
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

    # isfile (not exists): the stock nginx image symlinks access.log -> /dev/stdout;
    # opening that char device blocks forever. isfile is False for it, so we skip
    # it safely and only read a real access-log file. Read by offset (primed at
    # boot) so each request is seen once and a prior run's lines are never replayed.
    if include_web and os.path.isfile(NGINX_LOG):
        for line in tail_new_lines(NGINX_LOG):
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
                "url": uri, "user_agent": rec.get("http_user_agent", ""),
                # POST form body (nginx logs $request_body) — same 300-char cap as IDS payloads
                "payload": (rec.get("request_body", "") or "")[:300],
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


def process_agent_events(app, todo: list[dict], decided: set, retries: dict) -> None:
    """Run the graph over `todo` in chunks of TRIAGE_BATCH events.

    The graph leaves out of decided_eids only web-only events the model gave no
    decision for (IDS events fall back to the rule verdict inside it). Those
    are kept in `retries` (eid -> (event, attempts)) and retried *alone* on the
    next polls — alone, so an event that keeps breaking the model's output
    can't take a batch down with it. After MAX_RETRIES they fail closed as
    `warn`; bounded, so such a payload can't stall the loop forever.
    """
    for e in todo:
        retries.pop(e.get("eid", ""), None)     # a fresh copy (e.g. now IDS-flagged) wins
    batches = [[ev] for ev, _ in retries.values()]
    batches += [todo[i:i + TRIAGE_BATCH] for i in range(0, len(todo), TRIAGE_BATCH)]

    for batch in batches:
        result = app.invoke({"events": batch, "decisions": [],
                             "ambiguous_eids": [], "decided_eids": []})
        done = set(result.get("decided_eids", []))
        decided.update(done)
        for ev in batch:
            eid = ev.get("eid", "")
            if not eid or eid in done:
                retries.pop(eid, None)
                continue
            attempts = retries.get(eid, (ev, 0))[1] + 1
            if attempts <= MAX_RETRIES:
                retries[eid] = (ev, attempts)
                continue
            retries.pop(eid, None)
            record_decision(eid=eid, src_ip=ev.get("src_ip", ""), attack="unknown",
                            action="warn", confidence=0.0, mode=RESPONSE_MODE,
                            reason=f"no LLM decision after {attempts} attempts (fail-closed)")
            decided.add(eid)


def late_ids_alerts(alerts: list[dict], web_decided: set) -> list[str]:
    """eids whose IDS alert arrived after the request was already triaged from
    the web log — the model decided it without seeing the signature (D4: the
    nginx line can be read a poll before Suricata's alert)."""
    return [a["eid"] for a in alerts if a.get("eid") in web_decided]


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
    prime_position(NGINX_LOG)        # ...and its stale web-log lines
    if BLOCK_ENABLED:
        n = cleanup_stale_blocks()
        if n:
            print(f"[AGENT] removed {n} stale agent-block rule(s) left by a previous run")
    decided: set[str] = set()
    web_decided: set[str] = set()    # eids decided from the web log, for late_ids_alerts
    retries: dict[str, tuple[dict, int]] = {}

    app = None
    if RESPONSE_MODE in ("agent", "agent_ids"):
        wait_for_ollama()
        from graph import build_graph   # imported here so rule modes skip LangChain
        app = build_graph()

    while True:
        alerts = [normalize_alert(a) for a in read_new_alerts(EVE_LOG, limit=50)]

        if RESPONSE_MODE in ("rule_based", "naive"):
            handle_rule_based(alerts, RESPONSE_MODE, decided)
        else:
            late = late_ids_alerts(alerts, web_decided)
            if late:
                print(f"[AGENT] {len(late)} IDS alert(s) arrived after their request was "
                      f"already triaged from the web log: {late}")
            todo = collect_agent_events(alerts, decided,
                                        include_web=RESPONSE_MODE == "agent")
            if todo or retries:
                process_agent_events(app, todo, decided, retries)
                web_decided.update(e["eid"] for e in todo
                                   if e["source"] == "web" and e["eid"] in decided)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
