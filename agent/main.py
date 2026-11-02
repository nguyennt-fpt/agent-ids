"""AI Security Agent — polls IDS alerts and decides a response.

RESPONSE_MODE selects the decision engine (for A/B benchmarking):
  - rule_based : Suricata alerts only; block if severity <= 2 (IDS + auto-response)
  - naive      : Suricata alerts only; block on ANY alert (over-blocking baseline)
  - agent      : LangGraph engine (LLM + memory) over eve.json + nginx access.log
  - agent_ids  : ablation — the same LangGraph engine over eve.json ONLY, to tell
                 "sees more (2nd source)" apart from "reasons better"
  - waf        : industry baseline — OWASP CRS on ModSecurity (in-path, DetectionOnly);
                 attack iff CRS's inbound anomaly threshold rule 949110 fired

Tools are called in-process (no MCP hot path). The agent engine is a LangGraph
StateGraph; rule_based/naive stay pure Python and don't import LangChain.
"""

import json
import os
import sqlite3
import time
import uuid

import httpx

import approvals
from actions import SEV_MAP, guess_attack, record_decision, rule_flags
from tools.alert_reader import (
    extract_eid, normalize_alert, prime_position, read_new_alerts, strip_eid, tail_new_lines,
    web_eid,
)
from tools.firewall import cleanup_stale_blocks

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "agent")
BLOCK_ENABLED = os.getenv("BLOCK_ENABLED", "true").lower() == "true"
EVE_LOG = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")
WAF_LOG = os.getenv("WAF_LOG", "/var/log/waf/audit.json")   # ModSecurity JSON audit log
# events per triage call. 1 = each event judged on its own: in a batch the model's
# call on one event leans on the events before it (N1, EC2 2026-10-25: a plain
# request last in a batch, after an attack on the same page, was flagged 3/3;
# moved first, or alone, logged 3/3) — and which events share a batch is up to
# arrival timing. The system prompt is a cached prefix, so the extra calls are
# cheap. Upper bound when raised: ~100 output tokens/decision, num_predict 4096.
TRIAGE_BATCH = int(os.getenv("TRIAGE_BATCH", "1"))
# retries for a web-only event the model returned no decision for (then fail closed)
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
# Real traffic carries no benchmark eid. true: such web-log lines are judged too,
# each under its own id (alert_reader.web_eid), joined with the request's IDS alert.
# The benchmark sets false: its replay follows DVWA's redirects, and those eid-less
# follow-up requests would double the LLM load without ever being scored.
WEB_UNTAGGED = os.getenv("WEB_UNTAGGED", "true").lower() == "true"
# real-traffic alerts with the same source + signature within this window are
# triaged once (2026-10-27: one apt run's 211 alerts were triaged one by one and
# held real detections back >10 min). A benchmark eid is always decided.
ALERT_DEDUP_WINDOW_S = int(os.getenv("ALERT_DEDUP_WINDOW_S", "300"))
# HITL outside the demo (G5): where paused graph runs are checkpointed
CHECKPOINT_DB = os.getenv("HITL_CHECKPOINT_DB", "/app/data/checkpoints.db")


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


# ─── WAF baseline (OWASP CRS, no LLM) ──────────────────────────────────────────

# CRS tags its rules by attack class; first match wins
_CRS_TAGS = (("attack-sqli", "sqli"), ("attack-xss", "xss"), ("attack-rce", "cmdi"),
             ("attack-rfi", "rfi"), ("attack-lfi", "lfi"), ("attack-reputation-scanner", "scan"))


def handle_waf(decided: set) -> None:
    """One decision per audited transaction (the WAF audits every request).
    Attack = CRS's inbound anomaly score crossed its threshold (rule 949110),
    exactly what would have blocked with the rule engine On; DetectionOnly
    just logs it, so every mode sees the same traffic."""
    for line in tail_new_lines(WAF_LOG):
        try:
            tx = json.loads(line).get("transaction", {})
        except (ValueError, AttributeError):
            continue
        req = tx.get("request") or {}
        eid = extract_eid(req.get("uri", ""))
        if not eid or eid in decided:
            continue
        msgs = [m.get("details") or {} for m in tx.get("messages") or []]
        flagged = any(str(d.get("ruleId")) == "949110" for d in msgs)
        tags = {t for d in msgs for t in d.get("tags") or []}
        attack = next((a for tag, a in _CRS_TAGS if tag in tags), "unknown") if flagged else "none"
        headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        src = (headers.get("x-forwarded-for") or tx.get("client_ip") or "").split(",")[0].strip()
        rule_ids = sorted({str(d.get("ruleId")) for d in msgs if d.get("ruleId")})
        record_decision(eid=eid, src_ip=src, attack=attack, action="block" if flagged else "log",
                        confidence=1.0, reason=f"CRS rules {','.join(rule_ids) or '-'}",
                        mode="waf", severity="high" if flagged else "")
        decided.add(eid)


# ─── Agent engine (2 sources -> LangGraph) ─────────────────────────────────────

# Real traffic: an alert and the nginx line of one request are joined on (client
# port, method, uri) — not on the IP, which Suricata takes from a client-supplied
# X-Forwarded-For — and share one id, so the request is decided once whichever
# source is read first. Entries are kept _JOIN_TTL_S.
_JOIN_TTL_S = 120.0
_recent: dict[tuple, tuple[str, str, float]] = {}   # request key -> (id, nginx client ip, seen at)
_dedup_seen: dict[tuple, tuple[str, float]] = {}    # (src_ip, sid) -> (first id, when)
_clock = time.monotonic


def _request_key(port, method: str, uri: str) -> tuple | None:
    return (str(port), method or "", uri) if port and uri else None


def collect_agent_events(alerts: list[dict], decided: set,
                         include_web: bool = True) -> list[dict]:
    """Source 1: Suricata alerts. Source 2 (unless include_web=False, the
    agent_ids ablation): nginx requests Suricata did NOT alert on. Returns the
    dedup'd todo list, skipping already-decided eids. url/payload go to the
    model without the benchmark's eid parameter (strip_eid).

    Real traffic (no benchmark eid): a joined alert takes its web-log line's id
    and client IP (written back into the alert dict), and repeats of one source
    + signature within ALERT_DEDUP_WINDOW_S are suppressed — added to `decided`,
    so their web-log lines are skipped too."""
    now = _clock()
    for k in [k for k, v in _recent.items() if now - v[2] > _JOIN_TTL_S]:
        del _recent[k]
    for k in [k for k, v in _dedup_seen.items() if now - v[1] >= ALERT_DEDUP_WINDOW_S]:
        del _dedup_seen[k]

    # isfile (not exists): the stock nginx image symlinks access.log -> /dev/stdout;
    # opening that char device blocks forever. isfile is False for it, so we skip
    # it safely and only read a real access-log file. Read by offset (primed at
    # boot) so each request is seen once and a prior run's lines are never replayed.
    # Read before the alerts, so an alert can join its line in the same poll.
    lines: list[tuple[str, str, dict]] = []
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
            if not eid:
                if not WEB_UNTAGGED:
                    continue
                key = _request_key(rec.get("remote_port"), rec.get("method", ""), uri)
                hit = _recent.get(key) if key else None
                eid = hit[0] if hit else web_eid(rec)       # hit: its alert came a poll earlier
                if key and not hit:
                    _recent[key] = (eid, rec.get("remote_addr", ""), now)
            lines.append((eid, uri, rec))

    events: list[dict] = []
    alert_eids: set[str] = set()
    suppressed: dict[tuple, int] = {}
    for a in alerts:
        eid = a.get("eid", "")
        if eid.startswith("auto-"):                         # real traffic
            key = _request_key(a.get("src_port"), a.get("method", ""), a.get("url", ""))
            hit = _recent.get(key) if key else None
            if hit:
                eid = a["eid"] = hit[0]
                if hit[1] and hit[1] != a.get("src_ip"):
                    print(f"[AGENT] eid={eid}: alert src_ip {a.get('src_ip')} != nginx client "
                          f"{hit[1]} (X-Forwarded-For sent by the client?) -> using nginx's")
                    a["src_ip"] = hit[1]
            elif key:
                _recent[key] = (eid, "", now)
            dkey = (a.get("src_ip", ""), a.get("sid") or a.get("signature", ""))
            first = _dedup_seen.get(dkey)
            if first and first[0] != eid:
                suppressed[dkey] = suppressed.get(dkey, 0) + 1
                alert_eids.add(eid)
                decided.add(eid)
                continue
            if not first:
                _dedup_seen[dkey] = (eid, now)
        if eid:
            alert_eids.add(eid)
        events.append({
            "eid": eid, "src_ip": a.get("src_ip", ""), "source": "ids",
            "signature": a.get("signature", ""), "severity": a.get("severity", ""),
            "method": a.get("method", ""), "url": strip_eid(a.get("url", "")),
            "user_agent": a.get("user_agent", ""), "payload": strip_eid(a.get("payload", "")),
        })
    if suppressed:
        top = ", ".join(f"{ip} sid={sid} x{n}" for (ip, sid), n in list(suppressed.items())[:3])
        print(f"[AGENT] suppressed {sum(suppressed.values())} duplicate alert(s) "
              f"(same source + signature within {ALERT_DEDUP_WINDOW_S}s): {top}")

    for eid, uri, rec in lines:
        if eid in alert_eids:
            continue
        events.append({
            "eid": eid, "src_ip": rec.get("remote_addr", ""), "source": "web",
            "signature": "", "severity": "", "method": rec.get("method", ""),
            "url": strip_eid(uri), "user_agent": rec.get("http_user_agent", ""),
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


def _settle(batch: list[dict], done: set, decided: set, retries: dict) -> None:
    """After a graph run: mark `done` decided; queue the batch's undecided
    (web-only) events for a retry, or fail them closed once retries run out."""
    decided.update(done)
    for ev in batch:
        eid = ev.get("eid", "")
        if not eid or eid in done:
            retries.pop(eid, None)
            continue
        attempts = retries.get(eid, (ev, 0))[1] + 1
        if attempts <= MAX_RETRIES:
            retries[eid] = (ev, attempts)
            print(f"[AGENT] no decision for eid={eid} -> retry {attempts}/{MAX_RETRIES}")
            continue
        retries.pop(eid, None)
        print(f"[AGENT] no decision for eid={eid} after {attempts} attempts -> fail-closed warn")
        record_decision(eid=eid, src_ip=ev.get("src_ip", ""), attack="unknown",
                        action="warn", confidence=0.0, mode=RESPONSE_MODE,
                        reason=f"no LLM decision after {attempts} attempts (fail-closed)")
        decided.add(eid)


def process_agent_events(app, todo: list[dict], decided: set, retries: dict,
                         paused: dict | None = None) -> None:
    """Run the graph over `todo` in chunks of TRIAGE_BATCH events.

    The graph leaves out of decided_eids only web-only events the model gave no
    decision for (IDS events fall back to the rule verdict inside it). Those
    are kept in `retries` (eid -> (event, attempts)) and retried *alone* on the
    next polls — alone, so an event that keeps breaking the model's output
    can't take a batch down with it. After MAX_RETRIES they fail closed as
    `warn`; bounded, so such a payload can't stall the loop forever.

    With `paused` (HITL on: AUTO_APPROVE=false + a checkpointer), each batch
    runs in its own checkpointed thread. A batch the risk gate escalates stops
    at the interrupt: its items go to the approvals queue and the batch waits
    in `paused` (thread_id -> batch), neither decided nor retried, until
    resume_approved() continues it. The loop itself never blocks on a human.
    """
    for e in todo:
        retries.pop(e.get("eid", ""), None)     # a fresh copy (e.g. now IDS-flagged) wins
    batches = [[ev] for ev, _ in retries.values()]
    batches += [todo[i:i + TRIAGE_BATCH] for i in range(0, len(todo), TRIAGE_BATCH)]

    for batch in batches:
        state = {"events": batch, "decisions": [], "ambiguous_eids": [], "decided_eids": []}
        if paused is None:
            result = app.invoke(state)
        else:
            thread_id = f"batch-{uuid.uuid4().hex[:12]}"
            result = app.invoke(state, {"configurable": {"thread_id": thread_id}})
            if result.get("__interrupt__"):
                approvals.add_pending(thread_id, result["__interrupt__"][0].value["pending"])
                paused[thread_id] = batch
                print(f"[GATE] batch {thread_id} waits for a human — "
                      f"`docker exec agent python approve.py`")
                continue
        _settle(batch, set(result.get("decided_eids", [])), decided, retries)


def resume_approved(app, decided: set, retries: dict, paused: dict, memory: bool = False) -> None:
    """Continue every paused run whose escalated items are all answered (or
    expired -> warn). With memory on, the human's answer is ground truth for
    the model's proposed block — benign makes it a false-positive lesson, so
    the memory learns from real analysts, not only benchmark labels (#10)."""
    from langgraph.types import Command      # LangChain stays out of the rule modes

    for thread_id, answers in approvals.ready_threads().items():
        result = app.invoke(Command(resume=answers), {"configurable": {"thread_id": thread_id}})
        approvals.mark_resumed(thread_id)
        batch = paused.pop(thread_id, [])          # [] after an agent restart
        _settle(batch, set(result.get("decided_eids", [])), decided, retries)
        if memory:
            from tools.memory import record_feedback
            events = {e.get("eid"): e for e in batch}
            for item in approvals.items(thread_id):
                ev = events.get(item["eid"], {})
                truth = "benign" if answers.get(item["eid"]) == "benign" else "malicious"
                record_feedback(item["eid"], truth, "block", item["attack_type"] or "",
                                ev.get("payload") or ev.get("url", ""))


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
    prime_position(WAF_LOG)          # ...and the WAF's
    if BLOCK_ENABLED:
        n = cleanup_stale_blocks()
        if n:
            print(f"[AGENT] removed {n} stale agent-block rule(s) left by a previous run")
    decided: set[str] = set()
    web_decided: set[str] = set()    # eids decided from the web log, for late_ids_alerts
    retries: dict[str, tuple[dict, int]] = {}

    app = paused = None
    memory_on = False
    if RESPONSE_MODE in ("agent", "agent_ids"):
        wait_for_ollama()
        import graph                    # imported here so rule modes skip LangChain
        checkpointer = None
        if not graph.AUTO_APPROVE:      # real HITL: paused runs survive an agent restart
            from langgraph.checkpoint.sqlite import SqliteSaver
            checkpointer = SqliteSaver(sqlite3.connect(CHECKPOINT_DB, check_same_thread=False))
            paused = {}
            print(f"[AGENT] HITL on: escalated blocks wait for `approve.py` "
                  f"(timeout {approvals.TIMEOUT_S}s -> warn)")
        app = graph.build_graph(checkpointer)
        memory_on = graph.MEMORY_ENABLED

    while True:
        alerts = [normalize_alert(a) for a in read_new_alerts(EVE_LOG, limit=50)]

        if RESPONSE_MODE in ("rule_based", "naive"):
            handle_rule_based(alerts, RESPONSE_MODE, decided)
        elif RESPONSE_MODE == "waf":
            handle_waf(decided)
        else:
            todo = collect_agent_events(alerts, decided,
                                        include_web=RESPONSE_MODE == "agent")
            late = late_ids_alerts(alerts, web_decided)      # after: a joined alert has its line's id
            if late:
                print(f"[AGENT] {len(late)} IDS alert(s) arrived after their request was "
                      f"already triaged from the web log: {late}")
            if todo or retries:
                process_agent_events(app, todo, decided, retries, paused)
                web_decided.update(e["eid"] for e in todo
                                   if e["source"] == "web" and e["eid"] in decided)
            if paused is not None:
                resume_approved(app, decided, retries, paused, memory_on)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
