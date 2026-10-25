"""Per-request look at the last run of one mode (on the EC2 host, after run_ab.sh).

  1. actor IP agreement — corpus actor_ip vs nginx remote_addr vs the alert's
     client IP (dest_ip on to_client alerts): checks the XFF/realip set-up
  2. HTTP status of every replayed request (path / login redirect problems)
  3. every misclassified request with the decision's reason

eve.json lives in a docker volume, so it comes in on stdin:
  docker exec nginx cat /var/log/nginx/access.json.log > /tmp/nginx.log
  docker exec agent tail -n 100000 /var/log/suricata/eve.json \
    | python3 benchmark/inspect_run.py --nginx /tmp/nginx.log --mode agent
The DB keeps only the last run (run_ab.sh resets it), so run the mode to inspect last.
"""

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
MALICIOUS_ACTIONS = ("block", "warn")


def _jsonl(lines):
    for line in lines:
        try:
            yield json.loads(line)
        except ValueError:
            continue


def _eid(url: str) -> str:
    return url.split("eid=")[1].split("&")[0] if "eid=" in url else ""


def inspect(corpus: dict, sent: dict, nginx_lines, eve_lines, decisions: dict) -> dict:
    """decisions: eid -> (action, detail) of the run's first decision row."""
    nginx_ip = {}
    for r in _jsonl(nginx_lines):
        e = _eid(r.get("uri", ""))
        if e in sent:
            nginx_ip[e] = r.get("remote_addr")
    alert_ip: dict[str, set] = {}
    for ev in _jsonl(eve_lines):
        e = _eid((ev.get("http") or {}).get("url", ""))
        if ev.get("event_type") == "alert" and e in sent:
            client = ev.get("dest_ip") if ev.get("direction") == "to_client" else ev.get("src_ip")
            alert_ip.setdefault(e, set()).add(client)

    mismatches = []
    for e in sent:
        want = corpus.get(e, {}).get("actor_ip")
        if want and (nginx_ip.get(e) != want or alert_ip.get(e, {want}) != {want}):
            mismatches.append({"eid": e, "actor_ip": want, "nginx": nginx_ip.get(e),
                               "alerts": sorted(alert_ip.get(e, set()))})
    errors = []
    for e, g in sent.items():
        action, detail = decisions.get(e, ("-", ""))
        mal = g["label"] == "malicious"
        if mal != (action in MALICIOUS_ACTIONS):
            c = corpus.get(e, {})
            errors.append({"kind": "FN" if mal else "FP", "eid": e, "group": g["group"],
                           "alerted": e in alert_ip, "method": c.get("method", ""),
                           "path": c.get("path", ""), "input": c.get("body") or c.get("params", {}),
                           "action": action, "reason": detail.split("::")[-1].strip()})
    return {"replayed": len(sent), "nginx_logged": len(nginx_ip), "alerted": len(alert_ip),
            "mismatches": mismatches, "status": dict(Counter(g.get("status") for g in sent.values())),
            "errors": errors}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="agent")
    ap.add_argument("--nginx", required=True, help="copy of nginx access.json.log")
    ap.add_argument("--db", default=os.path.join(HERE, "..", "agent", "data", "events.db"))
    ap.add_argument("--sent", default=os.path.join(HERE, "report", "sent.jsonl"))
    ap.add_argument("--corpus", default=os.path.join(HERE, "attack_corpus", "corpus.jsonl"))
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as f:
        corpus = {r["eid"]: r for r in _jsonl(f)}
    with open(args.sent, encoding="utf-8") as f:
        sent = {r["eid"]: r for r in _jsonl(f)}
    conn = sqlite3.connect(args.db)
    decisions: dict[str, tuple] = {}
    for eid, action, detail in conn.execute(
            "SELECT eid, action, detail FROM events WHERE mode=? ORDER BY id", (args.mode,)):
        decisions.setdefault(eid, (action, detail or ""))
    conn.close()
    with open(args.nginx, encoding="utf-8", errors="replace") as f:
        r = inspect(corpus, sent, f, sys.stdin, decisions)

    print(f"replayed={r['replayed']} nginx-logged={r['nginx_logged']} alerted={r['alerted']} "
          f"actor-IP mismatches={len(r['mismatches'])}")
    for m in r["mismatches"]:
        print("  MISMATCH", m)
    print("HTTP status:", r["status"])
    print(f"{args.mode} errors: {len(r['errors'])}")
    for x in r["errors"]:
        print(f"  {x['kind']} {x['group']:13s} alerted={x['alerted']} {x['method']} {x['path']} "
              f"{json.dumps(x['input'], ensure_ascii=False)[:60]} -> {x['action']} :: {x['reason'][:90]}")


if __name__ == "__main__":
    main()
