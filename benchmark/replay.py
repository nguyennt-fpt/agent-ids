"""Replay the labeled corpus against the target through Nginx.

Each request carries its `eid` in the query string so it can be traced through
eve.json (Suricata) and the agent's SQLite decisions. Writes a ground-truth +
timing reference to report/sent.jsonl for score.py.

Usage:
  python replay.py --target http://localhost --delay 0.5
"""

import argparse
import json
import os
import time

import httpx

HERE = os.path.dirname(__file__)
CORPUS = os.path.join(HERE, "attack_corpus", "corpus.jsonl")
REPORT_DIR = os.path.join(HERE, "report")


def load_corpus(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--delay", type=float, default=0.5,
                    help="seconds between requests (let IDS+agent process)")
    ap.add_argument("--out", default=os.path.join(REPORT_DIR, "sent.jsonl"))
    args = ap.parse_args()

    os.makedirs(REPORT_DIR, exist_ok=True)
    rows = load_corpus(args.corpus)
    print(f"[REPLAY] {len(rows)} requests -> {args.target}")

    sent = []
    with httpx.Client(timeout=10, follow_redirects=True) as client:
        for r in rows:
            params = dict(r.get("params", {}))
            params["eid"] = r["eid"]                 # trace tag
            url = args.target.rstrip("/") + r["path"]
            headers = {"User-Agent": r.get("user_agent", "Mozilla/5.0")}
            ts_sent = time.time()
            status = None
            try:
                resp = client.request(r.get("method", "GET"), url,
                                      params=params, headers=headers)
                status = resp.status_code
            except Exception as e:
                status = f"error:{e}"
            sent.append({
                "eid": r["eid"], "ts_sent": ts_sent, "label": r["label"],
                "group": r["group"], "attack_type": r.get("attack_type", ""),
                "mitre": r.get("mitre", ""), "status": status,
            })
            time.sleep(args.delay)

    with open(args.out, "w", encoding="utf-8") as f:
        for s in sent:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"[REPLAY] done. ground-truth+timing -> {args.out}")


if __name__ == "__main__":
    main()
