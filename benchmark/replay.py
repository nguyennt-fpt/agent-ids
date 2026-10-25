"""Replay the labeled corpus against the target through Nginx.

Each request carries its `eid` in the query string so it can be traced through
eve.json (Suricata) and the agent's SQLite decisions. Writes a ground-truth +
timing reference to report/sent.jsonl for score.py.

Corpus v2 rows (docs/CORPUS_V2.md) also carry `split`, `seq` (replay order),
`actor_ip` (sent as X-Forwarded-For so nginx and Suricata see the actor) and
`body` (POST form fields). v1 rows without them replay as before.

Usage:
  python replay.py --target http://localhost --delay 0.5 [--split dev|test]
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


def select_rows(rows: list[dict], split: str | None) -> list[dict]:
    """Rows of `split` (all when None), in replay order (`seq`, else file order)."""
    if split:
        rows = [r for r in rows if r.get("split") == split]
    return sorted(rows, key=lambda r: r.get("seq", 0))


def build_request(r: dict, target: str) -> tuple[str, str, dict]:
    """(method, url, httpx kwargs) for one corpus row. The eid always rides in
    the query string — Suricata and nginx both log the URI, not the body."""
    params = dict(r.get("params", {}))
    params["eid"] = r["eid"]
    headers = {"User-Agent": r.get("user_agent", "Mozilla/5.0")}
    if r.get("actor_ip"):
        headers["X-Forwarded-For"] = r["actor_ip"]
    kw = {"params": params, "headers": headers}
    if r.get("body"):
        kw["data"] = r["body"]
    return r.get("method", "GET"), target.rstrip("/") + r["path"], kw


def make_client() -> httpx.Client:
    """One TCP connection per request (no keep-alive): sharing a connection put
    the bytes of one actor's request into another actor's IDS alert payload
    (EC2 2026-10-25). Real clients never share a socket."""
    return httpx.Client(timeout=10, follow_redirects=True,
                        limits=httpx.Limits(max_keepalive_connections=0))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--delay", type=float, default=0.5,
                    help="seconds between requests (let IDS+agent process)")
    ap.add_argument("--out", default=os.path.join(REPORT_DIR, "sent.jsonl"))
    ap.add_argument("--split", choices=["dev", "test"],
                    help="replay only this split (corpus v2); default: every row")
    args = ap.parse_args()

    os.makedirs(REPORT_DIR, exist_ok=True)
    rows = select_rows(load_corpus(args.corpus), args.split)
    print(f"[REPLAY] {len(rows)} requests -> {args.target}"
          + (f" (split={args.split})" if args.split else ""))

    sent = []
    with make_client() as client:
        for r in rows:
            method, url, kw = build_request(r, args.target)
            ts_sent = time.time()
            status = None
            try:
                resp = client.request(method, url, **kw)
                status = resp.status_code
            except Exception as e:
                status = f"error:{e}"
            sent.append({
                "eid": r["eid"], "ts_sent": ts_sent, "label": r["label"],
                "group": r["group"], "attack_type": r.get("attack_type", ""),
                "mitre": r.get("mitre", ""), "status": status,
                "split": r.get("split", ""),
            })
            time.sleep(args.delay)

    with open(args.out, "w", encoding="utf-8") as f:
        for s in sent:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"[REPLAY] done. ground-truth+timing -> {args.out}")


if __name__ == "__main__":
    main()
