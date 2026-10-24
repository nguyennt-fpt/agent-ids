"""Which replayed requests did Suricata alert on?  stdin: eve.json lines.

rule_based / naive / agent_ids only record a decision for alerted requests, so
score.py --alerted waits for exactly these eids instead of guessing from a quiet
DB. eve.json lives in a docker volume, so run_ab.sh pipes it in:
  docker compose exec -T agent tail -n 100000 /var/log/suricata/eve.json \
    | python3 alerted_eids.py --sent report/sent.jsonl > report/alerted.json
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from score import load_sent


def alerted_eids(lines, sent: dict) -> list[str]:
    """eids of `sent` with an alert raised during this replay. eids are
    deterministic, so eve.json also holds earlier runs' alerts for the same
    eids — only alerts from the run's first send onward count."""
    since = min(g["ts_sent"] for g in sent.values()) - 1
    out = set()
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event_type") != "alert":
            continue
        url = (e.get("http") or {}).get("url", "")
        eid = parse_qs(urlparse(url).query).get("eid", [""])[0]
        if eid not in sent:
            continue
        try:   # Suricata: 2026-09-29T16:51:10.542843+0000
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        except (KeyError, ValueError):
            continue
        if ts >= since:
            out.add(eid)
    return sorted(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sent", required=True)
    args = ap.parse_args()
    json.dump(alerted_eids(sys.stdin, load_sent(args.sent)), sys.stdout)


if __name__ == "__main__":
    main()
