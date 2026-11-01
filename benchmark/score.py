"""Score one RESPONSE_MODE run against ground truth.

Joins ground truth (report/sent.jsonl) with the agent's SQLite decisions by
`eid`, treating a malicious request as positive. A request with no recorded
decision counts as a benign prediction (benign traffic produces no IDS alert).

Appends one row to a summary CSV. Usage:
  python score.py --mode agent --run 1 --out report/summary_raw.csv
"""

import argparse
import csv
import json
import math
import os
import re
import sqlite3
import time
from datetime import datetime, timezone

HERE = os.path.dirname(__file__)
REPORT_DIR = os.path.join(HERE, "report")
DEFAULT_DB = os.path.join(HERE, "..", "agent", "data", "events.db")

MALICIOUS_ACTIONS = ("block", "warn")
# A safety cap, not the normal exit: scoring waits until every request has a
# decision, so a slow run shows up as latency (MTTB / p95), not as missed
# attacks. With 600s, one agent run fell >10 min behind and 52 undecided
# requests were scored benign (2026-10-27).
DECISION_TIMEOUT_S = 2700

_MITRE_ID = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def mitre_id(s: str) -> str:
    """Technique id out of free text: 'T1190 (Exploit Public-Facing App)' -> 'T1190'."""
    m = _MITRE_ID.search(s or "")
    return m.group(0).upper() if m else ""


def _to_epoch(iso_ts: str) -> float:
    try:
        return datetime.fromisoformat(iso_ts).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0


def load_sent(path: str) -> dict:
    gt = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                gt[r["eid"]] = r
    return gt


def _float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fetch_decisions(db: str, mode: str) -> dict:
    """eid -> {pred_malicious, first_flag_ts, mitre, confidence}. confidence is
    the deciding row's (first block/warn, else the first row); None on a DB
    that predates the column."""
    conn = sqlite3.connect(db)
    has_conf = "confidence" in {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    rows = conn.execute(
        f"SELECT eid, action, ts, mitre, {'confidence' if has_conf else 'NULL'} FROM events "
        "WHERE mode=? AND eid IS NOT NULL AND eid<>''",
        (mode,),
    ).fetchall()
    conn.close()
    out: dict[str, dict] = {}
    for eid, action, ts, mitre, conf in rows:
        d = out.setdefault(eid, {"pred_malicious": False, "first_flag_ts": None, "mitre": "",
                                 "confidence": _float(conf)})
        if action in MALICIOUS_ACTIONS:
            if not d["pred_malicious"]:
                d["confidence"] = _float(conf)
            d["pred_malicious"] = True
            ep = _to_epoch(ts)
            if d["first_flag_ts"] is None or ep < d["first_flag_ts"]:
                d["first_flag_ts"] = ep
            if mitre and not d["mitre"]:
                d["mitre"] = mitre
    return out


def p95(values: list[float]) -> float:
    """95th percentile, nearest rank (0.0 for no values)."""
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(0, math.ceil(0.95 * len(s)) - 1)]


def _decided_eids(db: str, mode: str) -> set[str]:
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT DISTINCT eid FROM events WHERE mode=?", (mode,)).fetchall()
    conn.close()
    return {r[0] for r in rows if r[0]}


def wait_for_decisions(db: str, mode: str, sent: dict, settle_s: float,
                       timeout_s: float, alerted: set | None = None) -> int:
    """Block until this mode's decisions are complete; return how many expected
    requests are still undecided (0 unless the timeout hit).

    agent / waf: they record a decision for every request they see (the WAF
    audits every transaction), so wait until every request that got an HTTP
    response has one — a single LLM invoke can outlast any fixed "no new rows"
    window. rule_based / naive / agent_ids only record alerted requests: with
    `alerted` (the eids Suricata alerted on, from alerted_eids.py) wait for
    exactly those — agent_ids has LLM latency too. Without it, fall back to
    "row count stable for settle_s".
    """
    deadline = time.time() + timeout_s
    if mode in ("agent", "waf"):
        expected = {eid for eid, g in sent.items() if isinstance(g.get("status"), int)}
    else:
        expected = alerted
    if expected is not None:
        while True:
            missing = expected - _decided_eids(db, mode)
            if not missing:
                return 0
            if time.time() >= deadline:
                print(f"[SCORE] WARNING: timeout, {len(missing)}/{len(expected)} eids "
                      f"have no {mode} decision (scored as benign)")
                return len(missing)
            time.sleep(2)

    last, stable_since = -1, time.time()
    while time.time() < deadline:
        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM events WHERE mode=?", (mode,)).fetchone()[0]
        conn.close()
        if n != last:
            last, stable_since = n, time.time()
        elif time.time() - stable_since >= settle_s:
            return 0
        time.sleep(2)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--sent", default=os.path.join(REPORT_DIR, "sent.jsonl"))
    ap.add_argument("--out", default=os.path.join(REPORT_DIR, "summary_raw.csv"))
    ap.add_argument("--settle", type=float, default=15,
                    help="DB-stable seconds (non-agent modes without --alerted)")
    ap.add_argument("--timeout", type=float, default=DECISION_TIMEOUT_S)
    ap.add_argument("--alerted", help="JSON list of alerted eids (alerted_eids.py)")
    ap.add_argument("--preds", default=os.path.join(REPORT_DIR, "preds.jsonl"),
                    help="append per-eid predictions here (input of bootstrap_ci.py)")
    args = ap.parse_args()

    gt = load_sent(args.sent)
    alerted = None
    if args.alerted:
        with open(args.alerted, encoding="utf-8") as f:
            alerted = set(json.load(f))
    undecided = wait_for_decisions(args.db, args.mode, gt, args.settle, args.timeout, alerted)
    dec = fetch_decisions(args.db, args.mode)

    tp = fp = fn = tn = 0
    mttbs = []
    # per-group: recall on evasion (malicious), fpr on fp_bait (benign)
    evasion_total = evasion_hit = 0
    fpbait_total = fpbait_fp = 0
    # MITRE accuracy over correctly-detected attacks (true positives)
    mitre_total = mitre_hit = 0

    preds = []
    for eid, g in gt.items():
        gt_mal = g["label"] == "malicious"
        d = dec.get(eid)
        pred_mal = bool(d and d["pred_malicious"])
        preds.append({"mode": args.mode, "run": args.run, "eid": eid,
                      "label": g["label"], "group": g["group"], "pred": pred_mal,
                      "confidence": d["confidence"] if d else None})

        if gt_mal and pred_mal:
            tp += 1
            if d and d["first_flag_ts"]:
                dt = d["first_flag_ts"] - g["ts_sent"]
                if dt >= 0:
                    mttbs.append(dt)
            if g.get("mitre"):
                mitre_total += 1
                mitre_hit += int(mitre_id(d.get("mitre", "")) == mitre_id(g["mitre"]))
        elif gt_mal and not pred_mal:
            fn += 1
        elif (not gt_mal) and pred_mal:
            fp += 1
        else:
            tn += 1

        if g["group"] == "evasion":
            evasion_total += 1
            evasion_hit += int(pred_mal)
        if g["group"] == "fp_bait":
            fpbait_total += 1
            fpbait_fp += int(pred_mal)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if gt else 0.0
    mttb = sum(mttbs) / len(mttbs) if mttbs else 0.0
    ttb_p95 = p95(mttbs)
    recall_evasion = evasion_hit / evasion_total if evasion_total else 0.0
    fpr_fpbait = fpbait_fp / fpbait_total if fpbait_total else 0.0
    mitre_acc = mitre_hit / mitre_total if mitre_total else 0.0

    row = {
        "mode": args.mode, "run": args.run,
        "split": ",".join(sorted({g.get("split", "") for g in gt.values()})),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4), "accuracy": round(accuracy, 4),
        "mttb_s": round(mttb, 3), "ttb_p95_s": round(ttb_p95, 3),
        "recall_evasion": round(recall_evasion, 4),
        "fpr_fpbait": round(fpr_fpbait, 4), "mitre_acc": round(mitre_acc, 4),
        "undecided": undecided,
    }

    os.makedirs(REPORT_DIR, exist_ok=True)
    new = not os.path.exists(args.out)
    with open(args.out, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)
    with open(args.preds, "a", encoding="utf-8") as f:
        for p in preds:
            f.write(json.dumps(p) + "\n")

    print(f"[SCORE] {args.mode} run{args.run}: "
          f"P={precision:.2f} R={recall:.2f} F1={f1:.2f} FPR={fpr:.2f} "
          f"MTTB={mttb:.1f}s p95={ttb_p95:.1f}s | evasion_recall={recall_evasion:.2f} "
          f"fp_bait_FPR={fpr_fpbait:.2f} MITRE_acc={mitre_acc:.2f}"
          + (f" | UNDECIDED={undecided}" if undecided else ""))


if __name__ == "__main__":
    main()
