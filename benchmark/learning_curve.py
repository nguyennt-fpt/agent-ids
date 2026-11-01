"""Learning curve for experience memory (Trụ 4A).

Each epoch: (1) EVALUATE — replay the eval split and score it, using only
lessons learned so far; (2) LEARN — replay the feedback split and write its
ground truth into the experience store. Feedback never comes from the eval
split: the old loop replayed one corpus and fed back the answers to the very
requests it re-scored next epoch, so the curve measured recall of memorized
answers (review #2). The splits are disjoint by payload family, so a lesson
quoting a feedback-split payload reveals nothing about eval requests.
Epoch 1 is evaluated before any feedback — the no-memory reference point.

Compare two invocations:
  python learning_curve.py --epochs 5 --memory on
  python learning_curve.py --epochs 5 --memory off
Then it overlays report/curve_on.csv vs curve_off.csv -> report/learning_curve.png

Requires the full stack running (Docker + Ollama). EC2.
"""

import argparse
import csv
import json
import os
import subprocess
import sqlite3
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
REPORT = os.path.join(HERE, "report")
AGENT_DATA = os.path.join(ROOT, "agent", "data")
CORPUS = os.path.join(HERE, "attack_corpus", "corpus.jsonl")
EVENTS_DB = os.path.join(AGENT_DATA, "events.db")

# import scoring + memory helpers; point memory at the bind-mounted DB
os.environ["MEMORY_DB"] = EVENTS_DB
sys.path.insert(0, HERE)                                   # score.py
sys.path.insert(0, os.path.join(ROOT, "agent"))            # tools.memory
from score import DECISION_TIMEOUT_S, load_sent, fetch_decisions, wait_for_decisions  # noqa: E402
from tools.memory import record_feedback                   # noqa: E402


def sh(cmd: list[str], **kw):
    return subprocess.run(cmd, cwd=ROOT, **kw)


def load_corpus_index() -> dict:
    idx = {}
    with open(CORPUS, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                fields = {**r.get("params", {}), **(r.get("body") or {})}   # POST rows carry it in body
                payload = " ".join(str(v) for v in fields.values())
                idx[r["eid"]] = {"attack_type": r.get("attack_type", ""), "payload": payload}
    return idx


def reset_events_only():
    sh(["docker", "compose", "exec", "-T", "agent", "python", "-c",
        "import sqlite3,os;d=os.getenv('DASHBOARD_DB','/app/data/events.db');"
        "c=sqlite3.connect(d);c.execute(\"DELETE FROM events WHERE mode='agent'\");"
        "c.commit();c.close()"], check=False)


def clear_experience():
    if os.path.exists(EVENTS_DB):
        c = sqlite3.connect(EVENTS_DB)
        try:
            c.execute("DELETE FROM experience")
            c.commit()
        except sqlite3.OperationalError:
            pass
        c.close()


def epoch_metrics(sent: dict, dec: dict) -> tuple[float, float]:
    tp = fp = fn = tn = 0
    for eid, g in sent.items():
        gt_mal = g["label"] == "malicious"
        pred_mal = bool(dec.get(eid, {}).get("pred_malicious"))
        if gt_mal and pred_mal:
            tp += 1
        elif gt_mal:
            fn += 1
        elif pred_mal:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return recall, fpr


def replay(split: str, target: str, delay: float) -> dict:
    """Replay one corpus split and wait until the agent decided all of it."""
    out = os.path.join(REPORT, f"sent_{split}.jsonl")
    subprocess.run([sys.executable, os.path.join(HERE, "replay.py"), "--target", target,
                    "--delay", str(delay), "--split", split, "--out", out], check=False)
    sent = load_sent(out)
    wait_for_decisions(EVENTS_DB, "agent", sent, settle_s=15, timeout_s=DECISION_TIMEOUT_S)
    return sent


def run(epochs: int, memory: str, target: str, delay: float,
        feedback_split: str = "dev", eval_split: str = "test"):
    if feedback_split == eval_split:
        raise ValueError("feedback and eval split must differ, or the curve scores "
                         "answers it was just told")
    mem_on = memory == "on"
    clear_experience()
    corpus_idx = load_corpus_index()
    out_csv = os.path.join(REPORT, f"curve_{memory}.csv")
    os.makedirs(REPORT, exist_ok=True)
    rows = []

    for epoch in range(1, epochs + 1):
        print(f"\n===== memory={memory} epoch={epoch}/{epochs} =====")
        env = {**os.environ, "RESPONSE_MODE": "agent", "BLOCK_ENABLED": "false",
               "MEMORY_ENABLED": "true" if mem_on else "false", "EPOCH": str(epoch)}
        sh(["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "agent"],
           env=env)
        time.sleep(12)
        reset_events_only()

        held = replay(eval_split, target, delay)            # 1. evaluate: lessons so far only
        recall, fpr = epoch_metrics(held, fetch_decisions(EVENTS_DB, "agent"))

        train = replay(feedback_split, target, delay)       # 2. learn from the other split
        dec = fetch_decisions(EVENTS_DB, "agent")
        train_recall, train_fpr = epoch_metrics(train, dec)
        if mem_on:
            for eid, g in train.items():
                meta = corpus_idx.get(eid, {})
                pred = "block" if dec.get(eid, {}).get("pred_malicious") else "log"
                record_feedback(eid, g["label"], pred,
                                meta.get("attack_type", ""), meta.get("payload", ""))

        rows.append({"epoch": epoch, "recall": round(recall, 4), "fpr": round(fpr, 4),
                     "train_recall": round(train_recall, 4), "train_fpr": round(train_fpr, 4)})
        print(f"   epoch {epoch}: eval recall={recall:.2f} fpr={fpr:.2f} | "
              f"feedback split recall={train_recall:.2f} fpr={train_fpr:.2f}")

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["epoch", "recall", "fpr", "train_recall", "train_fpr"])
        w.writeheader(); w.writerows(rows)
    print(f"\nwrote {out_csv}")
    return out_csv


def overlay_plot():
    on_csv = os.path.join(REPORT, "curve_on.csv")
    off_csv = os.path.join(REPORT, "curve_off.csv")
    if not (os.path.exists(on_csv) and os.path.exists(off_csv)):
        print("Run both --memory on and --memory off to produce the overlay plot.")
        return
    try:                                   # the EC2 host has no matplotlib; the CSVs are the result
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed — learning_curve.png skipped (CSVs written)")
        return

    def load(p):
        with open(p, encoding="utf-8") as f:
            return list(csv.DictReader(f))
    on, off = load(on_csv), load(off_csv)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    for ax, key, title in ((ax1, "fpr", "False Positive Rate ↓"),
                           (ax2, "recall", "Recall ↑")):
        ax.plot([int(r["epoch"]) for r in on], [float(r[key]) for r in on],
                "o-", label="memory ON")
        ax.plot([int(r["epoch"]) for r in off], [float(r[key]) for r in off],
                "s--", label="memory OFF")
        ax.set_xlabel("epoch"); ax.set_title(title); ax.legend(); ax.grid(alpha=.3)
    fig.suptitle("Experience-memory learning curve")
    fig.tight_layout()
    out = os.path.join(REPORT, "learning_curve.png")
    fig.savefig(out, dpi=130)
    print(f"wrote {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--memory", choices=["on", "off"], required=True)
    ap.add_argument("--target", default="http://localhost")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--feedback-split", default="dev", help="split whose answers feed memory")
    ap.add_argument("--eval-split", default="test", help="split the curve is scored on")
    args = ap.parse_args()
    run(args.epochs, args.memory, args.target, args.delay, args.feedback_split, args.eval_split)
    overlay_plot()


if __name__ == "__main__":
    main()
