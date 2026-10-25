"""Reliability of the agent's self-reported confidence (Phase F).

The graph acts on that number twice: a gray-band confidence sends an event to
the investigate loop, and a block below 0.90 goes to the human gate. Is it
calibrated? Bin decisions by confidence and compare each bin's mean confidence
with how often the decision was right; ECE = sum over bins of
(n_bin / n) * |accuracy - mean confidence|. The confidence is the model's
confidence in its own decision (block/warn or log), so "right" means the
decision matches the label. Rule-engine rows (always 1.0) are not calibration.

Input: report/preds.jsonl (score.py). Output: report/calibration.csv, a table,
and report/reliability.png when matplotlib is installed.
Usage: python calibration.py [--modes agent agent_ids]
"""

import argparse
import csv
import json
import os

HERE = os.path.dirname(__file__)
REPORT_DIR = os.path.join(HERE, "report")
EDGES = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)


def calibration(preds: list[dict], mode: str) -> tuple[list[dict], float, int]:
    """(bins, ECE, n) for one mode; rows without a confidence are skipped."""
    items = [(float(p["confidence"]), (p["label"] == "malicious") == bool(p["pred"]))
             for p in preds if p["mode"] == mode and p.get("confidence") is not None]
    bins, ece = [], 0.0
    for i, (lo, hi) in enumerate(zip(EDGES, EDGES[1:])):
        last = i == len(EDGES) - 2                      # the top bin includes 1.0
        b = [(c, ok) for c, ok in items if lo <= c < hi or (last and c == hi)]
        if not b:
            continue
        conf = sum(c for c, _ in b) / len(b)
        acc = sum(ok for _, ok in b) / len(b)
        ece += len(b) / len(items) * abs(acc - conf)
        bins.append({"mode": mode, "bin": f"[{lo:.1f}, {hi:.1f}{']' if last else ')'}",
                     "n": len(b), "mean_confidence": conf, "accuracy": acc})
    return bins, ece, len(items)


def _plot(results: dict, path: str) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[CAL] matplotlib not installed — reliability.png skipped")
        return
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="#888", label="perfectly calibrated")
    for mode, (bins, ece, _) in results.items():
        ax.plot([b["mean_confidence"] for b in bins], [b["accuracy"] for b in bins],
                "o-", label=f"{mode} (ECE {ece:.2f})")
    ax.set_xlabel("mean confidence"); ax.set_ylabel("accuracy")
    ax.set_title("Reliability of the agent's confidence"); ax.legend()
    fig.tight_layout(); fig.savefig(path, dpi=130)
    print(f"[CAL] wrote {path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preds", default=os.path.join(REPORT_DIR, "preds.jsonl"))
    ap.add_argument("--modes", nargs="+", default=["agent", "agent_ids"])
    args = ap.parse_args()

    with open(args.preds, encoding="utf-8") as f:
        preds = [json.loads(line) for line in f if line.strip()]
    results = {m: calibration(preds, m) for m in args.modes}
    results = {m: r for m, r in results.items() if r[2]}          # modes with data

    out = os.path.join(REPORT_DIR, "calibration.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["mode", "bin", "n", "mean_confidence", "accuracy"])
        w.writeheader()
        for bins, _, _ in results.values():
            w.writerows({**b, "mean_confidence": round(b["mean_confidence"], 3),
                         "accuracy": round(b["accuracy"], 3)} for b in bins)
    for mode, (bins, ece, n) in results.items():
        print(f"[CAL] {mode}: ECE={ece:.3f} over {n} decisions")
        for b in bins:
            print(f"   {b['bin']:12s} n={b['n']:4d}  conf={b['mean_confidence']:.2f}  acc={b['accuracy']:.2f}")
    if results:
        _plot(results, os.path.join(REPORT_DIR, "reliability.png"))


if __name__ == "__main__":
    main()
