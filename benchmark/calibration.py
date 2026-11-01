"""Reliability of the agent's self-reported confidence (Phase F).

The graph acts on that number twice: a gray-band confidence sends an event to
the investigate loop, and a block below 0.90 goes to the human gate. Is it
calibrated? The confidence is the model's probability that the request is an
attack — one scale for every action, so a sure-benign `log` is near 0 (the
schema and prompt define it so since 2026-11; before, it was undefined and the
model mostly, not always, used it this way). Bin decisions by confidence and
compare each bin's mean confidence with the fraction of attacks in it;
ECE = sum over bins of (n_bin / n) * |attack_rate - mean confidence|.
Rule-engine rows (always 1.0) are not calibration.

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
    items = [(float(p["confidence"]), p["label"] == "malicious")
             for p in preds if p["mode"] == mode and p.get("confidence") is not None]
    bins, ece = [], 0.0
    for i, (lo, hi) in enumerate(zip(EDGES, EDGES[1:])):
        last = i == len(EDGES) - 2                      # the top bin includes 1.0
        b = [(c, attack) for c, attack in items if lo <= c < hi or (last and c == hi)]
        if not b:
            continue
        conf = sum(c for c, _ in b) / len(b)
        rate = sum(attack for _, attack in b) / len(b)
        ece += len(b) / len(items) * abs(rate - conf)
        bins.append({"mode": mode, "bin": f"[{lo:.1f}, {hi:.1f}{']' if last else ')'}",
                     "n": len(b), "mean_confidence": conf, "attack_rate": rate})
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
        ax.plot([b["mean_confidence"] for b in bins], [b["attack_rate"] for b in bins],
                "o-", label=f"{mode} (ECE {ece:.2f})")
    ax.set_xlabel("mean confidence (P attack)"); ax.set_ylabel("fraction that are attacks")
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
        w = csv.DictWriter(f, fieldnames=["mode", "bin", "n", "mean_confidence", "attack_rate"])
        w.writeheader()
        for bins, _, _ in results.values():
            w.writerows({**b, "mean_confidence": round(b["mean_confidence"], 3),
                         "attack_rate": round(b["attack_rate"], 3)} for b in bins)
    for mode, (bins, ece, n) in results.items():
        print(f"[CAL] {mode}: ECE={ece:.3f} over {n} decisions")
        for b in bins:
            print(f"   {b['bin']:12s} n={b['n']:4d}  conf={b['mean_confidence']:.2f}  "
                  f"attacks={b['attack_rate']:.2f}")
    if results:
        _plot(results, os.path.join(REPORT_DIR, "reliability.png"))


if __name__ == "__main__":
    main()
