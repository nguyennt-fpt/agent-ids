"""Aggregate summary_raw.csv (N runs x 3 modes) into mean±std and plot.

Outputs:
  report/summary.csv  — one row per mode, mean±std per metric
  report/compare_quality.png, report/compare_mttb.png, report/compare_groups.png

Usage: python plot.py
"""

import csv
import os
import statistics as st

HERE = os.path.dirname(__file__)
REPORT_DIR = os.path.join(HERE, "report")
RAW = os.path.join(REPORT_DIR, "summary_raw.csv")
SUMMARY = os.path.join(REPORT_DIR, "summary.csv")

MODES = ["rule_based", "naive", "waf", "agent", "agent_ids"]   # waf = CRS baseline; agent_ids = ablation
METRICS = ["precision", "recall", "f1", "fpr", "accuracy",
           "mttb_s", "recall_evasion", "fpr_fpbait", "mitre_acc"]


def load_raw() -> dict:
    by_mode: dict[str, list[dict]] = {m: [] for m in MODES}
    with open(RAW, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["mode"] in by_mode:
                by_mode[row["mode"]].append(row)
    # only modes that ran (e.g. MODES=agent): an absent mode is not a row of zeros
    return {m: rows for m, rows in by_mode.items() if rows}


def mean_std(rows: list[dict], key: str) -> tuple[float, float]:
    vals = [float(r[key]) for r in rows] if rows else []
    if not vals:
        return 0.0, 0.0
    return st.mean(vals), (st.stdev(vals) if len(vals) > 1 else 0.0)


def aggregate(by_mode: dict) -> dict:
    agg = {}
    for m in by_mode:
        agg[m] = {k: mean_std(by_mode[m], k) for k in METRICS}
    return agg


def write_summary(agg: dict) -> None:
    with open(SUMMARY, "w", newline="", encoding="utf-8") as f:
        cols = ["mode"] + [f"{k}_mean" for k in METRICS] + [f"{k}_std" for k in METRICS]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for m in agg:
            row = {"mode": m}
            for k in METRICS:
                mean, std = agg[m][k]
                row[f"{k}_mean"] = round(mean, 4)
                row[f"{k}_std"] = round(std, 4)
            w.writerow(row)
    print(f"[PLOT] wrote {SUMMARY}")


def _bar(ax, metrics, agg, title, ylabel):
    x = range(len(metrics))
    width = 0.8 / len(agg)
    for i, m in enumerate(agg):
        means = [agg[m][k][0] for k in metrics]
        stds = [agg[m][k][1] for k in metrics]
        ax.bar([p + i * width for p in x], means, width, yerr=stds,
               capsize=3, label=m)
    ax.set_xticks([p + width * (len(agg) - 1) / 2 for p in x])
    ax.set_xticklabels(metrics, rotation=15)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.legend()


def plots(agg: dict) -> None:
    # imported here: the EC2 host has no matplotlib, and summary.csv must not depend on it
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[PLOT] matplotlib not installed — PNGs skipped (summary.csv written)")
        return
    fig, ax = plt.subplots(figsize=(8, 5))
    _bar(ax, ["precision", "recall", "f1", "fpr", "accuracy"], agg,
         "Detection quality by RESPONSE_MODE (mean±std)", "score")
    fig.tight_layout(); fig.savefig(os.path.join(REPORT_DIR, "compare_quality.png"), dpi=130)

    fig, ax = plt.subplots(figsize=(5, 5))
    colors = dict(zip(MODES, ["#888", "#c66", "#a7a", "#48a", "#8bd"]))
    means = [agg[m]["mttb_s"][0] for m in agg]
    stds = [agg[m]["mttb_s"][1] for m in agg]
    ax.bar(list(agg), means, yerr=stds, capsize=4, color=[colors[m] for m in agg])
    ax.set_title("Mean time-to-block (s) — lower=faster"); ax.set_ylabel("seconds")
    fig.tight_layout(); fig.savefig(os.path.join(REPORT_DIR, "compare_mttb.png"), dpi=130)

    fig, ax = plt.subplots(figsize=(7, 5))
    _bar(ax, ["recall_evasion", "fpr_fpbait", "mitre_acc"], agg,
         "Where the agent should win: evasion recall ↑ / fp_bait FPR ↓ / MITRE acc ↑", "rate")
    fig.tight_layout(); fig.savefig(os.path.join(REPORT_DIR, "compare_groups.png"), dpi=130)
    print(f"[PLOT] wrote PNGs to {REPORT_DIR}")


def print_table(agg: dict) -> None:
    try:
        from tabulate import tabulate
    except ImportError:
        tabulate = None
    headers = ["mode"] + METRICS
    table = []
    for m in agg:
        table.append([m] + [f"{agg[m][k][0]:.3f}±{agg[m][k][1]:.3f}" for k in METRICS])
    if tabulate:
        print(tabulate(table, headers=headers, tablefmt="github"))
    else:
        print(headers); [print(r) for r in table]


def main() -> None:
    by_mode = load_raw()
    agg = aggregate(by_mode)
    write_summary(agg)
    print_table(agg)
    plots(agg)


if __name__ == "__main__":
    main()
