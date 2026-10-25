"""Paired bootstrap confidence intervals over requests for the A/B summary.

mean±std over N runs only measures the model's run-to-run noise on the *same*
requests. With ~100 requests the larger uncertainty is which requests the corpus
happens to hold: resample eids with replacement — the same resample for every
mode, so mode differences are paired — recompute each metric per run and average
over runs. A difference whose 95% CI excludes 0 is a claim the data supports; one
that straddles 0 is not evidence either way.

Input: report/preds.jsonl (score.py). Output: report/ci.csv + a table.
Usage: python bootstrap_ci.py [--baseline rule_based waf] [--b 2000]
"""

import argparse
import csv
import json
import os
import random

HERE = os.path.dirname(__file__)
REPORT_DIR = os.path.join(HERE, "report")
METRICS = ("recall", "fpr", "precision", "f1")
NAN = float("nan")


def load_preds(path: str) -> dict:
    """mode -> run -> eid -> (is_malicious, predicted_malicious)."""
    out: dict = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = json.loads(line)
            out.setdefault(p["mode"], {}).setdefault(p["run"], {})[p["eid"]] = (
                p["label"] == "malicious", bool(p["pred"]))
    return out


def metrics(pairs) -> dict:
    tp = fp = fn = tn = 0
    for mal, pred in pairs:
        if mal:
            tp, fn = (tp + 1, fn) if pred else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if pred else (fp, tn + 1)
    return {
        "recall": tp / (tp + fn) if tp + fn else NAN,
        "fpr": fp / (fp + tn) if fp + tn else NAN,
        "precision": tp / (tp + fp) if tp + fp else NAN,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else NAN,
    }


def mode_metrics(runs: dict, eids: list) -> dict:
    """Each metric per run over `eids` (with repeats), averaged over runs;
    a run where the metric is undefined (e.g. no positives) is skipped."""
    per_run = [metrics(runs[r][e] for e in eids) for r in runs]
    out = {}
    for k in METRICS:
        vals = [m[k] for m in per_run if m[k] == m[k]]
        out[k] = sum(vals) / len(vals) if vals else NAN
    return out


def _ci(vals: list) -> tuple[float, float]:
    v = sorted(x for x in vals if x == x)
    if not v:
        return NAN, NAN
    return v[int(0.025 * (len(v) - 1))], v[int(0.975 * (len(v) - 1))]


def bootstrap(preds: dict, baselines, b: int, seed: int) -> list[dict]:
    """baselines: one mode or several (e.g. rule_based and waf); every other
    mode gets a paired "mode - baseline" CI against each, once per pair."""
    modes = sorted(preds)
    eids = sorted(set.intersection(*(set(runs[r]) for runs in preds.values() for r in runs)))
    pairs, seen = [], set()
    for base in ([baselines] if isinstance(baselines, str) else baselines):
        for m in modes:
            if base in preds and m != base and frozenset((m, base)) not in seen:
                seen.add(frozenset((m, base)))
                pairs.append((m, base))
    point = {m: mode_metrics(preds[m], eids) for m in modes}

    rng = random.Random(seed)
    samples = {m: {k: [] for k in METRICS} for m in modes}
    deltas = {p: {k: [] for k in METRICS} for p in pairs}
    for _ in range(b):
        s = rng.choices(eids, k=len(eids))
        vals = {m: mode_metrics(preds[m], s) for m in modes}
        for m in modes:
            for k in METRICS:
                samples[m][k].append(vals[m][k])
        for (m, base), d in deltas.items():
            for k in METRICS:
                d[k].append(vals[m][k] - vals[base][k])

    rows = []
    for m in modes:
        for k in METRICS:
            rows.append({"mode": m, "metric": k, "point": point[m][k],
                         **dict(zip(("lo", "hi"), _ci(samples[m][k])))})
    for m, base in pairs:
        for k in METRICS:
            rows.append({"mode": f"{m} - {base}", "metric": k,
                         "point": point[m][k] - point[base][k],
                         **dict(zip(("lo", "hi"), _ci(deltas[(m, base)][k])))})
    for r in rows:
        r["n_eids"] = len(eids)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preds", default=os.path.join(REPORT_DIR, "preds.jsonl"))
    ap.add_argument("--out", default=os.path.join(REPORT_DIR, "ci.csv"))
    ap.add_argument("--baseline", nargs="+", default=["rule_based"],
                    help="mode(s) every other mode is compared against")
    ap.add_argument("--b", type=int, default=2000, help="bootstrap resamples")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rows = bootstrap(load_preds(args.preds), args.baseline, args.b, args.seed)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["mode", "metric", "point", "lo", "hi", "n_eids"])
        w.writeheader()
        w.writerows({**r, **{k: round(r[k], 4) for k in ("point", "lo", "hi")}} for r in rows)
    print(f"[CI] paired bootstrap over {rows[0]['n_eids']} requests, B={args.b} -> {args.out}")
    for r in rows:
        print(f"  {r['mode']:26s} {r['metric']:9s} {r['point']:+.3f}  [{r['lo']:+.3f}, {r['hi']:+.3f}]")


if __name__ == "__main__":
    main()
