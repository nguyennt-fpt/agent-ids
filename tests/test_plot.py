"""plot.py aggregates only the modes that ran (MODES=agent must not add zero rows)."""

import csv

import plot


def test_summary_has_only_modes_that_ran(tmp_path, monkeypatch):
    raw, summary = tmp_path / "summary_raw.csv", tmp_path / "summary.csv"
    with open(raw, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["mode", "run"] + plot.METRICS)
        w.writeheader()
        for mode, run in [("rule_based", 1), ("agent", 1), ("agent", 2)]:
            w.writerow({"mode": mode, "run": run, **{k: 0.5 for k in plot.METRICS}})
    monkeypatch.setattr(plot, "RAW", str(raw))
    monkeypatch.setattr(plot, "SUMMARY", str(summary))

    plot.write_summary(plot.aggregate(plot.load_raw()))

    with open(summary, encoding="utf-8") as f:
        assert [r["mode"] for r in csv.DictReader(f)] == ["rule_based", "agent"]
