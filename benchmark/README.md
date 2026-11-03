# Benchmark — Pillar 1: A/B Evaluation Harness

Measures and compares **5 response configurations** on the same labeled attack corpus, to show with numbers whether an
AI agent improves on a plain rule-based IDS.

| Mode | Decision logic | Role |
|---|---|---|
| `rule_based` | Suricata alert; block if `severity ≤ 2` | Traditional IDS + auto-response |
| `naive` | Suricata alert; block **every** alert | Crude baseline (over-blocking) |
| `agent` | LLM + 2 sources (eve.json + nginx access.log) | Proposed method |
| `agent_ids` | same LLM graph, **eve.json only** | Ablation: separates "sees more" (source 2) from "reasons better" |
| `waf` | OWASP CRS on ModSecurity (inline, DetectionOnly); attack when rule `949110` (anomaly threshold exceeded) fires | Enterprise-standard baseline for web attacks |

Detailed design and rationale: [../docs/EXPERIMENT_DESIGN.md](../docs/EXPERIMENT_DESIGN.md).

## How it measures (summary)
- Every request carries a unique `eid` in its query string → traced through `eve.json` and the SQLite decisions.
- Binary decision: malicious (`block`/`warn`) vs benign (`log`/no decision).
- Compared with ground truth (`label` in the corpus) → **Precision / Recall / F1 / FPR / Accuracy / MTTB**, plus the
  latency `ttb_p95_s` (p95 time-to-block) and `undecided` (requests still without a decision when the wait times
  out — normally 0).
- A benign request that raises no alert has no entry → counted as predicted benign (handled in `score.py`).
- LLMs are non-deterministic → run **N=5**, report **mean ± std**. That std only measures the model's variation on the
  *same* requests; the uncertainty from *which requests were chosen* is measured with a **request-paired bootstrap**
  (`bootstrap_ci.py`): resample `eid`s with replacement, the same sample for every mode. A "mode − rule_based"
  difference counts as evidence only when its 95% CI excludes 0.

## Running

```bash
# 0. The system is running (see ../README.md). Model:
#    - real:   qwen2.5:14b  (EC2 GPU)
#    - test:   qwen2.5:3b   (local, change OLLAMA_MODEL in docker-compose)
pip install -r requirements.txt
python attack_corpus/build_corpus.py     # generates corpus.jsonl

# 1. Run the full A/B (5 modes × N runs) + aggregation + charts
N=5 TARGET=http://localhost bash run_ab.sh
#    SPLIT=dev while tuning; SPLIT=test for the final numbers; SPLIT=held_out (attacks never replayed while tuning) once, at the end

# Output:
#   report/summary_raw.csv  — one row per run
#   report/summary.csv      — mean±std per mode
#   report/preds.jsonl      — per-eid prediction for every run (bootstrap input)
#   report/ci.csv           — 95% request-paired bootstrap CI, including "mode - rule_based"
#   report/calibration.csv  — whether confidence (= probability of attack) matches the real attack rate
#                             (ECE; + reliability.png if matplotlib is installed)
#   report/logs/<mode>_run<N>.log — the agent container log for each run; agent* modes also print a [CALLS] line
#                             (LLM calls: triage / investigate steps / final decision / retries)
#   report/compare_quality.png, compare_mttb.png, compare_groups.png
# REPORT_TAG=<name> → copies the results to report/<name>/ (the next run clears the files in report/)
```

### Final numbers + appendix on sensitivity to IDS tuning

The main numbers run on **tuned** ET Open (`ids/rules/disable.conf`: turns off Modbus/DNP3 — they fail to load — and
the noisy rule `2221036`). The appendix re-runs exactly the same thing on **untuned** ET Open (`disable-untuned.conf`:
only Modbus/DNP3 off) to show the conclusions do not depend on turning that rule off. On the EC2 host, from the repo
root:

```bash
bash ids/update_rules.sh                      # tuned version (default)
REPORT_TAG=main SPLIT=test N=5 bash benchmark/run_ab.sh
bash ids/update_rules.sh untuned              # untuned ET Open
REPORT_TAG=etopen-untuned SPLIT=test N=5 bash benchmark/run_ab.sh
bash ids/update_rules.sh                      # back to the tuned version
```

`update_rules.sh` stops with an error if suricata-update did not install the ruleset (it silently keeps the old rules
when `suricata -T` fails), restarts Suricata, then checks that Ollama still has the GPU.

## Pillar 3 — Adversarial robustness (prompt injection)

Measures the **bypass** rate (real attacks whose final decision is not block/warn) with every request going through
**the production path**: `main.process_agent_events` → graph (structured output, salvage, investigate, act), including
retry + fail-closed. Two defense layers are toggled **independently** (2×2 design): the DEFENSE section in
`prompts/system.md`, and the `<<UNTRUSTED_DATA>>` fence (`wrap_untrusted`). Events are web-source shaped (no IDS
signature hint). Each batch pairs an injection sample with a few clean dev-set attacks → also measures **collateral
bypass** onto the other events in the batch. Nothing is written to the DB, the firewall is not touched, and the
investigate tools see empty logs. By default the agent triages **one event at a time** (`TRIAGE_BATCH=1`, N1) → one
model call per event, so collateral is 0 by construction; add `-e TRIAGE_BATCH=15` to `docker exec` to measure
collateral when batching.

```bash
# run inside the agent container (has langgraph + Ollama) — on EC2:
docker cp benchmark agent:/tmp/bench
# MEMORY_ENABLED=false: if the container still has the learning-curve env, triage would include old lessons
docker exec -e AGENT_DIR=/app -e MEMORY_ENABLED=false -e RESPONSE_MODE=agent agent \
  python /tmp/bench/adversarial/test_injection.py   # --repeats 2 --companions 3
docker cp agent:/tmp/bench/report/adversarial_graph.csv benchmark/report/
# -> bypass + collateral bypass per condition, the separate effect of each defense layer, with 95% CIs
```

The CI is a bootstrap over injection samples (repeats of the same sample are not independent). Sample set: **25**
techniques in 5 families (`injections.jsonl`, generated by `build_injections.py`; the first 12 are the set used up to
2026-10-27). The hard parse layer (action enum, per-item fail-closed, salvage) lives in `agent/schemas.py` and is
always on — it is not a variable of the experiment.

## Pillar 4 — Experience memory

Measures the **learning curve**: does the agent learn from its mistakes across epochs (memory on vs off). Each epoch
**evaluates first** on the test set (using only the lessons learned so far), **then learns** from the dev set's
feedback — the answers of the set being scored are never fed in (the old version replayed one corpus and fed back the
answers of those very requests → it measured memorization). Epoch 1 = the no-memory baseline.

```bash
docker exec ollama ollama pull nomic-embed-text     # embeddings for memory
python learning_curve.py --epochs 3 --memory on --delay 4    # the README numbers use exactly this command
python learning_curve.py --epochs 3 --memory off --delay 4
# -> report/curve_on.csv, curve_off.csv, learning_curve.png (FPR↓ / Recall↑ per epoch)
```

*Self-generated rules (Pillar 4B, 4-gate pipeline) were **cut from scope** and the code deleted — see
`docs/EXPERIMENT_DESIGN.md`, section "Pillar 4B".*

### Running step by step (debug)
```bash
RESPONSE_MODE=agent BLOCK_ENABLED=false WEB_UNTAGGED=false docker compose up -d --force-recreate --no-deps agent
python replay.py --target http://localhost --delay 0.5
python score.py --mode agent --run 1
python plot.py
```

## Reading the results
- `compare_quality.png` — Precision/Recall/F1/FPR/Accuracy per mode (error bars = std).
- `compare_groups.png` — **where the agent should win**: `recall_evasion` ↑ (catches the evasion Suricata misses) and
  `fpr_fpbait` ↓ (does not block attack-looking benign requests by mistake).
  Results 2026-11-03 (v4): wins on evasion (recall 1.00, WAF 0.88, IDS 0.27), does not win on fp_bait (FPR 0.08,
  WAF 0.07, IDS 0).
- `compare_mttb.png` — the agent is usually **slower** (a few seconds of LLM time) — an honest trade-off.
- Replay pacing: rule/WAF `DELAY` (0.5s), agent* `DELAY_LLM` (default 6s). Triaging one event at a time costs ~4.4s of
  LLM time per request on a T4; 4s pacing (2026-10-27) left no headroom → MTTB measured the queue and one run fell
  more than 10 minutes behind. Keep the load ≲75%.

## Notes
- `BLOCK_ENABLED=false` during benchmarks so the agent **records decisions but does not** firewall the replay source
  (otherwise it would block its own later requests).
- Corpus: **260 samples** (159 attacks / 101 benign; dev 52, test 147, held_out 61 — attacks only) from public
  sources — `attack_corpus/build_corpus.py`. The test set has been used for three final runs (2026-10-27, 2026-11-01,
  2026-11-03), held_out once (2026-11-03) → later prompt/logic changes need a new set that includes benign requests.
- `score.py` waits for decisions before scoring: `agent` mode waits until **every sent `eid`** has a decision;
  `rule_based`/`naive`/`agent_ids` wait for the `eid`s Suricata alerted on in this run (`alerted_eids.py` →
  `--alerted`, done automatically by `run_ab.sh`). At most `--timeout` (default 2700s — only a safety net: a slow run
  must show up as latency, not as "misses"); on timeout it prints the number of missing `eid`s and fills the
  `undecided` column. Run by hand without `--alerted` it falls back to "row count stable for `--settle` seconds".
- Every run recreates the agent container (`--force-recreate`) → a fresh `decided` set and read offsets; the agent
  reads both `eve.json` and the nginx log from the end of the file at startup (it does not reprocess the previous
  run's traffic).
- Ubuntu host (EC2): turn off the automatic apt timers and update by hand at the start of a session. apt downloads
  packages over HTTP → junk IDS alerts get into the agent's queue (run timeout 2026-10-27); apt installing packages →
  Ollama loses the GPU (`systemd`) or the NVIDIA driver versions drift apart and a reboot is needed (2026-11-01). Turn
  off: `sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer`. Before measuring:
  `sudo apt update && sudo apt upgrade -y` → reboot if NVIDIA/systemd/kernel packages changed →
  `docker exec ollama nvidia-smi -L`.
