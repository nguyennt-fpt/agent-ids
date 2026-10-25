#!/usr/bin/env bash
# A/B benchmark: run each RESPONSE_MODE x N times, then aggregate + plot.
# Run from repo root or anywhere: bash benchmark/run_ab.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"          # Ubuntu hosts have no bare `python`
N="${N:-5}"
TARGET="${TARGET:-http://localhost}"
DELAY="${DELAY:-0.5}"
# agent_ids = IDS-only ablation of the agent; e.g. MODES=agent to rerun one mode
read -r -a MODES <<< "${MODES:-rule_based naive agent agent_ids}"
# corpus v2: SPLIT=dev while tuning, SPLIT=test only for the final numbers
SPLIT_ARGS=()
[ -n "${SPLIT:-}" ] && SPLIT_ARGS=(--split "$SPLIT")
RAW="$HERE/report/summary_raw.csv"

mkdir -p "$HERE/report"
rm -f "$RAW" "$HERE/report/preds.jsonl"   # preds.jsonl: per-eid predictions for bootstrap_ci.py

# load the model before an LLM run, so the first batch's MTTB doesn't include a ~30s
# model load; same num_ctx as the agent, or Ollama reloads it on the first real call
warm_model() {
  curl -s -o /dev/null http://localhost:11434/api/generate -d \
    "{\"model\":\"${OLLAMA_MODEL:-qwen2.5:14b}\",\"prompt\":\"ok\",\"stream\":false,\"options\":{\"num_ctx\":8192,\"num_predict\":1}}" || true
}

reset_db() {
  docker compose exec -T agent python -c \
    "import sqlite3,os;d=os.getenv('DASHBOARD_DB','/app/data/events.db');\
c=sqlite3.connect(d);c.execute('DELETE FROM events');c.commit();c.close()" || true
}

for mode in "${MODES[@]}"; do
  for run in $(seq 1 "$N"); do
    echo "==================== mode=$mode run=$run/$N ===================="
    # restart agent with this mode; never firewall the replay source during benchmark.
    # --force-recreate: a plain `up -d` with an unchanged env is a no-op, so runs 2..N
    # would reuse the process whose `decided` set already holds every corpus eid.
    # --no-deps: leave ollama (and its loaded model) alone.
    RESPONSE_MODE="$mode" BLOCK_ENABLED=false docker compose up -d --force-recreate --no-deps agent
    sleep 12                      # agent boot (+ ollama readiness check)
    case "$mode" in agent*) warm_model ;; esac
    reset_db                      # clear prior decisions so runs don't mix
    "$PY" "$HERE/replay.py" --target "$TARGET" --delay "$DELAY" "${SPLIT_ARGS[@]}"
    sleep 3                       # let Suricata flush the last alerts
    # eids Suricata alerted on: what rule_based/naive/agent_ids must decide before scoring
    docker compose exec -T agent tail -n 100000 /var/log/suricata/eve.json \
      | "$PY" "$HERE/alerted_eids.py" --sent "$HERE/report/sent.jsonl" > "$HERE/report/alerted.json"
    "$PY" "$HERE/score.py" --mode "$mode" --run "$run" --out "$RAW" \
      --alerted "$HERE/report/alerted.json"
  done
done

"$PY" "$HERE/plot.py"
"$PY" "$HERE/bootstrap_ci.py"      # paired 95% CI over requests, incl. each mode - rule_based
"$PY" "$HERE/calibration.py"       # does the agent's confidence match how often it is right?
echo "Done. See $HERE/report/summary.csv, report/ci.csv and report/*.png"

# REPORT_TAG keeps this run's results apart from the next run (which clears the
# report files), e.g. REPORT_TAG=main / REPORT_TAG=etopen-untuned for the appendix
if [ -n "${REPORT_TAG:-}" ]; then
  dest="$HERE/report/$REPORT_TAG"
  mkdir -p "$dest"
  cp "$RAW" "$HERE/report/summary.csv" "$HERE/report/preds.jsonl" "$HERE/report/ci.csv" \
     "$HERE/report/calibration.csv" "$dest/"
  cp "$HERE"/report/*.png "$dest/" 2>/dev/null || true
  echo "Archived to $dest"
fi
