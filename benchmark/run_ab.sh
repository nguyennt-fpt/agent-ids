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
MODES=(rule_based naive agent)
RAW="$HERE/report/summary_raw.csv"

mkdir -p "$HERE/report"
rm -f "$RAW"

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
    reset_db                      # clear prior decisions so runs don't mix
    "$PY" "$HERE/replay.py" --target "$TARGET" --delay "$DELAY"
    "$PY" "$HERE/score.py" --mode "$mode" --run "$run" --out "$RAW"
  done
done

"$PY" "$HERE/plot.py"
echo "Done. See $HERE/report/summary.csv and report/*.png"
