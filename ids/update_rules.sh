#!/usr/bin/env bash
# Install ET Open into the running Suricata and reload it (run on the EC2 host).
#   bash ids/update_rules.sh            # tuned — disable.conf (main results)
#   bash ids/update_rules.sh untuned    # ET Open as shipped — disable-untuned.conf (appendix)
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-tuned}" in
  tuned)   conf=disable.conf ;;
  untuned) conf=disable-untuned.conf ;;
  *) echo "usage: $0 [tuned|untuned]" >&2; exit 2 ;;
esac

# suricata-update runs `suricata -T` before installing; on failure it quietly
# restores the previous file. Judge by its output, not only its exit code.
# (Matched with [[ ]] / here-strings, not `echo | grep -q`: with pipefail, grep -q
# quitting early SIGPIPEs echo on long output and the check silently fails.)
out=$(docker exec suricata suricata-update --no-reload \
        --disable-conf "/etc/suricata/rules/$conf" --output /etc/suricata/rules 2>&1) || true
grep -E "Disabled [0-9]+ rules|Writing rules" <<< "$out" || true
if [[ $out == *"Suricata test failed"* || $out != *"Writing rules"* ]]; then
  grep -E "<Error>" <<< "$out" >&2 || true
  echo "suricata-update did not install a new ruleset (previous rules kept)" >&2
  exit 1
fi

since=$(date -u +%Y-%m-%dT%H:%M:%S)
docker compose restart suricata >/dev/null
log=""
for _ in $(seq 1 40); do
  log=$(docker logs --since "$since" suricata 2>&1)
  [[ $log == *"Engine started"* ]] && break
  sleep 3
done
if grep -E "^E:" <<< "$log"; then
  echo "suricata restarted with errors (above)" >&2
  exit 1
fi
echo "suricata reloaded with $conf"
# restarting a container has cost Ollama its GPU before (NVML error) — check
docker exec ollama nvidia-smi -L >/dev/null 2>&1 && echo "ollama GPU ok" \
  || echo "WARNING: ollama lost the GPU -> docker compose restart ollama" >&2
