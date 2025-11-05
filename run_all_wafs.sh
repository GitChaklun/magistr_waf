#!/usr/bin/env bash
set -euo pipefail

WAFS=("waf" "modsec" "coraza")
DESIRED=${1:-3000}

for w in "${WAFS[@]}"; do
  echo "=== RUN for ${w} ==="
  # ensure container up (build if needed)
  docker compose up -d ${w} || true
  sleep 1
  ./attacker/run_if_pipeline.sh ${DESIRED} ${w}
  echo "=== DONE ${w} -> results/${w} ==="
  # optional: pause to inspect
  sleep 2
done

echo "ALL done. Results in results/<waf>/"
