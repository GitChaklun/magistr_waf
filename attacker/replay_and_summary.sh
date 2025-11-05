#!/usr/bin/env bash
set -euo pipefail
declare -A BASE=(
  [waf]="http://waf"
  [modsec]="http://modsec:8080"
  [coraza]="http://coraza:8080"
)

for s in waf modsec coraza; do
  in="/opt/results/$s/results.csv"
  out="/opt/results/$s/results.fixed.csv"
  base="${BASE[$s]}"
  echo "[replay] $s -> $base"
  python3 /opt/attacker/replay_fix_status.py --in "$in" --out "$out" --base "$base"
  mv "$out" "$in"
done

python3 /opt/attacker/summarize_waf_results.py \
  --roots /opt/results \
  --systems waf modsec coraza \
  --out /opt/results/summary_waf_all.csv \
  --by-type

echo "[replay] DONE"
sed -n '1,200p' /opt/results/summary_waf_all.csv
echo
sed -n '1,200p' /opt/results/summary_waf_all_by_type.csv
