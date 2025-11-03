#!/usr/bin/env bash
set -euo pipefail

# target берётся из переменных окружения TARGET или по умолчанию http://waf:80
TARGET="${TARGET:-http://waf:80}"
OUT_DIR="${OUT_DIR:-/opt/results}"
WORKERS="${WORKERS:-16}"
REPEAT="${REPEAT:-50}"
CONTAMINATION="${CONTAMINATION:-0.05}"

mkdir -p "$OUT_DIR"

echo "[attacker] Run ID: $(date -u +%Y%m%dT%H%M%SZ)"
echo "[attacker] Target: $TARGET"
echo "[attacker] Results dir: $OUT_DIR"

# 1) Генерируем запросы (results.csv)
echo "[attacker] Starting generate_requests.py ..."
python /opt/attacker/generate_requests.py --target "$TARGET" --out "$OUT_DIR/results.csv" --workers "$WORKERS" --repeat "$REPEAT" || {
  echo "[attacker] generate_requests.py exited with error" >&2
}

# 2) Конвертация access.log -> access_features_v2.csv
# предполагается, что nginx/openresty логирует в примонтированный том (например ./results/access.log)
if [ -f "$OUT_DIR/access.log" ]; then
  echo "[attacker] Found access.log, running access2features_v2.py ..."
  python /opt/attacker/access2features_v2.py --in "$OUT_DIR/access.log" --out "$OUT_DIR/access_features_v2.csv" || {
    echo "[attacker] access2features_v2.py failed" >&2
  }
else
  echo "[attacker] WARNING: access.log not found at $OUT_DIR/access.log — пропускаю access2features_v2"
fi

# 3) Тренировка / предсказание ML
if [ -f "$OUT_DIR/access_features.csv" ]; then
  echo "[attacker] Training IsolationForest ..."
  python /opt/attacker/train_isolationforest.py --in "$OUT_DIR/access_features.csv" --out "$OUT_DIR/ml_results.csv" --contamination "$CONTAMINATION" || {
    echo "[attacker] train_isolationforest.py failed" >&2
  }
else
  echo "[attacker] WARNING: access_features.csv not found — пропускаю ML" >&2
fi

echo "[attacker] Running combine_and_eval.py ..."
python /opt/attacker/combine_and_eval.py || echo "[attacker] combine_and_eval.py failed"


echo "[attacker] Done. Results are in $OUT_DIR"
# оставим контейнер завершённым (exit 0)
exit 0

