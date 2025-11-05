#!/usr/bin/env bash
set -euo pipefail

# Args:
#   $1 = DESIRED (скільки запитів приблизно згенерувати)
#   $2 = WAF_NAME (waf | modsec | coraza), за замовчуванням "waf"
DESIRED=${1:-3000}
WAF_NAME=${2:-waf}

# Шляхи: ХОСТ vs КОНТЕЙНЕР
HOST_OUTDIR="results/${WAF_NAME}"
CONT_OUTDIR="/opt/results/${WAF_NAME}"

echo "[run_if_pipeline] START: DESIRED=${DESIRED}, WAF_NAME=${WAF_NAME}"
echo "[run_if_pipeline] HOST_OUTDIR=${HOST_OUTDIR}, CONT_OUTDIR=${CONT_OUTDIR}"

# Підготовка локальних директорій (НА ХОСТІ!)
mkdir -p "${HOST_OUTDIR}" "${HOST_OUTDIR}/samples"

# Чистимо артефакти лише цього WAF-підкаталогу
rm -f "${HOST_OUTDIR}"/*.csv "${HOST_OUTDIR}"/*.png 2>/dev/null || true

# Обираємо цільовий URL усередині докер-мережі
if [ "${WAF_NAME}" = "coraza" ]; then
  TARGET_URL="http://coraza:8080"
else
  TARGET_URL="http://${WAF_NAME}"
fi
echo "[run_if_pipeline] TARGET=${TARGET_URL}"

# Рахуємо кількість пейлоадів, щоб отримати REPEAT
TOTAL=$(docker compose run --rm --entrypoint sh attacker -c "python3 - <<'PY'
import sys
sys.path.insert(0, '/opt/attacker')
from payloads import PAYLOADS
print(sum(len(v) for v in PAYLOADS.values()))
PY")
REPEAT=$(( (DESIRED + TOTAL - 1) / TOTAL ))
echo "[run_if_pipeline] TOTAL payloads=${TOTAL}, REPEAT=${REPEAT}"

# 1) Генерація трафіку
docker compose run --rm -e TGT="${TARGET_URL}" --entrypoint sh attacker -c \
  "python3 /opt/attacker/generate_requests.py \
     --target \"\$TGT\" \
     --out \"${CONT_OUTDIR}/results.csv\" \
     --repeat ${REPEAT} --workers 12 \
     --normal-ratio 0.5 --exclude idor"

# 2) Побудова фіч
docker compose run --rm --entrypoint sh attacker -c \
  "python3 /opt/attacker/access2features_v2.py \
     --in  \"${CONT_OUTDIR}/results.csv\" \
     --out \"${CONT_OUTDIR}/access_features_v2.csv\" \
     --force"

# 3) Перетворення в numeric
docker compose run --rm --entrypoint sh attacker -c "python3 - <<PY
import pandas as pd
fn='${CONT_OUTDIR}/access_features_v2.csv'
out='${CONT_OUTDIR}/access_features_numeric.csv'
df=pd.read_csv(fn, dtype=str)
cols=['req_time','uri_len','qparam_count','has_sqli','has_xss','has_lfi','has_cmdi',
      'uri_entropy','special_chars','frac_non_alnum','user_agent_suspicious']
for c in cols:
    if c in df.columns:
        df[c]=pd.to_numeric(df[c].astype(str).str.replace(r'[^0-9eE+\\.-]','', regex=True),
                            errors='coerce')
df.to_csv(out, index=False)
print('WROTE', out)
PY"

# 4) Тренування IsolationForest (швидкий прогін)
docker compose run --rm --entrypoint sh attacker -c \
  "python3 /opt/attacker/train_isolationforest_fixed.py \
     --in  \"${CONT_OUTDIR}/access_features_numeric.csv\" \
     --out \"${CONT_OUTDIR}/ml_results_c0_10_ne100.csv\" \
     --contamination 0.10 --n_estimators 100 --max_samples auto --random_state 7"

# 5) Виправлення uri у ML (агрегація/канонізація)
docker compose run --rm --entrypoint sh attacker -c \
  "python3 /opt/attacker/fix_ml_uri.py \
     --in  \"${CONT_OUTDIR}/ml_results_c0_10_ne100.csv\" \
     --out \"${CONT_OUTDIR}/ml_results_c0_10_ne100.fixed.csv\""

# 6) Злиття ML + results по нормалізованому URI (agg)
docker compose run --rm --entrypoint sh attacker -c \
  "python3 /opt/attacker/merge_agg_norm.py \
     --ml  \"${CONT_OUTDIR}/ml_results_c0_10_ne100.fixed.csv\" \
     --results \"${CONT_OUTDIR}/results.csv\" \
     --out \"${CONT_OUTDIR}/combined_fixed_agg.csv\""

# 7) Заповнення NaN у score/anomaly
docker compose run --rm --entrypoint sh attacker -c "python3 - <<PY
import pandas as pd
p='${CONT_OUTDIR}/combined_fixed_agg.csv'
df=pd.read_csv(p)
df['score']=pd.to_numeric(df['score'], errors='coerce').fillna(0.0)
df['anomaly']=pd.to_numeric(df['anomaly'], errors='coerce').fillna(0).astype(int)
df.to_csv(p, index=False)
print('Prepared', p, 'rows', len(df))
PY"

# 8) Реліз-репорт (без зайвих verbose-виводів у консоль)
docker compose run --rm --entrypoint sh attacker -c \
  "python3 /opt/attacker/report_results.py \
     --ml \"${CONT_OUTDIR}/ml_results_c0_10_ne100.fixed.csv\" \
     --combined \"${CONT_OUTDIR}/combined_fixed_agg.csv\" \
     --results  \"${CONT_OUTDIR}/results.csv\" \
     --top 20 --quiet"

echo "[run_if_pipeline] DONE → ${HOST_OUTDIR}"

