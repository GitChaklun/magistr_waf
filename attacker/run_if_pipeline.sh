#!/usr/bin/env bash
# attacker/run_if_pipeline.sh
# Run the full IF pipeline for one WAF target and store results under /opt/results/<waf>/
#
# Usage:
#   ./attacker/run_if_pipeline.sh DESIRED WAF_NAME
# Examples (inside attacker container or via `docker compose run attacker -c "...`):
#   ./attacker/run_if_pipeline.sh 3000 waf
#   ./attacker/run_if_pipeline.sh 1500 modsec
#
# Configurable via env:
#   WORKERS (default 12)
#   NORMAL_RATIO (default 0.5)
#   CONTAMINATION (default 0.10)
#   REPEAT_OVERRIDE - if set, use it instead of computed repeat
#
set -euo pipefail
IFS=$'\n\t'

DESIRED=${1:-3000}
WAF_NAME=${2:-waf}   # container name / host inside Docker network (waf, modsec, coraza)
OUT_ROOT="/opt/results"
OUTDIR="${OUT_ROOT}/${WAF_NAME}"

WORKERS=${WORKERS:-12}
NORMAL_RATIO=${NORMAL_RATIO:-0.5}
CONTAMINATION=${CONTAMINATION:-0.10}
N_ESTIMATORS=${N_ESTIMATORS:-100}
MAX_SAMPLES=${MAX_SAMPLES:-auto}
RND=${RND:-7}

echo "[run_if_pipeline] START: DESIRED=${DESIRED}, WAF_NAME=${WAF_NAME}, OUTDIR=${OUTDIR}"
echo "[run_if_pipeline] WORKERS=${WORKERS}, NORMAL_RATIO=${NORMAL_RATIO}, CONTAMINATION=${CONTAMINATION}"

# 0) prepare outdir (only for this WAF) - keep other WAF data intact
mkdir -p "${OUTDIR}"
# cleanup only this WAF outputs (don't remove other WAF results)
echo "[run_if_pipeline] Cleaning ${OUTDIR}/* ..."
rm -f "${OUTDIR}"/*.csv "${OUTDIR}"/*.png 2>/dev/null || true
mkdir -p "${OUTDIR}/samples" || true

# 0.5) quick permissions note (helpful when run as non-root)
umask 0002 || true

# 1) compute TOTAL payloads from attacker/payloads.py
echo "[run_if_pipeline] Computing total PAYLOADS..."
TOTAL=$(python3 - <<'PY'
import sys
sys.path.insert(0, '/opt')
try:
    from attacker.payloads import PAYLOADS
except Exception as e:
    print("0")
    sys.exit(0)
print(sum(len(v) for v in PAYLOADS.values()))
PY
)
TOTAL=${TOTAL:-0}
echo "[run_if_pipeline] TOTAL payload templates = ${TOTAL}"

# compute REPEAT so that we attempt ~DESIRED requests
if [ -n "${REPEAT_OVERRIDE:-}" ]; then
  REPEAT="${REPEAT_OVERRIDE}"
else
  if [ "$TOTAL" -le 0 ]; then
    REPEAT=1
  else
    REPEAT=$(( (DESIRED + TOTAL - 1) / TOTAL ))
  fi
fi
echo "[run_if_pipeline] REPEAT = ${REPEAT}"

# Target URL inside docker network
TARGET="http://${WAF_NAME}:80"
echo "[run_if_pipeline] TARGET = ${TARGET}"

# 1) Generate traffic
echo "[run_if_pipeline] 1) Generating traffic -> ${OUTDIR}/results.csv ..."
python3 /opt/attacker/generate_requests.py \
  --target "${TARGET}" \
  --out "${OUTDIR}/results.csv" \
  --repeat "${REPEAT}" \
  --workers "${WORKERS}" \
  --normal-ratio "${NORMAL_RATIO}"

# 2) Build features (force)
echo "[run_if_pipeline] 2) Building features -> ${OUTDIR}/access_features_v2.csv ..."
python3 /opt/attacker/access2features_v2.py --in "${OUTDIR}/results.csv" --out "${OUTDIR}/access_features_v2.csv" --force

# 3) Numeric conversion (produce access_features_numeric.csv)
echo "[run_if_pipeline] 3) Numeric conversion -> ${OUTDIR}/access_features_numeric.csv ..."
python3 - <<PY
import pandas as pd, sys, re
fn='${OUTDIR}/access_features_v2.csv'; out='${OUTDIR}/access_features_numeric.csv'
df=pd.read_csv(fn, dtype=str)
cols=['req_time','uri_len','qparam_count','has_sqli','has_xss','uri_entropy','special_chars','frac_non_alnum','user_agent_suspicious']
for c in cols:
    if c in df.columns:
        df[c]=pd.to_numeric(df[c].astype(str).str.replace(r'[^0-9eE+\\.-]','', regex=True), errors='coerce')
df.to_csv(out, index=False)
print('WROTE', out)
PY

# 4) Train IsolationForest (quick run)
ML_OUT="${OUTDIR}/ml_results_c${CONTAMINATION//./_}_ne${N_ESTIMATORS}.csv"
echo "[run_if_pipeline] 4) Training IsolationForest -> ${ML_OUT} (cont=${CONTAMINATION}) ..."
python3 /opt/attacker/train_isolationforest_fixed.py \
  --in "${OUTDIR}/access_features_numeric.csv" \
  --out "${ML_OUT}" \
  --contamination "${CONTAMINATION}" \
  --n_estimators "${N_ESTIMATORS}" \
  --max_samples "${MAX_SAMPLES}" \
  --random_state "${RND}"

# 5) Optional: fix ML uri file if helper exists
ML_FIXED="${ML_OUT}.fixed.csv"
if [ -f /opt/attacker/fix_ml_uri.py ]; then
  echo "[run_if_pipeline] 5) Running fix_ml_uri.py ..."
  python3 /opt/attacker/fix_ml_uri.py --in "${ML_OUT}" --out "${ML_FIXED}"
else
  echo "[run_if_pipeline] 5) fix_ml_uri.py not found -> copying ml file to .fixed.csv"
  cp -f "${ML_OUT}" "${ML_FIXED}"
fi

# 6) Merge ML + results -> combined_fixed_agg.csv (try helper or fallback)
COMBINED="${OUTDIR}/combined_fixed_agg.csv"
if [ -f /opt/attacker/merge_agg_norm.py ]; then
  echo "[run_if_pipeline] 6) Running merge_agg_norm.py ..."
  python3 /opt/attacker/merge_agg_norm.py --ml "${ML_FIXED}" --results "${OUTDIR}/results.csv" --out "${COMBINED}"
else
  echo "[run_if_pipeline] 6) merge_agg_norm.py not found -> using inline fallback merge..."
  python3 - <<'PY'
import pandas as pd
from urllib.parse import urlparse, parse_qsl, unquote
ml = pd.read_csv("${ML_FIXED}", dtype=str).fillna("")
res = pd.read_csv("${OUTDIR}/results.csv", dtype=str).fillna("")
def canon(s):
    if pd.isna(s) or s is None:
        return ""
    s=str(s).strip()
    if s.startswith("http://") or s.startswith("https://"):
        p=urlparse(s)
        s=(p.path or "/") + (('?'+p.query) if p.query else '')
    # if stored as CSV full line "ts,ip,GET,/path?..." try to extract last /... part
    if ',' in s and '/' in s:
        parts=s.split(',',6)
        for p in parts:
            if p.startswith('/'):
                s=p
                break
    if '?' in s:
        path,q = s.split('?',1)
        qs = [(unquote(k), unquote(v)) for k,v in parse_qsl(q, keep_blank_values=True)]
        qs = [(k,v) for (k,v) in qs if k != '_rnd']
        qs.sort()
        s = unquote(path) + (('?' + '&'.join(f'{k}={v}' for k,v in qs)) if qs else '')
    else:
        s = unquote(s)
    return s

ml['norm_uri'] = ml['uri'].map(canon)
res['norm_uri'] = res['url'].map(canon)
ml['score'] = pd.to_numeric(ml.get('score', None), errors='coerce')
ml['anomaly'] = pd.to_numeric(ml.get('anomaly', 0), errors='coerce').fillna(0).astype(int)
ml_agg = (ml.groupby('norm_uri', as_index=False)
            .agg(score_min=('score','min'), score_mean=('score','mean'), anomaly_max=('anomaly','max')))
merged = res.merge(ml_agg, on='norm_uri', how='left')
merged['score'] = merged['score_min'].fillna(merged['score_mean'])
merged['anomaly'] = merged['anomaly_max'].fillna(0).astype(int)
merged.to_csv("${COMBINED}", index=False)
print("WROTE ${COMBINED}")
PY
fi

# 7) Fill NaNs in score -> 0 (so report scripts won't complain)
echo "[run_if_pipeline] 7) Filling NaNs in score -> 0 ..."
python3 - <<PY
import pandas as pd
fn="${COMBINED}"
df=pd.read_csv(fn, dtype=str)
if 'score' in df.columns:
    import numpy as np
    df['score']=pd.to_numeric(df['score'], errors='coerce').fillna(0.0)
else:
    df['score']=0.0
df.to_csv(fn, index=False)
print('Prepared', fn, 'rows', len(df))
PY

# 8) Optional helper: fix_and_merge_ml.py (if exists) - keep for compatibility
if [ -f /opt/attacker/fix_and_merge_ml.py ]; then
  echo "[run_if_pipeline] Running fix_and_merge_ml.py (best-effort) ..."
  python3 /opt/attacker/fix_and_merge_ml.py --ml "${ML_OUT}" --results "${OUTDIR}/results.csv" --out "${COMBINED}" --force || true
fi

# 9) Produce report (quiet, but include snippets)
echo "[run_if_pipeline] 8) Producing report -> ${OUTDIR}/summary_if.csv and samples/ ..."
python3 /opt/attacker/report_results.py --ml "${ML_FIXED}" --combined "${COMBINED}" --results "${OUTDIR}/results.csv" --top 20 --quiet --show-snippets || true

echo "[run_if_pipeline] DONE. Artifacts in: ${OUTDIR}/"
ls -la "${OUTDIR}" || true
