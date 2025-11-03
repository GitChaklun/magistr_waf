#!/usr/bin/env python3
"""
combine_and_eval.py
Гнучке об'єднання results.csv та ml_results*.csv і виведення метрик.
Використовує RES_PATH або /opt/results за замовчуванням.
"""
import pandas as pd
from urllib.parse import urlparse
import sys, os, glob

RES_PATH = os.environ.get("RES_PATH", "/opt/results")
res_file = os.path.join(RES_PATH, "results.csv")

# знайдемо ml_results (нескілька варіантів: ml_results.csv, ml_results_v2.csv)
ml_candidates = glob.glob(os.path.join(RES_PATH, "ml_results*.csv"))
if not ml_candidates:
    print("No ml_results file found in", RES_PATH, file=sys.stderr)
    sys.exit(2)
ml_file = ml_candidates[0]

out_file = os.path.join(RES_PATH, "combined_results.csv")

if not os.path.exists(res_file):
    print("ERROR: results.csv not found at", res_file, file=sys.stderr)
    sys.exit(2)

print("Using:", res_file, "and", ml_file)

res = pd.read_csv(res_file, dtype=str, keep_default_na=False)
ml = pd.read_csv(ml_file, dtype=str, keep_default_na=False)

def url_to_uri(u):
    try:
        p = urlparse(u)
        path = p.path or '/'
        query = p.query
        return path + ('?' + query if query else '')
    except:
        return u

# create uri column in res if missing
if 'uri' not in res.columns:
    if 'url' in res.columns:
        res['uri'] = res['url'].apply(url_to_uri)
    else:
        res['uri'] = res.get('uri', '')

# ensure ml has uri column
if 'uri' not in ml.columns:
    print("ml file has no 'uri' column, trying to build from 'url'...", file=sys.stderr)
    if 'url' in ml.columns:
        ml['uri'] = ml['url'].apply(url_to_uri)
    else:
        print("Cannot find uri in ml results, aborting.", file=sys.stderr)
        sys.exit(3)

# ensure anomaly numeric
ml['anomaly'] = pd.to_numeric(ml.get('anomaly', 0), errors='coerce').fillna(0).astype(int)

# left join
df = res.merge(ml[['uri','anomaly']], on='uri', how='left', suffixes=('_res','_ml'))
df['anomaly'] = df['anomaly'].fillna(0).astype(int)

# is_attack detection
df['is_attack'] = df.get('attack_type', '').astype(str).str.strip() != ''

# blocked numeric
df['blocked'] = pd.to_numeric(df.get('blocked', 0), errors='coerce').fillna(0).astype(int)

tp = int(((df['is_attack']==True) & (df['anomaly']==1)).sum())
fn = int(((df['is_attack']==True) & (df['anomaly']==0)).sum())
fp = int(((df['is_attack']==False) & (df['anomaly']==1)).sum())
tn = int(((df['is_attack']==False) & (df['anomaly']==0)).sum())
def ratio(a,b): return float(a)/float(a+b) if (a+b)>0 else None

print("Rows total:", len(df))
print("Attacks total:", int(df['is_attack'].sum()))
print("Anomalies total (ML):", int(df['anomaly'].sum()))
print("TP",tp,"FN",fn,"FP",fp,"TN",tn)
print("TPR (Recall):", ratio(tp,fn))
print("FPR:", ratio(fp,tn))
print("Precision:", ratio(tp,fp))

# examples
print("\nDetected anomalies sample:")
print(df[df['anomaly']==1][['attack_id','attack_type','uri','blocked']].head(10).to_string(index=False))

print("\nMissed attacks sample (FN):")
print(df[(df['is_attack']==True) & (df['anomaly']==0)][['attack_id','attack_type','uri','blocked']].head(10).to_string(index=False))

print("\nFalse positives sample (FP):")
print(df[(df['is_attack']==False) & (df['anomaly']==1)][['attack_id','attack_type','uri','blocked']].head(10).to_string(index=False))

df.to_csv(out_file, index=False)
print("\nSaved combined CSV to", out_file)

