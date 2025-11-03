#!/usr/bin/env python3
import pandas as pd
import numpy as np

res = pd.read_csv("/opt/results/results.csv")
ml = pd.read_csv("/opt/results/ml_results.csv")

# Спробуємо обʼєднати по attack_id, якщо його нема — по URL
join_on = None
if 'attack_id' in res.columns and 'attack_id' in ml.columns:
    join_on = 'attack_id'
    df = res.merge(ml, on='attack_id', how='left', suffixes=('_res','_ml'))
else:
    # припускаємо, що в res є url, в ml — uri
    if 'url' in res.columns and 'uri' in ml.columns:
        df = res.merge(ml, left_on='url', right_on='uri', how='left', suffixes=('_res','_ml'))
    else:
        # якщо не змогли поєднати — з'єднуємо по часу або беремо обидва на розгляд
        df = res.copy()
        df['anomaly'] = 0

# нормалізація колонок
if 'blocked' in df.columns:
    df['blocked'] = pd.to_numeric(df['blocked'], errors='coerce').fillna(0).astype(int)
else:
    df['blocked'] = 0

df['anomaly'] = pd.to_numeric(df.get('anomaly', 0), errors='coerce').fillna(0).astype(int)
df['latency_ms'] = pd.to_numeric(df.get('latency_ms', df.get('latency', np.nan)), errors='coerce')

tp = len(df[(df['blocked']==1) & (df['anomaly']==1)])
fn = len(df[(df['blocked']==1) & (df['anomaly']==0)])
fp = len(df[(df['blocked']==0) & (df['anomaly']==1)])
tn = len(df[(df['blocked']==0) & (df['anomaly']==0)])

def ratio(a,b): return float(a)/float(a+b) if (a+b)>0 else None

print("Rows analyzed:", len(df))
print("TP:",tp,"FN:",fn,"FP:",fp,"TN:",tn)
print("TPR (Recall):", ratio(tp,fn))
print("FPR:", ratio(fp,tn))
print("Precision:", ratio(tp,fp))
print("Latency ms: mean", df['latency_ms'].mean(), " median", df['latency_ms'].median())

