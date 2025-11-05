#!/usr/bin/env python3
# attacker/diagnose_and_merge.py
import pandas as pd
from urllib.parse import urlparse, parse_qsl, urlencode
import sys, os

RES = os.environ.get('RES_IN','/opt/results/results.csv')
ML  = os.environ.get('ML_IN','/opt/results/ml_results_c0_10_ne100.csv')
OUT = os.environ.get('OUT','/opt/results/combined_results_normmerge.csv')

def norm_res(u):
    s=str(u)
    try:
        p=urlparse(s)
        path = p.path or '/'
        qs = dict(parse_qsl(p.query, keep_blank_values=True))
    except:
        if s.startswith('/'):
            path = s.split('?')[0]
            qs = dict(parse_qsl(s.split('?',1)[1] if '?' in s else ''))
        else:
            path = s; qs={}
    qs.pop('_rnd', None)
    qstr = ('?'+urlencode(qs)) if qs else ''
    return path + qstr

def norm_ml(u):
    s=str(u)
    if ',' in s and 'http' not in s:
        parts=s.split(',',5)
        cand=parts[3] if len(parts)>=4 else s
    else:
        cand=s
    if '?' in cand:
        path,cq=cand.split('?',1)
        qs = dict(parse_qsl(cq, keep_blank_values=True))
    else:
        path=cand; qs={}
    qs.pop('_rnd', None)
    qstr = ('?'+urlencode(qs)) if qs else ''
    return path + qstr

def main():
    print("Using:", RES, "and", ML)
    res = pd.read_csv(RES)
    ml  = pd.read_csv(ML)
    ml['anomaly'] = pd.to_numeric(ml.get('anomaly',0), errors='coerce').fillna(0).astype(int)
    res['norm_uri'] = (res['url'] if 'url' in res.columns else res.get('uri',res.iloc[:,0])).apply(norm_res)
    ml['norm_uri'] = ml['uri'].apply(norm_ml)
    df = res.merge(ml[['norm_uri','anomaly','score']], on='norm_uri', how='left')
    df['anomaly'] = df['anomaly'].fillna(0).astype(int)
    df['is_attack'] = (df['attack_type']!='normal').astype(int)
    TP = int(((df['is_attack']==1)&(df['anomaly']==1)).sum())
    FN = int(((df['is_attack']==1)&(df['anomaly']==0)).sum())
    FP = int(((df['is_attack']==0)&(df['anomaly']==1)).sum())
    TN = int(((df['is_attack']==0)&(df['anomaly']==0)).sum())
    def safe(a,b): return (a/b) if b>0 else None
    print('Rows total:', len(df))
    print('Attacks total:', int(df['is_attack'].sum()))
    print('Anomalies total (ML after merge):', int(df['anomaly'].sum()))
    print(f'TP {TP} FN {FN} FP {FP} TN {TN}')
    print('TPR:', safe(TP,TP+FN), 'FPR:', safe(FP,FP+TN), 'Precision:', safe(TP,TP+FP))
    print("\nDetected anomalies (sample):")
    cols = [c for c in ['attack_type','norm_uri','blocked','anomaly','score'] if c in df.columns]
    print(df[df.anomaly==1][cols].head(10).to_string(index=False))
    print("\nMissed attacks (FN sample):")
    print(df[(df.is_attack==1)&(df.anomaly==0)][cols].head(10).to_string(index=False))
    df.to_csv(OUT, index=False)
    print("\nWROTE", OUT)

if __name__=='__main__':
    main()

