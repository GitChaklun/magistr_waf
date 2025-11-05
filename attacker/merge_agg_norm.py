#!/usr/bin/env python3
import argparse, pandas as pd
from urllib.parse import urlparse, parse_qsl, unquote
def canon(s):
    if pd.isna(s): return ''
    s=str(s).strip()
    if s.startswith('http://') or s.startswith('https://'):
        p=urlparse(s); s=(p.path or '/') + (('?'+p.query) if p.query else '')
    if ',' in s and '/' in s:
        parts=s.split(',',6)
        for p in parts:
            if p.startswith('/'): s=p; break
    if '?' in s:
        path,q=s.split('?',1)
        qs=[(unquote(k),unquote(v)) for k,v in parse_qsl(q,keep_blank_values=True)]
        qs=[(k,v) for (k,v) in qs if k!='_rnd']; qs.sort()
        s=unquote(path)+ (('?' + '&'.join(f'{k}={v}' for k,v in qs)) if qs else '')
    else:
        s=unquote(s)
    return s

p=argparse.ArgumentParser()
p.add_argument('--ml', required=True)
p.add_argument('--results', required=True)
p.add_argument('--out', required=True)
a=p.parse_args()

ml=pd.read_csv(a.ml, dtype=str).fillna('')
res=pd.read_csv(a.results, dtype=str).fillna('')

ml['norm_uri']=ml['uri'].map(canon)
res['norm_uri']=res['url'].map(canon)

ml['score']=pd.to_numeric(ml['score'], errors='coerce')
ml['anomaly']=pd.to_numeric(ml['anomaly'], errors='coerce').fillna(0).astype(int)

ml_agg=(ml.groupby('norm_uri', as_index=False)
         .agg(score_min=('score','min'), score_mean=('score','mean'), anomaly_max=('anomaly','max')))

merged=res.merge(ml_agg, on='norm_uri', how='left')
merged['score']=merged['score_min'].fillna(merged['score_mean'])
merged['anomaly']=merged['anomaly_max'].fillna(0).astype(int)

merged.to_csv(a.out, index=False)
print('WROTE', a.out)
