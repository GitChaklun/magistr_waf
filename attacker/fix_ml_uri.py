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

p=argparse.ArgumentParser(); p.add_argument('--in',dest='inf',required=True); p.add_argument('--out',dest='outf',required=True)
a=p.parse_args()
ml=pd.read_csv(a.inf, dtype=str).fillna('')
ml['uri']=ml['uri'].astype(str)
ml['uri']=ml['uri'].map(canon)
ml.to_csv(a.outf, index=False)
print('WROTE', a.outf)
