#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--in", dest="infile", required=True)
parser.add_argument("--out", dest="outfile", required=True)
parser.add_argument("--contamination", type=float, default=0.05)
args = parser.parse_args()

df = pd.read_csv(args.infile)
# Simple feature matrix: uri_len, qparam_count, has_sqli, has_xss, status (as int), req_time (float)
df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(200)
df['req_time_f'] = pd.to_numeric(df['req_time'], errors='coerce').fillna(0.0)

X = df[['uri_len','qparam_count','has_sqli','has_xss','status','req_time_f']].values

clf = IsolationForest(contamination=args.contamination, random_state=42, n_jobs=-1)
clf.fit(X)
pred = clf.predict(X)  # -1 anomaly, 1 normal
df['anomaly'] = (pred == -1).astype(int)
df.to_csv(args.outfile, index=False)
print("Saved ML results to", args.outfile)

