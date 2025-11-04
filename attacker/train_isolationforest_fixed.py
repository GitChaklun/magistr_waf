#!/usr/bin/env python3
"""
Train IsolationForest robustly (fixed max_samples handling).
Outputs CSV with columns: score, anomaly, uri (if present).
Usage: python train_isolationforest_fixed.py --in <features.csv> --out <ml_results.csv> --contamination 0.1 --n_estimators 100 --max_samples 0.8 --random_state 7
"""
import argparse
import sys
import os
import pandas as pd
import numpy as np

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--in', dest='infile', required=True)
    p.add_argument('--out', dest='outfile', required=True)
    p.add_argument('--contamination', type=float, default=0.10)
    p.add_argument('--n_estimators', type=int, default=100)
    p.add_argument('--max_samples', default='auto')
    p.add_argument('--random_state', type=int, default=7)
    return p.parse_args()

def norm_max_samples(ms):
    # Accept 'auto', int, float (or numeric string)
    if isinstance(ms, str):
        if ms == 'auto':
            return 'auto'
        try:
            # convert to float if contains dot, else int
            if '.' in ms:
                return float(ms)
            else:
                return int(ms)
        except Exception:
            try:
                return float(ms)
            except:
                return ms
    return ms

def main():
    args = parse_args()
    infile = args.infile
    outfile = args.outfile
    if not os.path.exists(infile):
        print('ERROR: features infile not found:', infile, file=sys.stderr); sys.exit(2)
    df = pd.read_csv(infile)
    # pick numeric columns for training (exclude time/client_ip/uri if present)
    uri_col = 'uri' if 'uri' in df.columns else None
    # build numeric feature matrix
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    # if numeric columns include label 'anomaly', remove it
    if 'anomaly' in num_cols:
        num_cols = [c for c in num_cols if c!='anomaly']
    if len(num_cols)==0:
        print('No numeric features found in', infile, file=sys.stderr); sys.exit(3)
    X = df[num_cols].fillna(0).astype(float).values

    # lazy import sklearn to avoid failure if missing earlier
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import RobustScaler
    except Exception as e:
        print('Missing sklearn:', e, file=sys.stderr)
        sys.exit(4)

    # scale
    scaler = RobustScaler()
    Xs = scaler.fit_transform(X)

    ms = norm_max_samples(args.max_samples)
    # sanity check for max_samples acceptable types
    if isinstance(ms, float):
        if not (0.0 < ms <= 1.0):
            print('Invalid max_samples float:', ms, '— must be (0.0,1.0]', file=sys.stderr)
    if isinstance(ms, int):
        if ms < 1:
            print('Invalid max_samples int:', ms, file=sys.stderr)

    iso = IsolationForest(n_estimators=args.n_estimators,
                          max_samples=ms,
                          contamination=args.contamination,
                          random_state=args.random_state,
                          n_jobs=-1)
    print(f'Training IsolationForest (n_estimators={args.n_estimators}, max_samples={ms}, contamination={args.contamination})')
    iso.fit(Xs)
    # scores: use decision_function (higher = more normal). We'll invert so that *lower* -> anomaly similar to earlier
    try:
        scores = iso.decision_function(Xs)
    except:
        scores = iso.score_samples(Xs)
    preds = iso.predict(Xs)
    anoms = (preds == -1).astype(int)
    out_df = pd.DataFrame({'score': scores, 'anomaly': anoms})
    if uri_col:
        out_df['uri'] = df[uri_col].astype(str).values
    out_df.to_csv(outfile, index=False)
    print('WROTE', outfile, 'rows', len(out_df))

if __name__ == '__main__':
    main()

