#!/usr/bin/env python3
"""
train_isolationforest.py
Reads /opt/results/access_features_v2.csv, trains IsolationForest with scaling,
writes /opt/results/ml_results_c{contamination}.csv with columns: score, anomaly (0/1)
Usage:
  python train_isolationforest.py --in /opt/results/access_features_v2.csv --out /opt/results/ml_results_c0.10.csv --contamination 0.10
"""
import argparse, pandas as pd, numpy as np, os, sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import warnings
warnings.filterwarnings("ignore")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="infile", default="/opt/results/access_features_v2.csv")
    p.add_argument("--out", dest="outfile", default="/opt/results/ml_results.csv")
    p.add_argument("--contamination", dest="contamination", type=float, default=0.10)
    p.add_argument("--n_estimators", dest="n_estimators", type=int, default=200)
    p.add_argument("--max_samples", dest="max_samples", default="auto")
    p.add_argument("--random_state", dest="random_state", type=int, default=42)
    args = p.parse_args()

    if not os.path.exists(args.infile):
        print("ERROR: features file not found:", args.infile, file=sys.stderr)
        sys.exit(2)

    print("Loading features from", args.infile)
    df = pd.read_csv(args.infile)
    # Select numeric columns only (exclude time/client_ip etc.)
    numcols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
    if not numcols:
        print("ERROR: no numeric columns found in features", file=sys.stderr)
        sys.exit(3)
    X = df[numcols].fillna(0.0).astype(float)

    print("Numeric feature count:", len(numcols))
    print("Applying RobustScaler...")
    scaler = RobustScaler()
    Xs = scaler.fit_transform(X)

    print(f"Training IsolationForest (n_estimators={args.n_estimators}, max_samples={args.max_samples}, contamination={args.contamination})")
    iso = # ensure max_samples has correct numeric type for sklearn
    ms = args.max_samples
    if isinstance(ms, str):
        if ms == 'auto':
            pass
        else:
            try:
                # float if contains dot, else int
                ms = float(ms) if ('.' in str(ms)) else int(ms)
            except Exception:
                pass
    IsolationForest(n_estimators=args.n_estimators, max_samples=ms,
                          contamination=args.contamination, random_state=args.random_state, n_jobs=-1)
    iso.fit(Xs)

    # decision_function: higher => more normal; lower => more anomalous
    scores = iso.decision_function(Xs)  # continuous score
    # anomaly flag: scikit names outliers as -1 in predict; we'll map to 1 for anomaly
    preds = iso.predict(Xs)  # 1 for normal, -1 for anomaly
    anomaly = (preds == -1).astype(int)

    out = pd.DataFrame({
        "score": scores,
        "anomaly": anomaly
    })
    # Optionally include a few helpful original columns for debugging if present
    keep_cols = []
    for c in ['attack_type','uri','payload','response_code','blocked','latency_ms']:
        if c in df.columns:
            out[c] = df[c]

    print("Writing ML results to", args.outfile)
    out.to_csv(args.outfile, index=False)
    print("Wrote:", args.outfile, "rows:", len(out))
    # Print basic counts
    print("Anomalies total (ML):", int(out['anomaly'].sum()))
    print("Done.")

if __name__ == "__main__":
    main()

