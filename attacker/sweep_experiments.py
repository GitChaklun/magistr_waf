#!/usr/bin/env python3
# attacker/sweep_experiments.py
# Run a small experiment sweep: train IF, quantile-label, combine, metrics, samples.
import os, sys, subprocess, itertools, math
import pandas as pd
import numpy as np
from pathlib import Path

RES_DIR = Path("/opt/results")
ATT_DIR = Path("/opt/attacker")
RESULTS_CSV = RES_DIR / "results.csv"
FEATURES_CSV = RES_DIR / "access_features_v2.csv"

# Experiment grid (safe defaults)
contaminations = [0.02, 0.05, 0.10, 0.15]
n_estimators_list = [100, 500]     # choose 100 and 500 to compare speed vs quality
max_samples_list = [0.8]           # float is allowed if scikit supports it
random_state = 7

# Safety checks
if not RESULTS_CSV.exists():
    print("ERROR: results.csv not found at", RESULTS_CSV); sys.exit(2)
if not FEATURES_CSV.exists():
    print("ERROR: access_features_v2.csv not found at", FEATURES_CSV); sys.exit(2)

# helper to run command in container entrypoint context (we're inside container when running script)
def run_cmd(cmd):
    print("RUN:", cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        print("Command failed (rc={}): {}".format(rc, cmd))
    return rc

# 1) Train IsolationForest for each experiment
exp_rows = []
for n_estimators, max_samples in itertools.product(n_estimators_list, max_samples_list):
    tag_base = f"ne{n_estimators}_ms{str(max_samples).replace('.', '')}"
    for c in contaminations:
        tag = f"c{str(c).replace('.', '_')}_{tag_base}"
        out_ml = RES_DIR / f"ml_results_{tag}.csv"
        # train command (train_isolationforest_fixed.py must accept these args)
        cmd = f"python /opt/attacker/train_isolationforest_fixed.py --in {FEATURES_CSV} --out {out_ml} --contamination {c} --n_estimators {n_estimators} --max_samples {max_samples} --random_state {random_state}"
        rc = run_cmd(cmd)
        if rc != 0:
            print("TRAIN FAILED for", tag)
            continue
        # quantile labeling (explicit) to guarantee proportion
        try:
            df_ml = pd.read_csv(out_ml)
            if 'score' not in df_ml.columns:
                print("No score column in", out_ml, "skip quantile labelling")
                continue
            scores = df_ml['score'].astype(float).values
            th = np.quantile(scores, c)
            df_ml['anomaly_q'] = (scores <= th).astype(int)
            out_quant = RES_DIR / f"ml_results_{tag}_quant.csv"
            df_ml.to_csv(out_quant, index=False)
            print("WROTE", out_quant, "anoms", int(df_ml['anomaly_q'].sum()), "th", th)
        except Exception as e:
            print("ERR processing", out_ml, e)
            continue

# 2) Combine results.csv with each quant file, compute metrics, save combined and samples
r = pd.read_csv(RESULTS_CSV).reset_index(drop=True)
metrics = []
for c in contaminations:
    for n_estimators, max_samples in itertools.product(n_estimators_list, max_samples_list):
        tag_base = f"ne{n_estimators}_ms{str(max_samples).replace('.', '')}"
        tag = f"c{str(c).replace('.', '_')}_{tag_base}"
        quant_path = RES_DIR / f"ml_results_{tag}_quant.csv"
        if not quant_path.exists():
            print("skip, missing", quant_path)
            continue
        m = pd.read_csv(quant_path).reset_index(drop=True)
        n = min(len(r), len(m))
        rr = r.iloc[:n].copy().reset_index(drop=True)
        mm = m.iloc[:n].copy().reset_index(drop=True)
        # unify anomaly column
        if 'anomaly_q' in mm.columns:
            rr['ml_anomaly'] = mm['anomaly_q'].astype(int)
        elif 'anomaly' in mm.columns:
            rr['ml_anomaly'] = mm['anomaly'].astype(int)
        else:
            print("no anomaly col in", quant_path); continue
        rr['is_attack'] = rr['attack_type'].apply(lambda x: 0 if str(x).lower()=='normal' else 1)
        tp = int(((rr['is_attack']==1)&(rr['ml_anomaly']==1)).sum())
        fn = int(((rr['is_attack']==1)&(rr['ml_anomaly']==0)).sum())
        fp = int(((rr['is_attack']==0)&(rr['ml_anomaly']==1)).sum())
        tn = int(((rr['is_attack']==0)&(rr['ml_anomaly']==0)).sum())
        tpr = tp/(tp+fn) if (tp+fn)>0 else 0
        prec = tp/(tp+fp) if (tp+fp)>0 else None
        latency_mean = rr['latency_ms'].mean() if 'latency_ms' in rr.columns else None
        latency_median = rr['latency_ms'].median() if 'latency_ms' in rr.columns else None
        metrics.append({
            'tag': tag, 'n_rows': n, 'anoms': int(rr['ml_anomaly'].sum()),
            'TP': tp, 'FN': fn, 'FP': fp, 'TN': tn,
            'TPR': round(tpr,4), 'Precision': round(prec,4) if prec is not None else None,
            'latency_mean': latency_mean, 'latency_median': latency_median
        })
        # save combined
        out_comb = RES_DIR / f"combined_results_{tag}.csv"
        rr.to_csv(out_comb, index=False)
        print("WROTE combined", out_comb)
        # save samples (TP, FN, FP)
        def save_sample(df, cond, fname):
            s = df[cond].head(5)
            if len(s)>0:
                s.to_csv(RES_DIR / fname, index=False)
        save_sample(rr, (rr['is_attack']==1)&(rr['ml_anomaly']==1), f"samples_{tag}_TP.csv")
        save_sample(rr, (rr['is_attack']==1)&(rr['ml_anomaly']==0), f"samples_{tag}_FN.csv")
        save_sample(rr, (rr['is_attack']==0)&(rr['ml_anomaly']==1), f"samples_{tag}_FP.csv")

# summary
dfm = pd.DataFrame(metrics)
if len(dfm):
    dfm.to_csv(RES_DIR / "metrics_summary.csv", index=False)
    print("WROTE metrics_summary.csv")
    print(dfm.to_string(index=False))
else:
    print("No metrics collected")
print("DONE")

