#!/usr/bin/env python3
"""
fix_and_merge_ml.py
Нормалізує ML і results URI, приводить score/anomaly до numeric,
агрегує ML по norm_uri і мерджить в результуючий combined CSV.

Виклик:
python3 fix_and_merge_ml.py --ml /opt/results/ml_results_c0_10_ne100.csv \
                           --results /opt/results/results.csv \
                           --out /opt/results/combined_fixed_agg.csv [--force]
"""
import argparse
import os
import re
import pandas as pd


def norm_uri(u):
    if pd.isna(u) or u is None:
        return u
    s = str(u)
    # remove schema+host if present
    s = re.sub(r'^https?://[^/]+', '', s)
    # remove nonce param like _rnd=abcdef
    s = re.sub(r'([?&])?_rnd=[0-9a-fA-F]+', '', s)
    # remove trailing ? or & left by removal
    s = re.sub(r'[?&]$', '', s)
    # collapse ?& artifacts
    s = re.sub(r'\?&', '?', s)
    return s


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ml", required=True, help="ML file (score,anomaly,uri) csv")
    p.add_argument("--results", required=True, help="results.csv (attack_type,url,...)")
    p.add_argument("--out", required=True, help="output combined CSV path")
    p.add_argument("--force", action="store_true", help="overwrite output if exists")
    args = p.parse_args()

    if os.path.exists(args.out) and not args.force:
        print(f"[skip] output {args.out} exists (use --force to overwrite)")
        return

    print("Reading ML:", args.ml)
    ml = pd.read_csv(args.ml, dtype=str, keep_default_na=False, na_values=[''])
    print("Reading results:", args.results)
    res = pd.read_csv(args.results, dtype=str, keep_default_na=False, na_values=[''])

    # normalize column names if necessary
    if 'uri' not in ml.columns:
        candidates = [c for c in ml.columns if 'uri' in c.lower()]
        if candidates:
            ml = ml.rename(columns={candidates[0]: 'uri'})
    if 'url' not in res.columns:
        candidates = [c for c in res.columns if 'url' in c.lower()]
        if candidates:
            res = res.rename(columns={candidates[0]: 'url'})

    # Norm URIs
    ml['uri_norm'] = ml['uri'].apply(lambda x: norm_uri(x) if pd.notna(x) else x)
    res['norm_uri'] = res['url'].apply(lambda x: norm_uri(x) if pd.notna(x) else x)

    # numeric coercion
    if 'score' in ml.columns:
        ml['score'] = pd.to_numeric(ml['score'], errors='coerce')
    else:
        ml['score'] = pd.NA

    if 'anomaly' in ml.columns:
        ml['anomaly'] = pd.to_numeric(ml['anomaly'], errors='coerce').fillna(0).astype(int)
    else:
        ml['anomaly'] = 0

    # aggregate ML by uri_norm
    agg = ml.groupby('uri_norm', dropna=False).agg(
        score_mean=('score', 'mean'),
        score_min=('score', 'min'),
        score_count=('score', 'count'),
        anomaly_any=('anomaly', 'max')
    ).reset_index()

    # merge: left join results <- agg
    merged = res.merge(agg, left_on='norm_uri', right_on='uri_norm', how='left')

    # unify score and anomaly columns for downstream tools
    # prefer score_min if present, else score_mean
    merged['score'] = merged['score_min'].fillna(merged['score_mean'])
    merged['score'] = pd.to_numeric(merged['score'], errors='coerce')

    # anomaly: prefer anomaly_any
    if 'anomaly_any' in merged.columns:
        merged['anomaly'] = pd.to_numeric(merged['anomaly_any'], errors='coerce').fillna(0).astype(int)
    else:
        merged['anomaly'] = 0

    # diagnostics
    print("ML rows:", len(ml), "ML uniques(norm):", agg.shape[0])
    print("Results rows:", len(res), "After merge rows:", len(merged))
    nan_score = merged['score'].isna().sum()
    print("score NaN count:", nan_score)
    if nan_score:
        print("Sample rows with NaN score (first 8):")
        print(merged[merged['score'].isna()][['norm_uri', 'url']].head(8).to_string(index=False))
    print("anomaly value counts:")
    print(merged['anomaly'].value_counts(dropna=False).to_string())

    # save combined
    merged.to_csv(args.out, index=False)
    print("WROTE", args.out)


if __name__ == "__main__":
    main()
