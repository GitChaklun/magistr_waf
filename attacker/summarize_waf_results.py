#!/usr/bin/env python3
# attacker/summarize_waf_results.py
# Збирає TP/FP/FN/TN/TPR/FPR/ACC з results/<system>/results.csv
import argparse, os, sys
import pandas as pd

def compute_metrics(df: pd.DataFrame):
    df = df.copy()
    df["is_attack"] = df["attack_type"] != "normal"
    df["blocked"] = pd.to_numeric(df["blocked"], errors="coerce").fillna(0).astype(int)

    TP = int(((df.blocked == 1) & (df.is_attack)).sum())
    FP = int(((df.blocked == 1) & (~df.is_attack)).sum())
    FN = int(((df.blocked == 0) & (df.is_attack)).sum())
    TN = int(((df.blocked == 0) & (~df.is_attack)).sum())

    TPR = TP / (TP + FN) if (TP + FN) else 0.0
    FPR = FP / (FP + TN) if (FP + TN) else 0.0
    ACC = (TP + TN) / len(df) if len(df) else 0.0
    return TP, FP, FN, TN, TPR, FPR, ACC

def main():
    ap = argparse.ArgumentParser(description="Summarize WAF block metrics across systems.")
    ap.add_argument("--roots", default="/opt/results",
                    help="Корінь з підпапками results/<system>/results.csv (default: /opt/results)")
    ap.add_argument("--systems", nargs="+", default=["waf", "modsec", "coraza"],
                    help="Список систем для збору (default: waf modsec coraza)")
    ap.add_argument("--out", default="/opt/results/summary_waf_all.csv",
                    help="Куди писати зведений CSV (default: /opt/results/summary_waf_all.csv)")
    ap.add_argument("--by-type", action="store_true",
                    help="Додатково зберегти розбивку за attack_type у *_by_type.csv")
    ap.add_argument("--quiet", action="store_true",
                    help="Не друкувати таблиці в stdout")
    args = ap.parse_args()

    rows = []
    bytype_rows = []

    for s in args.systems:
        path = os.path.join(args.roots, s, "results.csv")
        if not os.path.exists(path):
            print(f"[WARN] missing {path}, skipping {s}", file=sys.stderr)
            continue

        df = pd.read_csv(path)
        TP, FP, FN, TN, TPR, FPR, ACC = compute_metrics(df)
        rows.append({
            "system": s, "TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "TPR": TPR, "FPR": FPR, "ACC": ACC
        })

        if args.by_type:
            attacks = df[df["attack_type"] != "normal"]
            for t, dft in attacks.groupby("attack_type"):
                tTP, tFP, tFN, tTN, tTPR, tFPR, tACC = compute_metrics(dft)
                bytype_rows.append({
                    "system": s, "attack_type": t,
                    "TP": tTP, "FP": tFP, "FN": tFN, "TN": tTN,
                    "TPR": tTPR, "FPR": tFPR, "ACC": tACC
                })

    out_df = pd.DataFrame(rows)
    out_df.to_csv(args.out, index=False)
    if not args.quiet:
        print(out_df.to_string(index=False))
    print(f"WROTE {args.out}")

    if args.by_type and bytype_rows:
        by_path = os.path.splitext(args.out)[0] + "_by_type.csv"
        by_df = pd.DataFrame(bytype_rows)
        by_df.to_csv(by_path, index=False)
        if not args.quiet:
            print("\n(by type)")
            print(by_df.to_string(index=False))
        print(f"WROTE {by_path}")

if __name__ == "__main__":
    main()
