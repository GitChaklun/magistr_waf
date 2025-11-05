"""
report_results.py — узагальнений звіт по IF-детектору:
- читає злитий файл (combine) з колонками щонайменше: attack_type, norm_uri, blocked, anomaly, score
- рахує TP/FP/FN/TN, TPR, FPR, ACC
- друкує зведення (quiet/verbose), опційно показує короткі body_snippet-и
- зберігає агреговані топ-таблички (detected/missed) та семпли

Приклад:
python3 report_results.py \
  --ml /opt/results/ml_results_c0.10_ne100.csv \
  --combined /opt/results/combined_fixed_agg.csv \
  --results /opt/results/results.csv \
  --top 20 --quiet --show-snippets
"""
from __future__ import annotations
import argparse
import os
import sys
import csv
from pathlib import Path

import pandas as pd

DEF_COMBINED = "/opt/results/combined_fixed_agg.csv"
DEF_RESULTS  = "/opt/results/results.csv"
DEF_ML       = "/opt/results/ml_results_c0.10_ne100.csv"

OUT_DIR          = Path("/opt/results")
OUT_DET_AGG      = OUT_DIR / "detected_agg_top20.csv"
OUT_MISS_AGG     = OUT_DIR / "missed_agg_top20.csv"
OUT_SAMPLES_DIR  = OUT_DIR / "samples"
OUT_SUMMARY_CSV  = OUT_DIR / "summary_if.csv"

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def safe_float_series(s: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").fillna(default)

def group_top(df: pd.DataFrame, by_cols: list[str], top: int, with_blocked: bool = True) -> pd.DataFrame:
    """
    Агрегація за (attack_type, norm_uri) з підрахунком 'count' і середнім score.
    blocked віддаємо як округлений mean (щоб було 0/1).
    """
    if df.empty:
        cols = ["count", "attack_type", "norm_uri", "score_mean"]
        if with_blocked:
            cols.append("blocked")
        return pd.DataFrame(columns=cols)

    g = (df
         .groupby(by_cols, as_index=False)
         .agg(count=("norm_uri", "size"),
              score_mean=("score", "mean")))
    if with_blocked and "blocked" in df.columns:
        blk = df.groupby(by_cols)["blocked"].mean().reset_index(name="blocked")
        g = g.merge(blk, on=by_cols, how="left")
        g["blocked"] = (g["blocked"].fillna(0).round().astype(int))

    g = g.sort_values(["count", "score_mean"], ascending=[False, True]).head(top)
    return g

def pick_samples(df: pd.DataFrame, each: int = 3) -> pd.DataFrame:
    if df.empty:
        return df
    return df.head(each).copy()

def print_snippets(df: pd.DataFrame, title: str, show_snippets: bool, results_df: pd.DataFrame | None) -> None:
    print(f"\n-- {title} (showing up to 10 rows) --")
    if df.empty:
        print("(empty)")
        return
    print(df.to_string(index=False))

    if show_snippets and results_df is not None and "body_snippet" in results_df.columns:
        print("\n-- Short body_snippet examples for top detected (up to 3 each) --")
        # очікуємо, що df має колонки attack_type, norm_uri
        for idx, row in df.head(10).iterrows():
            norm_uri = row.get("norm_uri", "")
            # обираємо будь-які входження рядка norm_uri у сирих результатах
            mask = results_df["url"].astype(str).str.contains(pd.escape(str(norm_uri)).replace("\\/", "/"), regex=True, na=False)
            subset = results_df[mask]
            if subset.empty:
                continue
            print(f"\n[{idx}] {norm_uri} -> {min(3, len(subset))} snippet(s):")
            for snip in subset["body_snippet"].head(3):
                one = str(snip).strip().replace("\n", r"\n")
                print(one[:300])

def main():
    ap = argparse.ArgumentParser(description="Make IF report from combined CSV")
    ap.add_argument("--ml", default=DEF_ML, help="ML results CSV (for reference only)")
    ap.add_argument("--combined", default=DEF_COMBINED, help="combined CSV with anomaly/score")
    ap.add_argument("--results", default=DEF_RESULTS, help="raw results.csv")
    ap.add_argument("--top", type=int, default=20, help="how many rows to show/save in top lists")
    ap.add_argument("--quiet", action="store_true", help="compact summary")
    ap.add_argument("--show-snippets", action="store_true", help="print short body_snippet samples")
    args = ap.parse_args()

    ensure_dir(OUT_DIR)
    ensure_dir(OUT_SAMPLES_DIR)

    # Читання даних
    try:
        df = pd.read_csv(args.combined, dtype=str)
    except Exception as e:
        print(f"ERROR: cannot read combined: {args.combined} -> {e}")
        sys.exit(2)

    # сирі результати (для snippets і допоміжних полів)
    res_df = None
    if Path(args.results).exists():
        try:
            res_df = pd.read_csv(args.results, dtype=str)
        except Exception as e:
            print(f"WARN: cannot read results: {args.results} -> {e}")

    # ML файл не обов'язковий, просто читаємо для контексту
    ml_df = None
    if Path(args.ml).exists():
        try:
            ml_df = pd.read_csv(args.ml, dtype=str)
        except Exception as e:
            print(f"WARN: cannot read ML: {args.ml} -> {e}")

    # Нормалізація колонок у combined
    # очікуємо: attack_type, norm_uri, blocked, anomaly, score
    for need in ["attack_type", "norm_uri"]:
        if need not in df.columns:
            df[need] = ""

    if "blocked" not in df.columns:
        df["blocked"] = 0
    else:
        df["blocked"] = safe_float_series(df["blocked"], 0).round().astype(int)

    # anomaly та score виправляємо до чисел
    df["anomaly"] = safe_float_series(df.get("anomaly", pd.Series([0]*len(df))), 0).round().astype(int)
    df["score"]   = safe_float_series(df.get("score", pd.Series([0.0]*len(df))), 0.0)

    # ground truth: attack_type != 'normal'
    df["is_attack"] = (df["attack_type"].astype(str) != "normal").astype(int)

    # confusion matrix
    y_true = df["is_attack"].values
    y_pred = df["anomaly"].values

    TP = int(((y_pred == 1) & (y_true == 1)).sum())
    FP = int(((y_pred == 1) & (y_true == 0)).sum())
    FN = int(((y_pred == 0) & (y_true == 1)).sum())
    TN = int(((y_pred == 0) & (y_true == 0)).sum())

    total = TP + FP + FN + TN
    tpr = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    acc = (TP + TN) / total if total > 0 else 0.0

    # Зведення
    if args.quiet:
        print("\n==== SUMMARY (quiet) ====")
        print("System  TP  FP  FN  TN      TPR      FPR      ACC")
        print(f"    IF {TP} {FP} {FN} {TN} {tpr:.6f} {fpr:.6f} {acc:.6f}")
    else:
        print("\n==== SUMMARY ====")
        print(f"TP={TP} FP={FP} FN={FN} TN={TN}")
        print(f"TPR={tpr:.6f} FPR={fpr:.6f} ACC={acc:.6f}")

    # Топ детектів (pred==1) та топ пропущених (FN)
    detected_df = df[(df["anomaly"] == 1)]
    missed_df   = df[(df["is_attack"] == 1) & (df["anomaly"] == 0)]

    det_agg  = group_top(detected_df, ["attack_type", "norm_uri"], args.top, with_blocked=True)
    miss_agg = group_top(missed_df,   ["attack_type", "norm_uri"], args.top, with_blocked=True)

    # збереження
    det_path  = OUT_DIR / f"detected_agg_top{args.top}.csv"
    miss_path = OUT_DIR / f"missed_agg_top{args.top}.csv"
    det_agg.to_csv(det_path, index=False)
    miss_agg.to_csv(miss_path, index=False)

    print_snippets(det_agg, f"Top detected (agg) (showing up to {args.top} rows)", args.show_snippets, res_df)
    print_snippets(miss_agg, f"Top missed (agg) (showing up to {args.top} rows)", args.show_snippets, res_df)

    print(f"\nAgg files written: {det_path} {miss_path}")

    # Семпли по топ-групах (по 3 рядки на кожну групу)
    OUT_SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    def dump_group_samples(agg_df: pd.DataFrame, src_df: pd.DataFrame, prefix: str) -> None:
        if agg_df.empty:
            return
        for i, row in enumerate(agg_df.itertuples(index=False), start=1):
            mask = (
                (src_df["attack_type"].astype(str) == str(row.attack_type)) &
                (src_df["norm_uri"].astype(str) == str(row.norm_uri))
            )
            sample = pick_samples(src_df[mask], each=3)
            if sample.empty: 
                continue
            # тільки корисні колонки
            keep = [c for c in ["attack_type","norm_uri","url","payload","response_code",
                                "blocked","anomaly","score","body_snippet"] if c in sample.columns]
            sample = sample[keep]
            sample.to_csv(OUT_SAMPLES_DIR / f"{prefix}_{i}.csv", index=False)

    dump_group_samples(det_agg, detected_df, "detected")
    dump_group_samples(miss_agg, missed_df,   "missed")

    print(f"Samples written to: {OUT_SAMPLES_DIR}")

    # summary CSV
    try:
        with open(OUT_SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["system","TP","FP","FN","TN","TPR","FPR","ACC"])
            w.writerow(["IF", TP, FP, FN, TN, f"{tpr:.6f}", f"{fpr:.6f}", f"{acc:.6f}"])
        print(f"Summary written to: {OUT_SUMMARY_CSV}")
    except Exception as e:
        print("WARN: could not write summary csv:", e)

if __name__ == "__main__":
    main()
