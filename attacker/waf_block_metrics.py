#!/usr/bin/env python3
"""
waf_block_metrics.py — порівняння WAF-блокувань за полем blocked/HTTP-кодом.

Приклад запуску (в контейнері attacker):
  python3 /opt/attacker/waf_block_metrics.py \
    --roots /opt/results \
    --systems waf modsec coraza \
    --out /opt/results/summary_waf_all.csv \
    --recalc-blocked \
    --by-type
"""
import argparse, os, sys
import pandas as pd

DEFAULT_CODES = {403, 406, 409, 413, 418, 451}

def load_results(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # привести типи
    if 'attack_type' not in df.columns:
        raise ValueError(f"{path}: 'attack_type' not found")
    if 'response_code' in df.columns:
        # витягнути цифри з можливих рядків
        rc = pd.to_numeric(df['response_code'].astype(str).str.extract(r'(\d+)')[0], errors='coerce')
        df['response_code'] = rc.astype('Int64')
    if 'blocked' in df.columns:
        df['blocked'] = pd.to_numeric(df['blocked'], errors='coerce').fillna(0).astype(int)
    return df

def recalc_blocked_from_codes(df: pd.DataFrame, code_set=DEFAULT_CODES) -> pd.DataFrame:
    if 'response_code' not in df.columns:
        return df
    rc = df['response_code'].fillna(-1).astype(int)
    blk = rc.isin(code_set).astype(int)
    out = df.copy()
    out['blocked'] = blk
    return out

def confusion(df: pd.DataFrame):
    is_attack = (df['attack_type'] != 'normal')
    blocked   = df['blocked'].astype(int)

    TP = int(((blocked == 1) & (is_attack)).sum())
    FP = int(((blocked == 1) & (~is_attack)).sum())
    FN = int(((blocked == 0) & (is_attack)).sum())
    TN = int(((blocked == 0) & (~is_attack)).sum())

    TPR = TP / (TP + FN) if (TP + FN) else 0.0
    FPR = FP / (FP + TN) if (FP + TN) else 0.0
    ACC = (TP + TN) / len(df) if len(df) else 0.0
    return TP, FP, FN, TN, TPR, FPR, ACC

def per_type(df: pd.DataFrame) -> pd.DataFrame:
    # Detection rate per attack_type: частка blocked серед кожного типу
    g = df.groupby('attack_type', as_index=False).agg(
        total=('blocked','count'),
        blocked=('blocked','sum')
    )
    g['rate'] = g['blocked'] / g['total'].replace(0, 1)
    return g.sort_values('rate', ascending=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--roots', default='/opt/results', help='корінь з підпапками waf/modsec/coraza')
    ap.add_argument('--systems', nargs='+', default=['waf','modsec','coraza'])
    ap.add_argument('--out', default='/opt/results/summary_waf_all.csv')
    ap.add_argument('--by-type', action='store_true')
    ap.add_argument('--recalc-blocked', action='store_true')
    ap.add_argument('--block-codes', default='403,406,409,413,418,451',
                    help='список кодів, які вважаємо блоком')
    args = ap.parse_args()

    code_set = {int(x.strip()) for x in args.block_codes.split(',') if x.strip()}

    rows = []
    bytype_out = []

    for s in args.systems:
        p = os.path.join(args.roots, s, 'results.csv')
        if not os.path.exists(p):
            print(f"[WARN] skip {s}: {p} not found", file=sys.stderr); continue
        df = load_results(p)
        if args.recalc_blocked:
            df = recalc_blocked_from_codes(df, code_set=code_set)
        TP, FP, FN, TN, TPR, FPR, ACC = confusion(df)
        rows.append(dict(system=s, TP=TP, FP=FP, FN=FN, TN=TN, TPR=TPR, FPR=FPR, ACC=ACC))
        if args.by_type:
            tmp = per_type(df)
            tmp.insert(0, 'system', s)
            bytype_out.append(tmp)

    if not rows:
        print("[ERROR] no systems processed", file=sys.stderr); sys.exit(2)

    summary = pd.DataFrame(rows)[['system','TP','FP','FN','TN','TPR','FPR','ACC']]
    # упорядкуємо за ACC
    summary = summary.sort_values('ACC', ascending=False).reset_index(drop=True)
    print(summary.to_string(index=False))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    summary.to_csv(args.out, index=False)
    print(f"WROTE {args.out}")

    if args.by_type and bytype_out:
        bt = pd.concat(bytype_out, ignore_index=True)
        out2 = os.path.join(os.path.dirname(args.out), 'summary_waf_by_type.csv')
        bt.to_csv(out2, index=False)
        print(f"WROTE {out2}")

if __name__ == '__main__':
    main()
