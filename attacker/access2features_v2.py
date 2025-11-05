#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
access2features_v2.py
Проста, стійка утиліта для перетворення логів / results.csv -> features CSV
Вихідний CSV має header:
time,client_ip,method,uri,status,req_time,uri_len,qparam_count,has_sqli,has_xss,uri_entropy,special_chars,frac_non_alnum,user_agent_suspicious

Запуск:
 python access2features_v2.py --in /opt/results/results.csv --out /opt/results/access_features_v2.csv
 або
 python access2features_v2.py --in /opt/results/access.log --out /opt/results/access_features_v2.csv
"""
import argparse
import csv
import math
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote

import hashlib
import statistics

try:
    import pandas as pd
    import numpy as np
except Exception as e:
    print("Missing dependency: pandas/numpy required. Install with pip install pandas numpy", file=sys.stderr)
    raise

# --- helpers ---------------------------------------------------------------
RE_SUSPECT_Sqli = re.compile(r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bWHERE\b|--|;--|\bOR\b\s+\d+=\d+)", re.I)
RE_XSS = re.compile(r"(<script\b|%3Cscript%3E|onerror=|onload=|<img\s|<svg\b|javascript:)", re.I)

def entropy(s: str) -> float:
    if not s:
        return 0.0
    # simple Shannon entropy
    freq = Counter(s)
    l = len(s)
    ent = 0.0
    for v in freq.values():
        p = v / l
        ent -= p * math.log2(p)
    return ent

def special_char_fraction(s: str) -> float:
    if not s:
        return 0.0
    total = len(s)
    special = sum(1 for c in s if not c.isalnum())
    return special / total if total else 0.0

def frac_non_alnum(s: str) -> float:
    if not s:
        return 0.0
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if not c.islower()) / len(letters) if letters else 0.0

def detect_sqli(s: str) -> int:
    if not isinstance(s, str):
        return 0
    return 1 if RE_SUSPECT_Sqli.search(s) else 0

def detect_xss(s: str) -> int:
    if not isinstance(s, str):
        return 0
    return 1 if RE_XSS.search(s) else 0

def is_suspicious_user_agent(ua: str) -> int:
    if not isinstance(ua, str):
        return 0
    ua_low = ua.lower()
    # simple heuristics
    bots = ['sqlmap', 'nikto', 'fuzz', 'curl', 'wget', 'python-requests', 'httpclient', 'masscan', 'scanner']
    for b in bots:
        if b in ua_low:
            return 1
    return 0

# normalize numeric strings
def parse_float_safe(x):
    try:
        if x is None:
            return float('nan')
        s = str(x).strip()
        if s == '':
            return float('nan')
        s = s.replace(',', '.')
        return float(s)
    except Exception:
        return float('nan')

# --- core processing ------------------------------------------------------
OUT_COLUMNS = [
    'time','client_ip','method','uri','status',
    'req_time','uri_len','qparam_count','has_sqli','has_xss',
    'uri_entropy','special_chars','frac_non_alnum','user_agent_suspicious'
]

def process_row_from_results_csv(row: dict) -> dict:
    """
    Expected minimal columns in results.csv: url or uri, payload (optional), response_code or response, latency or req_time, client_ip, method, user_agent
    We'll be flexible and use best-effort mapping.
    """
    res = {k: None for k in OUT_COLUMNS}
    # time
    for cand in ('date_time','time','timestamp'):
        if cand in row and pd.notna(row.get(cand)):
            res['time'] = row.get(cand)
            break
    # client_ip
    for cand in ('client_ip','ip','src_ip'):
        if cand in row and pd.notna(row.get(cand)):
            res['client_ip'] = row.get(cand)
            break
    # uri/url
    uri = None
    for cand in ('url','uri','request','path'):
        if cand in row and pd.notna(row.get(cand)):
            uri = str(row.get(cand))
            break
    # if payload present, use payload as part of uri for detection
    payload = row.get('payload') if 'payload' in row else None
    if not uri and payload:
        uri = payload
    if not uri:
        uri = '/'
    res['uri'] = uri
    # method
    for cand in ('method','http_method'):
        if cand in row and pd.notna(row.get(cand)):
            res['method'] = row.get(cand)
            break
    if res['method'] is None:
        res['method'] = 'GET'
    # status
    for cand in ('status','response_code','response'):
        if cand in row and pd.notna(row.get(cand)):
            try:
                res['status'] = int(str(row.get(cand)).strip())
            except Exception:
                res['status'] = row.get(cand)
            break
    # req_time/latency
    for cand in ('req_time','latency','latency_ms','time_ms'):
        if cand in row and pd.notna(row.get(cand)):
            res['req_time'] = parse_float_safe(row.get(cand))
            break
    # user agent
    ua = None
    for cand in ('user_agent','ua','User-Agent'):
        if cand in row and pd.notna(row.get(cand)):
            ua = row.get(cand)
            break

    # URL parsing
    try:
        up = urlparse(uri)
        path = up.path or '/'
        query = up.query or ''
        q = parse_qs(query)
        qcount = sum(len(v) for v in q.values()) if q else 0
        uri_len = len(unquote(uri))
    except Exception:
        path = uri
        qcount = uri.count('=')  # fallback
        uri_len = len(str(uri))

    # features
    text_for_detection = ''
    if payload and pd.notna(payload):
        text_for_detection = str(payload)
    else:
        text_for_detection = uri

    res['uri_len'] = int(uri_len)
    res['qparam_count'] = int(qcount)
    res['has_sqli'] = int(detect_sqli(text_for_detection))
    res['has_xss'] = int(detect_xss(text_for_detection))
    res['uri_entropy'] = float(entropy(uri))
    res['special_chars'] = float(special_char_fraction(uri))
    res['frac_non_alnum'] = float(special_char_fraction(uri))  # reuse as proxy
    res['user_agent_suspicious'] = int(is_suspicious_user_agent(ua))
    # fill missing basic columns
    if res['time'] is None:
        res['time'] = row.get('date_time') if 'date_time' in row else ''
    if res['client_ip'] is None:
        res['client_ip'] = row.get('src') if 'src' in row else ''
    if res['status'] is None:
        res['status'] = row.get('status') if 'status' in row else ''
    return res

def process_log_file(path: str):
    """
    If input is raw access.log (common log format), we will attempt to parse lines and extract: time, client_ip, method, uri, status, req_time (if present)
    Fallback: parse by splitting
    """
    out_rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            # try common log: ip - - [timestamp] "METHOD URI PROTOCOL" status bytes "ref" "ua"
            m = re.match(r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<rest>.*)', ln)
            if m:
                d = m.groupdict()
                row = {
                    'client_ip': d.get('ip'),
                    'time': d.get('time'),
                    'method': d.get('method'),
                    'uri': d.get('uri'),
                    'status': int(d.get('status')),
                }
                # try to extract UA at end
                ua_match = re.search(r'\"([^\"]+)\"$', ln)
                ua = ua_match.group(1) if ua_match else ''
                row['user_agent'] = ua
                # attempt to get latency if present (common in some logs)
                # fallback:  leave req_time empty
                # convert to features
                out_rows.append(process_row_from_results_csv(row))
            else:
                # fallback simple splitting
                parts = ln.split()
                ip = parts[0] if parts else ''
                uri = parts[6] if len(parts) > 6 else parts[-1] if parts else '/'
                row = {'client_ip': ip, 'uri': uri, 'method': parts[5] if len(parts) > 5 else 'GET'}
                out_rows.append(process_row_from_results_csv(row))
    return out_rows

def read_results_csv(path: str):
    # robust read with pandas (force dtype=str), then iterate rows
    try:
        df = pd.read_csv(path, dtype=str, low_memory=False)
    except Exception:
        # fallback to CSV module
        rows = []
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                rows.append(r)
        df = pd.DataFrame(rows)
    out = []
    if df.empty:
        return out
    # iterate rows as dict
    for _, r in df.iterrows():
        row = {k: (v if pd.notna(v) else None) for k, v in r.to_dict().items()}
        # normalize keys to lowercase
        low = {k.lower(): v for k, v in row.items()}
        out.append(process_row_from_results_csv(low))
    return out

def write_output(rows: list, out_path: str, force=False):
    # if exists and not force -> abort
    if os.path.exists(out_path) and not force:
        print(f"Output {out_path} already exists. Use --force to overwrite.", file=sys.stderr)
        # still print a message and continue to overwrite? for safety we abort
        # return False
    # ensure directory
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(OUT_COLUMNS)
        for r in rows:
            out_row = [r.get(c) if r.get(c) is not None else '' for c in OUT_COLUMNS]
            w.writerow(out_row)
    return True

# --- CLI ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Build features CSV from results.csv or access.log")
    parser.add_argument('--in', dest='infile', required=True, help='Input file (results.csv or access.log)')
    parser.add_argument('--out', dest='outfile', required=True, help='Output features CSV')
    parser.add_argument('--force', action='store_true', help='Overwrite existing output')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile
    if args.verbose:
        print("IN:", infile, "OUT:", outfile, file=sys.stderr)

    if not os.path.exists(infile):
        print("Input file not found:", infile, file=sys.stderr)
        sys.exit(2)

    rows = []
    try:
        # decide by extension: csv -> read as results CSV; else try log parser
        _, ext = os.path.splitext(infile.lower())
        if ext == '.csv':
            if args.verbose:
                print("Reading CSV input...", file=sys.stderr)
            rows = read_results_csv(infile)
        else:
            if args.verbose:
                print("Reading as raw log...", file=sys.stderr)
            rows = process_log_file(infile)
    except Exception as e:
        print("Error reading input:", e, file=sys.stderr)
        raise

    if args.verbose:
        print("Collected rows:", len(rows), file=sys.stderr)

    # If rows empty -> warn and still write header (so downstream doesn't crash)
    if not rows:
        print("Warning: no rows parsed. Will write header-only CSV.", file=sys.stderr)
        write_output([], outfile, force=args.force)
        sys.exit(0)

    # ensure numeric conversion for target columns (coerce)
    import numpy as _np
    for c in ['req_time','uri_len','qparam_count','has_sqli','has_xss','uri_entropy','special_chars','frac_non_alnum','user_agent_suspicious']:
        for r in rows:
            v = r.get(c)
            if v is None or v == '':
                r[c] = ''
            else:
                # try numeric conversion
                try:
                    if isinstance(v, (int, float)):
                        r[c] = v
                    else:
                        s = str(v).strip()
                        s = s.replace(',', '.')
                        r[c] = float(s)
                except Exception:
                    # fallback to 0
                    r[c] = 0.0 if c not in ('has_sqli','has_xss','user_agent_suspicious') else 0

    write_output(rows, outfile, force=args.force)
    if args.verbose:
        print("Wrote features:", outfile, file=sys.stderr)
    print(f"WROTE {outfile} rows={len(rows)}")

if __name__ == '__main__':
    main()

