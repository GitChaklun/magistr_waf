#!/usr/bin/env python3
"""
access2features_v2.py
Гнучкий парсер access.log -> access_features_v2.csv
Параметри:
  --in  /path/to/access.log
  --out /path/to/access_features_v2.csv
Якщо не вказані, використовує /opt/results/access.log -> /opt/results/access_features_v2.csv
"""
import csv, re, argparse, math, os
from urllib.parse import urlparse, parse_qs
from collections import Counter
import math
from collections import Counter
import numpy as np



def shannon_entropy(s):
    if not s: return 0.0
    cnt = Counter(s)
    length = len(s)
    return -sum((v/length)*(math.log2(v/length)) for v in cnt.values())

def count_special(s):
    return sum(1 for c in s if not c.isalnum() and c not in '/?=&')

def frac_non_alnum(s):
    if not s: return 0.0
    return sum(1 for c in s if not c.isalnum())/len(s)

parser = argparse.ArgumentParser()
parser.add_argument("--in", dest="infile", default=os.environ.get("RES_PATH","/opt/results") + "/access.log")
parser.add_argument("--out", dest="outfile", default=os.environ.get("RES_PATH","/opt/results") + "/access_features_v2.csv")
args = parser.parse_args()

INF = args.infile
OUTF = args.outfile

if not os.path.exists(INF):
    print("Input file not found:", INF)
    raise SystemExit(2)

with open(INF,'r', errors='ignore') as fh, open(OUTF,'w', newline='') as out:
    writer = csv.writer(out)
    header = ["time","client_ip","method","uri","status","req_time","uri_len","qparam_count","has_sqli","has_xss","uri_entropy","special_chars","frac_non_alnum","user_agent_suspicious"]
    writer.writerow(header)

def tokenise(s):
    if not isinstance(s, str): return []
    # split on non-word chars
    return [t for t in re.split(r'[^A-Za-z0-9]+', s) if t!='']

def avg_token_len(s):
    toks = tokenise(s)
    return (sum(len(t) for t in toks)/len(toks)) if toks else 0.0

def token_count(s):
    return len(tokenise(s))

def num_digits(s):
    if not isinstance(s,str): return 0
    return sum(c.isdigit() for c in s)

def upper_frac(s):
    if not isinstance(s,str): return 0.0
    letters = [c for c in s if c.isalpha()]
    return (sum(1 for c in letters if c.isupper())/len(letters)) if letters else 0.0

def shannon_entropy(s):
    if not isinstance(s,str) or s=='':
        return 0.0
    cnt = Counter(s)
    probs = [v/len(s) for v in cnt.values()]
    return -sum(p*math.log2(p) for p in probs if p>0)

# apply to dataframe 'df' with columns 'uri' and 'payload' or similar
# adjust names to actual df column names used in your script
if 'uri' in df.columns:
    df['path_depth'] = df['uri'].astype(str).apply(lambda x: len([p for p in x.split('/') if p!='']))
    df['num_digits'] = df['uri'].astype(str).apply(num_digits)
    df['avg_token_len'] = df['uri'].astype(str).apply(avg_token_len)
    df['token_count'] = df['uri'].astype(str).apply(token_count)
    df['upper_frac'] = df['uri'].astype(str).apply(upper_frac)
    df['param_value_entropy'] = df['uri'].astype(str).apply(lambda x: shannon_entropy(x.split('?')[-1] if '?' in x else ''))
else:
    # if script uses 'payload' column
    if 'payload' in df.columns:
        df['path_depth'] = df['payload'].astype(str).apply(lambda x: len([p for p in x.split('/') if p!='']))
        df['num_digits'] = df['payload'].astype(str).apply(num_digits)
        df['avg_token_len'] = df['payload'].astype(str).apply(avg_token_len)
        df['token_count'] = df['payload'].astype(str).apply(token_count)
        df['upper_frac'] = df['payload'].astype(str).apply(upper_frac)
        df['param_value_entropy'] = df['payload'].astype(str).apply(shannon_entropy)
# --- END extra features patch ---

    for line in fh:
        line=line.strip()
        if not line: continue

        # expected: time,ip,method,uri,status,req_time (some logs may include extra fields)
        parts = line.split(",",5)
        if len(parts) < 6:
            # fallback: try whitespace split (nginx default combined)
            toks = line.split()
            # try to reconstruct minimal fields
            time_s = toks[0] if toks else ""
            ip = toks[1] if len(toks)>1 else ""
            method = ""
            uri = toks[6] if len(toks)>6 else "/"
            status = toks[8] if len(toks)>8 else "0"
            req_time = "0"
        else:
            time_s, ip, method, uri, status, req_time = parts

        uri_len = len(uri)
        try:
            parsed = urlparse(uri)
            qcount = len(parse_qs(parsed.query)) if parsed.query else 0
            q = parsed.query or parsed.path or uri
        except:
            qcount = 0
            q = uri

        has_sqli = int(bool(re.search(r"('|--|%27|or\s+1=1|union|select|from|%20or%20)", q, re.I)))
        has_xss = int(bool(re.search(r"(<script|%3Cscript|<svg|onload=)", q, re.I)))
        uri_entropy = round(shannon_entropy(q),4)
        special_chars = count_special(q)
        frac_non = round(frac_non_alnum(q),4)

        # try to detect UA in the line (some logs include UA at the end)
        ua_susp = 1 if re.search(r"(sqlmap|nikto|fuzz|curl|bot|scanner|wget)", line.lower()) else 0

        writer.writerow([time_s, ip, method, uri, status, req_time, uri_len, qcount, has_sqli, has_xss, uri_entropy, special_chars, frac_non, ua_susp])

print("Wrote", OUTF)

