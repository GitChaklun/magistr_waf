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

