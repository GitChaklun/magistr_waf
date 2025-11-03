#!/usr/bin/env python3
import csv, re, sys, argparse
from urllib.parse import urlparse, parse_qs
parser = argparse.ArgumentParser()
parser.add_argument("--in", dest="infile", required=True)
parser.add_argument("--out", dest="outfile", required=True)
args = parser.parse_args()

def contains_sqli_chars(s):
    return int(bool(re.search(r"('|--|%27|%22|or\s+1=1|union|select|from)", s, re.I)))

def contains_xss_chars(s):
    return int(bool(re.search(r"(<script|%3Cscript|<svg|onload=)", s, re.I)))

with open(args.infile, "r") as fh, open(args.outfile, "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["time","client_ip","method","uri","status","req_time","uri_len","qparam_count","has_sqli","has_xss"])
    for line in fh:
        line=line.strip()
        if not line: continue
        # Expected format: 2025-11-03T09:32:00+00,172.18.0.4,GET,/?id=1%20OR%20'1',500,0.000
        parts = line.split(",",5)
        if len(parts) < 6:
            continue
        time_s, ip, method, uri, status, req_time = parts
        uri_len = len(uri)
        parsed = urlparse(uri)
        q = parsed.query or parsed.path
        qcount = len(parse_qs(parsed.query)) if parsed.query else 0
        has_sqli = contains_sqli_chars(q)
        has_xss = contains_xss_chars(q)
        writer.writerow([time_s, ip, method, uri, status, req_time, uri_len, qcount, has_sqli, has_xss])
print("Wrote", args.outfile)

