#!/usr/bin/env python3
# attacker/generate_requests.py
"""
Генерує HTTP GET-запити до target, пише /opt/results/results.csv
Особливості:
- підтягує PAYLOADS з attacker.payloads (fallback якщо нема)
- додає nonce _rnd в URL (щоб уникнути кешування)
- рандомізує headers з HEADERS_POOL
- розширена логіка blocked (403,406,429; пошук WAF-маркерів у тілі; опціонально 500 з маркером)
- підтримка --normal-ratio (пропорція normal відносно атак)
- simple multi-threaded через ThreadPool
"""
import argparse, uuid, random, csv, os, time
from multiprocessing.pool import ThreadPool

import sys, os
# ensure /opt is on sys.path so "attacker" package resolves to /opt/attacker
if '/opt' not in sys.path:
    sys.path.insert(0, '/opt')

# Try to import PAYLOADS from attacker.payloads, else fallback small default
try:
    from attacker.payloads import PAYLOADS
except Exception:
    PAYLOADS = {
        "sqli": ["/?id=1 OR 1=1"],
        "xss": ["/?q=<script>alert(1)</script>"],
        "idor": ["/rest/user/1"],
        "normal": ["/", "/home"]
    }

HEADERS_POOL = [
    {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"User-Agent":"curl/7.68.0"},
    {"User-Agent":"PostmanRuntime/7.28.4"},
    {"User-Agent":"python-requests/2.31.0"},
    {"User-Agent":"Googlebot/2.1 (+http://www.google.com/bot.html)"},
]

WAF_BODY_MARKERS = [
    "Blocked by WAF", "Access Denied", "Request blocked", "Forbidden",
    "You have been blocked", "ModSecurity", "coraza", "SecRule"
]

def build_item_list(repeat, normal_ratio):
    # flatten attacks and normals
    attack_keys = [k for k in PAYLOADS.keys() if k != "normal"]
    attacks = [(k, p) for k in attack_keys for p in PAYLOADS.get(k, [])]
    normals = [("normal", p) for p in PAYLOADS.get("normal", [])]

    items = []
    for _ in range(repeat):
        items.extend(attacks)
        items.extend(normals)
    random.shuffle(items)

    # If normal_ratio specified as proportion of total (e.g., 0.7 means 70% normal overall),
    # we need to sample normals so that normals/(attacks+normals) ~= normal_ratio.
    if 0.0 < normal_ratio < 1.0:
        attacks_only = [i for i in items if i[0] != "normal"]
        normals_only = [i for i in items if i[0] == "normal"]
        desired_normals = int(len(attacks_only) * (normal_ratio / (1.0 - normal_ratio))) if attacks_only else len(normals_only)
        if desired_normals < len(normals_only):
            normals_only = random.sample(normals_only, desired_normals)
        items = attacks_only + normals_only
        random.shuffle(items)

    return items

def send_one(args):
    idx, (atype, path), target = args
    import requests
    nonce = uuid.uuid4().hex[:6]
    path_with_nonce = f"{path}{'&' if '?' in path else '?'}_rnd={nonce}"
    url = target.rstrip("/") + path_with_nonce
    headers = random.choice(HEADERS_POOL).copy()
    headers["X-Request-Id"] = uuid.uuid4().hex[:8]
    try:
        start = time.time()
        r = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        latency_ms = int((time.time()-start)*1000)
        body = r.text or ""
        blocked = 0
        if r.status_code in (403, 406, 429):
            blocked = 1
        else:
            low = body.lower()
            for marker in WAF_BODY_MARKERS:
                if marker.lower() in low:
                    blocked = 1
                    break
            # consider some 500 responses as blocked if contain WAF markers
            if blocked == 0 and r.status_code == 500 and any(m.lower() in low for m in ["modsecurity","coraza","secrule"]):
                blocked = 1

        return {
            "attack_type": atype,
            "url": url,
            "payload": path,
            "response_code": r.status_code,
            "blocked": blocked,
            "latency_ms": latency_ms,
            "body_snippet": (body[:500].replace("\n"," ") if body else "")
        }
    except Exception as e:
        return {
            "attack_type": atype,
            "url": url,
            "payload": path,
            "response_code": 0,
            "blocked": 0,
            "latency_ms": -1,
            "body_snippet": str(e)[:500]
        }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="target base url (e.g. http://waf:80)")
    parser.add_argument("--out", required=True, help="/opt/results/results.csv")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--normal-ratio", type=float, default=0.2, help="proportion of normal traffic relative to attacks (0-1).")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    items = build_item_list(args.repeat, args.normal_ratio)
    total = len(items)
    print(f"Prepared {total} requests (repeat={args.repeat}, normal_ratio={args.normal_ratio})")

    pool = ThreadPool(processes=args.workers)
    task_args = [(i, items[i], args.target) for i in range(len(items))]
    results = pool.map(send_one, task_args)
    pool.close()
    pool.join()

    # write CSV
    keys = ["attack_type","url","payload","response_code","blocked","latency_ms","body_snippet"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        import csv
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()

