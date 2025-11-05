#!/usr/bin/env python3
# attacker/generate_requests.py
"""
Генерує HTTP-запити до target, пише /opt/results/results.csv
- підтягує PAYLOADS з attacker.payloads (fallback якщо нема)
- додає nonce _rnd в URL (щоб уникнути кешування)
- рандомізує headers з HEADERS_POOL
- розширена логіка blocked (403,406,429; пошук WAF-маркерів у тілі; опціонально 500 з маркером)
- підтримка --normal-ratio (пропорція normal відносно атак)
- підтримка --only / --exclude
- нове: --post-frac (частка запитів як POST) і --jitter-ms (рандомна пауза перед запитом, мс)
"""
import argparse, uuid, random, csv, os, time, sys
from multiprocessing.pool import ThreadPool

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

# globals (set in main)
POST_FRAC = 0.0
JITTER_MS = 0.0
TIMEOUT = 15

def build_item_list(repeat, normal_ratio, payloads_view):
    """Складає список (attack_type, path) з урахуванням нормалізації частки normal."""
    attack_keys = [k for k in payloads_view.keys() if k != "normal"]
    attacks = [(k, p) for k in attack_keys for p in payloads_view.get(k, [])]
    normals = [("normal", p) for p in payloads_view.get("normal", [])]

    items = []
    for _ in range(repeat):
        items.extend(attacks)
        items.extend(normals)
    random.shuffle(items)

    # Якщо задано normal_ratio (частка нормал. відносно атак)
    if 0.0 < normal_ratio < 1.0:
        attacks_only = [i for i in items if i[0] != "normal"]
        normals_only = [i for i in items if i[0] == "normal"]
        desired_normals = int(len(attacks_only) * (normal_ratio / (1.0 - normal_ratio))) if attacks_only else len(normals_only)
        if desired_normals < len(normals_only):
            normals_only = random.sample(normals_only, desired_normals)
        items = attacks_only + normals_only
        random.shuffle(items)

    return items, attack_keys

def send_one(args):
    idx, (atype, path), target = args
    import requests
    # jitter
    if JITTER_MS and JITTER_MS > 0:
        time.sleep(random.uniform(0, JITTER_MS/1000.0))

    nonce = uuid.uuid4().hex[:6]
    path_with_nonce = f"{path}{'&' if '?' in path else '?'}_rnd={nonce}"
    url = target.rstrip("/") + path_with_nonce
    headers = random.choice(HEADERS_POOL).copy()
    headers["X-Request-Id"] = uuid.uuid4().hex[:8]

    # decide method: POST with probability POST_FRAC, otherwise GET
    use_post = (random.random() < POST_FRAC)

    try:
        start = time.time()
        if use_post:
            # POST to same path; include payload info in body for WAF observation
            # If path contains query string, POST to path (without query) and put query as data
            # but simplest: POST to full URL; include payload in form field for body inspection
            r = requests.post(url, headers=headers, timeout=TIMEOUT, allow_redirects=True, data={"payload": path})
        else:
            r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
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
            # деякі 500 з WAF-маркерами теж рахуємо як блок
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
    global POST_FRAC, JITTER_MS
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="target base url (e.g. http://waf:80)")
    parser.add_argument("--out", required=True, help="/opt/results/results.csv")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--normal-ratio", type=float, default=0.2,
                        help="proportion of normal traffic relative to attacks (0-1).")
    # нові параметри фільтрації
    parser.add_argument("--only", default="", help="comma-separated attack types to include (e.g., sqli,xss)")
    parser.add_argument("--exclude", default="", help="comma-separated attack types to exclude (e.g., idor)")
    # post + jitter
    parser.add_argument("--post-frac", type=float, default=0.0, help="fraction of requests to send as POST (0..1)")
    parser.add_argument("--jitter-ms", type=float, default=0.0, help="max random jitter before each request in milliseconds")
    args = parser.parse_args()

    POST_FRAC = float(args.post_frac)
    JITTER_MS = float(args.jitter_ms)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    # --- побудувати відфільтрований вигляд PAYLOADS ---
    only_set = set([t.strip() for t in args.only.split(",") if t.strip()])
    exclude_set = set([t.strip() for t in args.exclude.split(",") if t.strip()])

    filtered_payloads = {}
    for k, v in PAYLOADS.items():
        if k == "normal":
            filtered_payloads[k] = v
            continue
        if only_set and k not in only_set:
            continue
        if exclude_set and k in exclude_set:
            continue
        filtered_payloads[k] = v

    items, attack_keys = build_item_list(args.repeat, args.normal_ratio, filtered_payloads)

    total = len(items)
    print(f"Prepared {total} requests (repeat={args.repeat}, normal_ratio={args.normal_ratio}, post_frac={POST_FRAC}, jitter_ms={JITTER_MS})")
    print(f"Included attacks: {', '.join(attack_keys) if attack_keys else '(none)'}")

    pool = ThreadPool(processes=args.workers)
    task_args = [(i, items[i], args.target) for i in range(len(items))]
    results = pool.map(send_one, task_args)
    pool.close()
    pool.join()

    # write CSV
    keys = ["attack_type","url","payload","response_code","blocked","latency_ms","body_snippet"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print("Wrote", args.out)

if __name__ == "__main__":
    main()
