#!/usr/bin/env python3
# attacker/replay_fix_status.py
import csv, argparse
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import requests

# Які HTTP-коди трактуємо як "заблоковано"
BLOCK_CODES = {403, 406, 418, 451}

def safe_path(path: str) -> str:
    if not path or any(c in path for c in ['<','>','"',"'"," "]):
        return "/"
    return path if path.startswith("/") else "/"+path

def canon_from_row(base, row):
    """
    Будуємо URL так:
      - беремо БАЗУ (http://waf | http://modsec:8080 | http://coraza:8080)
      - path беремо з row['url'] (якщо він адекватний), або '/'
      - query = існуючі параметри + наш payload-параметр
    """
    raw = (row.get("url","") or "").strip()
    attack = (row.get("attack_type","") or "").strip().lower()
    payload = (row.get("payload","") or "").strip()

    # 1) визначаємо ім'я параметра для payload
    if attack in ("lfi","path_traversal","traversal"):
        pkey = "file"
    else:
        # xss, sqli, cmdinj, cmdi, інші — у q=
        pkey = "q"

    # 2) розбираємо збережений url, беремо path+query, але path фільтруємо
    up = urlparse(raw)
    if up.scheme and up.netloc:
        path = safe_path(up.path or "/")
        qpairs = parse_qsl(up.query, keep_blank_values=True)
    else:
        if not raw.startswith("/"): raw = "/"+raw if raw else "/"
        up2 = urlparse(raw)
        path = safe_path(up2.path or "/")
        qpairs = parse_qsl(up2.query, keep_blank_values=True)

    # 3) додаємо payload як окремий параметр
    if payload:
        qpairs.append((pkey, payload))

    # 4) збираємо фінальний URL: base.host + path + новий query
    bp = urlparse(base)
    query = urlencode(qpairs, doseq=True)
    return urlunparse((bp.scheme, bp.netloc, path, "", query, ""))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    ap.add_argument("--base", required=True,
                   help="http://waf | http://modsec:8080 | http://coraza:8080")
    ap.add_argument("--timeout", type=int, default=6)
    args = ap.parse_args()

    with open(args.inp, newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    # гарантуємо наявність колонок
    for col in ("response_code","blocked","notes"):
        if col not in fieldnames:
            fieldnames.append(col)

    s = requests.Session()
    fixed = 0

    for row in rows:
        try:
            code = int(row.get("response_code","0"))
        except:
            code = 0

        # Реплеїмо лише ті, де код == 0 (невідомий)
        if code != 0:
            continue

        url = canon_from_row(args.base, row)
        note = row.get("notes","")
        try:
            resp = s.get(url, allow_redirects=False, timeout=args.timeout)
            new_code = int(resp.status_code)
        except Exception as e:
            new_code = 0
            tag = f"replay:{type(e).__name__}"
            note = (note + "|" + tag).strip("|")

        row["response_code"] = str(new_code)
        row["blocked"] = "1" if new_code in BLOCK_CODES else "0"
        row["notes"] = note
        fixed += 1

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Replayed {fixed} rows with response_code==0 -> {args.out}")

if __name__ == "__main__":
    main()
