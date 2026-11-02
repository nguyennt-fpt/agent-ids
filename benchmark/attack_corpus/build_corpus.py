"""Build the labeled attack corpus from PUBLIC payload sources (anti-bias).

Payloads are NOT hand-crafted to favor the agent — they are collected from
well-known public references (PayloadsAllTheThings, PortSwigger Web Security
Academy, OWASP, SecLists) and kept in two committed data files next to this
script, so the build is reproducible and the payloads are auditable:

  payloads_attack.txt          clear_attack + evasion, one payload per line
                               under `## <group> :: <attack_type>` sections,
                               optional `=== family ===` grouping (see the
                               file's own header for the format).
  payloads_benign_recon.json   fp_bait, benign_normal, and the recon group
                               (directory scan + login brute force).

v2 layout (docs/CORPUS_V2.md): deterministic eids, a benchmark actor per row
(sent as X-Forwarded-For), interleaved replay order (`seq`) in which each recon
chain is one contiguous burst, and a fixed dev/test split by payload family. Command
injection goes as a POST form, as DVWA's exec page does. Run: python build_corpus.py
"""

import hashlib
import json
import os
import random
import re

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "corpus.jsonl")
ATTACK_FILE = os.path.join(HERE, "payloads_attack.txt")
BENIGN_RECON_FILE = os.path.join(HERE, "payloads_benign_recon.json")

SEED = 20260930
DEV_FRACTION = 0.3
# documentation ranges (RFC 5737): not routable, and not private -> is_private()
# doesn't hide them from the block path
ATTACKERS = [f"203.0.113.{i}" for i in range(10, 15)]
USERS = [f"198.51.100.{i}" for i in range(10, 40)]
ATTACKER_BENIGN_SHARE = 0.25   # attackers browse normally too: IP history isn't a label oracle

# attack_type -> (DVWA page, injected parameter, MITRE technique). The payload
# file only carries the attack_type + payload string; the page/param/mitre live
# here so the data file stays a flat list of public payloads.
ATTACK_MAP = {
    "sqli": ("/vulnerabilities/sqli/", "id", "T1190"),
    "xss": ("/vulnerabilities/xss_r/", "name", "T1059.007"),
    "cmdi": ("/vulnerabilities/exec/", "ip", "T1059"),
    "lfi": ("/vulnerabilities/fi/", "page", "T1083"),
    "rfi": ("/vulnerabilities/fi/", "page", "T1190"),
}

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
# DVWA's exec page is a POST form — benign pings too, or the method would leak the label
POST_FORMS = {"/vulnerabilities/exec/"}

_SECTION = re.compile(r"##\s*(clear_attack|evasion|held_out)\s*::\s*(sqli|xss|cmdi|lfi|rfi)\b")
_FAMILY = re.compile(r"^===\s*(.+?)\s*===$")


def parse_attack_file(path: str) -> list[tuple]:
    """(group, attack_type, payload, family) per non-comment line. A line marks
    a family for the lines that follow it until the next family / section; a
    payload with no family gets its own (family=None here -> its eid later)."""
    out, group, atype, family = [], None, None, None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            s = raw.strip()
            m = _SECTION.match(s)
            if m:
                group, atype, family = m.group(1), m.group(2), None
                continue
            if not s or s.startswith("#"):
                continue
            fam = _FAMILY.match(s)
            if fam:
                family = fam.group(1)
                continue
            if group:
                out.append((group, atype, s, family))
    return out


def _attack_row(group: str, attack_type: str, payload: str, family: str | None) -> dict:
    path, param, mitre = ATTACK_MAP[attack_type]
    row = dict(group=group, label="malicious", attack_type=attack_type, mitre=mitre,
               method="GET", path=path, params={param: payload}, user_agent=_UA,
               source=f"public payload ({attack_type})")
    if family:
        row["family"] = f"{group}:{attack_type}:{family}"
    if path in POST_FORMS:
        row.update(method="POST", params={}, body={param: payload, "Submit": "Submit"})
    return row


def _benign_row(group: str, path: str, params: dict, source: str, rationale: str = "") -> dict:
    row = dict(group=group, label="benign", attack_type="none", mitre="",
               method="GET", path=path, params=dict(params), user_agent=_UA, source=source)
    if rationale:
        row["rationale"] = rationale
    if path in POST_FORMS:
        row.update(method="POST", params={}, body={**params, "Submit": "Submit"})
    return row


def _recon_rows(recon: dict) -> list[dict]:
    """A directory-scan chain (GET sensitive paths) and a login brute-force
    chain (POST /login.php, what rule 9000050 thresholds on). Each chain is one
    family (so it stays whole on one side of the split) and `_order` keeps its
    requests in sequence after the global shuffle."""
    rows = []
    for i, p in enumerate(recon.get("dirscan_paths", [])):
        rows.append(dict(group="recon", label="malicious", attack_type="scan",
                         mitre="T1595", method="GET", path=p, params={}, user_agent=_UA,
                         source="SecLists Discovery/Web-Content", family="recon:dirscan",
                         _order=i))
    bf = recon.get("bruteforce", {})
    user = bf.get("username", "admin")
    for i, pw in enumerate(bf.get("passwords", [])):
        rows.append(dict(group="recon", label="malicious", attack_type="bruteforce",
                         mitre="T1110", method="POST", path="/login.php", params={},
                         body={"username": user, "password": pw, "Login": "Login"},
                         user_agent=_UA, source="SecLists Common-Credentials",
                         family="recon:bruteforce", _order=i))
    return rows


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
    # a recon chain is one scanner: same actor for every request in the family
    if row["group"] == "recon":
        return random.Random(f"{SEED}-{row['family']}").choice(ATTACKERS)
    rng = random.Random(f"{SEED}-{row['eid']}")
    if row["label"] == "malicious":
        return rng.choice(ATTACKERS)
    if row["group"] == "benign_normal" and rng.random() < ATTACKER_BENIGN_SHARE:
        return rng.choice(ATTACKERS)
    return rng.choice(USERS)


def _interleave(rows: list[dict]) -> None:
    """Shuffle so a replay (and triage batch) is no longer all-attacks-then-all-
    benign. Each recon chain is shuffled as ONE unit, in order: a scan or a brute
    force is a burst — rule 9000050 only fires on 10 logins within 60 s, and
    spread across the whole replay it never would."""
    units: list[list[dict]] = []
    chains: dict[str, list[dict]] = {}
    for r in rows:
        if r["group"] == "recon":
            chains.setdefault(r["family"], []).append(r)
        else:
            units.append([r])
    units += [sorted(c, key=lambda r: r["_order"]) for c in chains.values()]
    random.Random(SEED).shuffle(units)
    rows[:] = [r for u in units for r in u]
    for seq, r in enumerate(rows):
        r.pop("_order", None)
        r["seq"] = seq


def build() -> list[dict]:
    rows: list[dict] = []
    for group, atype, payload, family in parse_attack_file(ATTACK_FILE):
        rows.append(_attack_row(group, atype, payload, family))

    with open(BENIGN_RECON_FILE, encoding="utf-8") as f:
        data = json.load(f)
    for e in data.get("fp_bait", []):
        rows.append(_benign_row("fp_bait", e["path"], e.get("params", {}),
                                e.get("source", ""), e.get("rationale", "")))
    for e in data.get("benign_normal", []):
        rows.append(_benign_row("benign_normal", e["path"], e.get("params", {}),
                                e.get("source", "")))
    rows += _recon_rows(data.get("recon", {}))

    for r in rows:
        r["eid"] = _eid(r)
        r.setdefault("family", r["eid"])      # a payload with no declared family is its own
        r["actor_ip"] = _assign_actor(r)
    assert len({r["eid"] for r in rows}) == len(rows), "duplicate corpus rows"
    _assign_splits(rows)
    # held_out is a fully held-out test set — never exposed during development
    for r in rows:
        if r["group"] == "held_out":
            r["split"] = "test"
    _interleave(rows)
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
    n_mal = sum(r["label"] == "malicious" for r in rows)
    print(f"Wrote {len(rows)} entries to {OUT}  (malicious {n_mal} / benign {len(rows) - n_mal})")
    print("By group x split:", json.dumps(counts, indent=2, sort_keys=True))
