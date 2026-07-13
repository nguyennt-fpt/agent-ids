"""Enforcement + audit helpers shared by the rule-based engines and the
LangGraph agent.

Direct in-process calls (no MCP): the firewall and notifier functions are plain
Python, so the agent calls them straight rather than round-tripping through a
stdio JSON-RPC server.
"""

import os

from tools.firewall import block_ip
from tools.notifier import send_alert

# benchmark sets BLOCK_ENABLED=false so the agent records decisions without
# firewalling the replay source (which would break subsequent requests).
BLOCK_ENABLED = os.getenv("BLOCK_ENABLED", "true").lower() == "true"

PRIVATE_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.")

SEV_MAP = {1: "high", 2: "medium", 3: "low"}


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def guess_attack(signature: str) -> str:
    s = signature.lower()
    if "sql" in s:
        return "sqli"
    if "xss" in s:
        return "xss"
    if "command" in s or "exec" in s:
        return "cmdi"
    if "rfi" in s or "remote file" in s:
        return "rfi"
    if "lfi" in s or "traversal" in s or "file inclusion" in s:
        return "lfi"
    if "brute" in s:
        return "bruteforce"
    if "scanner" in s:
        return "scan"
    return "unknown"


def record_decision(*, eid: str, src_ip: str, attack: str, action: str,
                    confidence: float, reason: str, mode: str,
                    mitre: str = "", severity: str = "", note: str = "") -> None:
    """Persist one decision (with MITRE enrichment) and optionally enforce a block."""
    action = str(action)
    if action == "block" and BLOCK_ENABLED and src_ip and not is_private(src_ip):
        res = block_ip(src_ip, 3600)
        if res.get("status") not in ("blocked", "already_blocked"):
            print(f"[BLOCK-FAIL] {src_ip}: {res}")   # don't report a block that didn't happen
    msg = f"[{mode}] {action.upper()} {attack} eid={eid} conf={confidence} :: {reason}"
    send_alert(msg, src_ip=src_ip, attack_type=attack, action=action, eid=eid,
               mode=mode, mitre=mitre, severity=severity, note=note)
    print(msg)
