import shlex
import subprocess
import threading
from datetime import datetime, timedelta

# Blocked sources live in one ipset with per-entry timeouts, matched by a single
# DOCKER-USER rule: the kernel expires each block itself (so a block outlives an
# agent restart and still ends on time), and the lookup is a hash, not one
# iptables rule per IP. (Before: per-IP rules whose expiry timers lived in RAM.)
SET = "agent-block"
_SET_RULE = ["DOCKER-USER", "-m", "set", "--match-set", SET, "src", "-j", "DROP",
             "-m", "comment", "--comment", "agent-block-set"]
_lock = threading.Lock()


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, (result.stdout + result.stderr).strip()


def _ensure_set() -> tuple[int, str]:
    """Create the set and its DROP rule unless both exist."""
    rc, out = _run(["ipset", "create", SET, "hash:ip", "timeout", "3600", "-exist"])
    if rc != 0:
        return rc, out
    if _run(["iptables", "-C"] + _SET_RULE)[0] != 0:
        return _run(["iptables", "-I"] + _SET_RULE)
    return 0, ""


def block_ip(ip: str, ttl_seconds: int = 3600) -> dict:
    """Drop traffic from ip to the containers for ttl_seconds (kernel-side expiry)."""
    with _lock:
        rc, out = _ensure_set()
        if rc != 0:
            return {"status": "error", "ip": ip, "detail": out}
        if _run(["ipset", "test", SET, ip])[0] == 0:
            return {"status": "already_blocked", "ip": ip}
        rc, out = _run(["ipset", "add", SET, ip, "timeout", str(ttl_seconds), "-exist"])
        if rc != 0:
            return {"status": "error", "ip": ip, "detail": out}
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        return {"status": "blocked", "ip": ip, "expires_at": expires_at.isoformat()}


def unblock_ip(ip: str) -> dict:
    """Lift the block on ip before its timeout."""
    with _lock:
        rc, out = _run(["ipset", "del", SET, ip, "-exist"])
        if rc != 0:
            return {"status": "error", "ip": ip, "detail": out}
        return {"status": "unblocked", "ip": ip}


def cleanup_stale_blocks() -> int:
    """Delete per-IP agent-block-<ip> rules left in DOCKER-USER by the agent
    before the ipset version: their expiry timers died with that process, so
    they would never expire. The set's own rule stays — its entries time out in
    the kernel. Only this agent's rules (matched by comment) are touched.
    Returns how many were removed."""
    rc, out = _run(["iptables", "-S", "DOCKER-USER"])
    if rc != 0:
        return 0
    removed = 0
    for line in out.splitlines():
        if (line.startswith("-A DOCKER-USER ") and "agent-block-" in line
                and "agent-block-set" not in line):
            # shlex: iptables -S quotes the comment ("agent-block-…"); a plain split keeps the quotes
            rc, _ = _run(["iptables", "-D"] + shlex.split(line)[1:])
            removed += rc == 0
    return removed


def get_blocked_ips() -> list[dict]:
    """Currently blocked IPs with their expiry, read from the kernel's set."""
    rc, out = _run(["ipset", "list", SET, "-output", "save"])
    if rc != 0:
        return []
    now = datetime.utcnow()
    blocked = []
    for line in out.splitlines():
        parts = line.split()          # add agent-block 203.0.113.9 timeout 3542
        if len(parts) >= 5 and parts[0] == "add" and parts[3] == "timeout":
            remaining = int(parts[4])
            blocked.append({"ip": parts[2], "remaining_s": remaining,
                            "expires_at": (now + timedelta(seconds=remaining)).isoformat()})
    return blocked
