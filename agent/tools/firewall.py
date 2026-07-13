import subprocess
import threading
import time
from datetime import datetime, timedelta

_blocked: dict[str, datetime] = {}
_lock = threading.Lock()


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, (result.stdout + result.stderr).strip()


def block_ip(ip: str, ttl_seconds: int = 3600) -> dict:
    """Add DROP rule for ip in DOCKER-USER chain. Auto-expires after ttl_seconds."""
    with _lock:
        if ip in _blocked:
            return {"status": "already_blocked", "ip": ip}
        rc, out = _run([
            "iptables", "-I", "DOCKER-USER", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"agent-block-{ip}"
        ])
        if rc != 0:
            return {"status": "error", "ip": ip, "detail": out}
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        _blocked[ip] = expires_at
        threading.Thread(target=_auto_expire, args=(ip, ttl_seconds), daemon=True).start()
        return {"status": "blocked", "ip": ip, "expires_at": expires_at.isoformat()}


def unblock_ip(ip: str) -> dict:
    """Remove DROP rule for ip."""
    with _lock:
        rc, out = _run([
            "iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"agent-block-{ip}"
        ])
        _blocked.pop(ip, None)
        if rc != 0:
            return {"status": "error", "ip": ip, "detail": out}
        return {"status": "unblocked", "ip": ip}


def get_blocked_ips() -> list[dict]:
    """Return currently blocked IPs with expiry times."""
    with _lock:
        now = datetime.utcnow()
        return [
            {"ip": ip, "expires_at": exp.isoformat(), "remaining_s": int((exp - now).total_seconds())}
            for ip, exp in _blocked.items()
            if exp > now
        ]


def _auto_expire(ip: str, delay: int) -> None:
    time.sleep(delay)
    unblock_ip(ip)
