import os
import subprocess

RULES_PATH = os.getenv("CUSTOM_RULES_PATH", "/etc/suricata/rules/custom.rules")
SURICATA_SOCKET = os.getenv("SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket")


def append_rule(rule: str) -> dict:
    """Append a Suricata rule line to the custom rules file and signal reload."""
    rule = rule.strip()
    if not rule or rule.startswith("#"):
        return {"status": "error", "detail": "Empty or comment-only rule"}
    if not rule.startswith("alert ") and not rule.startswith("drop "):
        return {"status": "error", "detail": "Rule must start with alert/drop action"}

    try:
        with open(RULES_PATH, "a", encoding="utf-8") as f:
            f.write("\n" + rule + "\n")
    except OSError as e:
        return {"status": "error", "detail": str(e)}

    reload_result = _reload_suricata()
    return {"status": "appended", "rule": rule, "reload": reload_result}


def _reload_suricata() -> str:
    """Signal Suricata to reload rules via suricatasc."""
    result = subprocess.run(
        ["suricatasc", "-c", "reload-rules"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        return "reloaded"
    return f"reload_failed: {result.stderr.strip()}"


def list_custom_rules() -> list[str]:
    """Return all non-comment lines from the custom rules file."""
    if not os.path.exists(RULES_PATH):
        return []
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]
