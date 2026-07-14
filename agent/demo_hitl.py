"""Interactive human-in-the-loop demo (bài 06) — approve or deny an autonomous
block through the LangGraph risk gate.

The headless agent auto-approves (AUTO_APPROVE=true) so the benchmark never
blocks. This script sets AUTO_APPROVE=false and a MemorySaver checkpointer, so
the `risk_gate` node calls interrupt() and pauses for you. A denied block is
downgraded to warn, not dropped.

Run inside the agent container (it reaches Ollama and reads /app/prompts):
  docker exec -e AUTO_APPROVE=false -it agent python demo_hitl.py
"""

import os
import uuid

os.environ["AUTO_APPROVE"] = "false"       # exercise the real gate
os.environ.setdefault("MEMORY_ENABLED", "false")
os.environ.setdefault("BLOCK_ENABLED", "false")   # demo: never actually firewall

from langgraph.checkpoint.memory import MemorySaver   # noqa: E402
from langgraph.types import Command                   # noqa: E402

from graph import build_graph                          # noqa: E402

# one clear SQLi (high-confidence attack) -> the gate should ask to block it
SAMPLE_EVENTS = [
    {"eid": "demo-sqli", "src_ip": "203.0.113.7", "source": "ids",
     "signature": "ET WEB_SERVER SQL Injection UNION SELECT", "severity": 1,
     "method": "GET",
     "url": "/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -",
     "user_agent": "curl/8.0",
     "payload": "1' UNION SELECT user,password FROM users-- -"},
]


def main() -> None:
    app = build_graph(checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}
    state = {"events": SAMPLE_EVENTS, "decisions": [],
             "ambiguous_eids": [], "decided_eids": []}

    print("Running agent graph (AUTO_APPROVE=false)...")
    result = app.invoke(state, config)

    # loop while the graph is paused waiting for human approval
    while result.get("__interrupt__"):
        payload = result["__interrupt__"][0].value
        print("\n=== HUMAN APPROVAL REQUIRED (bài 06 HITL) ===")
        approvals = {}
        for p in payload.get("pending", []):
            print(f"  BLOCK {p['src_ip']}  eid={p['eid']}  attack={p['attack_type']}  "
                  f"conf={p['confidence']}")
            print(f"  analyst_note: {p['analyst_note']}")
            ans = input("  approve this block? [y/N] ").strip().lower()
            approvals[p["eid"]] = "approve" if ans == "y" else "deny"
        result = app.invoke(Command(resume=approvals), config)

    print("\n=== FINAL DECISIONS ===")
    for d in result.get("decisions", []):
        print(f"  eid={d['eid']}  action={d['action']}  "
              f"attack={d.get('attack_type')}  conf={d.get('confidence')}")


if __name__ == "__main__":
    main()
