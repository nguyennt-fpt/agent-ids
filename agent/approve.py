"""Answer the HITL gate's escalated blocks (G5) — run inside the agent container.

  docker exec agent python approve.py                    # list what waits for you
  docker exec agent python approve.py <eid> approve      # block the source
  docker exec agent python approve.py <eid> warn         # attack, but don't firewall
  docker exec agent python approve.py <eid> benign       # false positive -> log

The agent resumes the paused batch once every item in it is answered; items
left unanswered for HITL_TIMEOUT_S become warn. benign is also fed back to the
experience memory as the model's mistake (when MEMORY_ENABLED).
"""

import sys
from datetime import datetime

import approvals


def main(argv: list[str]) -> int:
    if len(argv) == 1:
        items = approvals.pending()
        if not items:
            print("nothing waiting for approval")
        for i in items:
            age = datetime.now().timestamp() - i["ts"]
            print(f"{i['eid']}  {i['src_ip']:15s} {i['attack_type'] or '-':10s} "
                  f"conf={i['confidence']}  waiting {age / 60:.0f} min  :: {i['note']}")
        return 0
    if len(argv) == 3 and argv[2] in approvals.ANSWERS:
        if approvals.answer(argv[1], argv[2]):
            print(f"{argv[1]}: {argv[2]} — the agent resumes on its next poll")
            return 0
        print(f"{argv[1]}: no open approval with that eid", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
