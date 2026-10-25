"""inspect_run.py — actor-IP agreement, status counts, misclassified requests."""

import json

from inspect_run import inspect

CORPUS = {"e1": {"actor_ip": "203.0.113.10", "method": "GET", "path": "/a", "params": {"q": "x"}},
          "e2": {"actor_ip": "198.51.100.10", "method": "GET", "path": "/b", "params": {}},
          "e3": {"actor_ip": "198.51.100.11", "method": "GET", "path": "/c", "params": {}}}
SENT = {"e1": {"label": "malicious", "group": "clear_attack", "status": 200},
        "e2": {"label": "benign", "group": "benign_normal", "status": 404},
        "e3": {"label": "benign", "group": "fp_bait", "status": 200}}


def _lines(*objs):
    return [json.dumps(o) for o in objs] + ["not json"]


def test_inspect():
    nginx = _lines({"remote_addr": "203.0.113.10", "uri": "/a?q=x&eid=e1"},
                   {"remote_addr": "172.18.0.1", "uri": "/b?eid=e2"},            # realip failed
                   {"remote_addr": "198.51.100.11", "uri": "/c?eid=e3"})
    eve = _lines({"event_type": "alert", "src_ip": "203.0.113.10", "http": {"url": "/a?q=x&eid=e1"}},
                 {"event_type": "alert", "direction": "to_client", "src_ip": "127.0.0.1",
                  "dest_ip": "203.0.113.10", "http": {"url": "/a?q=x&eid=e1"}},   # response alert
                 {"event_type": "http", "src_ip": "127.0.0.1", "http": {"url": "/c?eid=e3"}})
    decisions = {"e1": ("block", "[agent] BLOCK :: sqli in q"), "e3": ("warn", "x :: page name")}
    r = inspect(CORPUS, SENT, nginx, eve, decisions)

    assert (r["replayed"], r["nginx_logged"], r["alerted"]) == (3, 3, 1)
    assert [m["eid"] for m in r["mismatches"]] == ["e2"]          # client IP per direction is right
    assert r["status"] == {200: 2, 404: 1}
    assert [(x["kind"], x["eid"], x["reason"]) for x in r["errors"]] == [("FP", "e3", "page name")]
