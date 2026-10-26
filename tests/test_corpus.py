"""Corpus v2 framework (docs/CORPUS_V2.md): deterministic build, family-level
dev/test split, actors, POST forms; replay request construction."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmark", "attack_corpus"))

import build_corpus  # noqa: E402
from replay import build_request, make_client, select_rows  # noqa: E402


@pytest.fixture(scope="module")
def rows():
    return build_corpus.build()


def test_build_is_deterministic(rows):
    again = build_corpus.build()
    assert [(r["eid"], r["split"], r["actor_ip"], r["seq"]) for r in rows] == \
           [(r["eid"], r["split"], r["actor_ip"], r["seq"]) for r in again]


def test_eids_unique_and_seq_is_a_permutation(rows):
    assert len({r["eid"] for r in rows}) == len(rows)
    assert sorted(r["seq"] for r in rows) == list(range(len(rows)))


def test_no_family_on_both_sides_of_the_split(rows):
    sides: dict[str, set] = {}
    for r in rows:
        sides.setdefault(r["family"], set()).add(r["split"])
    assert all(len(s) == 1 for s in sides.values())


def test_both_splits_hold_every_label(rows):
    got = {(r["split"], r["label"]) for r in rows}
    assert got == {("dev", "malicious"), ("dev", "benign"),
                   ("test", "malicious"), ("test", "benign")}


def test_paths_are_dvwa_root_paths(rows):
    assert not any(r["path"].startswith("/dvwa") for r in rows)


def test_exec_page_is_always_a_post_form(rows):
    execs = [r for r in rows if r["path"] == "/vulnerabilities/exec/"]
    assert execs and all(r["method"] == "POST" and r["body"].get("Submit") for r in execs)
    assert any(r["label"] == "benign" for r in execs)       # method can't leak the label


def test_actors(rows):
    for r in rows:
        if r["label"] == "malicious" or r["group"] == "benign_normal":
            continue
        assert r["actor_ip"] in build_corpus.USERS            # fp_bait comes from users
    assert all(r["actor_ip"] in build_corpus.ATTACKERS
               for r in rows if r["label"] == "malicious")


def test_recon_chains_are_present_ordered_and_malicious(rows):
    recon = [r for r in rows if r["group"] == "recon"]
    assert recon and all(r["label"] == "malicious" for r in recon)
    data = json.load(open(os.path.join(os.path.dirname(__file__), "..", "benchmark",
                                        "attack_corpus", "payloads_benign_recon.json"),
                          encoding="utf-8"))["recon"]
    dirscan = sorted((r for r in recon if r["family"] == "recon:dirscan"), key=lambda r: r["seq"])
    assert [r["path"] for r in dirscan] == data["dirscan_paths"]        # chain order kept
    assert all(r["method"] == "GET" and r["attack_type"] == "scan" for r in dirscan)
    brute = sorted((r for r in recon if r["family"] == "recon:bruteforce"), key=lambda r: r["seq"])
    assert [r["body"]["password"] for r in brute] == data["bruteforce"]["passwords"]
    assert all(r["method"] == "POST" and r["path"] == "/login.php" for r in brute)
    assert len({r["actor_ip"] for r in brute}) == 1                    # one scanner per chain


def test_declared_families_group_variants(rows):
    members: dict[str, int] = {}
    for r in rows:
        members[r["family"]] = members.get(r["family"], 0) + 1
    assert any(n > 1 for f, n in members.items() if ":" in f)           # `=== family ===` took effect


def test_build_request_sets_xff_body_and_eid():
    row = {"eid": "abc", "method": "POST", "path": "/vulnerabilities/exec/",
           "params": {}, "body": {"ip": "8.8.8.8", "Submit": "Submit"},
           "actor_ip": "198.51.100.10", "user_agent": "UA"}
    method, url, kw = build_request(row, "http://h/")
    assert (method, url) == ("POST", "http://h/vulnerabilities/exec/")
    assert kw["params"] == {"eid": "abc"}
    assert kw["headers"]["X-Forwarded-For"] == "198.51.100.10"
    assert kw["data"] == {"ip": "8.8.8.8", "Submit": "Submit"}


def test_v1_row_replays_without_xff_or_body():
    method, _, kw = build_request({"eid": "e", "path": "/x", "params": {"a": "1"}}, "http://h")
    assert method == "GET" and "X-Forwarded-For" not in kw["headers"] and "data" not in kw


def test_replay_opens_one_connection_per_request():
    ports = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"                     # would keep the connection open

        def do_GET(self):
            ports.append(self.client_address[1])
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with make_client() as client:
            for _ in range(3):
                client.get(f"http://127.0.0.1:{srv.server_port}/")
    finally:
        srv.shutdown()
    assert len(set(ports)) == 3                           # no actor shares a socket


def test_select_rows_filters_split_and_orders_by_seq():
    rows = [{"eid": "b", "split": "dev", "seq": 2}, {"eid": "a", "split": "test", "seq": 0},
            {"eid": "c", "split": "dev", "seq": 1}]
    assert [r["eid"] for r in select_rows(rows, "dev")] == ["c", "b"]
    assert [r["eid"] for r in select_rows(rows, None)] == ["a", "c", "b"]
