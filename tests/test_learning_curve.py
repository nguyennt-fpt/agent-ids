"""G1 — the learning curve never feeds back answers from the split it scores."""

import csv
import json
import types

import pytest

import learning_curve as lc

SENT = {"dev": {"d1": {"label": "malicious"}, "d2": {"label": "benign"}},
        "test": {"t1": {"label": "malicious"}, "t2": {"label": "benign"}}}


@pytest.fixture
def offline(monkeypatch, tmp_path):
    """Stub out docker / replay; record the order of replays and feedback."""
    calls = []
    monkeypatch.setattr(lc, "sh", lambda *a, **k: None)
    monkeypatch.setattr(lc, "time", types.SimpleNamespace(sleep=lambda s: None))
    monkeypatch.setattr(lc, "reset_events_only", lambda: None)
    monkeypatch.setattr(lc, "clear_experience", lambda: None)
    monkeypatch.setattr(lc, "load_corpus_index", lambda: {})
    monkeypatch.setattr(lc, "replay", lambda split, target, delay: calls.append(("replay", split))
                        or SENT[split])
    monkeypatch.setattr(lc, "fetch_decisions", lambda db, mode: {
        "t1": {"pred_malicious": True}, "d1": {"pred_malicious": False}})
    monkeypatch.setattr(lc, "record_feedback", lambda eid, *a: calls.append(("feedback", eid)))
    monkeypatch.setattr(lc, "REPORT", str(tmp_path))
    return calls


def test_eval_first_then_feedback_from_the_other_split_only(offline):
    out = lc.run(2, "on", "http://x", 0)
    epoch = [("replay", "test"), ("replay", "dev"), ("feedback", "d1"), ("feedback", "d2")]
    assert offline == epoch * 2
    with open(out, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert (rows[0]["recall"], rows[0]["fpr"]) == ("1.0", "0.0")             # scored on test
    assert (rows[0]["train_recall"], rows[0]["train_fpr"]) == ("0.0", "0.0")  # dev: d1 missed


def test_memory_off_replays_the_same_traffic_without_feedback(offline):
    lc.run(1, "off", "http://x", 0)
    assert offline == [("replay", "test"), ("replay", "dev")]


def test_same_split_for_feedback_and_eval_is_refused(offline):
    with pytest.raises(ValueError):
        lc.run(1, "on", "http://x", 0, feedback_split="dev", eval_split="dev")


def test_lesson_payload_includes_post_bodies(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(json.dumps({"eid": "c1", "attack_type": "cmdi", "params": {},
                                  "body": {"ip": "VALUE", "Submit": "Submit"}}) + "\n")
    monkeypatch.setattr(lc, "CORPUS", str(corpus))
    assert "VALUE" in lc.load_corpus_index()["c1"]["payload"]
