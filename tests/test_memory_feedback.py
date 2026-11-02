"""Experience memory: feedback judges only the latest decision on a request, so
an earlier mistake's lesson survives the agent getting it right later."""

import pytest

from tools import memory


@pytest.fixture
def mem(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "DB_PATH", str(tmp_path / "events.db"))
    monkeypatch.setattr(memory, "_ready", False)
    monkeypatch.setattr(memory, "_embed", lambda text: None)       # token-overlap similarity
    return memory


def test_lesson_of_a_mistake_survives_a_later_correct_decision(mem):
    mem.add_experience("e1", "", "page=file1.php", "lfi", "block", epoch=1)
    assert mem.record_feedback("e1", "benign", "block", "lfi", "page=file1.php") is False
    mem.add_experience("e1", "", "page=file1.php", "none", "log", epoch=2)
    assert mem.record_feedback("e1", "benign", "log", "none", "page=file1.php") is True

    (case,) = mem.retrieve_similar("page=file1.php", k=3)           # one case per eid
    assert case["was_correct"] is False and "FALSE POSITIVE" in case["lesson"]


def test_retrieval_returns_distinct_requests(mem):
    for eid, payload in (("a", "name=Alice"), ("b", "name=Bob")):
        for epoch in (1, 2):
            mem.add_experience(eid, "", payload, "none", "log", epoch=epoch)
            mem.record_feedback(eid, "benign", "log", "none", payload)
    assert len(mem.retrieve_similar("name=Alice", k=3)) == 2
