"""G5 — answering escalated blocks from the dashboard. The pending rows are
written by the agent's own approvals module, so the shared schema is tested too."""

import importlib.util
import os

import pytest

pytest.importorskip("flask")

import approvals  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "dashboard_app", os.path.join(os.path.dirname(__file__), "..", "dashboard", "app.py"))
dash = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dash)

TOKEN = "s3cret-token"


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = str(tmp_path / "events.db")
    monkeypatch.setattr(approvals, "DB_PATH", db)
    monkeypatch.setattr(dash, "DB_PATH", db)
    monkeypatch.setattr(dash, "APPROVAL_TOKEN", TOKEN)
    return dash.app.test_client()


def _post(client, eid, answer, token=TOKEN):
    headers = {"X-Approval-Token": token} if token is not None else {}
    return client.post(f"/api/approvals/{eid}", json={"answer": answer}, headers=headers)


def test_lists_pending_and_an_answer_reaches_the_agent(client):
    approvals.add_pending("t1", [{"eid": "e1", "src_ip": "198.51.100.7", "attack_type": "sqli",
                                  "confidence": 0.8, "analyst_note": "<b>n</b>"}])
    d = client.get("/api/approvals").get_json()
    assert d["enabled"] and [p["eid"] for p in d["pending"]] == ["e1"]
    assert d["pending"][0]["note"] == "<b>n</b>"          # raw in JSON; the page escapes it

    r = _post(client, "e1", "benign")
    assert r.status_code == 200
    assert approvals.ready_threads() == {"t1": {"e1": "benign"}}   # what the agent resumes with
    assert client.get("/api/approvals").get_json()["pending"] == []


@pytest.mark.parametrize("token", [None, "", "wrong", "s3cret-token-but-longer"])
def test_write_needs_the_exact_token(client, token):
    approvals.add_pending("t1", [{"eid": "e1"}])
    assert _post(client, "e1", "approve", token=token).status_code == 403
    assert approvals.ready_threads() == {}


def test_no_token_configured_means_no_writes(client, monkeypatch):
    monkeypatch.setattr(dash, "APPROVAL_TOKEN", "")
    approvals.add_pending("t1", [{"eid": "e1"}])
    assert client.get("/api/approvals").get_json()["enabled"] is False
    assert _post(client, "e1", "approve", token="").status_code == 403


def test_bad_answer_and_unknown_eid(client):
    approvals.add_pending("t1", [{"eid": "e1"}])
    assert _post(client, "e1", "block").status_code == 400          # not approve/warn/benign
    assert _post(client, "nope", "approve").status_code == 404
    assert _post(client, "e1", "warn").status_code == 200
    assert _post(client, "e1", "approve").status_code == 404        # already answered


def test_fresh_db_without_the_table(client):
    assert client.get("/api/approvals").get_json()["pending"] == []
    assert _post(client, "e1", "approve").status_code == 404
