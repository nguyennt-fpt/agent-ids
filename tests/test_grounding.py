"""The model's stated evidence is checked against the event: a reason that cites
an IDS alert which never fired is marked unverified (stored, shown on the
dashboard), and such a block always goes to the human gate."""

import sqlite3

import actions
from gate import check_grounding, needs_human
from tools import notifier

WEB = {"source": "web", "url": "/vulnerabilities/fi/?page=file1.php", "payload": ""}
IDS = {"source": "ids", "severity": 2, "url": "/?id=1%27%20OR%201=1", "payload": ""}


def test_web_event_reason_citing_the_ids_is_unverified():
    assert check_grounding(WEB, {"reason": "IDS severity 1, file inclusion"})
    assert check_grounding(WEB, {"analyst_note": "matches a Suricata rule"})
    assert check_grounding(WEB, {"reason": "page parameter names a local file"}) == ""


def test_ids_event_reason_must_quote_the_alerts_severity():
    assert check_grounding(IDS, {"reason": "IDS severity 2, SQLi"}) == ""
    assert "severity 1" in check_grounding(IDS, {"reason": "IDS severity 1"})
    assert check_grounding(IDS, {"reason": "Suricata flagged SQL injection"}) == ""


def test_encoding_claim_needs_an_encoded_request():
    assert check_grounding(WEB, {"analyst_note": "encoded payload in page"})
    assert check_grounding(IDS, {"reason": "URL-encoded quote in id"}) == ""


def test_unverified_block_needs_a_human_even_when_confident():
    assert not needs_human("block", 0.97)
    assert needs_human("block", 0.97, grounded=False)
    assert not needs_human("warn", 0.97, grounded=False)           # only blocks are gated


def test_grounding_is_stored_with_the_decision(tmp_path, monkeypatch):
    db = tmp_path / "events.db"
    monkeypatch.setattr(notifier, "DB_PATH", str(db))
    monkeypatch.setattr(notifier, "_db_ready", False)
    monkeypatch.setattr(actions, "BLOCK_ENABLED", False)
    why = "cites IDS evidence, but no IDS alert fired"
    for eid, unverified in (("e1", why), ("e2", ""), ("e3", None)):
        actions.record_decision(eid=eid, src_ip="198.51.100.9", attack="lfi", action="warn",
                                confidence=0.85, reason="r", mode="agent", unverified=unverified)
    conn = sqlite3.connect(db)
    assert dict(conn.execute("SELECT eid, grounded FROM events")) == {"e1": "0", "e2": "1", "e3": None}
    (detail,) = conn.execute("SELECT detail FROM events WHERE eid='e1'").fetchone()
    assert detail.endswith(f"[unverified: {why}]")


def test_older_db_gains_the_grounded_column(tmp_path, monkeypatch):
    db = tmp_path / "events.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
                 "src_ip TEXT, attack TEXT, action TEXT, detail TEXT)")
    conn.commit()
    monkeypatch.setattr(notifier, "DB_PATH", str(db))
    monkeypatch.setattr(notifier, "_db_ready", False)
    notifier.send_alert("m", eid="e1", action="log", grounded="1")
    assert sqlite3.connect(db).execute("SELECT grounded FROM events").fetchone() == ("1",)
