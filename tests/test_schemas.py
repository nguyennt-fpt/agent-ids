"""B1 — unknown action fails closed per item; B2 — salvage valid items from
truncated / partly-invalid model output; B3 — rule-based verdict helper."""

import json

import pytest

from actions import rule_flags
from schemas import Decision, DecisionList, salvage_decisions


def _item(eid, action="block", **kw):
    return {"eid": eid, "action": action, "attack_type": "sqli", "confidence": 0.9, **kw}


@pytest.mark.parametrize("raw,want", [
    ("block", "block"), ("BLOCK", "block"), (" log ", "log"),
    ("alert", "warn"), ("allow", "warn"), ("", "warn"),
])
def test_action_outside_enum_becomes_warn(raw, want):
    assert Decision(eid="e1", action=raw).action.value == want


@pytest.mark.parametrize("schema", [Decision.model_json_schema(),
                                    DecisionList.model_json_schema()["$defs"]["Decision"]])
def test_model_writes_reason_before_action(schema):
    # Ollama's grammar emits required fields first, in property order
    assert list(schema["properties"])[:3] == ["eid", "reason", "action"]
    assert schema["required"] == ["eid", "reason", "action"]
    assert Decision(eid="e1", action="log").reason == ""     # code may still omit it


def test_whole_valid_output_parses():
    text = json.dumps({"decisions": [_item("e1"), _item("e2", "log")]})
    assert [d.eid for d in salvage_decisions(text)] == ["e1", "e2"]


def test_truncated_output_keeps_every_complete_item():
    full = json.dumps({"decisions": [_item("e1"), _item("e2", "log"), _item("e3")]})
    cut = full[: full.index('"e3"') + 10]            # num_predict hit inside item 3
    assert [d.eid for d in salvage_decisions(cut)] == ["e1", "e2"]


def test_one_invalid_item_drops_only_itself():
    items = [_item("e1"), {"action": "block"}, _item("e3", confidence="high")]
    got = salvage_decisions(json.dumps({"decisions": items}))
    assert [d.eid for d in got] == ["e1", "e3"]        # missing eid -> dropped
    assert got[1].confidence == 0.0                    # bad confidence clamped, kept


def test_fenced_output_is_salvaged():
    text = "```json\n" + json.dumps({"decisions": [_item("e1")]}) + "\n```"
    assert [d.eid for d in salvage_decisions(text)] == ["e1"]


@pytest.mark.parametrize("text", ["", "not json", "{\"decisions\": ", "[1, 2]"])
def test_garbage_yields_nothing(text):
    assert salvage_decisions(text) == []


@pytest.mark.parametrize("sev,want", [(1, True), (2, True), ("2", True), (3, False),
                                      ("", False), (None, False)])
def test_rule_flags(sev, want):
    assert rule_flags(sev) is want
