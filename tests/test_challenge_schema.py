"""Format and safety regression tests using plain local JSON."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from site_audit.challenges import ChallengeError, _read_json, validate_collection, validate_pack_file


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "lab_challenges" / "challenge_collection.schema.json"
PACK_PATH = ROOT / "lab_challenges" / "challenges.v1.json"


def inputs() -> tuple[dict, dict]:
    return json.loads(PACK_PATH.read_text(encoding="utf-8")), json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_original_challenge_collection_is_valid():
    assert validate_pack_file(PACK_PATH, SCHEMA_PATH) == []


def test_schema_is_valid_json_schema_when_optional_checker_available():
    # The runtime validator itself has no external dependencies.
    try:
        import jsonschema
    except ImportError:
        return
    collection, schema = inputs()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(collection, schema)


def test_default_on_is_mandatory_and_disable_contract_is_exact():
    collection, schema = inputs()
    collection["feature_control"]["enabled_by_default"] = False
    assert any("enabled_by_default" in issue for issue in validate_collection(collection, schema))
    collection["feature_control"]["enabled_by_default"] = True
    collection["feature_control"]["disable_env"] = "OTHER"
    assert any("disable_env" in issue for issue in validate_collection(collection, schema))


def test_duplicate_challenge_ids_are_rejected():
    collection, schema = inputs()
    collection["challenges"][1]["id"] = collection["challenges"][0]["id"]
    assert any("duplicate challenge" in issue for issue in validate_collection(collection, schema))


def test_duplicate_answers_and_stale_answer_reference_are_rejected():
    collection, schema = inputs()
    assessment = collection["challenges"][0]["assessment"]
    assessment["choices"][1]["id"] = "a"
    assessment["correct_choice_id"] = "d"
    issues = validate_collection(collection, schema)
    assert any("duplicate choice" in issue for issue in issues)
    assert any("no matching choice" in issue for issue in issues)


def test_unapproved_remote_address_is_rejected():
    collection, schema = inputs()
    collection["challenges"][0]["scenario"]["context"] += " See https://example.invalid"
    assert any("remote address" in issue for issue in validate_collection(collection, schema))


def test_active_markup_is_rejected():
    collection, schema = inputs()
    collection["challenges"][0]["assessment"]["rationale"] = "Use a safe response <b>bold</b> as ordinary text."
    assert any("active markup" in issue for issue in validate_collection(collection, schema))


def test_unexpected_fields_and_missing_safety_requirements_are_rejected():
    collection, schema = inputs()
    collection["challenges"][0]["new_network_field"] = "not permitted"
    collection["challenges"][0]["safety"]["offline_only"] = False
    issues = validate_collection(collection, schema)
    assert any("unknown field" in issue for issue in issues)
    assert any("offline_only" in issue for issue in issues)


def test_boolean_is_not_accepted_for_integer_minutes():
    collection, schema = inputs()
    collection["challenges"][0]["estimated_minutes"] = True
    assert any("expected integer" in issue for issue in validate_collection(collection, schema))


def test_duplicate_json_keys_raise_instead_of_last_value_wins(tmp_path):
    file = tmp_path / "duplicate.json"
    file.write_text('{"a": 1, "a": 2}', encoding="utf-8")
    try:
        _read_json(file)
    except ChallengeError as exc:
        assert "duplicate JSON object key" in str(exc)
    else:
        raise AssertionError("duplicate keys were accepted")


def test_schema_has_no_remote_references():
    _, schema = inputs()
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref":
                    assert item.startswith("#/")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(schema)


def test_collection_is_deterministic_without_randomized_inputs():
    collection, schema = inputs()
    assert validate_collection(copy.deepcopy(collection), schema) == validate_collection(collection, schema)


def test_duplicate_artifact_ids_are_rejected():
    collection, schema = inputs()
    artifact = copy.deepcopy(collection["challenges"][0]["scenario"]["artifacts"][0])
    collection["challenges"][0]["scenario"]["artifacts"].append(artifact)
    assert any("duplicate artifact" in issue for issue in validate_collection(collection, schema))
