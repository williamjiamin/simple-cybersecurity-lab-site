"""Deterministic, dependency-free validation of the local defensive lab format.

The published JSON Schema is the format authority. This interpreter supports all
schema keywords used by that document, then checks cross-field invariants.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class ChallengeError(ValueError):
    """The challenge source does not satisfy the approved offline format."""


MAX_DOCUMENT_BYTES = 1024 * 1024
UNSAFE_TEXT = re.compile(
    r"(?:https?://|\bwww\.|<\s*/?\s*[a-z]|javascript\s*:|data\s*:\s*text/html|\x00)",
    flags=re.IGNORECASE,
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ChallengeError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ChallengeError(f"document exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ChallengeError(f"unable to parse JSON at {path.name}: {exc}") from exc


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ChallengeError(f"unsupported type in schema: {expected}")


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ChallengeError("external schema references are not allowed")
    cursor: Any = root
    for token in ref[2:].split("/"):
        part = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(cursor, dict) or part not in cursor:
            raise ChallengeError(f"unknown local schema reference: {ref}")
        cursor = cursor[part]
    if not isinstance(cursor, dict):
        raise ChallengeError(f"schema reference does not lead to a definition: {ref}")
    return cursor


def _validate_node(value: Any, node: dict[str, Any], root: dict[str, Any], pointer: str, problems: list[str]) -> None:
    if "$ref" in node:
        _validate_node(value, _resolve_ref(root, node["$ref"]), root, pointer, problems)
        return

    expected = node.get("type")
    if expected is not None and not _matches_type(value, expected):
        problems.append(f"{pointer}: expected {expected}")
        return

    if "const" in node and (type(value) is not type(node["const"]) or value != node["const"]):
        problems.append(f"{pointer}: value does not match constant")
    if "enum" in node and value not in node["enum"]:
        problems.append(f"{pointer}: value outside permitted enumeration")

    if isinstance(value, dict):
        props = node.get("properties", {})
        for field in node.get("required", []):
            if field not in value:
                problems.append(f"{pointer}/{field}: required field missing")
        if node.get("additionalProperties") is False:
            for field in sorted(set(value) - set(props)):
                problems.append(f"{pointer}/{field}: unknown field")
        for field in sorted(set(value) & set(props)):
            _validate_node(value[field], props[field], root, f"{pointer}/{field}", problems)

    elif isinstance(value, list):
        if len(value) < node.get("minItems", 0):
            problems.append(f"{pointer}: too few array elements")
        if "maxItems" in node and len(value) > node["maxItems"]:
            problems.append(f"{pointer}: too many array elements")
        if node.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            problems.append(f"{pointer}: array values must be unique")
        if "items" in node:
            for index, item in enumerate(value):
                _validate_node(item, node["items"], root, f"{pointer}/{index}", problems)

    elif isinstance(value, str):
        if len(value) < node.get("minLength", 0):
            problems.append(f"{pointer}: string too short")
        if "maxLength" in node and len(value) > node["maxLength"]:
            problems.append(f"{pointer}: string too long")
        if "pattern" in node and re.search(node["pattern"], value) is None:
            problems.append(f"{pointer}: invalid identifier format")

    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in node and value < node["minimum"]:
            problems.append(f"{pointer}: below minimum")
        if "maximum" in node and value > node["maximum"]:
            problems.append(f"{pointer}: above maximum")


def validate_collection(collection: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Return sorted, stable issue strings; never execute or fetch challenge content."""
    problems: list[str] = []
    _validate_node(collection, schema, schema, "$", problems)

    challenges = collection.get("challenges") if isinstance(collection, dict) else None
    if not isinstance(challenges, list):
        return sorted(set(problems))

    seen_challenges: set[str] = set()
    for index, challenge in enumerate(challenges):
        prefix = f"$/challenges/{index}"
        if not isinstance(challenge, dict):
            continue
        challenge_id = challenge.get("id")
        if isinstance(challenge_id, str):
            if challenge_id in seen_challenges:
                problems.append(f"{prefix}/id: duplicate challenge identifier")
            seen_challenges.add(challenge_id)

        assessment = challenge.get("assessment")
        if isinstance(assessment, dict):
            choices = assessment.get("choices")
            if isinstance(choices, list):
                choice_ids = [item.get("id") for item in choices if isinstance(item, dict)]
                if len(choice_ids) != len(set(choice_ids)):
                    problems.append(f"{prefix}/assessment/choices: duplicate choice identifier")
                if assessment.get("correct_choice_id") not in choice_ids:
                    problems.append(f"{prefix}/assessment/correct_choice_id: no matching choice")

        scenario = challenge.get("scenario")
        if isinstance(scenario, dict):
            artifacts = scenario.get("artifacts")
            if isinstance(artifacts, list):
                ids = [item.get("id") for item in artifacts if isinstance(item, dict)]
                if len(ids) != len(set(ids)):
                    problems.append(f"{prefix}/scenario/artifacts: duplicate artifact identifier")

        def scan_text(node: Any, path: str) -> None:
            if isinstance(node, str) and UNSAFE_TEXT.search(node):
                problems.append(f"{path}: remote address, active markup, or prohibited scheme in text")
            elif isinstance(node, list):
                for i, val in enumerate(node):
                    scan_text(val, f"{path}/{i}")
            elif isinstance(node, dict):
                for key in sorted(node):
                    scan_text(node[key], f"{path}/{key}")

        scan_text(challenge, prefix)

    return sorted(set(problems))


def validate_pack_file(pack_path: Path, schema_path: Path) -> list[str]:
    try:
        schema = _read_json(schema_path)
        collection = _read_json(pack_path)
        if not isinstance(schema, dict) or not isinstance(collection, dict):
            return ["root must be a JSON object"]
        return validate_collection(collection, schema)
    except (ChallengeError, OSError) as exc:
        return [str(exc)]
