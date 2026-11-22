"""Fixture-driven accessibility, security-policy, header, and CLI tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from site_audit.audit import audit_enabled, audit_site, bypassed_report, labs_enabled


ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "tests" / "fixtures" / "pass_site"
BAD = ROOT / "tests" / "fixtures" / "fail_site"
HEADERS = ROOT / "tests" / "fixtures" / "headers.observed.synthetic.json"
PACK = ROOT / "lab_challenges" / "challenges.v1.json"
SCHEMA = ROOT / "lab_challenges" / "challenge_collection.schema.json"


def run(root, headers=None):
    return audit_site(root, headers, PACK, SCHEMA)


def failures(report):
    return [item for item in report["findings"] if item["status"] == "FAIL"]


def test_valid_fixture_with_synthetic_header_records_passes():
    report = run(GOOD, HEADERS)
    assert report["summary"]["all"] is True, failures(report)
    assert report["summary"]["fail"] == 0
    assert report["summary"]["unverified"] == 0


def test_missing_header_capture_is_explicitly_unverified():
    report = run(GOOD)
    assert report["summary"]["fail"] == 0
    assert report["summary"]["unverified"] == 18
    assert report["summary"]["all"] is False
    assert report["summary"]["locally_clear"] is True


def test_local_html_issues_are_reported():
    report = run(BAD)
    codes = {entry["code"] for entry in failures(report)}
    assert {"HTML_LANGUAGE", "HTML_CHARSET", "HTML_VIEWPORT", "A11Y_MAIN", "A11Y_IMAGE_ALT", "LINK_LOCAL_TARGETS", "META_CSP_MISSING"} <= codes


def test_csp_injection_is_detected_in_a_local_copy(tmp_path):
    shutil.copytree(GOOD, tmp_path / "site")
    page = tmp_path / "site" / "index.html"
    text = page.read_text(encoding="utf-8")
    text = text.replace("script-src 'none'", "script-src 'unsafe-inline'")
    page.write_text(text, encoding="utf-8")
    codes = {item["code"] for item in failures(run(page.parent, HEADERS))}
    assert "META_CSP_POLICY" in codes


def test_header_policy_errors_are_detected_without_network_calls(tmp_path):
    record = json.loads(HEADERS.read_text(encoding="utf-8"))
    record["responses"][0]["headers"]["Strict-Transport-Security"] = "max-age=3"
    record["responses"][0]["headers"]["Permissions-Policy"] = "camera=(self)"
    record["responses"][0]["headers"]["Content-Security-Policy"] += "; script-src 'unsafe-inline'"
    snapshot = tmp_path / "bad.json"
    snapshot.write_text(json.dumps(record), encoding="utf-8")
    codes = {entry["code"] for entry in failures(run(GOOD, snapshot))}
    assert {"HTTP_HSTS", "HTTP_PERMISSIONS_POLICY", "HTTP_CSP_POLICY"} <= codes


def test_snapshot_rejects_desired_policy_as_evidence():
    report = run(GOOD, ROOT / "security" / "headers.expected.json")
    assert "HEADER_SNAPSHOT_INPUT" in {entry["code"] for entry in failures(report)}
    assert report["summary"]["unverified"] == 18


def test_missing_header_page_is_unverified_not_passed(tmp_path):
    record = json.loads(HEADERS.read_text(encoding="utf-8"))
    record["responses"] = record["responses"][:2]
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    report = run(GOOD, path)
    assert report["summary"]["unverified"] == 6
    assert report["summary"]["all"] is False


def test_local_link_fragment_validation(tmp_path):
    shutil.copytree(GOOD, tmp_path / "site")
    page = tmp_path / "site" / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace('href="#main"', 'href="#unknown"'), encoding="utf-8")
    assert "LINK_LOCAL_TARGETS" in {item["code"] for item in failures(run(page.parent, HEADERS))}


def test_new_window_links_must_have_safe_rel(tmp_path):
    shutil.copytree(GOOD, tmp_path / "site")
    page = tmp_path / "site" / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace('href="support.html"', 'href="support.html" target="_blank"'), encoding="utf-8")
    assert "LINK_NEW_WINDOW" in {item["code"] for item in failures(run(page.parent, HEADERS))}


def test_kill_switch_defaults_on_and_explicit_off_bypasses():
    assert audit_enabled({})
    assert labs_enabled({})
    assert not audit_enabled({"SCL_SITE_AUDIT_ENABLED": "0"})
    assert not labs_enabled({"SCL_LABS_ENABLED": "0"})
    assert bypassed_report()["summary"]["all"] is False
    assert bypassed_report()["mode"] == "disabled_legacy_unchanged"


def test_report_is_bitwise_deterministic():
    first = json.dumps(run(GOOD, HEADERS), sort_keys=True)
    second = json.dumps(run(GOOD, HEADERS), sort_keys=True)
    assert first == second


def test_cli_outputs_pass_fail_rows_and_all_flag(tmp_path):
    output = tmp_path / "report.json"
    cmd = [sys.executable, "-m", "site_audit", "--site-root", str(GOOD), "--headers-file", str(HEADERS),
           "--challenge-pack", str(PACK), "--schema", str(SCHEMA), "--json-out", str(output)]
    completed = subprocess.run(cmd, cwd=ROOT, check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS HTTP_CSP_POLICY" in completed.stdout
    assert "ALL=true" in completed.stdout
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["all"]


def test_cli_disable_preserves_success_without_lying_about_verification():
    cmd = [sys.executable, "-m", "site_audit", "--site-root", str(BAD)]
    env = {**os.environ, "SCL_SITE_AUDIT_ENABLED": "0"}
    completed = subprocess.run(cmd, cwd=ROOT, check=False, capture_output=True, text=True, env=env)
    assert completed.returncode == 0
    assert "SKIP AUDIT_DISABLED" in completed.stdout
    assert "ALL=false" in completed.stdout


def test_cli_strict_headers_needs_real_snapshot():
    cmd = [sys.executable, "-m", "site_audit", "--site-root", str(GOOD),
           "--challenge-pack", str(PACK), "--schema", str(SCHEMA), "--require-verified-headers"]
    completed = subprocess.run(cmd, cwd=ROOT, check=False, capture_output=True, text=True)
    assert completed.returncode == 1
    assert "UNVERIFIED HTTP_CONTENT_SECURITY_POLICY" in completed.stdout


def test_malformed_url_is_reported_instead_of_crashing(tmp_path):
    shutil.copytree(GOOD, tmp_path / "site")
    page = tmp_path / "site" / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace('href="support.html"', 'href="https://[invalid"'), encoding="utf-8")
    assert "LINK_LOCAL_TARGETS" in {item["code"] for item in failures(run(page.parent, HEADERS))}


def test_inline_scripts_and_styles_are_rejected(tmp_path):
    shutil.copytree(GOOD, tmp_path / "site")
    page = tmp_path / "site" / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace('<main id="main">', '<main id="main" style="color: blue"><script></script>'), encoding="utf-8")
    codes = {item["code"] for item in failures(run(page.parent, HEADERS))}
    assert {"CSP_INLINE_STYLES", "CSP_SCRIPT_FREE"} <= codes


def test_audit_is_read_only_with_and_without_kill_switch():
    from hashlib import sha256
    pages = sorted(GOOD.glob("*"))
    original = [sha256(page.read_bytes()).hexdigest() for page in pages]
    run(GOOD, HEADERS)
    bypassed_report()
    assert original == [sha256(page.read_bytes()).hexdigest() for page in pages]
