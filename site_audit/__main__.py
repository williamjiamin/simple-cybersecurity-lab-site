"""Command-line entrypoint. Print deterministic PASS/FAIL rows and ALL verdict."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import audit_enabled, audit_site, bypassed_report, labs_enabled


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only static-site security and accessibility audit")
    parser.add_argument("--site-root", type=Path, default=Path("."), help="publishing directory")
    parser.add_argument("--headers-file", type=Path, default=None, help="observed response-header evidence JSON")
    parser.add_argument("--challenge-pack", type=Path, default=None, help="local challenge pack")
    parser.add_argument("--schema", type=Path, default=None, help="local challenge JSON schema")
    parser.add_argument("--json-out", type=Path, default=None, help="write deterministic JSON report")
    parser.add_argument("--require-verified-headers", action="store_true", help="exit with failure for unverified responses")
    args = parser.parse_args()

    if audit_enabled():
        report = audit_site(args.site_root, args.headers_file, args.challenge_pack, args.schema,
                            check_challenges=labs_enabled())
    else:
        report = bypassed_report()

    for item in report["findings"]:
        print(f"{item['status']} {item['code']} {item['path']}: {item['detail']}")
    print(f"ALL={'true' if report['summary']['all'] else 'false'}")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    if report["mode"] == "disabled_legacy_unchanged":
        return 0
    if report["summary"]["fail"] > 0:
        return 1
    if args.require_verified_headers and report["summary"]["unverified"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
