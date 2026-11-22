"""Offline static-site accessibility, link, content-policy, and header checks.

All checks are read-only. Network requests are intentionally unsupported.
Passing this checker is not an accessibility certification or a live scan.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .challenges import validate_pack_file


VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})
HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
CSP_UNSAFE = frozenset({"'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'", "*", "http:", "https:"})
REQUIRED_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy", "frame-protection",
)


@dataclass(frozen=True)
class Finding:
    code: str
    status: str
    severity: str
    path: str
    detail: str


class Document(HTMLParser):
    """Small lexical scanner; it deliberately does not render styles or run scripts."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_attrs: dict[str, str] | None = None
        self.doctype = False
        self.stack: list[dict[str, Any]] = []
        self.elements: list[dict[str, Any]] = []
        self.ids: list[str] = []
        self.main_count = 0
        self.meta_csp: list[str] = []
        self.meta_charset = False
        self.meta_viewport = False
        self.inline_handlers: list[str] = []
        self.inline_style_attrs: list[str] = []
        self.style_tag_count = 0
        self.script_tag_count = 0
        self.links: list[dict[str, Any]] = []
        self.headings: list[tuple[int, str]] = []
        self.titles: list[str] = []
        self.labels_for: set[str] = set()
        self.controls: list[dict[str, Any]] = []
        self.images: list[dict[str, Any]] = []
        self.assets: list[tuple[str, str]] = []
        self.duplicate_attrs: list[str] = []

    def handle_decl(self, decl: str) -> None:
        if decl.lower().startswith("doctype html"):
            self.doctype = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, closed=tag in VOID_TAGS)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, closed=True)

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], closed: bool) -> None:
        names = [name.lower() for name, _ in attrs]
        for name in sorted(set(names)):
            if names.count(name) > 1:
                self.duplicate_attrs.append(f"{tag}[{name}]")
        attributes = {name.lower(): value or "" for name, value in attrs}
        frame: dict[str, Any] = {"tag": tag, "attrs": attributes, "text": [], "alt_text": []}
        self.elements.append(frame)
        if tag == "html" and self.html_attrs is None:
            self.html_attrs = attributes
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "main":
            self.main_count += 1
        if tag == "meta":
            if attributes.get("charset", "").lower() == "utf-8":
                self.meta_charset = True
            if attributes.get("name", "").lower() == "viewport" and "width=device-width" in attributes.get("content", "").lower().replace(" ", ""):
                self.meta_viewport = True
            if attributes.get("http-equiv", "").lower() == "content-security-policy":
                self.meta_csp.append(attributes.get("content", ""))
        if tag == "script":
            self.script_tag_count += 1
        if tag == "style":
            self.style_tag_count += 1
        if "style" in attributes:
            self.inline_style_attrs.append(tag)
        if tag == "label" and attributes.get("for"):
            self.labels_for.add(attributes["for"])
        if tag in {"input", "textarea", "select"} and not (tag == "input" and attributes.get("type", "").lower() == "hidden"):
            self.controls.append({"attrs": attributes, "tag": tag, "inside_label": any(ancestor["tag"] == "label" for ancestor in self.stack)})
        if tag == "img":
            self.images.append(attributes)
            if attributes.get("alt"):
                for parent in self.stack:
                    if parent["tag"] in {"a", "button"}:
                        parent["alt_text"].append(attributes["alt"])
            if attributes.get("src"):
                self.assets.append(("img", attributes["src"]))
        if tag == "link" and "stylesheet" in attributes.get("rel", "").lower().split() and attributes.get("href"):
            self.assets.append(("stylesheet", attributes["href"]))
        if tag == "script" and attributes.get("src"):
            self.assets.append(("script", attributes["src"]))
        if tag == "iframe" and not attributes.get("title") and not attributes.get("aria-label"):
            self.images.append({"iframe_missing_title": "1"})
        for name in names:
            if name.startswith("on") and len(name) > 2:
                self.inline_handlers.append(f"{tag}[{name}]")
        if not closed:
            self.stack.append(frame)
        else:
            self._finish(frame)

    def handle_data(self, data: str) -> None:
        for frame in self.stack:
            frame["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                for frame in reversed(self.stack[index:]):
                    self._finish(frame)
                del self.stack[index:]
                return

    def finish(self) -> None:
        for frame in reversed(self.stack):
            self._finish(frame)
        self.stack.clear()

    def _finish(self, frame: dict[str, Any]) -> None:
        tag, attrs = frame["tag"], frame["attrs"]
        readable = " ".join("".join(frame["text"]).split())
        if tag in HEADINGS:
            self.headings.append((int(tag[1]), readable))
        elif tag == "title":
            self.titles.append(readable)
        elif tag in {"a", "button"}:
            self.links.append({
                "tag": tag, "attrs": attrs,
                "name": readable or " ".join(frame["alt_text"]).strip(),
            })


def _finding(code: str, status: str, path: str, detail: str, severity: str = "error") -> Finding:
    return Finding(code, status, severity if status == "FAIL" else "info", path, detail)


def _check(ok: bool, code: str, path: str, failure: str, success: str = "verified") -> Finding:
    return _finding(code, "PASS" if ok else "FAIL", path, success if ok else failure)


def _local_ref(site_root: Path, page: Path, ref: str) -> tuple[str | None, str | None]:
    """Return resolved local reference and a local issue, or neither for remote links."""
    value = ref.strip()
    if value.startswith(("#", "?")):
        return page.resolve().as_posix(), None
    try:
        url = urlsplit(value)
    except ValueError:
        return None, "malformed URL"
    if url.scheme or url.netloc or value.startswith("//"):
        return None, None
    if value.startswith("/"):
        return None, None  # Base-path-relative references need a deployment-aware review.
    try:
        target = (page.parent / unquote(url.path)).resolve()
    except (OSError, RuntimeError):
        return None, "unresolvable local link"
    if not target.is_relative_to(site_root.resolve()):
        return None, "local reference leaves the publishing directory"
    if target.is_dir():
        target = target / "index.html"
    if not target.is_file():
        return None, "local destination does not exist"
    return target.as_posix(), None


def _scan_page(site_root: Path, page: Path) -> tuple[list[Finding], Document]:
    findings: list[Finding] = []
    rel = page.relative_to(site_root).as_posix()
    document = Document()
    try:
        document.feed(page.read_text(encoding="utf-8"))
        document.close()
        document.finish()
    except (OSError, UnicodeError, ValueError) as exc:
        return [_finding("HTML_READ", "FAIL", rel, f"cannot read document: {exc}")], document

    add = findings.append
    add(_check(document.doctype, "HTML_DOCTYPE", rel, "missing HTML5 doctype"))
    add(_check(bool(document.html_attrs and document.html_attrs.get("lang", "").strip()), "HTML_LANGUAGE", rel, "html language attribute missing"))
    add(_check(len(document.titles) == 1 and bool(document.titles[0]), "HTML_TITLE", rel, "require exactly one meaningful document title"))
    add(_check(document.meta_charset, "HTML_CHARSET", rel, "declare UTF-8 character encoding"))
    add(_check(document.meta_viewport, "HTML_VIEWPORT", rel, "missing responsive viewport declaration"))
    add(_check(document.main_count == 1, "A11Y_MAIN", rel, "require exactly one main landmark"))
    h1 = sum(level == 1 for level, _ in document.headings)
    add(_check(h1 == 1, "A11Y_H1", rel, "require exactly one level-one heading"))
    add(_check(all(text for _, text in document.headings), "A11Y_HEADING_NAMES", rel, "a heading has no readable text"))
    levels = [level for level, _ in document.headings]
    add(_check(not levels or (levels[0] == 1 and all(next_level <= current + 1 for current, next_level in zip(levels, levels[1:]))),
               "A11Y_HEADING_ORDER", rel, "first heading must be level one; do not skip heading levels"))
    add(_check(len(document.ids) == len(set(document.ids)) and all(document.ids), "A11Y_UNIQUE_IDS", rel, "missing or duplicate id attribute"))
    add(_check(not document.duplicate_attrs, "HTML_DUPLICATE_ATTRIBUTES", rel, "duplicated attributes: " + ", ".join(document.duplicate_attrs)))
    add(_check(not document.inline_handlers, "CSP_INLINE_HANDLERS", rel, "inline script event attributes are not permitted"))
    add(_check(not document.inline_style_attrs and document.style_tag_count == 0, "CSP_INLINE_STYLES", rel, "inline styles conflict with style-src self"))
    add(_check(document.script_tag_count == 0, "CSP_SCRIPT_FREE", rel, "site contract forbids active script elements"))

    bad_images = [f"image {i + 1}" for i, attrs in enumerate(document.images) if "alt" not in attrs and "iframe_missing_title" not in attrs]
    untitled_frames = [i for i, attrs in enumerate(document.images) if "iframe_missing_title" in attrs]
    add(_check(not bad_images, "A11Y_IMAGE_ALT", rel, "missing alt attributes: " + ", ".join(bad_images)))
    add(_check(not untitled_frames, "A11Y_FRAME_TITLE", rel, "embedded frame requires an accessible title"))

    bad_controls: list[str] = []
    for control in document.controls:
        attrs = control["attrs"]
        control_id = attrs.get("id", "")
        aria_labelledby = attrs.get("aria-labelledby", "").split()
        labeled = bool(
            control["inside_label"] or attrs.get("aria-label", "").strip() or
            (aria_labelledby and all(label in document.ids for label in aria_labelledby)) or
            (control_id and control_id in document.labels_for)
        )
        if control["tag"] == "input" and attrs.get("type", "").lower() in {"submit", "button", "reset"}:
            labeled = labeled or bool(attrs.get("value", "").strip())
        if not labeled:
            bad_controls.append(control_id or control["tag"])
    add(_check(not bad_controls, "A11Y_CONTROL_LABELS", rel, "unlabelled controls: " + ", ".join(bad_controls)))

    empty_actions = [entry["tag"] for entry in document.links if not (entry["name"] or entry["attrs"].get("aria-label", "").strip() or entry["attrs"].get("title", "").strip() or (entry["attrs"].get("aria-labelledby", "") in document.ids))]
    add(_check(not empty_actions, "A11Y_ACTION_NAMES", rel, "interactive elements lack accessible names"))

    broken_links: list[str] = []
    bad_targets: list[str] = []
    bad_schemes: list[str] = []
    for entry in document.links:
        if entry["tag"] != "a":
            continue
        attrs = entry["attrs"]
        href = attrs.get("href", "")
        if not href:
            broken_links.append("anchor without href")
            continue
        try:
            parsed = urlsplit(href)
        except ValueError:
            broken_links.append(f"{href[:80]} (malformed URL)")
            continue
        if parsed.scheme.lower() not in {"", "https", "mailto", "tel"} or href.lower().startswith("//"):
            bad_schemes.append(href[:80])
        if attrs.get("target", "").lower() == "_blank" and not {"noopener", "noreferrer"}.issubset(set(attrs.get("rel", "").lower().split())):
            bad_targets.append(href[:80])
        destination, issue = _local_ref(site_root, page, href)
        if issue:
            broken_links.append(f"{href[:80]} ({issue})")
        elif destination and parsed.fragment and destination.endswith(".html"):
            try:
                other = Document()
                other.feed(Path(destination).read_text(encoding="utf-8"))
                if unquote(parsed.fragment) not in other.ids:
                    broken_links.append(f"{href[:80]} (fragment target missing)")
            except (OSError, UnicodeError):
                broken_links.append(f"{href[:80]} (fragment target unreadable)")
    for element, url in document.assets:
        _, issue = _local_ref(site_root, page, url)
        if issue:
            broken_links.append(f"{element}: {url[:80]} ({issue})")
    add(_check(not bad_schemes, "LINK_ALLOWED_SCHEMES", rel, "disallowed or insecure URL schemes: " + ", ".join(bad_schemes)))
    add(_check(not bad_targets, "LINK_NEW_WINDOW", rel, "new window links require rel=noopener noreferrer"))
    add(_check(not broken_links, "LINK_LOCAL_TARGETS", rel, "broken local links: " + ", ".join(broken_links)))
    return findings, document


def _parse_csp(value: str) -> tuple[dict[str, list[str]], list[str]]:
    directives: dict[str, list[str]] = {}
    issues: list[str] = []
    for section in value.split(";"):
        tokens = section.strip().split()
        if not tokens:
            continue
        key = tokens[0].lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", key):
            issues.append("invalid directive identifier")
        if key in directives:
            issues.append(f"duplicate directive: {key}")
        directives[key] = tokens[1:]
    return directives, issues


def _check_csp(policy: str, path: str, meta: bool) -> Finding:
    directives, issues = _parse_csp(policy)
    for key, expected in (("default-src", "'none'"), ("object-src", "'none'"),
                          ("base-uri", "'none'"), ("form-action", "'none'"),
                          ("script-src", "'none'")):
        if directives.get(key) != [expected]:
            issues.append(f"{key} must be {expected}")
    if directives.get("style-src") != ["'self'"]:
        issues.append("style-src must be 'self' for the script-free site")
    if directives.get("frame-src") != ["'none'"]:
        issues.append("frame-src must be 'none'")
    if directives.get("connect-src") != ["'none'"]:
        issues.append("connect-src must be 'none' for the offline site")
    if directives.get("font-src") != ["'none'"]:
        issues.append("font-src must be 'none' for the local font stack")
    if not set(directives.get("img-src", [])).issubset({"'self'", "data:"}) or not directives.get("img-src"):
        issues.append("img-src must restrict to self and optional data")
    for key, sources in directives.items():
        if any(source.lower() in CSP_UNSAFE or source.lower().startswith("http:") for source in sources):
            issues.append(f"unsafe source in {key}")
    if meta and any(key in directives for key in {"frame-ancestors", "sandbox", "report-uri", "report-to"}):
        issues.append("unsupported directive in meta CSP")
    if not meta and directives.get("frame-ancestors") != ["'none'"]:
        issues.append("HTTP CSP must set frame-ancestors 'none'")
    return _check(not issues, "META_CSP_POLICY" if meta else "HTTP_CSP_POLICY", path,
                  "; ".join(sorted(set(issues))), "restrictive content policy verified")


def _read_header_snapshot(snapshot_path: Path | None) -> tuple[dict[str, dict[str, str]] | None, str | None]:
    if snapshot_path is None:
        return None, None
    try:
        blob = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"cannot read snapshot: {exc}"
    if not isinstance(blob, dict) or blob.get("evidence_type") != "observed_response_headers" or not isinstance(blob.get("responses"), list):
        return None, "snapshot must contain evidence_type=observed_response_headers and responses array"
    records: dict[str, dict[str, str]] = {}
    for item in blob["responses"]:
        if not isinstance(item, dict) or not isinstance(item.get("page"), str) or not isinstance(item.get("headers"), dict):
            return None, "malformed header response record"
        page = item["page"]
        if page in records or not re.fullmatch(r"[a-zA-Z0-9_.-]+\.html", page):
            return None, "duplicate or invalid response page"
        headers = item["headers"]
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
            return None, "header names and values must be strings"
        lowered = {k.lower(): v for k, v in headers.items()}
        if len(lowered) != len(headers):
            return None, "duplicate case-insensitive response header"
        records[page] = lowered
    return records, None


def _verify_headers(page: str, headers: dict[str, str] | None) -> list[Finding]:
    if headers is None:
        return [Finding("HTTP_" + key.upper().replace("-", "_"), "UNVERIFIED", "info", page,
                        "No observed HTTP response-header record for this page; local files cannot prove server headers.")
                for key in REQUIRED_HEADERS]
    results: list[Finding] = []
    csp = headers.get("content-security-policy", "")
    if csp:
        results.append(_check_csp(csp, page, meta=False))
    else:
        results.append(_finding("HTTP_CSP_POLICY", "FAIL", page, "missing Content-Security-Policy response header"))
    hsts = headers.get("strict-transport-security", "")
    seconds = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)(?:\s*;|\s*$)", hsts, flags=re.IGNORECASE)
    results.append(_check(bool(seconds and int(seconds.group(1)) >= 31536000), "HTTP_HSTS", page,
                          "Strict-Transport-Security must specify max-age of at least 31536000"))
    results.append(_check(headers.get("x-content-type-options", "").strip().lower() == "nosniff",
                          "HTTP_NOSNIFF", page, "X-Content-Type-Options must be nosniff"))
    results.append(_check(headers.get("referrer-policy", "").strip().lower() in {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"},
                          "HTTP_REFERRER_POLICY", page, "Referrer-Policy must restrict cross-origin data disclosure"))
    permission_text = headers.get("permissions-policy", "").lower()
    permissions = {name.strip(): value.strip() for name, _, value in (chunk.strip().partition("=") for chunk in permission_text.split(",")) if name}
    results.append(_check(all(permissions.get(key) == "()" for key in ("camera", "microphone", "geolocation")),
                          "HTTP_PERMISSIONS_POLICY", page, "Permissions-Policy must disable camera, microphone, and geolocation"))
    directives, _ = _parse_csp(csp)
    frame_ancestors = directives.get("frame-ancestors") == ["'none'"]
    frame_option = headers.get("x-frame-options", "").strip().lower() == "deny"
    results.append(_check(frame_ancestors or frame_option, "HTTP_FRAME_PROTECTION", page,
                          "set frame-ancestors 'none' or X-Frame-Options DENY"))
    return results


def audit_site(site_root: Path, header_snapshot: Path | None = None,
               challenge_pack: Path | None = None, schema_path: Path | None = None,
               check_challenges: bool = True) -> dict[str, Any]:
    """Return stable machine-readable results. Root pages only are considered public."""
    root = site_root.resolve()
    findings: list[Finding] = []
    if not root.is_dir():
        findings.append(_finding("SITE_ROOT", "FAIL", ".", "site root is not a directory"))
        pages: list[Path] = []
    else:
        pages = sorted(root.glob("*.html"))
        if not pages:
            findings.append(_finding("SITE_PAGES", "FAIL", ".", "no publishing-root HTML pages found"))

    headers, issue = _read_header_snapshot(header_snapshot)
    if issue:
        findings.append(_finding("HEADER_SNAPSHOT_INPUT", "FAIL", "security", issue))

    for page in pages:
        rel = page.relative_to(root).as_posix()
        scanned, document = _scan_page(root, page)
        findings.extend(scanned)
        page_headers = headers.get(rel) if headers is not None else None
        if document.meta_csp:
            findings.append(_check(len(document.meta_csp) == 1, "META_CSP_COUNT", rel, "require at most one meta CSP declaration"))
            for policy in document.meta_csp:
                findings.append(_check_csp(policy, rel, meta=True))
        elif not page_headers or not page_headers.get("content-security-policy"):
            findings.append(_finding("META_CSP_MISSING", "FAIL", rel,
                                     "no enforceable local CSP; add a compatible meta policy or supply observed HTTP CSP"))
        findings.extend(_verify_headers(rel, page_headers))

    if check_challenges:
        pack = challenge_pack or (root / "lab_challenges" / "challenges.v1.json")
        schema = schema_path or (root / "lab_challenges" / "challenge_collection.schema.json")
        errors = validate_pack_file(pack, schema)
        findings.append(_check(not errors, "OFFLINE_CHALLENGE_SCHEMA", "lab_challenges",
                               "; ".join(errors[:20]) + (f"; and {len(errors) - 20} more" if len(errors) > 20 else ""),
                               "collection, identifiers, answers, offline restrictions and schema verified"))
    else:
        findings.append(Finding("OFFLINE_CHALLENGE_SCHEMA", "SKIP", "info", "lab_challenges", "Explicit lab kill switch active"))

    records = sorted((asdict(record) for record in findings),
                     key=lambda entry: (entry["path"], entry["code"], entry["detail"]))
    summary = {state.lower(): sum(item["status"] == state for item in records)
               for state in ("PASS", "FAIL", "UNVERIFIED", "SKIP")}
    summary["all"] = summary["fail"] == 0 and summary["unverified"] == 0 and summary["skip"] == 0
    summary["locally_clear"] = summary["fail"] == 0
    return {"report_schema": "site-static-audit/1", "mode": "offline_read_only", "summary": summary, "findings": records}


def audit_enabled(env: dict[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return values.get("SCL_SITE_AUDIT_ENABLED", "1") != "0"


def labs_enabled(env: dict[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return values.get("SCL_LABS_ENABLED", "1") != "0"


def bypassed_report() -> dict[str, Any]:
    return {"report_schema": "site-static-audit/1", "mode": "disabled_legacy_unchanged",
            "summary": {"pass": 0, "fail": 0, "unverified": 0, "skip": 1, "all": False, "locally_clear": False},
            "findings": [asdict(Finding("AUDIT_DISABLED", "SKIP", "info", ".", "Kill switch active; no checks or changes performed"))]}
