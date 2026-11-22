# Private draft: offline site assurance runbook

The supplied project context describes a script-free static site with three publishing-root pages, one stylesheet, and no package or build system. This patch adds files only; it does not alter existing pages, source control branches, hosting, or visitors' data.

## Local execution

From the repository root:

```sh
python3 -m pytest -q
python3 -m site_audit --site-root . --json-out local-audit.json
```

The auditor checks the publishing-root `*.html` documents only. It validates document language, title, heading progression, a main landmark, alt text, control labels, link names and local destinations, new-window safety, duplicate IDs and attributes, local assets, inline behavior, and a restrictive content policy. It separately checks the local defensive-lab challenge collection, including answer-key integrity, duplicate identifiers, and prohibition of remote addresses or executable markup in scenario text.

The tool never fetches a URL, executes HTML or challenge content, writes to the publishing tree, accesses credentials, or scans a third-party system. `--json-out` is an explicit report destination. JSON findings and output order are deterministic. `ALL=false` means that at least one finding is failed, unverified, or skipped; `locally_clear` captures whether local checks failed independently of remote HTTP evidence.

## Security headers: evidence and limits

An HTML file and a repository listing cannot establish which HTTP response headers a remote server sends. Do not treat `security/headers.expected.json` as observation. It deliberately lacks the `evidence_type` field and will be rejected as captured evidence.

To record actual deployment behavior, first inspect the response headers for each published page using an authorized browser or an ordinary HEAD/GET request. Capture the observed values into a separate JSON file with this structure:

```json
{
  "evidence_type": "observed_response_headers",
  "responses": [
    {
      "page": "index.html",
      "headers": {
        "Content-Security-Policy": "default-src 'none'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'; script-src 'none'; style-src 'self'; img-src 'self'; font-src 'none'; connect-src 'none'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "X-Frame-Options": "DENY"
      }
    }
  ]
}
```

This is an **illustrative format**, not a claim about live responses. Include a response record for every published HTML page. Incomplete records produce `UNVERIFIED` rows. Values should be transcribed from a captured response, not from a desired-policy file. A supplied snapshot is evidence provided by the operator; the tool cannot independently authenticate its provenance.

Run the stronger release gate after capture:

```sh
python3 -m site_audit --site-root . --headers-file local-headers.observed.json --require-verified-headers --json-out verified-audit.json
```

The audit requires an HTTP CSP that denies embedded framing, restricts script execution, prohibits objects and forms, and limits local resources. It checks HSTS duration, content-type sniffing protection, referrer disclosure, sensitive device permissions, and clickjacking defenses. Other routes and assets must be reviewed separately before a deployment claim.

A static hosting arrangement may not permit custom HTTP response headers. The optional `security/csp-meta.template.html` provides a **local HTML policy** that can be adopted only after compatibility testing. A meta-delivered CSP cannot establish HTTP-level HSTS, X-Frame-Options, X-Content-Type-Options, or Permissions-Policy, and cannot enforce `frame-ancestors`. Those controls require support from the serving layer. Do not copy HTTP-only CSP directives into the meta tag. Place any meta policy early in the document head before stylesheets and other resources. If a host cannot configure the headers, retain `UNVERIFIED` findings and document the deployment limitation rather than fabricating compliance.

## Safety and accessibility scope

The scenarios contain no targets, code execution, live addresses, or exercise payloads. Every assessment is a deterministic single-choice evaluation of a defensive decision. The collection does not collect user data.

This validator is a static, lexical screen. It does not compute rendered contrast, prove focus visibility, exercise a screen reader, simulate assistive technology, or assess all accessibility success criteria. Carry out separate visual, keyboard, text-resizing, and screen-reader reviews before making public accessibility claims. A complete privacy-policy audit likewise requires checking actual runtime data flows, which are outside the supplied static-site context.

## Opt-out and preservation of existing behavior

`SCL_SITE_AUDIT_ENABLED` defaults to `1`; setting it to exactly `0` bypasses the auditor, changes no site bytes, exits successfully, and emits `SKIP AUDIT_DISABLED` followed by `ALL=false`. `SCL_LABS_ENABLED` defaults to `1`; setting it to exactly `0` bypasses the challenge-format test. The collection separately declares the native integration contract: enabled by default, `SCL_LABS_ENABLED=0` restores pre-integration behavior. The native app was not included, so native runtime behavior cannot be verified here.

## Reproducible fixture checks

The files under `tests/fixtures` are deliberately **synthetic**, with local-only HTML and a synthetic header capture. They are not snapshots of a public deployment. A passing fixture demonstrates validator behavior, not site compliance. The negative fixtures verify that omissions are detected. The checked-in test suite runs without network access.
