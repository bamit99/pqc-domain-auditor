# Security Policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[Private Vulnerability Reporting](
https://github.com/bamit99/pqc-domain-auditor/security/advisories/new)
("Report a vulnerability" button on this repository's Security tab).

Please **do not open a public issue** for anything you believe is exploitable.

When reporting, include:

- The version or commit you used (`pqcaudit version`, or the commit SHA).
- Affected component (CLI, discovery, probe backend, report builders, Go dialer).
- Steps to reproduce, plus any output or logs (redact any data that identifies
  scanned targets you are not authorized to discuss).
- Your assessment of impact, if you have one.

You can expect an initial response within 7 days. Fixes are released on the
default branch; please keep reports confidential until a fix is available.

## Scope

- The Python package in `src/pqcaudit/` (CLI, discovery, probe orchestration,
  scoring, remediation and report builders).
- The bundled Go dialer in `src/pqcaudit/probe/godialer/`.

Out of scope:

- Misuse of the tool itself (scanning domains you are not authorized to
  assess) — see "Ethics & scope" in the README.
- Vulnerabilities in third-party LLM providers or local LLM runtimes reached
  through the optional `--llm` narrative feature.
- Reports about specific end-user TLS configurations produced by normal use of
  the tool.
