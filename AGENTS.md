# AGENTS.md — pqc-domain-auditor

Guidance for AI coding agents working in this repository. Keep it factual and current;
the human-facing walkthrough lives in [README.md](README.md).

## What this project is

A CLI (`pqcaudit`) that audits a domain's **Post-Quantum (ML-KEM) TLS readiness**.
It passively discovers hostnames (certificate transparency logs + DNS), performs
real TLS handshakes against each host on port 443, classifies each endpoint, scores
the domain 0–100, and emits remediation guidance plus reports in four formats.

## Environment (this machine)

- Windows 11, bash/git-bash shell. **Native tools get forward-slash paths** (`E:/Git/...`),
  not MSYS `/c/...` paths — MSYS path translation is disabled here.
- Python venv is committed-adjacent at `.venv/` (gitignored). It is already created
  and has the package installed editable. **Use `.venv/Scripts/python.exe` directly**;
  do not create a new venv or `pip install` into the system interpreter.
- Probe backends available and verified: **Go 1.26.5** and **OpenSSL 3.5.7**.
  The Go dialer binary is auto-built into `C:\Users\amitb\.cache\pqcaudit\godialer.exe`.

## Commands

Run from the repo root.

```bash
# Verify a probe backend is usable (do this first — most failures are here)
./.venv/Scripts/pqcaudit.exe preflight

# Smoke test the full pipeline against a known-good domain
./.venv/Scripts/pqcaudit.exe scan example.com -o reports/ -f md

# Tests / lint / types
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/ruff.exe check src/ tests/
./.venv/Scripts/mypy.exe src/

# Rebuild / vet the Go dialer after editing main.go
cd src/pqcaudit/probe/godialer && go build . && go vet .
```

To use the installed console script after activating the venv (`source .venv/Scripts/activate`),
the bare name `pqcaudit` works the same as `./.venv/Scripts/pqcaudit.exe`.

## Architecture (read before changing behavior)

```
src/pqcaudit/
├── cli.py                  # Typer app + rich terminal output; all options live here
├── config.py               # env-based Settings (PQC_* vars) + LLM config
├── discovery/              # crtsh.py (+ certspotter), dns.py, orchestrator.py
├── probe/
│   ├── preflight.py        # backend detection (Go dialer > OpenSSL 3.5+) + auto-build
│   ├── openssl_probe.py    # `openssl s_client` handshake probes
│   ├── go_probe.py         # parses godialer JSON, normalizes to the same result shape
│   ├── orchestrator.py     # runs the probe matrix, backend-agnostic
│   └── godialer/main.go    # Go TLS dialer (native X25519MLKEM768), built to a binary
├── analysis/               # models.py (verdicts) + scoring.py (0–100 model)
├── remediation/            # engine.py (deterministic snippets) + llm.py (optional narrative)
└── report/exporters.py     # markdown / html / json / csv
```

Data flow: `discover(domain)` → `audit_host(...)` per hostname → `remediate_host(...)`
→ `domain_score(...)` → `exporters.*`.

## Invariants — do not break these

- **The two probe backends must stay verdict- and score-identical.** Any change to probe
  logic in one backend needs the mirror change in the other, or the same scan gives
  different answers depending on what's installed. `tests/test_go_probe.py` and
  `tests/test_openssl_probe.py` guard this.
- **A missing legacy-TLS finding is not proof of absence.** The Go dialer cannot do the
  TLS 1.0/1.1 probe (Go's `crypto/tls` dropped those versions). Without OpenSSL present,
  report it as "detection unavailable", never as "no legacy TLS".
- **Discovery is passive.** CT logs + DNS only. Do not add active brute-force enumeration.
- **Remediation is deterministic by default.** The LLM narrative is additive and optional;
  the tool must be fully functional with no LLM configured and no network egress beyond
  the scan itself.
- **ML-KEM group names are exact.** Use `X25519MLKEM768` (hybrid), `MLKEM768` / `MLKEM1024`
  (pure). A previous commit fixed wrong codepoints here — check RFC 9794 / FIPS 203 before
  touching group strings.
- **Scoring weights are a public model** (PQ offered 40 / PQ preferred 25 / TLS1.3 15 /
  classical fallback 10 / quantum-safe symmetric 10; PQ certificate = bonus). Changing
  weights changes every reported score — treat as a deliberate, called-out change.

## Conventions

- Python ≥3.10, `from __future__ import annotations`, line length 100 (ruff), mypy clean.
- Ruff ignores `B008` (typer `Option(...)` defaults are idiomatic) and `ISC004`.
- Async probes use asyncio; pytest runs with `asyncio_mode = "auto"`.
- Windows CSV export must keep `newline=""` on the file handle (double-`\r\n` otherwise).

## Pitfalls already hit

- **Typer aliases must pass real values, not defaults.** An alias that calls a
  `@app.command` function with no arguments receives that function's `OptionInfo` default
  object, not the string. Call it with explicit args (e.g. `preflight_check(backend="auto")`)
  or `AttributeError: 'OptionInfo' object has no attribute ...` follows.
- `reports/` is gitignored — never commit generated reports; use them as local evidence only.
- The `godialer` binary is gitignored in both source and cache locations; don't commit it.
