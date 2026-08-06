# PQC Domain Auditor

Post-Quantum (ML-KEM) TLS readiness auditor.

Give it a domain. It passively discovers the domain's subdomains from
certificate-transparency logs and DNS, then actively probes each hostname with
real TLS handshakes to determine whether the endpoint is **post-quantum ready**
— i.e. can negotiate the NIST-standardized hybrid key exchange
**`X25519MLKEM768`** (RFC 9794) / pure **ML-KEM** (FIPS 203) on TLS 1.3.

For every host that is not ready, it produces a concrete, deterministic
**remediation guide** (nginx / Apache / HAProxy / Caddy / IIS / CDN / IDP
config snippets), with an optional **LLM-generated narrative** on top.

```
pqcaudit scan example.com -o reports/
```

---

## Why this matters

Classical key exchange (RSA, ECDH/X25519) is vulnerable to
*harvest-now-decrypt-later* attacks once a cryptographically-relevant quantum
computer exists. Post-quantum TLS adds **ML-KEM** key encapsulation so that a
recorded session cannot be decrypted later — regardless of whether the classical
half is ever broken.

- **Hybrid** `X25519MLKEM768` = X25519 + ML-KEM-768 (recommended deployment)
- **Pure** `MLKEM768` = ML-KEM only
- Certificates signed with classical RSA/ECDSA remain the norm; ML-DSA (FIPS 204)
  certificates are the next phase and flagged as such (not blocking).

## How the check works

For every discovered hostname on port 443, the tool runs several
`openssl s_client` handshakes and parses the negotiated group:

| Probe | What it proves |
|---|---|
| Default handshake | Which key-exchange group the server picks on its own |
| `-groups X25519MLKEM768` | Does the server accept the hybrid post-quantum group? |
| `-groups MLKEM768` | Does the server accept pure ML-KEM? |
| `-groups X25519` | Is classical fallback preserved (no client lockout)? |
| TLS 1.0/1.1 probe | Legacy protocol detection (advisory) |
| HTTP `Server` header | Stack detection for targeted remediation |

Each host is classified:

```
🟢 ready         hybrid PQ negotiated by default
🟡 capable       PQ supported but classical preferred
🟠 pure-only     pure ML-KEM only (no hybrid)
🔴 not-ready     no post-quantum key exchange
🔴 legacy        TLS 1.0/1.1 enabled and no PQ
⚪ unreachable   no TLS endpoint on scanned ports
```

## Requirements

- **Python 3.10+**
- One TLS probe backend:
  - **Go dialer** (preferred): a prebuilt `godialer` binary
    (`C:\Users\<you>\.cache\pqcaudit\godialer.exe`, or `~/.cache/pqcaudit/`
    on macOS/Linux). On machines with **Go >= 1.24** installed, the tool
    builds it automatically on first run — Go's standard library has native
    `X25519MLKEM768` (RFC 9794) support, so no OpenSSL needed at all. To use a
    prebuilt binary (e.g. on the probe box), set `PQC_GO_DIALER`.
  - **OpenSSL >= 3.5** (native ML-KEM support) — first LTS release with
    ML-KEM is OpenSSL 3.5 (Ubuntu 25.04, RHEL 10).

Backend selection is automatic (`auto`): **Go dialer > OpenSSL 3.5+**. Control
it with `PQC_BACKEND=auto|go|openssl`. In Go mode, OpenSSL (any version) is
still used for the legacy TLS 1.0/1.1 probe when available.

On first run the tool **preflights** the backend and, if it is missing or too
old, prints exact install instructions for your platform:

| Platform | Command |
|---|---|
| Windows | `winget install GoLang.Go` (auto-builds `godialer`) or `winget install ShiningLight.OpenSSL.Light` |
| macOS | `brew install go` or `brew install openssl@3` |
| Linux | `sudo apt install golang-go` or OpenSSL 3.5+ (see LTS caveat below) |

> **OpenSSL LTS caveat:** `sudo apt install openssl` on Ubuntu 24.04 / Debian 12
> / RHEL 9 installs **3.0.x**, which has *no* ML-KEM groups and will fail
> preflight. Either install OpenSSL 3.5+ (e.g. the `openssl3` PPA on Ubuntu),
> or simply install Go (`golang-go`) and let the tool build the `godialer`
> backend — no system package upgrade required.

If OpenSSL lives somewhere non-standard, set `PQC_OPENSSL_BIN` to its path.

## Installation

```bash
git clone <this-repo>
cd pqc-domain-auditor
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -e .
pqcaudit preflight   # verify a probe backend (Go dialer or OpenSSL 3.5+)
```

## Usage

```bash
# Full audit (CT logs + DNS discovery, all report formats)
pqcaudit scan example.com

# Restrict report formats / output dir / ports
pqcaudit scan example.com -o reports/ -f md,html
pqcaudit scan example.com -p 443,8443

# Tune speed / reliability
pqcaudit scan example.com -c 64 -t 8

# Discovery sources
pqcaudit scan example.com --no-dns   # certificate transparency only
pqcaudit scan example.com --no-ct    # DNS records only

# Add an LLM narrative on top of deterministic remediation
pqcaudit scan example.com --llm ollama
pqcaudit scan example.com --llm openai
```

### LLM configuration (optional)

All via environment variables — the tool is fully functional without any of
these (deterministic remediation only):

| Variable | Purpose |
|---|---|
| `PQC_LLM_PROVIDER` | `openai`, `anthropic`, `ollama`, or a custom OpenAI-compatible URL |
| `PQC_LLM_MODEL` | Model name (defaults per provider) |
| `PQC_LLM_API_KEY` | API key (OpenAI / Anthropic) |
| `PQC_LLM_BASE_URL` | Base URL override (e.g. `http://localhost:11434`) |
| `PQC_LLM_ENDPOINT` | Full chat-completions endpoint override |

Example (Ollama local):
```bash
$env:PQC_LLM_PROVIDER="ollama"
$env:PQC_LLM_MODEL="llama3.1"
pqcaudit scan example.com --llm ollama
```

> **Data-egress note:** when `--llm` selects an external provider (openai,
> anthropic, or a custom URL), the per-host scan summary (hostnames, resolved
> IPs, certificate issuers, TLS groups) is sent to that provider to generate
> the narrative. For sensitive / internal asset inventories, prefer `ollama`
> (local inference) — no scan data leaves the machine.

## Output

Terminal: a `rich` summary table. Files (default `reports/`):

| Format | File |
|---|---|
| Markdown | `<domain>-pqc.md` |
| HTML dashboard | `<domain>-pqc.html` |
| JSON | `<domain>-pqc.json` |
| CSV | `<domain>-pqc.csv` |

The score (0–100) follows a public PQC TLS readiness scoring model:

| Criterion | Weight |
|---|---|
| PQ key exchange offered | 40 |
| PQ preferred by default | 25 |
| TLS 1.3 | 15 |
| Classical fallback preserved | 10 |
| Quantum-safe symmetric cipher | 10 |
| PQ (ML-DSA/SLH-DSA) certificate | bonus |

*All TLS 1.3 AEAD suites (AES-128/256-GCM, ChaCha20-Poly1305) are quantum-safe,
so the symmetric-cipher criterion is satisfied by any TLS 1.3 connection —
regardless of whether the probe backend (OpenSSL vs Go dialer) negotiates
AES-128-GCM or AES-256-GCM.*

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/
mypy src/
```

## Layout

```
src/pqcaudit/
├── cli.py                  # typer CLI + rich output
├── config.py               # env-based settings + LLM config
├── discovery/              # crt.sh + dnspython enumeration
├── probe/                  # preflight + s_client probes, Go dialer backend
│   ├── preflight.py        # backend detection (Go dialer / OpenSSL) + auto-build
│   ├── go_probe.py         # godialer JSONL parsing + result normalization
│   └── godialer/           # Go TLS dialer (X25519MLKEM768), buildable to a binary
├── analysis/               # verdict classification + scoring
├── remediation/            # deterministic fixes + optional LLM narrative
└── report/                 # markdown / html / json / csv exporters
```

## Ethics & scope

This tool performs **passive discovery** (certificate transparency, DNS) and
only probes TLS endpoints of hosts that the domain itself references. Use it on
domains you own or are authorized to assess. Active brute-force enumeration is
deliberately **not** included.
