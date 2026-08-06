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

## Quick start (first-time user)

You need Python 3.10+ and **one** of two TLS probe backends. The tool picks the
best one automatically.

### 1. Get the code

```bash
git clone <this-repo>
cd pqc-domain-auditor
```

### 2. Create a virtual environment and install

```bash
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -e .
```

That installs the `pqcaudit` command and all Python dependencies.

### 3. Install ONE probe backend

The actual TLS handshakes need a library that understands ML-KEM groups. Pick
one — the tool prefers Go, but falls back to OpenSSL automatically.

**Option A — Go 1.24+ (recommended, easiest on every OS):**

| Platform | Command |
|---|---|
| Windows | `winget install GoLang.Go` |
| macOS | `brew install go` |
| Linux | `sudo apt install golang-go` |

That's it. On first scan the tool compiles a small `godialer` binary from the
bundled Go source (into `~/.cache/pqcaudit/`) and reuses it on every later run.
No system package upgrade required. Go's standard library has native
`X25519MLKEM768` support since Go 1.24.

**Option B — OpenSSL 3.5+ (the original backend):**

| Platform | Command |
|---|---|
| Windows | `winget install ShiningLight.OpenSSL.Light` |
| macOS | `brew install openssl@3` |
| Linux | OpenSSL 3.5+ (Ubuntu 25.04+, RHEL 10, Debian sid, or the `openssl3` PPA) |

> **OpenSSL LTS caveat:** `sudo apt install openssl` on Ubuntu 24.04 / Debian 12
> / RHEL 9 installs **3.0.x**, which has *no* ML-KEM groups and will fail
> preflight. On those distros, prefer the Go backend (Option A) — no system
> package upgrade required.

### 4. Verify the backend

```bash
pqcaudit preflight
```

Expected output (Go backend):
```
OK Go dialer backend: C:\Users\you\.cache\pqcaudit\godialer.exe
OK OpenSSL 3.5.6 available for the legacy TLS probe
```

Expected output (OpenSSL backend):
```
OK OpenSSL 3.5.6 at /usr/bin/openssl
Groups: MLKEM1024, MLKEM768, X25519MLKEM768, ...
```

If preflight fails, the error message includes platform-specific install hints.

### 5. Run your first scan

```bash
pqcaudit scan example.com
```

You'll see a live `rich` summary table in the terminal, and four report files
written to `reports/`:

```
reports/example-com-pqc.md      # markdown report
reports/example-com-pqc.html    # styled HTML dashboard
reports/example-com-pqc.json    # machine-readable
reports/example-com-pqc.csv     # spreadsheet-friendly
```

That's it — you're auditing post-quantum TLS readiness.

---

## Why this matters

Classical key exchange (RSA, ECDH/X25519) is vulnerable to
*harvest-now-decrypt-later* attacks once a cryptographically-relevant quantum
computer exists. Post-quantum TLS adds **ML-KEM** key encapsulation so that a
recorded session cannot be decrypted later — regardless of whether the classical
half is ever broken.

- **Hybrid** `X25519MLKEM768` = X25519 + ML-KEM-768 (recommended deployment)
- **Pure** `MLKEM768` / `MLKEM1024` = ML-KEM only
- Certificates signed with classical RSA/ECDSA remain the norm; ML-DSA (FIPS 204)
  certificates are the next phase and flagged as such (not blocking).

## How the check works

For every discovered hostname on port 443, the tool runs several real TLS
handshakes and parses the negotiated group. The probe backend (Go dialer or
OpenSSL) is selected automatically — both produce the same verdict and score.

| Probe | What it proves |
|---|---|
| Default handshake | Which key-exchange group the server picks on its own |
| Forced hybrid (`X25519MLKEM768` + SecP hybrids) | Does the server accept a hybrid post-quantum group? |
| Forced pure (`MLKEM768` / `MLKEM1024`) | Does the server accept pure ML-KEM? |
| Forced classical (`X25519`) | Is classical fallback preserved (no client lockout)? |
| TLS 1.0/1.1 probe | Legacy protocol detection (advisory; OpenSSL backend only) |
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

> **Backend note:** the Go dialer cannot perform the TLS 1.0/1.1 legacy probe
> (Go's `crypto/tls` dropped those protocol versions). If OpenSSL is present on
> the system, the tool uses it for the legacy probe even in Go mode. In pure-Go
> mode (no OpenSSL), the legacy finding is reported as "detection unavailable"
> rather than "no legacy TLS" — so a missing legacy flag is never mistaken for
> proof that TLS 1.0/1.1 is disabled.

## Requirements

- **Python 3.10+**
- One TLS probe backend (see Quick start above):
  - **Go dialer** (preferred): built automatically from the bundled source when
    Go >= 1.24 is installed, or point `PQC_GO_DIALER` at a prebuilt binary.
  - **OpenSSL >= 3.5** (native ML-KEM support).

Backend selection is automatic (`auto`): **Go dialer > OpenSSL 3.5+**. Control
it with `--backend auto|go|openssl` or `PQC_BACKEND=auto|go|openssl`.

If OpenSSL lives somewhere non-standard, set `PQC_OPENSSL_BIN` to its path.

## Installation

See [Quick start](#quick-start-first-time-user) above for the full walkthrough.

The short version for someone who already has Go or OpenSSL installed:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows
# source .venv/bin/activate         # macOS/Linux
pip install -e .
pqcaudit preflight                   # verify a probe backend
```

Alternatively, install pinned dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
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

# Add hostnames CT logs can't see (e.g. behind wildcard certs)
pqcaudit scan example.com --hosts api.example.com,internal.example.com

# Force a specific probe backend
pqcaudit scan example.com --backend go
pqcaudit scan example.com --backend openssl

# Add an LLM narrative on top of deterministic remediation
pqcaudit scan example.com --llm ollama
pqcaudit scan example.com --llm openai
```

### CLI commands

| Command | Purpose |
|---|---|
| `pqcaudit scan <domain>` | Discover subdomains and audit their PQC TLS readiness |
| `pqcaudit preflight` | Verify a probe backend (Go dialer or OpenSSL 3.5+) is available |
| `pqcaudit version` | Show tool version |

Run `pqcaudit scan --help` to see every flag.

### Environment variables (all optional)

| Variable | Default | Purpose |
|---|---|---|
| `PQC_BACKEND` | `auto` | Probe backend: `auto`, `go`, or `openssl` |
| `PQC_GO_DIALER` | *(auto-build)* | Path to a prebuilt `godialer` binary |
| `PQC_OPENSSL_BIN` | `openssl` | Path to an OpenSSL binary |
| `PQC_TIMEOUT` | `10` | Per-handshake timeout (seconds) |
| `PQC_CONCURRENCY` | `32` | Max concurrent probes |
| `PQC_PORTS` | `443` | Comma-separated ports to probe |
| `PQC_CRTSH_BASE` | `https://crt.sh` | crt.sh base URL override |
| `PQC_DNS_RESOLVER` | *(system)* | Custom DNS resolver IP |

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

The Go dialer can be built and vetted independently:

```bash
cd src/pqcaudit/probe/godialer
go build .
go vet .
```

## Layout

```
src/pqcaudit/
├── cli.py                  # typer CLI + rich output
├── config.py               # env-based settings + LLM config
├── discovery/              # crt.sh + dnspython enumeration
├── probe/                  # preflight + probe backends
│   ├── preflight.py        # backend detection (Go dialer / OpenSSL) + auto-build
│   ├── openssl_probe.py    # openssl s_client handshake probes
│   ├── go_probe.py         # godialer JSON parsing + result normalization
│   ├── orchestrator.py     # runs the probe matrix, backend-agnostic
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

## License

MIT — see [LICENSE](LICENSE).