"""OpenSSL ``s_client`` probe execution and output parsing.

Each probe is a separate ``openssl s_client`` invocation. A single hostname is
probed with several handshakes:

1. **default**       — what the server negotiates on its own (group, protocol, cipher)
2. **hybrid forced** — ``-groups X25519MLKEM768`` (does the server accept hybrid PQ?)
3. **pure forced**   — ``-groups MLKEM768``        (does the server accept pure ML-KEM?)
4. **classical**     — ``-groups X25519``          (is classical fallback preserved?)
5. **legacy**        — TLS 1.0/1.1 detection (best-effort)
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

NEW_LINE_RE = re.compile(r"New, (TLSv1\.[123]), Cipher is (\S+)")
PROTOCOL_RE = re.compile(r"^Protocol\s*:\s*(TLSv1\.[123])", re.MULTILINE)
CIPHER_RE = re.compile(r"^Cipher\s*:\s*(\S+)", re.MULTILINE)
GROUP_TLS13_RE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
SERVER_TEMP_KEY_RE = re.compile(r"(?:Server|Peer) Temp Key:\s*(\S+),")
PEER_SIG_TYPE_RE = re.compile(r"Peer signature type:\s*(\S+)")
ISSUER_RE = re.compile(r"^issuer\s*=\s*(.+)$", re.MULTILINE)
SERVER_HEADER_RE = re.compile(r"^Server:\s*(.+)$", re.MULTILINE)
SUBJECT_RE = re.compile(r"^subject\s*=\s*(.+)$", re.MULTILINE)

FAILURE_MARKERS = ("handshake failure", "alert", "no peer certificate available", "WRONG_VERSION_NUMBER")
CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
CERT_END = "-----END CERTIFICATE-----"


@dataclass
class ProbeOutcome:
    success: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    group: str | None = None
    cert_pem: str | None = None
    server_header: str | None = None
    issuer: str | None = None
    subject: str | None = None
    peer_signature_type: str | None = None
    error: str | None = None
    raw_output: str = ""


def _first_cert(pem: str) -> str | None:
    if CERT_BEGIN not in pem:
        return None
    start = pem.index(CERT_BEGIN)
    end = pem.index(CERT_END, start) + len(CERT_END)
    return pem[start:end]


def parse_probe_output(output: str) -> ProbeOutcome:
    """Parse the full ``openssl s_client`` stdout into a structured outcome."""
    outcome = ProbeOutcome(raw_output=output)
    lowered = output.lower()

    if any(marker in lowered for marker in ("no peer certificate available",)):
        outcome.error = "no peer certificate available"
        return outcome

    m = NEW_LINE_RE.search(output)
    if m:
        outcome.tls_version = m.group(1)
        outcome.cipher = m.group(2)
        outcome.success = True
    else:
        m = PROTOCOL_RE.search(output)
        if m:
            outcome.tls_version = m.group(1)
            cm = CIPHER_RE.search(output)
            if cm and cm.group(1) not in ("None", ""):
                outcome.cipher = cm.group(1)
                outcome.success = True

    m = GROUP_TLS13_RE.search(output)
    if m:
        outcome.group = m.group(1)

    m = SERVER_TEMP_KEY_RE.search(output)
    if m and outcome.group is None:
        outcome.group = m.group(1)

    m = PEER_SIG_TYPE_RE.search(output)
    if m:
        outcome.peer_signature_type = m.group(1)

    m = ISSUER_RE.search(output)
    if m:
        outcome.issuer = m.group(1).strip()

    m = SUBJECT_RE.search(output)
    if m:
        outcome.subject = m.group(1).strip()

    m = SERVER_HEADER_RE.search(output)
    if m:
        outcome.server_header = m.group(1).strip()

    outcome.cert_pem = _first_cert(output)

    if not outcome.success and any(marker in lowered for marker in FAILURE_MARKERS):
        outcome.error = "handshake failure"
    return outcome


HTTP_REQUEST = "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"


async def run_probe(
    openssl_bin: str,
    host: str,
    port: int = 443,
    *,
    groups: str | None = None,
    force_tls13: bool = False,
    force_legacy_version: str | None = None,
    send_http: bool = False,
    timeout: float = 12.0,
) -> ProbeOutcome:
    """Run a single ``openssl s_client`` probe and return the parsed outcome."""
    cmd = [openssl_bin, "s_client", "-connect", f"{host}:{port}", "-servername", host]
    if groups:
        cmd += ["-groups", groups]
    if force_tls13:
        cmd += ["-tls1_3"]
    if force_legacy_version:
        cmd += [f"-{force_legacy_version}"]

    input_bytes: bytes | None = None
    if send_http:
        input_bytes = HTTP_REQUEST.format(host=host).encode("ascii")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(input=input_bytes), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            outcome = ProbeOutcome(error=f"timeout after {timeout}s")
            log.debug("Probe timeout for %s:%s (%s)", host, port, groups or "default")
            return outcome
    except OSError as exc:
        return ProbeOutcome(error=str(exc))

    output = stdout_bytes.decode("utf-8", errors="replace")
    return parse_probe_output(output)
