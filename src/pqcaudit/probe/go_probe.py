"""Go-based TLS dialer probe (fallback backend for OpenSSL < 3.5).

Each invocation of the ``godialer`` binary performs ONE probe and prints one
JSON object. This module runs it and maps the JSON into the same
:class:`~pqcaudit.probe.openssl_probe.ProbeOutcome` shape the OpenSSL backend
produces, so the orchestrator is backend-agnostic.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging

from .openssl_probe import ProbeOutcome

log = logging.getLogger(__name__)

# Go reports the hybrid P-256/P-384 ML-KEM groups with different spellings
# than OpenSSL; normalise so PQ_GROUPS matching in scoring.py stays consistent.
GROUP_NORMALIZE = {
    "P-256MLKEM768": "SecP256r1MLKEM768",
    "P-384MLKEM1024": "SecP384r1MLKEM1024",
}


def _pem_from_der_b64(der_b64: str | None) -> str | None:
    if not der_b64:
        return None
    try:
        der = base64.b64decode(der_b64)
        body = base64.encodebytes(der).decode("ascii")
        return "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"
    except Exception as exc:  # noqa: BLE001 - best-effort cert decoding
        log.debug("Could not decode go dialer certificate: %s", exc)
        return None


def parse_go_output(line: str, probe_name: str = "") -> ProbeOutcome:
    """Map one JSON line from the go dialer into a ProbeOutcome."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return ProbeOutcome(error=f"invalid go dialer output: {line[:200]}")

    group = data.get("group")
    return ProbeOutcome(
        success=bool(data.get("ok")),
        tls_version=data.get("tls_version") or None,
        cipher=data.get("cipher") or None,
        group=GROUP_NORMALIZE.get(group, group) if group else None,
        cert_pem=_pem_from_der_b64(data.get("cert_der_b64")),
        server_header=data.get("server_header") or None,
        error=data.get("error") or None,
        raw_output=line,
    )


async def run_go_probe(
    go_dialer: str,
    host: str,
    port: int = 443,
    *,
    probe: str = "default",
    timeout: float = 12.0,
) -> ProbeOutcome:
    """Run one probe through the godialer binary and parse its output."""
    cmd = [go_dialer, "-host", host, "-port", str(port), "-probe", probe, "-timeout", str(timeout)]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ProbeOutcome(error=f"timeout after {timeout}s")
    except OSError as exc:
        return ProbeOutcome(error=str(exc))

    text = stdout_bytes.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            return parse_go_output(stripped, probe)
    return ProbeOutcome(error=f"no JSON output from go dialer: {text[:200]}")
