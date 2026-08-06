"""Probe orchestration: run the probe matrix against a hostname and classify it.

Supports two backends transparently:
  - ``openssl`` (OpenSSL >= 3.5 s_client)
  - ``go``       (static godialer binary built from Go >= 1.24)
In ``go`` mode an available OpenSSL binary is still used for the TLS 1.0/1.1
legacy probe (the Go client dropped those protocol versions).
"""

from __future__ import annotations

import asyncio
import logging

from ..analysis.models import HostProbeResult, HostResult
from ..analysis.scoring import HYBRID_GROUPS, PQ_GROUPS, PURE_MLKEM_GROUPS, classify_host
from .go_probe import run_go_probe
from .openssl_probe import ProbeOutcome, run_probe
from .preflight import ProbeBackend

log = logging.getLogger(__name__)

HYBRID_GROUP = "X25519MLKEM768"
PURE_GROUP = "MLKEM768"
CLASSICAL_GROUP = "X25519"


def _parse_cert_signature(cert_pem: str | None) -> tuple[str | None, str | None]:
    """Return ``(signature_algorithm, issuer)`` from the peer certificate PEM."""
    if not cert_pem:
        return None, None
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        sig_alg = cert.signature_algorithm_oid._name or None
        issuer = cert.issuer.rfc4514_string()
        return sig_alg, issuer
    except Exception as exc:  # noqa: BLE001 - best-effort cert parsing
        log.debug("Cert parse failed: %s", exc)
        return None, None


async def _default_probe(
    backend: ProbeBackend, host: str, port: int, *, timeout: float
) -> ProbeOutcome:
    if backend.mode == "go":
        return await run_go_probe(backend.go_dialer, host, port, probe="default", timeout=timeout)
    return await run_probe(backend.openssl_bin, host, port, send_http=True, timeout=timeout)


async def _forced_probe(
    backend: ProbeBackend, host: str, port: int, *, probe: str, timeout: float
) -> ProbeOutcome:
    """Run a group-forcing probe (hybrid / pure / classical)."""
    if backend.mode == "go":
        return await run_go_probe(backend.go_dialer, host, port, probe=probe, timeout=timeout)
    groups = {"hybrid": HYBRID_GROUP, "pure": PURE_GROUP, "classical": CLASSICAL_GROUP}[probe]
    return await run_probe(backend.openssl_bin, host, port, groups=groups, force_tls13=True, timeout=timeout)


async def _legacy_probe(
    backend: ProbeBackend, host: str, port: int, *, timeout: float
) -> bool:
    """Detect TLS 1.0/1.1. Requires an OpenSSL binary; False in pure-Go mode."""
    if backend.mode == "go" and not backend.openssl_bin:
        return False
    openssl = backend.openssl_bin
    legacy = await run_probe(openssl, host, port, force_legacy_version="tls1", timeout=timeout)
    if not legacy.success:
        legacy = await run_probe(openssl, host, port, force_legacy_version="tls1_1", timeout=timeout)
    return legacy.success


async def probe_host(
    backend: ProbeBackend,
    host: str,
    port: int = 443,
    *,
    timeout: float = 12.0,
) -> HostProbeResult:
    """Run the full probe matrix for one (host, port) and build a HostProbeResult."""
    result = HostProbeResult(host=host, port=port)

    default = await _default_probe(backend, host, port, timeout=timeout)
    if not default.success:
        result.error = default.error or "unreachable"
        return result

    result.reachable = True
    result.tls_version = default.tls_version
    result.cipher = default.cipher
    result.default_group = default.group
    result.server_header = default.server_header
    result.cert_signature_algorithm, result.cert_issuer = _parse_cert_signature(default.cert_pem)

    hybrid = await _forced_probe(backend, host, port, probe="hybrid", timeout=timeout)
    result.hybrid_supported = hybrid.success and hybrid.group in HYBRID_GROUPS

    pure = await _forced_probe(backend, host, port, probe="pure", timeout=timeout)
    result.pure_mlkem_supported = pure.success and pure.group in PURE_MLKEM_GROUPS

    classical = await _forced_probe(backend, host, port, probe="classical", timeout=timeout)
    result.classical_fallback_ok = classical.success

    # A host is "PQ-preferred" when the group it negotiates by default is any
    # post-quantum group (hybrid or pure). This must agree with classify_host,
    # which marks a host READY whenever the default group is in PQ_GROUPS.
    result.hybrid_preferred = result.default_group in PQ_GROUPS

    result.legacy_tls_present = await _legacy_probe(backend, host, port, timeout=timeout)

    return result


async def audit_host(
    backend: ProbeBackend,
    hostname: str,
    ips: list[str],
    ports: tuple[int, ...] = (443,),
    *,
    concurrency: int = 32,
    timeout: float = 12.0,
) -> HostResult:
    """Audit one hostname across the configured ports and classify it."""
    host_result = HostResult(hostname=hostname, ips=ips, discovered_by=["dns"])

    sem = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> HostProbeResult:
        async with sem:
            return await probe_host(backend, hostname, port, timeout=timeout)

    probes = await asyncio.gather(*(_probe(p) for p in ports))
    host_result.probes = {probe.port: probe for probe in probes}
    classify_host(host_result)
    return host_result
