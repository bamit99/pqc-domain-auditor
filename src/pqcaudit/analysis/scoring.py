"""Verdict classification and post-quantum readiness scoring.

Scoring mirrors the assessment used for the Colt PQC TLS report:
  - PQ key exchange offered         40
  - PQ preferred by default         25
  - TLS 1.3                         15
  - Classical fallback preserved    10
  - Quantum-safe symmetric cipher   10
  - PQ (ML-DSA/SLH-DSA) cert        bonus
"""

from __future__ import annotations

from .models import HostProbeResult, HostResult, Verdict

PQ_GROUPS = frozenset(
    {
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
        "MLKEM512",
        "MLKEM768",
        "MLKEM1024",
        "X25519Kyber768Draft00",
    }
)
PURE_MLKEM_GROUPS = frozenset({"MLKEM512", "MLKEM768", "MLKEM1024"})
HYBRID_GROUPS = frozenset({"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"})

QUANTUM_SAFE_CIPHERS = frozenset(
    {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    }
)

PQ_SIGNATURE_ALGS = frozenset(
    {
        "MLDSA44",
        "MLDSA65",
        "MLDSA87",
        "mldsa44",
        "mldsa65",
        "mldsa87",
        "SLHDSA",
        "slhdsa",
    }
)


def _group_is_pq(group: str | None) -> bool:
    return group in PQ_GROUPS


def classify_host(host: HostResult) -> None:
    """Set verdict and score on a HostResult based on its probe outcomes."""
    probe = host.primary_probe
    if probe is None or not probe.reachable:
        host.verdict = Verdict.UNREACHABLE
        host.score = 0
        return

    if probe.legacy_tls_present and not probe.hybrid_supported and not probe.pure_mlkem_supported:
        host.verdict = Verdict.LEGACY
        host.score = score_host(probe)
        return

    if probe.hybrid_preferred or _group_is_pq(probe.default_group):
        host.verdict = Verdict.READY
    elif probe.hybrid_supported or probe.pure_mlkem_supported:
        host.verdict = Verdict.PURE_ONLY if probe.pure_mlkem_supported and not probe.hybrid_supported else Verdict.CAPABLE
    else:
        host.verdict = Verdict.NOT_READY

    host.score = score_host(probe)


def score_host(probe: HostProbeResult) -> int:
    """Return the 0-100 post-quantum readiness score for a probe."""
    score = 0

    if probe.hybrid_supported or _group_is_pq(probe.default_group) or probe.pure_mlkem_supported:
        score += 40

    if probe.hybrid_preferred or _group_is_pq(probe.default_group):
        score += 25

    if probe.tls_version and probe.tls_version.startswith("TLSv1.3"):
        score += 15

    if probe.classical_fallback_ok:
        score += 10

    if probe.cipher in QUANTUM_SAFE_CIPHERS:
        score += 10

    if probe.cert_signature_algorithm in PQ_SIGNATURE_ALGS:
        score += 10

    return min(score, 100)


def domain_score(hosts: list[HostResult]) -> tuple[int, dict[str, int]]:
    """Aggregate host scores into a domain score and verdict summary counts."""
    reachable = [h for h in hosts if h.verdict is not None and h.verdict != Verdict.UNREACHABLE]
    if not reachable:
        return 0, {}

    average = round(sum(h.score for h in reachable) / len(reachable))
    summary: dict[str, int] = {}
    for v in Verdict:
        summary[v.value] = sum(1 for h in hosts if h.verdict == v)
    return average, summary
