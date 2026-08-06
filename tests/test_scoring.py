"""Tests for verdict classification and scoring."""

from pqcaudit.analysis.models import HostProbeResult, HostResult, Verdict
from pqcaudit.analysis.scoring import classify_host, domain_score, score_host


def _probe(**kw) -> HostProbeResult:
    defaults = {
        "host": "x.example.com",
        "port": 443,
        "reachable": True,
        "tls_version": "TLSv1.3",
    }
    defaults.update(kw)
    return HostProbeResult(**defaults)


def _host(probe: HostProbeResult) -> HostResult:
    host = HostResult(hostname=probe.host, probes={443: probe})
    return host


def test_ready_when_hybrid_preferred():
    probe = _probe(default_group="X25519MLKEM768", hybrid_supported=True, hybrid_preferred=True,
                   pure_mlkem_supported=True, classical_fallback_ok=True,
                   cipher="TLS_AES_256_GCM_SHA384", cert_signature_algorithm="rsa_pss_rsae_sha256")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.READY
    assert host.score == 100


def test_not_ready_when_no_pq():
    probe = _probe(default_group="X25519", hybrid_supported=False, hybrid_preferred=False,
                   pure_mlkem_supported=False, classical_fallback_ok=True,
                   cipher="TLS_AES_128_GCM_SHA256", cert_signature_algorithm="ecdsa_secp256r1_sha256")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.NOT_READY
    assert host.score == 35  # TLS 1.3 (15) + fallback (10) + quantum-safe cipher (10)


def test_capable_when_hybrid_supported_not_preferred():
    probe = _probe(default_group="X25519", hybrid_supported=True, hybrid_preferred=False,
                   pure_mlkem_supported=True, classical_fallback_ok=True,
                   cipher="TLS_AES_256_GCM_SHA384")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.CAPABLE


def test_pure_only_when_only_mlkem_supported_but_classical_default():
    probe = _probe(default_group="X25519", hybrid_supported=False, hybrid_preferred=False,
                   pure_mlkem_supported=True, classical_fallback_ok=True, cipher="TLS_AES_256_GCM_SHA384")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.PURE_ONLY


def test_ready_when_pure_mlkem_defaulted():
    probe = _probe(default_group="MLKEM768", hybrid_supported=False, hybrid_preferred=False,
                   pure_mlkem_supported=True, classical_fallback_ok=True, cipher="TLS_AES_256_GCM_SHA384")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.READY


def test_unreachable():
    probe = _probe(reachable=False, error="timeout")
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.UNREACHABLE
    assert host.score == 0


def test_legacy():
    probe = _probe(tls_version="TLSv1.2", legacy_tls_present=True, hybrid_supported=False,
                   pure_mlkem_supported=False, classical_fallback_ok=True)
    host = _host(probe)
    classify_host(host)
    assert host.verdict == Verdict.LEGACY


def test_domain_score_aggregation():
    hosts = [
        _host(_probe(default_group="X25519MLKEM768", hybrid_supported=True, hybrid_preferred=True,
                     pure_mlkem_supported=True, classical_fallback_ok=True, cipher="TLS_AES_256_GCM_SHA384")),
        _host(_probe(default_group="X25519", hybrid_supported=False, hybrid_preferred=False,
                     pure_mlkem_supported=False, classical_fallback_ok=True, cipher="TLS_AES_128_GCM_SHA256")),
    ]
    for h in hosts:
        classify_host(h)
    score, summary = domain_score(hosts)
    assert score == 68  # (100 + 35) / 2 rounded
    assert summary[Verdict.READY.value] == 1
    assert summary[Verdict.NOT_READY.value] == 1


def test_score_host_mldsa_bonus():
    probe = _probe(default_group="X25519MLKEM768", hybrid_supported=True, hybrid_preferred=True,
                   pure_mlkem_supported=True, classical_fallback_ok=True,
                   cipher="TLS_AES_256_GCM_SHA384", cert_signature_algorithm="mldsa65")
    assert score_host(probe) == 100  # capped
