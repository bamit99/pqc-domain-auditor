"""Tests for the deterministic remediation engine."""

from pqcaudit.analysis.models import HostProbeResult, HostResult, Verdict
from pqcaudit.analysis.scoring import classify_host
from pqcaudit.remediation.engine import remediate_host


def _host(probe_kwargs: dict, hostname: str = "www.example.com") -> HostResult:
    defaults = {
        "host": hostname,
        "port": 443,
        "reachable": True,
        "tls_version": "TLSv1.3",
    }
    defaults.update(probe_kwargs)
    probe = HostProbeResult(**defaults)
    host = HostResult(hostname=hostname, probes={443: probe})
    classify_host(host)
    return host


def test_ready_host_no_remediation():
    host = _host({
        "default_group": "X25519MLKEM768",
        "hybrid_supported": True,
        "hybrid_preferred": True,
        "pure_mlkem_supported": True,
        "classical_fallback_ok": True,
        "cert_signature_algorithm": "ecdsa_secp256r1_sha256",
    })
    items = remediate_host(host)
    # Only the low-priority cert signature note should appear.
    assert len(items) == 1
    assert "ML-DSA" in items[0]


def test_nginx_not_ready_gets_nginx_fix():
    host = _host({
        "default_group": "X25519",
        "hybrid_supported": False,
        "pure_mlkem_supported": False,
        "classical_fallback_ok": True,
        "server_header": "nginx/1.27.0",
    })
    items = remediate_host(host)
    text = "\n".join(items)
    assert "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1" in text


def test_netiq_detection():
    host = _host({
        "default_group": "X25519",
        "hybrid_supported": False,
        "pure_mlkem_supported": False,
        "classical_fallback_ok": True,
        "server_header": "Novell NetIQ Access Manager",
    })
    items = remediate_host(host)
    text = "\n".join(items)
    assert "NetIQ" in text or "Identity Provider" in text


def test_unreachable_host():
    host = HostResult(
        hostname="down.example.com",
        probes={443: HostProbeResult(host="down.example.com", port=443)},
    )
    items = remediate_host(host)
    assert len(items) == 1
    assert "unreachable" in items[0]


def test_pq_but_not_preferred_gets_reorder_advice():
    host = _host({
        "default_group": "X25519",
        "hybrid_supported": True,
        "hybrid_preferred": False,
        "pure_mlkem_supported": True,
        "classical_fallback_ok": True,
        "server_header": "nginx/1.27.0",
    })
    items = remediate_host(host)
    text = "\n".join(items)
    assert "not preferred" in text


def test_legacy_tls_flagged():
    host = _host({
        "tls_version": "TLSv1.2",
        "default_group": "X25519",
        "hybrid_supported": False,
        "pure_mlkem_supported": False,
        "classical_fallback_ok": True,
        "legacy_tls_present": True,
        "server_header": "nginx/1.27.0",
    })
    assert host.verdict == Verdict.LEGACY
    text = "\n".join(remediate_host(host))
    assert "Legacy TLS" in text


def test_legacy_probe_skipped_emits_advisory():
    # Pure-Go mode, no OpenSSL: legacy detection unavailable. The remediation
    # must warn the reader not to interpret the missing legacy flag as proof
    # that TLS 1.0/1.1 is disabled.
    host = _host({
        "default_group": "X25519",
        "hybrid_supported": False,
        "pure_mlkem_supported": False,
        "classical_fallback_ok": True,
        "legacy_tls_present": False,
        "legacy_probe_skipped": True,
        "server_header": "nginx/1.27.0",
    })
    text = "\n".join(remediate_host(host))
    assert "Legacy TLS 1.0/1.1 detection unavailable" in text
    # The "detected" finding (a separate high-priority item) must not appear,
    # because the probe was skipped and no legacy TLS was actually found.
    assert "high] Legacy TLS detected" not in text


def test_legacy_probe_skipped_suppressed_when_legacy_present():
    # Edge case: if legacy_tls_present is True AND skipped is True (shouldn't
    # normally happen, but defends against contradictory output), the
    # "detected" item wins and the "unavailable" advisory is suppressed.
    host = _host({
        "tls_version": "TLSv1.2",
        "default_group": "X25519",
        "hybrid_supported": False,
        "pure_mlkem_supported": False,
        "classical_fallback_ok": True,
        "legacy_tls_present": True,
        "legacy_probe_skipped": True,
        "server_header": "nginx/1.27.0",
    })
    text = "\n".join(remediate_host(host))
    assert "Legacy TLS detected" in text
    assert "detection unavailable" not in text
