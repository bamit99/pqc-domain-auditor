"""Tests for the Go dialer probe output parsing."""

import json

from pqcaudit.probe.go_probe import parse_go_output


def _line(**kw) -> str:
    data = {"probe": "default", "ok": True, "tls_version": "TLSv1.3"}
    data.update(kw)
    return json.dumps(data)


def test_parse_go_output_success():
    line = _line(
        cipher="TLS_AES_256_GCM_SHA384",
        group="X25519MLKEM768",
        server_header="cloudflare",
    )
    outcome = parse_go_output(line)
    assert outcome.success
    assert outcome.tls_version == "TLSv1.3"
    assert outcome.cipher == "TLS_AES_256_GCM_SHA384"
    assert outcome.group == "X25519MLKEM768"
    assert outcome.server_header == "cloudflare"


def test_parse_go_output_normalizes_hybrid_spelling():
    # Go reports the P-256/P-384 hybrid groups differently than OpenSSL.
    assert parse_go_output(_line(group="P-256MLKEM768")).group == "SecP256r1MLKEM768"
    assert parse_go_output(_line(group="P-384MLKEM1024")).group == "SecP384r1MLKEM1024"
    assert parse_go_output(_line(group="X25519")).group == "X25519"


def test_parse_go_output_failure():
    line = _line(ok=False, error="handshake failed: tls: handshake failure")
    outcome = parse_go_output(line)
    assert not outcome.success
    assert "handshake failed" in (outcome.error or "")


def test_parse_go_output_invalid_json():
    outcome = parse_go_output("not json at all")
    assert not outcome.success
    assert outcome.error


def test_parse_go_output_cert_pem():
    import base64

    der = b"\x30\x82\x01\x00\x02\x01\x01"  # tiny fake DER
    line = _line(cert_der_b64=base64.b64encode(der).decode("ascii"))
    outcome = parse_go_output(line)
    assert outcome.cert_pem
    assert outcome.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert outcome.cert_pem.rstrip().endswith("-----END CERTIFICATE-----")
