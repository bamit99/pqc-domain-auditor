"""Tests for openssl s_client output parsing."""

from pqcaudit.probe.openssl_probe import parse_probe_output

TLS13_HYBRID_OUTPUT = """
CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global G2
verify error:num=20:unable to get local issuer certificate
subject=CN = www.example.com
issuer=C = US, O = DigiCert Inc, CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 20 (unable to get local issuer certificate)
---
Negotiated TLS1.3 group: X25519MLKEM768
Post-handshake New Session Ticket arrived:
-----BEGIN CERTIFICATE-----
MIIBgTCCASegAwIBAgIUIAAAAAAAAAAAAAAAAAAAAAAAAAAwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJZXhhbXBsZS5jb20wHhcNMjYwMTAxMDAwMDAwWhcNMjYwMzAx
MDAwMDAwWjAUMRIwEAYDVQQDDAlleGFtcGxlLmNvbTAvMA0GCWCGSAFlAwQCAQUA
BA==
-----END CERTIFICATE-----
"""

FAILURE_OUTPUT = """
CONNECTED(00000003)
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 5 bytes and written 421 bytes
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Alert: handshake failure
"""

TLS12_OUTPUT = """
CONNECTED(00000003)
subject=CN = www.example.com
issuer=C = US, O = Let's Encrypt, CN = R3
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2237 bytes and written 427 bytes
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
"""

HTTP_OUTPUT = """
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group: X25519
HTTP/1.1 200 OK
Server: nginx/1.27.0
Content-Type: text/html
Connection: close
"""


def test_parse_tls13_hybrid():
    outcome = parse_probe_output(TLS13_HYBRID_OUTPUT)
    assert outcome.success
    assert outcome.tls_version == "TLSv1.3"
    assert outcome.cipher == "TLS_AES_256_GCM_SHA384"
    assert outcome.group == "X25519MLKEM768"
    assert outcome.issuer and "DigiCert" in outcome.issuer
    assert outcome.cert_pem and outcome.cert_pem.startswith("-----BEGIN CERTIFICATE-----")


def test_parse_failure():
    outcome = parse_probe_output(FAILURE_OUTPUT)
    assert not outcome.success
    assert outcome.error == "no peer certificate available"


def test_parse_tls12_temp_key():
    outcome = parse_probe_output(TLS12_OUTPUT)
    assert outcome.success
    assert outcome.tls_version == "TLSv1.2"
    assert outcome.cipher == "ECDHE-RSA-AES128-GCM-SHA256"
    assert outcome.group == "X25519"
    assert outcome.peer_signature_type == "ECDSA"


def test_parse_http_server_header():
    outcome = parse_probe_output(HTTP_OUTPUT)
    assert outcome.server_header == "nginx/1.27.0"
    assert outcome.group == "X25519"
