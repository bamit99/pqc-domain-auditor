"""Deterministic remediation engine.

Maps observed probe findings to concrete, copy-pasteable remediation steps.
Stack detection uses the HTTP ``Server`` header (captured during the default
probe) plus behavioural signals from the handshake.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..analysis.models import HostResult, Verdict

STACK_FIXES: dict[str, tuple[str, str]] = {
    "nginx": (
        "nginx (OpenSSL 3.5+)",
        "Add the hybrid post-quantum group to your TLS configuration, keeping a "
        "classical fallback for older clients:\n\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n\n"
        "Rebuild nginx against OpenSSL 3.5+ (nginx 1.27+). Verify with:\n"
        "    openssl s_client -groups X25519MLKEM768 -connect <host>:443 | grep 'Negotiated'",
    ),
    "apache": (
        "Apache httpd (OpenSSL 3.5+)",
        "Enable the hybrid post-quantum group via mod_ssl, keeping classical fallback:\n\n"
        "    SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:P-256\n\n"
        "Requires OpenSSL 3.5+ on the platform. Restart httpd and verify with:\n"
        "    openssl s_client -groups X25519MLKEM768 -connect <host>:443 | grep 'Negotiated'",
    ),
    "caddy": (
        "Caddy (Go 1.24+)",
        "Caddy enables X25519MLKEM768 by default when built on Go 1.24+. If a custom "
        "`key_exchange_algorithms` (or `curves`) directive exists, it replaces the default "
        "list - include `x25519mlkem768` in it. Otherwise no change is needed.",
    ),
    "haproxy": (
        "HAProxy 3.x (OpenSSL 3.5+)",
        "Set the post-quantum hybrid group for TLS bindings:\n\n"
        "    ssl-default-bind-curves X25519MLKEM768:X25519:secp256r1\n\n"
        "Build HAProxy against OpenSSL 3.5+ and restart.",
    ),
    "iis": (
        "Microsoft IIS / SCHANNEL",
        "IIS uses the OS SCHANNEL TLS stack. Upgrade to Windows Server 2022/2025 or a "
        "platform that ships an OpenSSL 3.5+/BoringSSL TLS library in front of IIS, or "
        "terminate TLS at a reverse proxy that supports hybrid ML-KEM groups. SCHANNEL "
        "does not yet expose X25519MLKEM768.",
    ),
    "cloudflare": (
        "Cloudflare (CDN edge)",
        "Cloudflare enables X25519MLKEM768 on essentially all proxied sites. If the scan "
        "target behind Cloudflare still reports no PQ group, the connection is reaching a "
        "non-CDN origin directly (or an Enterprise 'Custom SSL' setup). Enable 'Post-quantum "
        "support' in the Cloudflare dashboard (SSL/TLS > Edge Certificates) and ensure the "
        "origin also supports ML-KEM for end-to-end protection.",
    ),
    "akamai": (
        "Akamai (CDN edge)",
        "Enable post-quantum key exchange for the delivery property via Akamai Control Center "
        "(TLS > Post-quantum). Akamai supports X25519MLKEM768 on its edge; the origin should "
        "also be upgraded for end-to-end protection.",
    ),
    "aws": (
        "AWS (ELB / CloudFront / ALB)",
        "AWS edge supports hybrid ML-KEM for TLS termination. Enable it in the service "
        "configuration (CloudFront: security-policy/custom TLS options) and upgrade the "
        "origin's TLS library to OpenSSL 3.5+ so the handshake is PQ end-to-end.",
    ),
    "f5": (
        "F5 BIG-IP",
        "Upgrade BIG-IP to a TMOS version whose TLS library supports hybrid ML-KEM groups "
        "(TMOS 17.x+/18.x with updated OpenSSL), then add X25519MLKEM768 to the client- and "
        "server-side cipher/curve configuration (SSL profiles > Client/Server > Cipher Group).",
    ),
    "citrix": (
        "Citrix ADC / NetScaler",
        "Upgrade Citrix ADC/NetScaler to a release that ships OpenSSL 3.5+ with hybrid ML-KEM "
        "support, then add X25519MLKEM768 to the SSL profile's ECC curve list.",
    ),
    "netiq": (
        "NetIQ / Micro Focus Identity Provider",
        "The Identity Provider (IDP) origin uses its own TLS library and rejects PQ-hybrid "
        "handshakes. Enable X25519MLKEM768 (and other ML-KEM hybrids) on the IDP origin's TLS "
        "termination, or front it with a PQ-capable reverse proxy. IDP login portals are the "
        "most sensitive surface (SSO) - prioritise this endpoint.",
    ),
    "istio": (
        "Istio / Envoy",
        "Upgrade Envoy/Istio to a build with OpenSSL 3.5+ or BoringSSL ML-KEM support and "
        "enable the hybrid group in the gateway/filter chain. Envoy's default curve list "
        "should include x25519mlkem768 for TLS 1.3.",
    ),
}

GENERIC_FIX = (
    "Generic / unknown server",
    "Upgrade the TLS termination stack to a library with native ML-KEM support "
    "(OpenSSL 3.5+, BoringSSL, rustls 0.22+, Go 1.24+ crypto/tls, GnuTLS 3.8.6+ or NSS), "
    "enable TLS 1.3, and offer the hybrid group X25519MLKEM768 (RFC 9794) with a classical "
    "X25519/P-256 fallback:\n\n"
    "    -groups X25519MLKEM768:X25519:secp256r1\n\n"
    "Verify after change: openssl s_client -groups X25519MLKEM768 -connect <host>:443 should "
    "report 'Negotiated TLS1.3 group: X25519MLKEM768'.",
)

TLS13_FIX = (
    "TLS 1.3 is not enabled",
    "Enable TLS 1.3 - hybrid ML-KEM key exchange is only defined for TLS 1.3. "
    "Keep TLS 1.2 for legacy clients but ensure TLS 1.3 is offered and preferred.",
)


def _detect_stack(server_header: str | None) -> str | None:
    if not server_header:
        return None
    header = server_header.lower()
    if "cloudflare" in header:
        return "cloudflare"
    if "akamaighost" in header or "akamai" in header:
        return "akamai"
    if "amazon" in header or "awselb" in header or "cloudfront" in header or "s3" in header:
        return "aws"
    if "nginx" in header:
        return "nginx"
    if "apache" in header:
        return "apache"
    if "caddy" in header:
        return "caddy"
    if "haproxy" in header:
        return "haproxy"
    if "iis" in header or "microsoft-iis" in header:
        return "iis"
    if "netiq" in header or "novell" in header:
        return "netiq"
    if "f5" in header or "big-ip" in header:
        return "f5"
    if "citrix" in header or "netscaler" in header:
        return "citrix"
    if "istio" in header or "envoy" in header:
        return "istio"
    return None


@dataclass
class RemediationItem:
    priority: str
    title: str
    detail: str


def remediate_host(host: HostResult) -> list[str]:
    """Return a list of remediation text blocks for a host, or [] when fully ready."""
    probe = host.primary_probe
    if probe is None or not probe.reachable:
        return [
            "Host is unreachable or has no TLS endpoint on the scanned port(s). "
            "Verify DNS/A records, firewalling, and that a TLS service is listening "
            "before remediation can be assessed."
        ]

    stack = _detect_stack(probe.server_header) or ""
    items: list[RemediationItem] = []
    stack_name, stack_fix = STACK_FIXES.get(stack, GENERIC_FIX)

    pq_any = probe.hybrid_supported or probe.pure_mlkem_supported

    if host.verdict in (Verdict.NOT_READY, Verdict.LEGACY) or not pq_any:
        if probe.legacy_tls_present:
            items.append(RemediationItem("high", "Legacy TLS detected",
                "TLS 1.0/1.1 is enabled. Disable legacy protocols and require TLS 1.2+ "
                "(prefer TLS 1.3)."))
        if not (probe.tls_version or "").startswith("TLSv1.3"):
            items.append(RemediationItem("high", *TLS13_FIX))
        items.append(RemediationItem("high", f"Enable hybrid post-quantum key exchange ({stack_name})",
                                     stack_fix))
    elif not probe.hybrid_preferred and (probe.hybrid_supported or probe.pure_mlkem_supported):
        items.append(RemediationItem("medium", "PQC supported but not preferred",
            "The server accepts post-quantum groups but prefers a classical group on the "
            "default handshake. Reorder groups so X25519MLKEM768 is first in the curve list "
            "while keeping X25519/P-256 as fallback."))
    elif probe.pure_mlkem_supported and not probe.hybrid_supported:
        items.append(RemediationItem("medium", "Pure ML-KEM only - add hybrid",
            "Server supports pure ML-KEM only. Add the hybrid group X25519MLKEM768 so modern "
            "clients negotiate a hybrid handshake and the deployment is not single-algorithm."))

    if probe.hybrid_supported and not probe.classical_fallback_ok:
        items.append(RemediationItem("medium", "Classical fallback missing",
            "PQ-only with no classical fallback risks locking out older clients. Keep "
            "X25519 / P-256 in the supported-groups list."))

    if probe.cert_signature_algorithm and "ML-DSA" not in (probe.cert_signature_algorithm or ""):
        items.append(RemediationItem("low", "Certificate signature is classical",
            f"Certificate signed with {probe.cert_signature_algorithm}. Session confidentiality "
            "is already PQ-protected by key exchange, but plan ML-DSA (FIPS 204) certificates "
            "once CAs issue them - this closes the last classical link (authentication)."))

    return [f"[{item.priority}] {item.title}:\n{item.detail}" for item in items]


def summarise_findings(host: HostResult) -> str:
    """One-line human summary used by the LLM narrative prompt."""
    probe = host.primary_probe
    if probe is None:
        return f"{host.hostname}: unreachable"
    bits = [
        f"tls={probe.tls_version}",
        f"group={probe.default_group}",
        f"hybrid={probe.hybrid_supported}",
        f"pure={probe.pure_mlkem_supported}",
        f"fallback={probe.classical_fallback_ok}",
        f"cert_sig={probe.cert_signature_algorithm}",
        f"score={host.score}",
    ]
    return f"{host.hostname}: " + ", ".join(bits)
