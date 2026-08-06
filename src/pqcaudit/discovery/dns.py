"""DNS record gathering and resolution via dnspython."""

from __future__ import annotations

import logging

import dns.resolver

log = logging.getLogger(__name__)

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    return resolver


def _collect_names(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> set[str]:
    """Return names referenced by a record type for the domain."""
    names: set[str] = set()
    try:
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
        return names
    for rdata in answers:
        for token in rdata.to_text().split():
            if token in ("IN", rtype, "MX", "TXT", "NS", "CNAME", "A", "AAAA"):
                continue
            cleaned = token.strip('"').lower()
            if "." in cleaned:
                names.add(cleaned)
    return names


def discover_from_dns(domain: str) -> set[str]:
    """Return hostnames referenced by the domain's own DNS records."""
    resolver = _resolver()
    names: set[str] = set()
    for rtype in RECORD_TYPES:
        names.update(_collect_names(resolver, domain, rtype))
    return {n for n in names if n == domain or n.endswith("." + domain)}


def resolve_hostnames(hostnames: set[str]) -> dict[str, list[str]]:
    """Resolve each hostname to its A/AAAA addresses (empty list on failure)."""
    resolver = _resolver()
    out: dict[str, list[str]] = {}
    for hostname in hostnames:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, rtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                continue
            ips.extend(rdata.to_text() for rdata in answers)
        out[hostname] = ips
    return out
