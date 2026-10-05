"""DNS record gathering and resolution via dnspython."""

from __future__ import annotations

import logging
import threading

import dns.resolver

log = logging.getLogger(__name__)

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")

# One Resolver per worker thread. dnspython Resolvers are not safe to share
# across threads doing concurrent queries, and constructing one per lookup is
# needlessly expensive (it re-reads the system resolver config every time).
_local = threading.local()


def _resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    if nameservers:
        resolver.nameservers = list(nameservers)
    return resolver


def _thread_resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    """Resolver for the calling thread, cached per (thread, nameservers)."""
    key = tuple(nameservers or ())
    cache = getattr(_local, "cache", None)
    if cache is None:
        cache = {}
        _local.cache = cache
    resolver = cache.get(key)
    if resolver is None:
        resolver = _resolver(nameservers)
        cache[key] = resolver
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


def discover_from_dns(domain: str, nameservers: list[str] | None = None) -> set[str]:
    """Return hostnames referenced by the domain's own DNS records."""
    resolver = _resolver(nameservers)
    names: set[str] = set()
    for rtype in RECORD_TYPES:
        names.update(_collect_names(resolver, domain, rtype))
    return {n for n in names if n == domain or n.endswith("." + domain)}


def resolve_one(hostname: str, nameservers: list[str] | None = None) -> tuple[list[str], bool]:
    """Resolve one hostname to its A/AAAA addresses.

    Returns ``(ips, timed_out)``. ``timed_out`` is True when a lookup failed with
    a timeout or a no-usable-nameserver error - the signal that the local
    resolver is rate-limiting us - as opposed to NXDOMAIN/NoAnswer, which means
    the name genuinely does not exist. The distinction matters: a throttled
    resolver makes a healthy domain look unreachable.
    """
    resolver = _thread_resolver(nameservers)
    ips: list[str] = []
    timed_out = False
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.resolver.NoNameservers, dns.resolver.Timeout, dns.exception.DNSException):
            timed_out = True
            continue
        ips.extend(rdata.to_text() for rdata in answers)
    return ips, timed_out


def resolve_hostnames(
    hostnames: set[str], nameservers: list[str] | None = None
) -> dict[str, list[str]]:
    """Resolve each hostname to its A/AAAA addresses (empty list on failure)."""
    return {hostname: resolve_one(hostname, nameservers)[0] for hostname in hostnames}
