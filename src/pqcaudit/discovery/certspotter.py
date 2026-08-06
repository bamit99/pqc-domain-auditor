"""Certificate Transparency enumeration via CertSpotter's public API.

Used as a fallback when crt.sh is unavailable; no API key required at low
volume (rate-limited).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

import httpx

log = logging.getLogger(__name__)

BASE = "https://api.certspotter.com/v1/issuances"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _extract_names(entries: Iterable[dict]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        for name in entry.get("dns_names") or []:
            name = name.strip().lower()
            if name and not name.startswith("*."):
                names.add(name)
    return names


async def fetch_certspotter(
    client: httpx.AsyncClient,
    domain: str,
    base: str = BASE,
) -> set[str]:
    """Return hostnames for ``domain`` from CertSpotter (or empty set on failure)."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    try:
        resp = await client.get(base, params=params)
        resp.raise_for_status()
        entries = resp.json()
        if not isinstance(entries, list):
            return set()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("CertSpotter query failed for %s: %s", domain, exc)
        return set()

    names = _extract_names(entries)
    return {n for n in names if n == domain or n.endswith("." + domain)}
