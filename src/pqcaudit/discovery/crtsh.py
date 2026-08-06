"""Certificate Transparency log enumeration via crt.sh.

Passive: no traffic is sent toward the target until the later TLS probe phase.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable

import httpx

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)
RETRIES = 3
RETRY_DELAY = 2.0


async def _fetch_page(client: httpx.AsyncClient, url: str) -> list[dict]:
    last_error: Exception | None = None
    for attempt in range(RETRIES):
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                return []
            return data
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
            log.warning("crt.sh attempt %d/%d failed: %s", attempt + 1, RETRIES, exc)
            if attempt < RETRIES - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
    raise last_error  # type: ignore[misc]


def _extract_names(entries: Iterable[dict]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        name = entry.get("name_value") or ""
        for part in name.splitlines():
            part = part.strip()
            if not part:
                continue
            if part.startswith("*."):
                continue
            names.add(part.lower())
    return names


async def fetch_crt_sh(client: httpx.AsyncClient, domain: str, base: str = "https://crt.sh") -> set[str]:
    """Return all hostnames for ``domain`` found in certificate transparency logs."""
    url = f"{base}/?q=%25.{domain}&output=json"
    try:
        entries = await _fetch_page(client, url)
    except httpx.HTTPError as exc:
        log.warning("crt.sh query failed for %s: %s", domain, exc)
        return set()
    names = _extract_names(entries)
    # Keep names that are within the audited domain.
    return {n for n in names if n == domain or n.endswith("." + domain)}
