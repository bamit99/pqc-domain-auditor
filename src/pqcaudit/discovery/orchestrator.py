"""High-level discovery orchestrator."""

from __future__ import annotations

import asyncio
import logging

import httpx

from . import certspotter, crtsh, dns

log = logging.getLogger(__name__)


async def discover(
    domain: str,
    use_ct: bool = True,
    use_dns: bool = True,
    crtsh_base: str = "https://crt.sh",
) -> tuple[set[str], dict[str, list[str]]]:
    """Enumerate hostnames for ``domain`` and resolve them.

    Returns ``(hostnames, ip_map)`` where ``ip_map`` maps each hostname to its
    resolved addresses.
    """
    candidates: set[str] = {domain}

    if use_ct:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=True) as client:
            log.info("Querying certificate transparency logs for %s", domain)
            ct_names = await crtsh.fetch_crt_sh(client, domain, base=crtsh_base)
            if ct_names:
                candidates |= ct_names
            else:
                log.info("crt.sh returned no data for %s; falling back to CertSpotter", domain)
                candidates |= await certspotter.fetch_certspotter(client, domain)

    if use_dns:
        log.info("Gathering DNS records for %s", domain)
        candidates |= dns.discover_from_dns(domain)

    # Resolve in a thread pool (dnspython is blocking).
    loop = asyncio.get_running_loop()
    ip_map = await loop.run_in_executor(None, dns.resolve_hostnames, candidates)

    # Keep only hosts that actually resolve; the apex host may have empty A but
    # still be valid, so keep it only if it resolved.
    resolvable = {h for h, ips in ip_map.items() if ips}
    hostnames = resolvable or {domain}
    return set(hostnames), ip_map
