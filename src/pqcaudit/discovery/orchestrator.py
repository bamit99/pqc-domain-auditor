"""High-level discovery orchestrator.

Discovery is passive: certificate-transparency logs and DNS records are
queried, but no traffic is sent toward the target itself until the later TLS
probe phase.

DNS fan-out is deliberately resolver-friendly. A large domain can surface tens
of thousands of CT names; firing them at the local resolver in parallel looks
like an attack, and a resolver that decides to rate-limit us turns every lookup
into a timeout - which the scan would then report as a dead domain. Lookups are
therefore paced (``resolve_rps`` queries per second, spread over time by a token
bucket), capped in flight (``resolve_concurrency``), and the candidate list is
truncated at ``max_hosts`` with the shallowest names first.

``on_stage`` is an optional ``(message) -> None`` callback invoked at each phase
boundary so a caller (the CLI) can show progress. It runs on the event loop
thread, so keep it cheap.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import certspotter, crtsh, dns

log = logging.getLogger(__name__)

# Resolver-friendly defaults: 8 lookups in flight at 15 queries per second is
# mild enough for a shared or corporate resolver, and 2000 candidates keeps a
# 10k-name CT domain from hammering it.
RESOLVE_CONCURRENCY = 8
RESOLVE_RPS = 15.0
MAX_HOSTS = 2000

# Share of lookups that time out before we blame the resolver for rate-limiting
# us rather than the hosts being dead.
THROTTLE_TIMEOUT_RATIO = 0.30

StageCallback = Callable[[str], None]


def _stage(on_stage: StageCallback | None, message: str) -> None:
    if on_stage is not None:
        on_stage(message)


def _shallow_first(names: set[str]) -> list[str]:
    """Order candidates so the apex and shallow subdomains come first.

    Truncation has to be deterministic, so two runs of the same domain resolve
    the same set, and it has to favour the names most likely to be live.
    """
    return sorted(names, key=lambda n: (n.count("."), n))


class _RateLimiter:
    """Token bucket pacing DNS lookups at ``rps`` queries per second.

    Each acquire waits until the query is allowed, then advances the allowance
    by one interval. Holding the lock across the sleep is what makes the spacing
    real: acquires are serialised onto the meter, so a burst of candidates is
    spread over time instead of fired at the resolver at once.
    """

    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
                self._next += self._interval
            else:
                self._next = now + self._interval


async def discover(
    domain: str,
    use_ct: bool = True,
    use_dns: bool = True,
    crtsh_base: str = "https://crt.sh",
    on_stage: StageCallback | None = None,
    resolve_concurrency: int = RESOLVE_CONCURRENCY,
    resolve_rps: float = RESOLVE_RPS,
    max_hosts: int = MAX_HOSTS,
    nameservers: list[str] | None = None,
) -> tuple[set[str], dict[str, list[str]]]:
    """Enumerate hostnames for ``domain`` and resolve them.

    Returns ``(hostnames, ip_map)``. ``hostnames`` is the set of candidates that
    actually resolved - empty when nothing does - and ``ip_map`` maps each
    candidate that was looked up to its addresses.
    """
    candidates: set[str] = {domain}

    if use_ct:
        _stage(on_stage, f"querying certificate transparency logs ({crtsh_base})")
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=True) as client:
            log.info("Querying certificate transparency logs for %s", domain)
            ct_names = await crtsh.fetch_crt_sh(client, domain, base=crtsh_base)
            if ct_names:
                _stage(on_stage, f"crt.sh returned {len(ct_names)} hostname(s)")
                candidates |= ct_names
            else:
                _stage(on_stage, "crt.sh returned no data; trying CertSpotter")
                log.info("crt.sh returned no data for %s; falling back to CertSpotter", domain)
                spotter = await certspotter.fetch_certspotter(client, domain)
                if spotter:
                    _stage(on_stage, f"CertSpotter returned {len(spotter)} hostname(s)")
                else:
                    _stage(on_stage, "CertSpotter returned no data")
                candidates |= spotter

    loop = asyncio.get_running_loop()
    workers = max(1, resolve_concurrency)

    # dnspython is blocking, so every lookup runs in a worker thread. A dedicated
    # pool is required: asyncio's default executor silently caps at
    # min(32, cpu+4), so a semaphore alone cannot control the concurrency.
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns") as executor:
        if use_dns:
            _stage(on_stage, f"gathering DNS records for {domain}")
            log.info("Gathering DNS records for %s", domain)
            dns_names = await loop.run_in_executor(executor, dns.discover_from_dns, domain, nameservers)
            candidates |= dns_names

        ordered = _shallow_first(candidates)
        total = len(ordered)
        if max_hosts > 0 and total > max_hosts:
            kept = ordered[:max_hosts]
            _stage(
                on_stage,
                f"truncating {total} candidates to {max_hosts} (shallowest first); "
                f"{total - max_hosts} not resolved",
            )
        else:
            kept = ordered

        _stage(
            on_stage,
            f"resolving {len(kept)} candidate hostname(s) at {resolve_rps} query/s "
            f"with {workers} in flight",
        )

        sem = asyncio.Semaphore(workers)
        limiter = _RateLimiter(resolve_rps)

        async def _resolve(hostname: str) -> tuple[str, list[str], bool]:
            async with sem:
                await limiter.acquire()
                ips, timed_out = await loop.run_in_executor(
                    executor, dns.resolve_one, hostname, nameservers
                )
                return hostname, ips, timed_out

        results = await asyncio.gather(*(_resolve(h) for h in kept))
        ip_map: dict[str, list[str]] = {h: ips for h, ips, _ in results}
        timeouts = sum(1 for _, _, timed_out in results if timed_out)

        if kept and timeouts / len(kept) >= THROTTLE_TIMEOUT_RATIO:
            _stage(
                on_stage,
                f"warn: {timeouts} of {len(kept)} lookups timed out - the resolver is likely "
                f"rate-limiting us; lower --resolve-rps / --resolve-concurrency",
            )
            log.warning(
                "%s of %s DNS lookups timed out for %s - the resolver is likely rate-limiting. "
                "Lower PQC_RESOLVE_RPS / PQC_RESOLVE_CONCURRENCY.",
                timeouts,
                len(kept),
                domain,
            )

    resolvable = {h for h, ips in ip_map.items() if ips}
    _stage(on_stage, f"{len(resolvable)} of {len(kept)} candidate hostname(s) resolved")

    return resolvable, ip_map
