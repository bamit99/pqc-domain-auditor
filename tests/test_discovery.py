"""Tests for DNS resolution semantics and the resolver-friendly discovery fan-out."""

from __future__ import annotations

import threading
import time

import dns.resolver

from pqcaudit.discovery import dns as dns_mod
from pqcaudit.discovery.orchestrator import discover


class _FakeRData:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _StubResolver:
    """Fake dnspython Resolver keyed by (hostname, record type)."""

    def __init__(self, behaviour: dict[tuple[str, str], tuple[str, list[str]]]) -> None:
        self.behaviour = behaviour

    def resolve(self, qname: str, qtype: str = "A", raise_on_no_answer: bool = True) -> list[_FakeRData]:
        mode, payload = self.behaviour.get((qname, qtype), ("nxdomain", []))
        if mode == "ok":
            return [_FakeRData(ip) for ip in payload]
        if mode == "nxdomain":
            raise dns.resolver.NXDOMAIN
        if mode == "noanswer":
            raise dns.resolver.NoAnswer
        if mode == "nonameservers":
            raise dns.resolver.NoNameservers
        if mode == "timeout":
            raise dns.resolver.Timeout
        raise AssertionError(f"unknown mode {mode}")


def test_resolve_one_returns_ips_and_no_timeout(monkeypatch):
    stub = _StubResolver({("a.example.com", "A"): ("ok", ["1.2.3.4"])})
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("a.example.com")
    assert ips == ["1.2.3.4"]
    assert timed_out is False


def test_resolve_one_collects_a_and_aaaa(monkeypatch):
    stub = _StubResolver(
        {
            ("a.example.com", "A"): ("ok", ["1.2.3.4"]),
            ("a.example.com", "AAAA"): ("ok", ["2001:db8::1"]),
        }
    )
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("a.example.com")
    assert ips == ["1.2.3.4", "2001:db8::1"]
    assert timed_out is False


def test_resolve_one_treats_nxdomain_as_absence_not_throttle(monkeypatch):
    stub = _StubResolver({})
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("gone.example.com")
    assert ips == []
    assert timed_out is False


def test_resolve_one_treats_noanswer_as_absence_not_throttle(monkeypatch):
    stub = _StubResolver({("a.example.com", "A"): ("noanswer", []), ("a.example.com", "AAAA"): ("ok", ["1.2.3.4"])})
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("a.example.com")
    assert ips == ["1.2.3.4"]
    assert timed_out is False


def test_resolve_one_treats_timeout_as_throttle_signal(monkeypatch):
    stub = _StubResolver({("a.example.com", "A"): ("timeout", [])})
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("a.example.com")
    assert ips == []
    assert timed_out is True


def test_resolve_one_treats_no_nameservers_as_throttle_signal(monkeypatch):
    stub = _StubResolver({("a.example.com", "A"): ("nonameservers", [])})
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: stub)
    ips, timed_out = dns_mod.resolve_one("a.example.com")
    assert ips == []
    assert timed_out is True


def test_resolver_applies_configured_nameservers():
    # PQC_DNS_RESOLVER must reach the resolver, not stay dead config.
    assert dns_mod._resolver(["10.0.0.53"]).nameservers == ["10.0.0.53"]


def test_thread_resolver_caches_per_thread():
    main = dns_mod._thread_resolver()
    assert dns_mod._thread_resolver() is main
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as ex:
        other = ex.submit(dns_mod._thread_resolver).result()
    assert other is not main


async def test_discover_returns_empty_when_nothing_resolves(monkeypatch):
    # No fallback to the apex domain: an empty result must stay empty so the CLI
    # can fail with the real reason instead of scoring a dead-looking domain.
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: set())
    monkeypatch.setattr(dns_mod, "_thread_resolver", lambda nameservers=None: _StubResolver({}))
    hostnames, ip_map = await discover("example.com", use_ct=False, resolve_rps=0)
    assert hostnames == set()
    assert ip_map == {"example.com": []}


async def test_discover_truncates_to_max_hosts_shallowest_first(monkeypatch):
    names = {"a.example.com", "b.example.com", "deep.sub.example.com", "example.com"}
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: names)

    def fake_resolve_one(hostname, nameservers=None):
        return ["10.0.0.1"], False

    monkeypatch.setattr(dns_mod, "resolve_one", fake_resolve_one)
    hostnames, _ = await discover("example.com", use_ct=False, resolve_rps=0, max_hosts=2)
    assert hostnames == {"example.com", "a.example.com"}


async def test_discover_caps_in_flight_at_resolve_concurrency(monkeypatch):
    names = {f"h{i}.example.com" for i in range(10)}
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: names)
    active, peak = 0, 0
    lock = threading.Lock()

    def fake_resolve_one(hostname, nameservers=None):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return ["10.0.0.1"], False

    monkeypatch.setattr(dns_mod, "resolve_one", fake_resolve_one)
    await discover("example.com", use_ct=False, resolve_concurrency=3, resolve_rps=0)
    assert peak <= 3


async def test_discover_paces_lookups_at_resolve_rps(monkeypatch):
    names = {f"h{i}.example.com" for i in range(6)}
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: names)
    stamps: list[float] = []

    def fake_resolve_one(hostname, nameservers=None):
        stamps.append(time.monotonic())
        return ["10.0.0.1"], False

    monkeypatch.setattr(dns_mod, "resolve_one", fake_resolve_one)
    rps = 20.0
    await discover("example.com", use_ct=False, resolve_concurrency=6, resolve_rps=rps)
    # The apex domain is always a candidate, so 6 subdomains means 7 lookups.
    assert len(stamps) == 7
    # Seven lookups at 20/s must span at least five intervals, not fire at once.
    assert max(stamps) - min(stamps) >= 5 / rps


async def test_discover_runs_dns_lookups_off_the_event_loop(monkeypatch):
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: set())
    loop_thread = threading.current_thread().name
    threads: list[str] = []

    def spy(hostname, nameservers=None):
        threads.append(threading.current_thread().name)
        return ["10.0.0.1"], False

    monkeypatch.setattr(dns_mod, "resolve_one", spy)
    await discover("example.com", use_ct=False, resolve_rps=0)
    assert threads
    assert all(t != loop_thread for t in threads)


async def test_discover_warns_when_lookups_time_out(monkeypatch):
    names = {f"h{i}.example.com" for i in range(10)}
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: names)

    def fake_resolve_one(hostname, nameservers=None):
        return [], True

    monkeypatch.setattr(dns_mod, "resolve_one", fake_resolve_one)
    stages: list[str] = []
    hostnames, _ = await discover("example.com", use_ct=False, resolve_rps=0, on_stage=stages.append)
    assert hostnames == set()
    assert any("timed out" in s and "rate-limiting" in s for s in stages)


async def test_discover_does_not_warn_below_throttle_threshold(monkeypatch):
    names = {f"h{i}.example.com" for i in range(10)}
    monkeypatch.setattr(dns_mod, "discover_from_dns", lambda domain, nameservers=None: names)

    def fake_resolve_one(hostname, nameservers=None):
        timed_out = hostname in ("h0.example.com", "h1.example.com")
        return ([] if timed_out else ["10.0.0.1"]), timed_out

    monkeypatch.setattr(dns_mod, "resolve_one", fake_resolve_one)
    stages: list[str] = []
    hostnames, _ = await discover("example.com", use_ct=False, resolve_rps=0, on_stage=stages.append)
    # 2 of 11 candidates (the 10 subdomains plus the apex) time out = 18%, below
    # the 30% threshold, so the resolver is not blamed.
    assert len(hostnames) == 9
    assert not any("rate-limiting" in s for s in stages)
