"""CLI integration tests: progress output, hard failures, and the unreachable table."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pqcaudit.analysis.models import HostProbeResult, HostResult
from pqcaudit.analysis.scoring import classify_host
from pqcaudit.cli import app
from pqcaudit.probe.preflight import PreflightResult

runner = CliRunner()


def _preflight() -> PreflightResult:
    return PreflightResult(
        ok=True,
        backend="go",
        go_dialer="godialer.exe",
        openssl_bin="",
        openssl_version="",
        groups={"X25519MLKEM768"},
        error="",
    )


def _probe(hostname: str, reachable: bool, error: str | None = None) -> HostResult:
    probe = HostProbeResult(
        host=hostname,
        port=443,
        reachable=reachable,
        tls_version="TLS 1.3" if reachable else None,
        default_group="X25519MLKEM768" if reachable else None,
        hybrid_supported=reachable,
        hybrid_preferred=reachable,
        classical_fallback_ok=reachable,
        server_header="nginx" if reachable else None,
        error=error,
    )
    host = HostResult(hostname=hostname, ips=["10.0.0.1"], probes={443: probe})
    # audit_host classifies before returning; the fake must do the same so the
    # CLI sees real verdicts.
    classify_host(host)
    return host


def test_scan_exits_1_when_nothing_resolves(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("pqcaudit.cli.preflight", lambda *a, **kw: _preflight())

    async def fake_discover(domain, **kwargs):
        return set(), {}

    monkeypatch.setattr("pqcaudit.cli.discover", fake_discover)
    result = runner.invoke(app, ["scan", "example.com", "-o", str(tmp_path)])
    assert result.exit_code == 1
    assert "No resolvable hostnames found" in result.stdout
    assert not list(tmp_path.iterdir())


def test_progress_lines_go_to_stderr_not_stdout(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("pqcaudit.cli.preflight", lambda *a, **kw: _preflight())
    hosts = {f"h{i}.example.com" for i in range(30)}

    async def fake_discover(domain, **kwargs):
        return hosts, {h: ["10.0.0.1"] for h in hosts}

    monkeypatch.setattr("pqcaudit.cli.discover", fake_discover)

    async def fake_audit_host(backend, hostname, ips, **kwargs):
        return _probe(hostname, True)

    monkeypatch.setattr("pqcaudit.cli.audit_host", fake_audit_host)
    result = runner.invoke(app, ["scan", "example.com", "-o", str(tmp_path)])
    assert result.exit_code == 0
    # Heartbeat rule: every host up to 25, then every 25th, then the last.
    assert "[25/30]" in result.stderr
    assert "[30/30]" in result.stderr
    assert "[25/30]" not in result.stdout
    assert "PQC TLS readiness for example.com" in result.stdout


def test_unreachable_hosts_are_listed_in_the_terminal(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("pqcaudit.cli.preflight", lambda *a, **kw: _preflight())
    hosts = {"dead.example.com", "live.example.com"}

    async def fake_discover(domain, **kwargs):
        return hosts, {h: ["10.0.0.1"] for h in hosts}

    monkeypatch.setattr("pqcaudit.cli.discover", fake_discover)

    async def fake_audit_host(backend, hostname, ips, **kwargs):
        if hostname == "dead.example.com":
            return _probe(hostname, False, "connection refused")
        return _probe(hostname, True)

    monkeypatch.setattr("pqcaudit.cli.audit_host", fake_audit_host)
    result = runner.invoke(app, ["scan", "example.com", "-o", str(tmp_path)])
    assert result.exit_code == 0
    assert "Unreachable / errored hosts (1)" in result.stdout
    assert "dead.example.com" in result.stdout
    assert "connection refused" in result.stdout
    assert "1 host(s) unreachable" in result.stderr


def test_scan_flags_reach_the_discovery_fan_out(monkeypatch, tmp_path: Path):
    captured: dict[str, object] = {}
    monkeypatch.setattr("pqcaudit.cli.preflight", lambda *a, **kw: _preflight())

    async def fake_discover(domain, **kwargs):
        captured.update(kwargs)
        return {"example.com"}, {"example.com": ["10.0.0.1"]}

    monkeypatch.setattr("pqcaudit.cli.discover", fake_discover)

    async def fake_audit_host(backend, hostname, ips, **kwargs):
        return _probe(hostname, True)

    monkeypatch.setattr("pqcaudit.cli.audit_host", fake_audit_host)
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "-o",
            str(tmp_path),
            "--resolve-concurrency",
            "4",
            "--resolve-rps",
            "7",
            "--max-hosts",
            "123",
        ],
    )
    assert result.exit_code == 0
    assert captured["resolve_concurrency"] == 4
    assert captured["resolve_rps"] == 7.0
    assert captured["max_hosts"] == 123


def test_env_vars_reach_the_discovery_fan_out(monkeypatch, tmp_path: Path):
    # Unset flags must leave the PQC_* environment in charge, not override it
    # with the flag default.
    monkeypatch.setenv("PQC_RESOLVE_CONCURRENCY", "3")
    monkeypatch.setenv("PQC_RESOLVE_RPS", "9")
    monkeypatch.setenv("PQC_MAX_HOSTS", "500")
    monkeypatch.setenv("PQC_DNS_RESOLVER", "10.0.0.53")
    captured: dict[str, object] = {}
    monkeypatch.setattr("pqcaudit.cli.preflight", lambda *a, **kw: _preflight())

    async def fake_discover(domain, **kwargs):
        captured.update(kwargs)
        return {"example.com"}, {"example.com": ["10.0.0.1"]}

    monkeypatch.setattr("pqcaudit.cli.discover", fake_discover)

    async def fake_audit_host(backend, hostname, ips, **kwargs):
        return _probe(hostname, True)

    monkeypatch.setattr("pqcaudit.cli.audit_host", fake_audit_host)
    result = runner.invoke(app, ["scan", "example.com", "-o", str(tmp_path)])
    assert result.exit_code == 0
    assert captured["resolve_concurrency"] == 3
    assert captured["resolve_rps"] == 9.0
    assert captured["max_hosts"] == 500
    assert captured["nameservers"] == ["10.0.0.53"]
