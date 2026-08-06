"""CLI entrypoint for pqc-domain-auditor."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from . import __version__
from .analysis.models import DomainResult, Verdict
from .analysis.scoring import domain_score
from .config import Settings
from .discovery.orchestrator import discover
from .probe.orchestrator import audit_host
from .probe.preflight import preflight
from .remediation.engine import remediate_host
from .remediation.llm import generate_narrative
from .report import exporters

app = typer.Typer(
    name="pqcaudit",
    help="Post-Quantum (ML-KEM) TLS readiness auditor with remediation guidance.",
    add_completion=False,
)
console = Console()

VERDICT_STYLE = {
    Verdict.READY: ("green", "ready"),
    Verdict.CAPABLE: ("yellow", "capable"),
    Verdict.PURE_ONLY: ("yellow", "pure-only"),
    Verdict.NOT_READY: ("red", "not-ready"),
    Verdict.LEGACY: ("red", "legacy"),
    Verdict.UNREACHABLE: ("dim", "unreachable"),
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )


def _valid_domain(value: str) -> str:
    import re

    value = value.strip().lower().rstrip(".")
    if not value or " " in value:
        raise typer.BadParameter(f"invalid domain: '{value}'")
    # Reject anything that isn't a dot-separated sequence of LDH labels.
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", value) or ".." in value:
        raise typer.BadParameter(f"invalid domain: '{value}'")
    if any(label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise typer.BadParameter(f"invalid domain: '{value}'")
    return value


def _write_report(result: DomainResult, narrative: str | None, outdir: Path, formats: list[str]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    slug = result.domain.replace(".", "-")
    written: list[str] = []
    if "json" in formats:
        path = outdir / f"{slug}-pqc.json"
        path.write_text(exporters.to_json(result), encoding="utf-8")
        written.append(str(path))
    if "csv" in formats:
        path = outdir / f"{slug}-pqc.csv"
        # newline="" prevents the csv module's \r\n from being doubled on Windows.
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(exporters.to_csv(result))
        written.append(str(path))
    if "md" in formats or "markdown" in formats:
        path = outdir / f"{slug}-pqc.md"
        path.write_text(exporters.to_markdown(result, narrative), encoding="utf-8")
        written.append(str(path))
    if "html" in formats:
        path = outdir / f"{slug}-pqc.html"
        path.write_text(exporters.to_html(result, narrative), encoding="utf-8")
        written.append(str(path))
    for written_path in written:
        console.print(f"  [bold green]wrote[/] {written_path}")


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Root domain to audit, e.g. example.com", callback=_valid_domain),
    outdir: Path = typer.Option(Path("reports"), "--outdir", "-o", help="Directory for report files"),
    formats: str = typer.Option("md,html,json,csv", "--format", "-f", help="Comma-separated report formats"),
    ports: str = typer.Option("443", "--port", "-p", help="Comma-separated ports to probe"),
    concurrency: int = typer.Option(32, "--concurrency", "-c", help="Max concurrent probes"),
    timeout: float = typer.Option(12.0, "--timeout", "-t", help="Per-handshake timeout (seconds)"),
    use_ct: bool = typer.Option(True, "--ct/--no-ct", help="Use certificate transparency logs"),
    use_dns: bool = typer.Option(True, "--dns/--no-dns", help="Use DNS records for discovery"),
    hosts: str | None = typer.Option(
        None,
        "--hosts",
        help="Comma-separated extra hostnames to audit (e.g. endpoints behind wildcard certs "
        "that CT logs cannot enumerate)",
    ),
    llm_provider: str | None = typer.Option(
        None,
        "--llm",
        help="LLM provider for narrative: openai, anthropic, ollama, or a custom OpenAI-compatible URL",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging"),
) -> None:
    """Discover subdomains of DOMAIN and audit their post-quantum TLS readiness."""
    asyncio.run(
        _scan_async(
            domain=domain,
            outdir=outdir,
            formats=formats,
            ports=ports,
            concurrency=concurrency,
            timeout=timeout,
            use_ct=use_ct,
            use_dns=use_dns,
            extra_hosts=hosts,
            llm_provider=llm_provider,
            verbose=verbose,
        )
    )


async def _scan_async(
    *,
    domain: str,
    outdir: Path,
    formats: str,
    ports: str,
    concurrency: int,
    timeout: float,
    use_ct: bool,
    use_dns: bool,
    extra_hosts: str | None,
    llm_provider: str | None,
    verbose: bool,
) -> None:
    _setup_logging(verbose)
    settings = Settings(
        concurrency=concurrency,
        connect_timeout=timeout,
        ports=tuple(int(p) for p in ports.split(",")),
    )

    console.print(f"[bold]pqc-domain-auditor v{__version__}[/]")
    console.print(f"Auditing [bold cyan]{domain}[/] ...")

    console.print("Checking OpenSSL preflight ...")
    pre = preflight(settings.openssl_bin)
    if not pre.ok:
        console.print(f"[bold red]Preflight failed:[/]\n{pre.error}")
        raise typer.Exit(1)
    console.print(f"  [green]ok[/] OpenSSL {pre.version} with ML-KEM groups")

    start = time.monotonic()
    hostnames, ip_map = await discover(
        domain, use_ct=use_ct, use_dns=use_dns, crtsh_base=settings.crtsh_base
    )

    added_hosts: set[str] = set()
    if extra_hosts:
        from .discovery.dns import resolve_hostnames

        added_hosts = {h.strip().lower() for h in extra_hosts.split(",") if h.strip()}
        added_hosts -= hostnames
        added_ips = await asyncio.get_running_loop().run_in_executor(
            None, resolve_hostnames, added_hosts
        )
        ip_map.update({h: ips for h, ips in added_ips.items() if ips})
        hostnames = hostnames | {h for h, ips in added_ips.items() if ips}

    console.print(f"Discovered [bold]{len(hostnames)}[/] resolvable hostnames for [cyan]{domain}[/]")

    sem = asyncio.Semaphore(settings.concurrency)

    async def _audit(hostname: str):
        async with sem:
            return await audit_host(
                settings.openssl_bin,
                hostname,
                ip_map.get(hostname, []),
                ports=settings.ports,
                concurrency=settings.concurrency,
                timeout=settings.connect_timeout,
            )

    audited = await asyncio.gather(*(_audit(h) for h in hostnames))

    for host in audited:
        host.remediation = remediate_host(host)

    score, summary = domain_score(audited)
    result = DomainResult(
        domain=domain,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=time.monotonic() - start,
        hosts=audited,
        domain_score=score,
        summary=summary,
    )

    narrative: str | None = None
    provider = llm_provider or settings.llm_provider
    if provider:
        console.print(f"Generating LLM narrative via [cyan]{provider}[/] ...")
        narrative = await generate_narrative(
            result,
            provider=provider,
            model=settings.llm_model,
            api_key=settings.llm_api_key,
            base_url=settings.llm_base_url,
            endpoint=settings.llm_endpoint,
        )
        if narrative:
            console.print("  [green]ok[/] narrative generated")
        else:
            console.print("  [yellow]warn[/] narrative unavailable - deterministic remediation only")

    table = Table(title=f"PQC TLS readiness for {domain} - {score}/100", show_lines=False)
    table.add_column("Hostname", style="bold")
    table.add_column("Verdict")
    table.add_column("Score")
    table.add_column("TLS")
    table.add_column("Group")
    table.add_column("Hybrid")
    table.add_column("Pure")
    table.add_column("Fallback")
    table.add_column("Server")

    for host in sorted(audited, key=lambda h: h.hostname):
        probe = host.primary_probe
        verdict = host.verdict
        color, label = VERDICT_STYLE.get(verdict, ("dim", "n/a"))
        table.add_row(
            host.hostname,
            f"[{color}]{label}[/]",
            str(host.score),
            (probe.tls_version or "-") if probe else "-",
            (probe.default_group or "-") if probe else "-",
            "yes" if probe and probe.hybrid_supported else "no",
            "yes" if probe and probe.pure_mlkem_supported else "no",
            "ok" if probe and probe.classical_fallback_ok else "-",
            (probe.server_header or "-") if probe else "-",
        )
    console.print(table)

    fmt_list = [f.strip().lower() for f in formats.split(",") if f.strip()]
    console.print(f"Writing reports to [bold]{outdir}[/] ...")
    _write_report(result, narrative, outdir, fmt_list)

    console.print(
        f"[bold green]Done.[/] {len(audited)} hosts in {result.duration_seconds:.1f}s. "
        f"Domain score: {score}/100"
    )


@app.command("preflight", help="Alias for preflight-check.")
def preflight_alias() -> None:
    """Alias for preflight-check."""
    preflight_check()


@app.command("preflight-check")
def preflight_check() -> None:
    """Check that the required OpenSSL binary with ML-KEM support is available."""
    settings = Settings()
    pre = preflight(settings.openssl_bin)
    if pre.ok:
        console.print(f"[green]OK[/] OpenSSL {pre.version} at {pre.openssl_bin}")
        console.print(f"Groups: {', '.join(sorted(pre.groups))}")
    else:
        console.print(f"[bold red]FAILED[/]\n{pre.error}")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show tool version."""
    console.print(f"pqc-domain-auditor v{__version__}")


if __name__ == "__main__":
    app()
