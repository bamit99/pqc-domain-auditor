"""Report exporters: markdown, HTML, JSON, CSV."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

from ..analysis.models import DomainResult, HostResult, Verdict

VERDICT_STYLE = {
    Verdict.READY: ("🟢", "ready"),
    Verdict.CAPABLE: ("🟡", "capable"),
    Verdict.PURE_ONLY: ("🟠", "pure-only"),
    Verdict.NOT_READY: ("🔴", "not-ready"),
    Verdict.LEGACY: ("🔴", "legacy"),
    Verdict.UNREACHABLE: ("⚪", "unreachable"),
}


def _verdict_mark(verdict: Verdict | None) -> str:
    if verdict is None:
        return "⚪ n/a"
    symbol, label = VERDICT_STYLE.get(verdict, ("⚪", verdict.value))
    return f"{symbol} {label}"


def _host_row(host: HostResult) -> dict:
    probe = host.primary_probe
    return {
        "hostname": host.hostname,
        "ips": ",".join(host.ips),
        "verdict": host.verdict.value if host.verdict else "",
        "score": host.score,
        "tls_version": probe.tls_version if probe else "",
        "group": probe.default_group if probe else "",
        "hybrid_supported": probe.hybrid_supported if probe else False,
        "pure_mlkem": probe.pure_mlkem_supported if probe else False,
        "fallback": probe.classical_fallback_ok if probe else False,
        "cipher": probe.cipher if probe else "",
        "cert_signature": probe.cert_signature_algorithm if probe else "",
        "server": probe.server_header if probe else "",
        "error": probe.error if probe else "",
    }


def to_json(result: DomainResult) -> str:
    data = result.model_dump()
    data["hosts"] = [_host_row(h) for h in result.hosts]
    return json.dumps(data, indent=2, default=str)


def to_csv(result: DomainResult) -> str:
    rows = [_host_row(h) for h in result.hosts]
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def to_markdown(result: DomainResult, narrative: str | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Post-Quantum TLS Readiness Report",
        "",
        f"**Target:** `{result.domain}`",
        f"**Date:** {now}",
        f"**Duration:** {result.duration_seconds:.1f}s",
        f"**Domain score:** {result.domain_score}/100",
        f"**Hosts scanned:** {len(result.hosts)}",
        "",
    ]
    if result.summary:
        parts = [f"{k}: {v}" for k, v in result.summary.items() if v > 0]
        if parts:
            lines += ["**Summary:** " + ", ".join(parts), ""]

    if narrative:
        lines += ["---", "", "## Remediation Narrative", "", narrative, ""]

    lines += ["---", "", "## Host Results", ""]
    for host in sorted(result.hosts, key=lambda h: h.hostname):
        probe = host.primary_probe
        lines += [f"### {host.hostname} — {_verdict_mark(host.verdict)}", ""]
        if probe:
            lines += [
                f"- **TLS version:** {probe.tls_version or 'n/a'}",
                f"- **Negotiated group:** `{probe.default_group or 'n/a'}`",
                f"- **Hybrid X25519MLKEM768:** {'yes' if probe.hybrid_supported else 'no'}",
                f"- **Pure ML-KEM:** {'yes' if probe.pure_mlkem_supported else 'no'}",
                f"- **Classical fallback:** {'ok' if probe.classical_fallback_ok else 'missing'}",
                f"- **Cipher:** {probe.cipher or 'n/a'}",
                f"- **Cert signature:** {probe.cert_signature_algorithm or 'n/a'}",
                f"- **Server:** {probe.server_header or 'n/a'}",
                f"- **Score:** {host.score}/100",
                "",
            ]
            if probe.error:
                lines += [f"- **Error:** {probe.error}", ""]
        if host.remediation:
            lines += ["**Remediation:**", ""]
            for item in host.remediation:
                lines += [f"- {item}", ""]
        lines += ["---", ""]
    return "\n".join(lines)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PQC TLS Readiness Report - {{domain}}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 1000px; color: #1a1a1a; }
  h1 { border-bottom: 3px solid #2563eb; padding-bottom: .4rem; }
  .meta { color: #555; margin-bottom: 1.5rem; }
  .badge { display: inline-block; padding: .15rem .6rem; border-radius: 999px; font-size: .8rem; color: #fff; }
  .b-ready { background: #16a34a; } .b-capable { background: #ca8a04; }
  .b-pure_only { background: #ea580c; } .b-not_ready { background: #dc2626; }
  .b-legacy { background: #b91c1c; } .b-unreachable { background: #9ca3af; }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #e5e7eb; }
  th { background: #f3f4f6; }
  pre { background: #0f172a; color: #e2e8f0; padding: .8rem; border-radius: 6px; overflow-x: auto; }
  .narrative { background: #eff6ff; border-left: 4px solid #2563eb; padding: 1rem; border-radius: 4px; }
</style>
</head>
<body>
<h1>Post-Quantum TLS Readiness Report</h1>
<div class="meta">
  Target: <code>{{domain}}</code> &middot; {{date}} &middot; Duration: {{duration}}s<br>
  <strong>Domain score: {{score}}/100</strong> &middot; Hosts scanned: {{host_count}}
</div>
{{narrative}}
<h2>Host Results</h2>
<table>
<tr><th>Hostname</th><th>Verdict</th><th>Score</th><th>TLS</th><th>Group</th><th>Hybrid</th><th>Pure</th><th>Fallback</th><th>Cert sig</th><th>Server</th></tr>
{{rows}}
</table>
{{remediation}}
</body>
</html>
"""


def _html_badge(verdict: Verdict | None) -> str:
    if verdict is None:
        return ""
    _, label = VERDICT_STYLE.get(verdict, ("", verdict.value))
    return f'<span class="badge b-{verdict.value}">{html.escape(label)}</span>'


def to_html(result: DomainResult, narrative: str | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows: list[str] = []
    for host in sorted(result.hosts, key=lambda h: h.hostname):
        probe = host.primary_probe
        rows.append(
            "<tr>"
            f"<td>{html.escape(host.hostname)}</td>"
            f"<td>{_html_badge(host.verdict)}</td>"
            f"<td>{host.score}</td>"
            f"<td>{html.escape((probe.tls_version or '') if probe else '')}</td>"
            f"<td>{html.escape((probe.default_group or '') if probe else '')}</td>"
            f"<td>{'yes' if probe and probe.hybrid_supported else 'no'}</td>"
            f"<td>{'yes' if probe and probe.pure_mlkem_supported else 'no'}</td>"
            f"<td>{'ok' if probe and probe.classical_fallback_ok else ''}</td>"
            f"<td>{html.escape((probe.cert_signature_algorithm or '') if probe else '')}</td>"
            f"<td>{html.escape((probe.server_header or '') if probe else '')}</td>"
            "</tr>"
        )

    remediation_blocks: list[str] = []
    for host in sorted(result.hosts, key=lambda h: h.hostname):
        if host.remediation:
            items = "\n".join(f"<li>{html.escape(item)}</li>" for item in host.remediation)
            remediation_blocks.append(f"<h3>{html.escape(host.hostname)}</h3><ul>{items}</ul>")

    narrative_html = ""
    if narrative:
        narrative_html = f'<h2>Remediation Narrative</h2><div class="narrative">{html.escape(narrative)}</div>'

    body = HTML_TEMPLATE.replace("{{domain}}", html.escape(result.domain))
    body = body.replace("{{date}}", html.escape(now))
    body = body.replace("{{duration}}", f"{result.duration_seconds:.1f}")
    body = body.replace("{{score}}", str(result.domain_score))
    body = body.replace("{{host_count}}", str(len(result.hosts)))
    body = body.replace("{{narrative}}", narrative_html)
    body = body.replace("{{rows}}", "\n".join(rows))
    body = body.replace(
        "{{remediation}}",
        "<h2>Remediation Details</h2>" + "\n".join(remediation_blocks) if remediation_blocks else "",
    )
    return body
