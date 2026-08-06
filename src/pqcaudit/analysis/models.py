"""Pydantic data models shared across discovery, probe, analysis, and report."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    READY = "ready"
    CAPABLE = "capable"
    PURE_ONLY = "pure_only"
    NOT_READY = "not_ready"
    LEGACY = "legacy"
    UNREACHABLE = "unreachable"

    @property
    def label(self) -> str:
        return self.value.replace("_", "-")


class HostProbeResult(BaseModel):
    """Raw handshake results for a single (host, port)."""

    host: str
    port: int
    reachable: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    default_group: str | None = None
    hybrid_supported: bool = False
    hybrid_preferred: bool = False
    pure_mlkem_supported: bool = False
    classical_fallback_ok: bool = False
    cert_signature_algorithm: str | None = None
    cert_issuer: str | None = None
    server_header: str | None = None
    error: str | None = None
    legacy_tls_present: bool = False

    @property
    def pq_score(self) -> int:
        score = 0
        if self.default_group and self.default_group != "None":
            score += 1
        return score


class HostResult(BaseModel):
    """A single discovered hostname with its probe outcome."""

    hostname: str
    ips: list[str] = Field(default_factory=list)
    discovered_by: list[str] = Field(default_factory=list)
    verdict: Verdict | None = None
    score: int = 0
    probes: dict[int, HostProbeResult] = Field(default_factory=dict)
    remediation: list[str] = Field(default_factory=list)

    @property
    def primary_probe(self) -> HostProbeResult | None:
        return self.probes.get(443)


class DomainResult(BaseModel):
    """Aggregate result for one audited domain."""

    domain: str
    scanned_at: str = ""
    duration_seconds: float = 0.0
    hosts: list[HostResult] = Field(default_factory=list)
    domain_score: int = 0
    summary: dict[str, int] = Field(default_factory=dict)

    @property
    def reachable_hosts(self) -> list[HostResult]:
        return [h for h in self.hosts if h.verdict is not None]
