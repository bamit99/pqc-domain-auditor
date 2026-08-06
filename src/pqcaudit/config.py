"""Configuration and LLM provider abstraction.

The tool must work deterministically with zero configuration. Optional LLM
narrative generation is enabled only when a provider is configured via
environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Settings:
    """Runtime settings, resolved from environment variables with sane defaults."""

    openssl_bin: str = field(
        default_factory=lambda: os.environ.get("PQC_OPENSSL_BIN", "openssl")
    )
    connect_timeout: float = field(default_factory=lambda: float(os.environ.get("PQC_TIMEOUT", "10")))
    handshake_retries: int = field(default_factory=lambda: int(os.environ.get("PQC_RETRIES", "1")))
    concurrency: int = field(default_factory=lambda: int(os.environ.get("PQC_CONCURRENCY", "32")))
    crtsh_base: str = field(default_factory=lambda: os.environ.get("PQC_CRTSH_BASE", "https://crt.sh"))
    dns_resolver: str = field(default_factory=lambda: os.environ.get("PQC_DNS_RESOLVER", ""))
    ports: tuple[int, ...] = field(
        default_factory=lambda: tuple(int(p) for p in os.environ.get("PQC_PORTS", "443").split(","))
    )

    # LLM narrative (optional)
    llm_provider: str = field(
        default_factory=lambda: os.environ.get("PQC_LLM_PROVIDER", "").strip().lower()
    )
    llm_model: str = field(default_factory=lambda: os.environ.get("PQC_LLM_MODEL", ""))
    llm_api_key: str = field(default_factory=lambda: os.environ.get("PQC_LLM_API_KEY", ""))
    llm_base_url: str = field(default_factory=lambda: os.environ.get("PQC_LLM_BASE_URL", ""))
    llm_endpoint: str = field(default_factory=lambda: os.environ.get("PQC_LLM_ENDPOINT", ""))

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_provider)

    def as_llm_client_kwargs(self) -> dict[str, Any]:
        """Return kwargs to build an LLM client for the configured provider."""
        kwargs: dict[str, Any] = {
            "api_key": self.llm_api_key or None,
            "model": self.llm_model or None,
            "base_url": self.llm_base_url or None,
            "endpoint": self.llm_endpoint or None,
        }
        return kwargs
