"""Optional LLM narrative generation.

Deterministic remediation is always produced; the LLM layer is an optional
enhancement that writes a human-readable prose narrative from the findings.
Provider-agnostic (OpenAI-compatible chat, Anthropic, Ollama, custom endpoint).
"""

from __future__ import annotations

import logging

import httpx

from ..analysis.models import DomainResult
from .engine import summarise_findings

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a post-quantum cryptography (PQC) readiness advisor. Given TLS scan "
    "findings for an organisation's subdomains, write a concise, expert remediation "
    "narrative (about 3-6 paragraphs). Reference the specific algorithms "
    "(ML-KEM / X25519MLKEM768 hybrid key exchange, ML-DSA certificates) and the "
    "highest-risk endpoints. Be concrete and actionable. Do not invent data."
)


def _build_prompt(result: DomainResult) -> str:
    lines = [f"Domain: {result.domain}", f"Domain score: {result.domain_score}/100"]
    lines.append(f"Hosts scanned: {len(result.hosts)}")
    for host in result.hosts:
        lines.append(" - " + summarise_findings(host))
    lines.append("")
    lines.append("Write the remediation narrative now.")
    return "\n".join(lines)


async def generate_narrative(
    result: DomainResult,
    *,
    provider: str,
    model: str = "",
    api_key: str = "",
    base_url: str = "",
    endpoint: str = "",
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """Return an LLM-generated narrative, or None when generation fails."""
    if not provider:
        return None

    prompt = _build_prompt(result)
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    try:
        if provider == "ollama":
            url = f"{base_url or 'http://localhost:11434'}/api/chat"
            payload = {
                "model": model or "llama3.1",
                "stream": False,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            }
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content")

        if provider == "anthropic":
            url = f"{base_url or 'https://api.anthropic.com'}/v1/messages"
            headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
            payload = {
                "model": model or "claude-3-5-sonnet-latest",
                "max_tokens": 2000,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            }
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            return "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")

        # OpenAI-compatible chat completions (OpenAI, Foundry, Azure, LM Studio, etc.)
        url = endpoint or f"{base_url or 'https://api.openai.com/v1'}/chat/completions"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": model or "gpt-4o",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001 - LLM failure must not break the scan
        log.warning("LLM narrative generation failed: %s", exc)
        return None
    finally:
        if owns_client:
            await client.aclose()
