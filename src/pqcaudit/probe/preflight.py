"""Preflight checks for the required OpenSSL binary.

PQC (ML-KEM) TLS groups require OpenSSL >= 3.5. The tool detects the binary,
verifies version and available groups, and raises an actionable error with
install guidance when unsupported.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

MIN_MAJOR, MIN_MINOR = 3, 5

VERSION_RE = re.compile(r"^OpenSSL\s+(\d+)\.(\d+)\.(\d+)")

INSTALL_HINTS = {
    "win32": "winget install ShiningLight.OpenSSL.Light\n"
    "      (or: choco install openssl --params='/VERSION:3.5')\n"
    "      Then set PQC_OPENSSL_BIN to the full path if not on PATH.",
    "darwin": "brew install openssl@3",
    "linux": "sudo apt install openssl   # needs >= 3.5 (Debian sid / Ubuntu 25.04+)\n"
    "      Or build from https://github.com/openssl/openssl",
}

REQUIRED_GROUPS = ("X25519MLKEM768", "MLKEM768", "MLKEM1024")


@dataclass
class PreflightResult:
    ok: bool
    openssl_bin: str = ""
    version: str = ""
    groups: set[str] = field(default_factory=set)
    error: str = ""


def _which(bin_name: str) -> str | None:
    found = shutil.which(bin_name)
    if found:
        return found
    # On Windows shutil.which may miss apps in Miniconda Library/bin.
    try:
        proc = subprocess.run(
            ["where", bin_name] if _is_windows() else ["which", bin_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _is_windows() -> bool:
    import sys

    return sys.platform == "win32"


def _run(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, "", str(exc)


def _parse_version(text: str) -> str:
    match = VERSION_RE.search(text)
    if not match:
        return ""
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def preflight(openssl_bin: str = "openssl") -> PreflightResult:
    """Verify an OpenSSL binary with ML-KEM support is available."""
    bin_path = _which(openssl_bin) or openssl_bin

    code, out, err = _run([bin_path, "version"])
    if code != 0:
        return PreflightResult(
            ok=False,
            openssl_bin=bin_path,
            error=f"Could not run '{bin_path}': {err.strip() or out.strip()}\n\n"
            f"Install OpenSSL 3.5+ (see install hints for this platform):\n{INSTALL_HINTS.get(_os_key(), INSTALL_HINTS['linux'])}",
        )

    version = _parse_version(out)
    major, minor = 0, 0
    m = VERSION_RE.search(out)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))

    if (major, minor) < (MIN_MAJOR, MIN_MINOR):
        return PreflightResult(
            ok=False,
            openssl_bin=bin_path,
            version=version,
            error=f"OpenSSL {version or 'unknown'} detected, but ML-KEM TLS groups require "
            f"OpenSSL >= {MIN_MAJOR}.{MIN_MINOR}.\n\n"
            f"Install hints for this platform:\n{INSTALL_HINTS.get(_os_key(), INSTALL_HINTS['linux'])}",
        )

    code, out, err = _run([bin_path, "list", "-tls1_3", "-tls-groups"])
    groups = set(out.split(":"))

    missing = [g for g in REQUIRED_GROUPS if g not in groups]
    if code != 0 or missing:
        return PreflightResult(
            ok=False,
            openssl_bin=bin_path,
            version=version,
            groups=groups,
            error=f"OpenSSL {version} lacks required post-quantum TLS groups (missing: {', '.join(missing)}). "
            f"Install OpenSSL >= {MIN_MAJOR}.{MIN_MINOR} built with ML-KEM support.",
        )

    return PreflightResult(ok=True, openssl_bin=bin_path, version=version, groups=groups)


def _os_key() -> str:
    import sys

    if sys.platform == "win32":
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"
