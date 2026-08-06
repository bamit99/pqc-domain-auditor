"""Preflight checks: pick the best available TLS probe backend.

Backends, in preference order:

1. **Go dialer** — a small static binary built from
   ``src/pqcaudit/probe/godialer`` that speaks ML-KEM via Go's ``crypto/tls``
   (X25519MLKEM768 ships in the standard library since Go 1.24). Resolved from
   ``PQC_GO_DIALER`` if set, otherwise built on demand from the Go toolchain.
2. **OpenSSL >= 3.5** — native ML-KEM TLS groups (the original backend).

In Go-dialer mode an OpenSSL binary (any version) is still used for the TLS
1.0/1.1 *legacy* probe, because the Go client dropped those protocol versions.
The tool fails with actionable install guidance only when neither backend is
available.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

MIN_MAJOR, MIN_MINOR = 3, 5
MIN_GO_REVISION = 24  # X25519MLKEM768 shipped in Go 1.24's crypto/tls

VERSION_RE = re.compile(r"^OpenSSL\s+(\d+)\.(\d+)\.(\d+)")
GO_VERSION_RE = re.compile(r"go1\.(\d+)(?:\.(\d+))?")

REQUIRED_GROUPS = ("X25519MLKEM768", "MLKEM768", "MLKEM1024")

INSTALL_HINTS = {
    "win32": "winget install ShiningLight.OpenSSL.Light\n"
    "      (or: choco install openssl --params='/VERSION:3.5')\n"
    "      Then set PQC_OPENSSL_BIN to the full path if not on PATH.",
    "darwin": "brew install openssl@3",
    "linux": "sudo apt install openssl   # note: LTS distros ship 3.0.x and will "
    "NOT have ML-KEM groups.\n"
    "      Use the openssl3 PPA, build from https://github.com/openssl/openssl, or "
    "prefer the Go backend:\n"
    "        - install Go >= 1.24 and this tool will build the dialer automatically, or\n"
    "        - set PQC_GO_DIALER to a prebuilt godialer binary.",
}

GO_HINTS = (
    "Go backend: install Go >= 1.24 (the tool builds the dialer on first run), or\n"
    "      build it yourself:  go build ./src/pqcaudit/probe/godialer\n"
    "      and point PQC_GO_DIALER at the resulting binary."
)


@dataclass
class ProbeBackend:
    """Which probe backend to use and where its binaries live."""

    mode: str = "openssl"  # "go" | "openssl"
    go_dialer: str = ""  # path to the godialer binary (go mode)
    openssl_bin: str = ""  # used for the legacy TLS 1.0/1.1 probe in go mode


@dataclass
class PreflightResult:
    ok: bool
    backend: str = ""  # "go" | "openssl"
    go_dialer: str = ""
    openssl_bin: str = ""
    openssl_version: str = ""
    groups: set[str] = field(default_factory=set)
    error: str = ""


def _is_windows() -> bool:
    return sys.platform == "win32"


def _os_key() -> str:
    if sys.platform == "win32":
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


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


def _run(args: list[str], timeout: int = 60, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, "", str(exc)


def _parse_version(text: str) -> str:
    match = VERSION_RE.search(text)
    if not match:
        return ""
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def _go_dialer_source_dir() -> Path:
    return Path(__file__).resolve().parent / "godialer"


def _go_version_at_least(text: str) -> bool:
    match = GO_VERSION_RE.search(text)
    if not match:
        return False
    return int(match.group(1)) >= MIN_GO_REVISION


def _build_go_dialer(go_bin: str) -> str | None:
    """Best-effort build of the godialer binary into a user cache dir."""
    src_dir = _go_dialer_source_dir()
    if not (src_dir / "main.go").is_file() or not (src_dir / "go.mod").is_file():
        log.debug("godialer source not found at %s", src_dir)
        return None

    cache_dir = Path.home() / ".cache" / "pqcaudit"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("Could not create dialer cache dir %s: %s", cache_dir, exc)
        return None

    exe_name = "godialer.exe" if _is_windows() else "godialer"
    out = cache_dir / exe_name
    code, _, err = _run([go_bin, "build", "-o", str(out), "."], timeout=300, cwd=str(src_dir))
    if code != 0:
        log.warning("go build of godialer failed: %s", err.strip())
        return None
    if out.is_file():
        log.debug("built go dialer at %s", out)
        return str(out)
    return None


def _go_dialer_cache_path() -> Path:
    return Path.home() / ".cache" / "pqcaudit" / ("godialer.exe" if _is_windows() else "godialer")


def _resolve_go_dialer(go_dialer_env: str) -> str | None:
    """Return a usable godialer binary path, or None.

    Priority: explicit ``PQC_GO_DIALER`` path, then a previously built binary
    in the user cache (no Go toolchain needed on the probe machine), then an
    on-demand build when Go >= 1.24 is installed.
    """
    if go_dialer_env:
        path = Path(go_dialer_env).expanduser()
        if path.is_file():
            return str(path)
        log.warning("PQC_GO_DIALER set but '%s' is not a file; ignoring", go_dialer_env)
    cached = _go_dialer_cache_path()
    if cached.is_file():
        log.debug("reusing cached go dialer at %s", cached)
        return str(cached)
    go_bin = _which("go")
    if not go_bin:
        return None
    code, out, _ = _run([go_bin, "version"])
    if code != 0 or not _go_version_at_least(out):
        log.debug("go %s too old (need 1.24+): %s", out.strip(), go_bin)
        return None
    return _build_go_dialer(go_bin)


def _check_openssl(openssl_bin: str) -> tuple[str, str, bool, set[str]]:
    """Return (bin_path, version, ok_for_pq, groups)."""
    bin_path = _which(openssl_bin) or openssl_bin
    code, out, _ = _run([bin_path, "version"], timeout=20)
    if code != 0:
        return bin_path, "", False, set()
    version = _parse_version(out)
    major, minor = 0, 0
    m = VERSION_RE.search(out)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) < (MIN_MAJOR, MIN_MINOR):
        return bin_path, version, False, set()

    code, out, _ = _run([bin_path, "list", "-tls1_3", "-tls-groups"], timeout=20)
    groups = set(out.split(":"))
    missing = [g for g in REQUIRED_GROUPS if g not in groups]
    ok = code == 0 and not missing
    return bin_path, version, ok, groups if ok else set()


def preflight(
    openssl_bin: str = "openssl",
    *,
    backend_pref: str = "auto",
    go_dialer_env: str = "",
) -> PreflightResult:
    """Resolve the best probe backend, preferring the Go dialer when available."""
    mode = (backend_pref or "auto").strip().lower()

    go_dialer = _resolve_go_dialer(go_dialer_env) if mode in ("auto", "go") else None
    openssl_path, openssl_version, openssl_ok, groups = _check_openssl(openssl_bin)

    if mode == "auto":
        mode = "go" if go_dialer else ("openssl" if openssl_ok else "")
    elif mode == "go" and not go_dialer:
        mode = "openssl" if openssl_ok else ""

    if mode == "go":
        if not go_dialer:
            return PreflightResult(
                ok=False,
                error="Go backend selected but no godialer binary is available.",
            )
        return PreflightResult(
            ok=True,
            backend="go",
            go_dialer=go_dialer,
            openssl_bin=openssl_path if openssl_path else "",
            openssl_version=openssl_version,
        )

    if mode == "openssl":
        return PreflightResult(
            ok=True,
            backend="openssl",
            openssl_bin=openssl_path,
            openssl_version=openssl_version,
            groups=groups,
        )

    # No usable backend.
    reasons: list[str] = []
    if not go_dialer:
        reasons.append("no Go dialer (install Go >= 1.24 or set PQC_GO_DIALER)")
    if not openssl_ok:
        hint = (
            f"OpenSSL {openssl_version or 'not found'}: ML-KEM TLS groups require "
            f"OpenSSL >= {MIN_MAJOR}.{MIN_MINOR}"
        )
        reasons.append(hint)
    error = "No post-quantum probe backend available.\n" + "\n".join(f"  - {r}" for r in reasons)
    error += f"\n\n{GO_HINTS}\n\nOpenSSL install hints for this platform:\n{INSTALL_HINTS.get(_os_key(), INSTALL_HINTS['linux'])}"
    return PreflightResult(ok=False, error=error)
