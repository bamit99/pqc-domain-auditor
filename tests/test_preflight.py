"""Tests for probe backend selection in preflight."""

import pqcaudit.probe.preflight as preflight_mod
from pqcaudit.probe.preflight import (
    _go_version_at_least,
    _resolve_go_dialer,
    preflight,
)


def _openssl_ok() -> tuple[str, str, bool, set[str]]:
    return ("/usr/bin/openssl", "3.5.1", True, {"X25519MLKEM768", "MLKEM768", "MLKEM1024"})


def _openssl_old() -> tuple[str, str, bool, set[str]]:
    return ("/usr/bin/openssl", "3.0.13", False, set())


def _openssl_missing() -> tuple[str, str, bool, set[str]]:
    return ("openssl", "", False, set())


def test_auto_prefers_go_dialer(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: "/home/u/.cache/pqcaudit/godialer")
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_ok())
    result = preflight()
    assert result.ok
    assert result.backend == "go"
    assert result.go_dialer == "/home/u/.cache/pqcaudit/godialer"


def test_auto_falls_back_to_openssl(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: None)
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_ok())
    result = preflight()
    assert result.ok
    assert result.backend == "openssl"
    assert result.groups


def test_auto_fails_without_any_backend(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: None)
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_missing())
    result = preflight()
    assert not result.ok
    assert "Go" in result.error
    assert "OpenSSL" in result.error


def test_go_mode_keeps_openssl_for_legacy_probe(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: "/tmp/godialer")
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_old())
    result = preflight(backend_pref="go")
    assert result.ok
    assert result.backend == "go"
    assert result.openssl_bin == "/usr/bin/openssl"


def test_forced_openssl_wins_over_go(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: "/tmp/godialer")
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_ok())
    result = preflight(backend_pref="openssl")
    assert result.ok
    assert result.backend == "openssl"


def test_forced_go_without_go_falls_back_to_openssl(monkeypatch):
    monkeypatch.setattr(preflight_mod, "_resolve_go_dialer", lambda env: None)
    monkeypatch.setattr(preflight_mod, "_check_openssl", lambda b: _openssl_ok())
    result = preflight(backend_pref="go")
    assert result.ok
    assert result.backend == "openssl"


def test_go_version_parse():
    assert _go_version_at_least("go version go1.26.5 windows/amd64")
    assert _go_version_at_least("go version go1.24.0 linux/amd64")
    assert not _go_version_at_least("go version go1.23.6 darwin/arm64")
    assert not _go_version_at_least("not go")


def test_reuses_cached_dialer_without_go_toolchain(monkeypatch, tmp_path):
    cached = tmp_path / "godialer.exe"
    cached.write_text("binary")
    monkeypatch.setattr(preflight_mod, "_go_dialer_cache_path", lambda: cached)
    monkeypatch.setattr(preflight_mod, "_which", lambda name: None)
    assert _resolve_go_dialer("") == str(cached)


def test_go_dialer_env_beats_cache(monkeypatch, tmp_path):
    explicit = tmp_path / "custom" / "godialer.exe"
    explicit.parent.mkdir()
    explicit.write_text("binary")
    monkeypatch.setattr(preflight_mod, "_go_dialer_cache_path", lambda: tmp_path / "godialer.exe")
    assert _resolve_go_dialer(str(explicit)) == str(explicit)
