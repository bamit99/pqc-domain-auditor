"""Tests for crt.sh parsing and hostname filtering."""

from pqcaudit.discovery.crtsh import _extract_names


def test_extract_names_dedupes_and_filters_wildcards():
    entries = [
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "WWW.EXAMPLE.COM"},
        {"name_value": "blog.example.org"},
    ]
    names = _extract_names(entries)
    # Extractor dedupes and drops wildcards; domain filtering happens in fetch_crt_sh.
    assert names == {"www.example.com", "api.example.com", "blog.example.org"}


def test_extract_names_handles_empty():
    assert _extract_names([]) == set()
    assert _extract_names([{"name_value": None}]) == set()
