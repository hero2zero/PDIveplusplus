"""Unit tests for pure helpers in lib/utils.py.

These functions are deterministic and (mostly) side-effect free, so they are
the cheapest, highest-value place to start a test suite. Network-touching
branches of validate_targets are exercised via monkeypatched DNS.
"""
import pytest

from lib import utils
from lib.utils import (
    load_targets_from_file,
    parse_port_spec,
    registrable_domain,
    validate_targets,
)


class TestParsePortSpec:
    def test_simple_list(self):
        assert parse_port_spec("80,443") == [80, 443]

    def test_sorted_and_deduped(self):
        assert parse_port_spec("443,80,80,443") == [80, 443]

    def test_range_expansion(self):
        assert parse_port_spec("80,8000-8002") == [80, 8000, 8001, 8002]

    def test_reversed_range_is_normalized(self):
        assert parse_port_spec("8002-8000") == [8000, 8001, 8002]

    def test_whitespace_tolerated(self):
        assert parse_port_spec("  80 , 443 ") == [80, 443]

    def test_empty_parts_skipped(self):
        assert parse_port_spec("80,,443") == [80, 443]

    def test_empty_string_yields_empty(self):
        assert parse_port_spec("") == []

    @pytest.mark.parametrize("spec", ["0", "65536", "70000", "65534-65536"])
    def test_out_of_range_raises(self, spec):
        with pytest.raises(ValueError):
            parse_port_spec(spec)

    def test_non_integer_raises(self):
        with pytest.raises(ValueError):
            parse_port_spec("http")


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("host-1-2.cybera.net", "cybera.net"),
            ("www.example.com", "example.com"),
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("example.com.", "example.com"),
            ("sub.example.co.uk", "example.co.uk"),
            ("a.b.c.com.au", "c.com.au"),
        ],
    )
    def test_reduces_to_registrable(self, host, expected):
        assert registrable_domain(host) == expected

    @pytest.mark.parametrize("host", [None, "", "localhost", "1.2.3.4", "::1"])
    def test_non_domain_returns_none(self, host):
        assert registrable_domain(host) is None


class TestValidateTargets:
    def test_ip_and_cidr_pass_without_dns(self, monkeypatch):
        # Guard: these must NOT trigger a DNS lookup.
        def _boom(_):
            raise AssertionError("gethostbyname should not be called for IP/CIDR")

        monkeypatch.setattr(utils.socket, "gethostbyname", _boom)
        valid, resolved = validate_targets(["1.2.3.4", "10.0.0.0/24"])
        assert valid == ["1.2.3.4", "10.0.0.0/24"]
        assert resolved == {}

    def test_hostname_resolved_and_cached(self, monkeypatch):
        monkeypatch.setattr(
            utils.socket, "gethostbyname", lambda h: "93.184.216.34"
        )
        valid, resolved = validate_targets(["example.com"])
        assert valid == ["example.com"]
        assert resolved == {"example.com": "93.184.216.34"}

    def test_unresolvable_hostname_dropped(self, monkeypatch):
        import socket as _socket

        def _fail(_):
            raise _socket.gaierror("no such host")

        monkeypatch.setattr(utils.socket, "gethostbyname", _fail)
        valid, resolved = validate_targets(["1.2.3.4", "bad.invalid"])
        assert valid == ["1.2.3.4"]
        assert "bad.invalid" not in resolved


class TestLoadTargetsFromFile:
    def test_strips_blanks_and_comments(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text(
            "example.com\n"
            "\n"
            "  10.0.0.1  \n"
            "# a comment\n"
            "sub.example.com\n"
        )
        assert load_targets_from_file(str(f)) == [
            "example.com",
            "10.0.0.1",
            "sub.example.com",
        ]

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_targets_from_file(str(tmp_path / "nope.txt")) == []
