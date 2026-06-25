"""Unit tests for the pure helper methods on lib.discovery.Discovery.

_is_valid_hostname and extract_domain are deterministic string/IP checks with
no network access, so they are safe to unit test directly. A Discovery instance
is built with a minimal ScannerConfig (no scan is ever run).
"""
import pytest

from lib.discovery import Discovery
from lib.utils import ScannerConfig


@pytest.fixture
def discovery():
    return Discovery(ScannerConfig(targets=[]))


class TestIsValidHostname:
    @pytest.mark.parametrize(
        "host",
        ["example.com", "sub.example.com", "a-b.example.io", "x.co"],
    )
    def test_valid(self, discovery, host):
        assert discovery._is_valid_hostname(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "",
            "   ",
            "localhost",        # no dot / no TLD
            "1.2.3.4",          # IP literal
            "12345",            # all digits
            "AS15169",          # ASN
            "a/b.com",          # contains slash
            "example.123",      # numeric TLD
            "-bad.com",         # label starts with hyphen
        ],
    )
    def test_invalid(self, discovery, host):
        assert discovery._is_valid_hostname(host) is False


class TestExtractDomain:
    @pytest.mark.parametrize("target", ["1.2.3.4", "10.0.0.0/24", "::1"])
    def test_ip_or_cidr_returns_none(self, discovery, target):
        assert discovery.extract_domain(target) is None

    @pytest.mark.parametrize(
        "target,expected",
        [
            ("Example.COM", "example.com"),
            ("  example.com  ", "example.com"),
            ("sub.example.com", "sub.example.com"),
        ],
    )
    def test_domain_normalized(self, discovery, target, expected):
        assert discovery.extract_domain(target) == expected
