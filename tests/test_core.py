"""Unit tests for active-mode live-host assembly in lib/core.py.

Focus: explicitly-supplied single-host targets must always be scanned in active
mode, even when host discovery reports them unresponsive. Multi-host CIDR ranges
are still routed through (mocked) host discovery.
"""
import pytest

from lib.core import PDIve, _is_multi_host_network
from lib.utils import ScannerConfig


class TestIsMultiHostNetwork:
    @pytest.mark.parametrize("target", ["10.0.0.0/24", "192.168.0.0/16", "2001:db8::/120"])
    def test_ranges_are_multi_host(self, target):
        assert _is_multi_host_network(target) is True

    @pytest.mark.parametrize("target", ["64.202.143.139", "1.2.3.4/32", "example.com", "not-an-ip"])
    def test_single_hosts_and_names_are_not(self, target):
        assert _is_multi_host_network(target) is False


def _make_pdive(tmp_path, targets):
    config = ScannerConfig(
        targets=targets,
        output_dir=str(tmp_path),
        discovery_mode="active",
        # keep enumeration off so passive_discovery is not invoked
        enable_amass=False,
        enable_dnsdumpster=False,
        enable_crtsh=False,
    )
    return PDIve(config)


class TestActiveLiveHosts:
    def test_supplied_ips_always_scanned_even_if_discovery_finds_nothing(self, tmp_path, monkeypatch):
        pdive = _make_pdive(tmp_path, ["64.202.143.139", "205.153.153.87", "64.202.143.184"])
        # Simulate host discovery declaring everything dead.
        monkeypatch.setattr(
            pdive.discovery, "host_discovery",
            lambda inputs: {"live_hosts": [], "unresponsive_count": len(inputs)},
        )
        live = pdive._active_live_hosts()
        assert set(live) == {"64.202.143.139", "205.153.153.87", "64.202.143.184"}

    def test_cidr_range_goes_through_discovery(self, tmp_path, monkeypatch):
        captured = {}

        def fake_discovery(inputs):
            captured["inputs"] = list(inputs)
            return {"live_hosts": ["10.0.0.5"], "unresponsive_count": 0}

        pdive = _make_pdive(tmp_path, ["1.2.3.4", "10.0.0.0/24"])
        monkeypatch.setattr(pdive.discovery, "host_discovery", fake_discovery)
        live = pdive._active_live_hosts()
        # The CIDR is sent to discovery; the single IP is not.
        assert captured["inputs"] == ["10.0.0.0/24"]
        # Supplied single host always present; discovery-found host added.
        assert "1.2.3.4" in live
        assert "10.0.0.5" in live
