# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #365 : plages TEST-NET (RFC 5737) internes par defaut, externes sur demande.

Documente le comportement : `ipaddress` range 192.0.2.0/24, 198.51.100.0/24
et 203.0.113.0/24 parmi les adresses privees, donc beaconing et
exfiltration restent muets sur une capture de demonstration qui les
utilise -- sauf avec `treat_test_net_as_external` (CLI `--test-net-external`).
"""

from __future__ import annotations

import pytest
from conftest import make_pkt
from test_beaconing import _beacon

from netcross_core.models import Report
from netcross_core.security.address_scope import TEST_NET_RANGES, is_external, is_test_net
from netcross_core.security.beaconing import BeaconingThresholds, detect_beaconing
from netcross_core.security.exfiltration import ExfiltrationThresholds, detect_exfiltration
from netcross_core.security.findings import apply_security_findings

TEST_NETS = ["192.0.2.10", "198.51.100.7", "203.0.113.200"]
CLIENT = "192.168.1.10"


def _upload(dst, count=100, size=1400):
    return [make_pkt(src=CLIENT, dst=dst, length=size, ts=43200.0 + i, proto="TCP") for i in range(count)]


@pytest.mark.parametrize("address", TEST_NETS)
def test_test_net_interne_par_defaut_comme_ipaddress(address):
    assert is_test_net(address)
    assert not is_external(address)
    assert is_external(address, treat_test_net_as_external=True)


@pytest.mark.parametrize("address", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "fe80::1", "", "n/a"])
def test_option_ne_rend_pas_externe_le_reste_du_prive(address):
    assert not is_external(address, treat_test_net_as_external=True)


def test_adresse_globale_externe_avec_ou_sans_option():
    assert is_external("93.184.216.34")
    assert is_external("93.184.216.34", treat_test_net_as_external=True)
    assert not is_test_net("93.184.216.34")


def test_trois_plages_rfc5737():
    assert [str(n) for n in TEST_NET_RANGES] == ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]


@pytest.mark.parametrize("c2", TEST_NETS)
def test_beaconing_muet_sur_test_net_par_defaut(c2):
    pkts = _beacon(dst=c2)
    assert detect_beaconing(pkts).suspicions == []
    assert detect_beaconing(pkts, BeaconingThresholds(treat_test_net_as_external=True)).suspicions


@pytest.mark.parametrize("dst", TEST_NETS)
def test_exfiltration_muette_sur_test_net_par_defaut(dst):
    pkts = _upload(dst)
    base = {"min_volume_bytes": 100_000, "min_packets_for_volume": 5}
    assert detect_exfiltration(pkts, ExfiltrationThresholds(**base)).alerts == []
    alerts = detect_exfiltration(pkts, ExfiltrationThresholds(**base, treat_test_net_as_external=True)).alerts
    assert alerts


def test_apply_security_findings_option_test_net():
    """Capture de demonstration : beaconing vers 203.0.113.200."""
    pkts = _beacon(dst="203.0.113.200")
    report = Report()
    apply_security_findings(report, pkts)
    assert "beaconing" not in [f.get("detector") for f in report.security_findings]
    apply_security_findings(report, pkts, treat_test_net_as_external=True)
    assert "beaconing" in [f.get("detector") for f in report.security_findings]


def test_exfiltration_rapportee_une_seule_fois():
    """Les constats d'exfiltration etaient ajoutes deux fois (avant et apres
    correlation au beaconing/tunneling DNS)."""
    pkts = [
        make_pkt(src=CLIENT, dst="93.184.216.34", length=1400, ts=43200.0 + i, proto="TCP", sport=40000 + i % 3)
        for i in range(8000)
    ]
    report = Report()
    apply_security_findings(report, pkts)
    exfil = [f for f in report.security_findings if f.get("detector") == "exfiltration"]
    assert report.exfiltration_alerts
    assert len(exfil) == len(report.exfiltration_alerts)


def test_cli_option_test_net_external(monkeypatch, capsys):
    import sys

    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "--test-net-external" in capsys.readouterr().out
