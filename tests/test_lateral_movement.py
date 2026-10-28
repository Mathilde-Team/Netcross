# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.security.lateral_movement -- tests (issue #149, SCENARIO-3).

Couvre les 5 detecteurs :
- port_scan (1 source -> N ports sur M hotes)
- host_scan (1 source -> plage d'IPs consecutives)
- brute_force (tentatives SSH/RDP repetees vers N hotes)
- unusual_protocol (SMB/RDP/WinRM depuis un poste utilisateur)
- new_connection (paire interne non dans baseline)

Et les anti faux positifs : trafic normal, adresses externes, ports ignores.
"""

from __future__ import annotations

from netcross_core.security.lateral_movement import (
    LateralMovementEvent,
    LateralMovementThresholds,
    detect_lateral_movement,
)
from tests.conftest import make_pkt

# --- Port scan -------------------------------------------------------------


def test_port_scan_detecte_source_vers_n_ports_sur_m_hotes():
    """1 source contacte 20 ports sur 5 hotes -> port_scan."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port + 1000, flags="S.......", proto="TCP")
        for host in range(1, 6)
        for port in range(1, 21)
    ]
    result = detect_lateral_movement(pkts)
    scans = [e for e in result.events if e.event_type == "port_scan"]
    assert len(scans) == 1
    assert scans[0].source == "192.168.1.100"
    assert "scan de ports" in scans[0].details
    assert result.suspicious


def test_port_scan_non_detecte_trafic_normal():
    """1 source vers 2 ports sur 2 hotes -> pas de scan."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port, flags="S.......", proto="TCP")
        for host in range(1, 3)
        for port in [80, 443]
    ]
    result = detect_lateral_movement(pkts)
    scans = [e for e in result.events if e.event_type == "port_scan"]
    assert len(scans) == 0


def test_port_scan_ignore_adresses_externes():
    """Source externe -> pas un mouvement lateral interne."""
    pkts = [make_pkt(src="8.8.8.8", dst="192.168.1.1", dport=port + 1000, flags="S.......") for port in range(1, 21)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "port_scan"]) == 0


def test_port_scan_ignore_ports_dns_ntp():
    """DNS (53) et NTP (123) ne sont pas des cibles de scan."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port, flags="S.......")
        for host in range(1, 6)
        for port in [53, 123]
    ]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "port_scan"]) == 0


def test_port_scan_syn_only_desactive():
    """Si scan_syn_only=False, les paquets non-SYN sont aussi comptes."""
    thresholds = LateralMovementThresholds(scan_syn_only=False)
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port + 1000, flags=".A.......")
        for host in range(1, 6)
        for port in range(1, 21)
    ]
    result = detect_lateral_movement(pkts, thresholds)
    scans = [e for e in result.events if e.event_type == "port_scan"]
    assert len(scans) == 1


# --- Host scan -------------------------------------------------------------


def test_host_scan_detecte_plage_ip_consecutives():
    """1 source contacte 192.168.1.1-50 -> host_scan."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=445, flags="S.......") for host in range(1, 51)
    ]
    result = detect_lateral_movement(pkts)
    scans = [e for e in result.events if e.event_type == "host_scan"]
    assert len(scans) == 1
    assert "scan d'hotes" in scans[0].details


def test_host_scan_non_detecte_peu_d_hotes():
    """5 hotes consecutifs < seuil de 10 -> pas de scan."""
    pkts = [make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=445, flags="S.......") for host in range(1, 6)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "host_scan"]) == 0


def test_host_scan_detecte_plage_dans_meme_24():
    """IPs consecutives dans le meme /24 meme si d'autres prefixes existent."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=445, flags="S.......") for host in range(1, 16)
    ]
    pkts.extend(
        make_pkt(src="192.168.1.100", dst=f"192.168.2.{host}", dport=445, flags="S.......") for host in range(1, 4)
    )
    result = detect_lateral_movement(pkts)
    scans = [e for e in result.events if e.event_type == "host_scan"]
    assert len(scans) == 1


# --- Brute force -----------------------------------------------------------


def test_brute_force_ssh_detecte():
    """20 tentatives SSH vers 3 hotes dans 300s -> brute_force."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", sport=50000 + i, dport=22, ts=float(i), proto="TCP")
        for i in range(20)
        for host in [1, 2, 3]
    ]
    result = detect_lateral_movement(pkts)
    bf = [e for e in result.events if e.event_type == "brute_force"]
    assert len(bf) == 1
    assert "brute force" in bf[0].details


def test_brute_force_rdp_detecte():
    """15 tentatives RDP (3389) vers 2 hotes -> brute_force."""
    # Issue #346 : une tentative = une session -> port source distinct
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{(i % 2) + 1}", sport=50000 + i, dport=3389, ts=float(i))
        for i in range(15)
    ]
    result = detect_lateral_movement(pkts)
    bf = [e for e in result.events if e.event_type == "brute_force"]
    assert len(bf) == 1


def test_brute_force_non_detecte_peu_de_tentatives():
    """5 tentatives vers 1 hote -> seuil non atteint."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.1", dport=22, ts=float(i)) for i in range(5)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "brute_force"]) == 0


def test_brute_force_non_detecte_vers_un_seul_hote():
    """20 tentatives vers 1 seul hote -> min_hosts non atteint."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.1", dport=22, ts=float(i)) for i in range(20)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "brute_force"]) == 0


def test_brute_force_ignore_adresses_externes():
    """Brute force vers des hotes externes -> pas un mouvement lateral."""
    pkts = [make_pkt(src="192.168.1.100", dst="8.8.8.8", dport=22, ts=float(i)) for i in range(20)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "brute_force"]) == 0


# --- Unusual protocol ------------------------------------------------------


def test_unusual_protocol_smb_detecte():
    """SMB (port 445) depuis un poste utilisateur (sport > 1024) -> unusual_protocol."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=50000, dport=445, proto="TCP")]
    result = detect_lateral_movement(pkts)
    unusual = [e for e in result.events if e.event_type == "unusual_protocol"]
    assert len(unusual) == 1
    assert "SMB" in unusual[0].details


def test_unusual_protocol_rdp_detecte():
    """RDP (port 3389) depuis un poste utilisateur -> unusual_protocol."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=50000, dport=3389)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "unusual_protocol"]) == 1


def test_unusual_protocol_non_detecte_depuis_serveur():
    """Sport <= 1024 -> pas un poste utilisateur."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=445, dport=50000)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "unusual_protocol"]) == 0


def test_unusual_protocol_non_detecte_trafic_normal():
    """HTTP normal (port 80) -> pas un protocole inhabituel."""
    pkts = [make_pkt(src="192.168.1.100", dst="192.168.1.50", sport=50000, dport=80)]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "unusual_protocol"]) == 0


# --- New connection --------------------------------------------------------


def test_new_connection_detecte_hors_baseline():
    """Paire (src, dst) non dans baseline -> new_connection."""
    thresholds = LateralMovementThresholds(
        new_connection_baseline_pairs=frozenset({("192.168.1.1", "192.168.1.2")}),
    )
    pkts = [
        make_pkt(src="192.168.1.1", dst="192.168.1.2"),  # dans baseline
        make_pkt(src="192.168.1.1", dst="192.168.1.99"),  # pas dans baseline
    ]
    result = detect_lateral_movement(pkts, thresholds)
    new_conns = [e for e in result.events if e.event_type == "new_connection"]
    assert len(new_conns) == 1
    assert new_conns[0].source == "192.168.1.1"


def test_new_connection_desactive_sans_baseline():
    """Baseline vide -> pas de detection (tout serait nouveau)."""
    pkts = [make_pkt(src="192.168.1.1", dst="192.168.1.2")]
    result = detect_lateral_movement(pkts)
    assert len([e for e in result.events if e.event_type == "new_connection"]) == 0


def test_new_connection_ignore_adresses_externes():
    """Connexion vers externe -> pas un mouvement lateral interne."""
    thresholds = LateralMovementThresholds(
        new_connection_baseline_pairs=frozenset({("192.168.1.1", "192.168.1.2")}),
    )
    pkts = [make_pkt(src="192.168.1.1", dst="8.8.8.8")]  # externe
    result = detect_lateral_movement(pkts, thresholds)
    assert len([e for e in result.events if e.event_type == "new_connection"]) == 0


# --- Integration / result --------------------------------------------------


def test_resultat_vide_sur_trafic_normal():
    """Trafic normal interne -> aucun evenement, suspicious=False."""
    pkts = [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, flags=".A......."),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, flags=".A......."),
    ]
    result = detect_lateral_movement(pkts)
    assert len(result.events) == 0
    assert result.suspicious is False


def test_resultat_events_by_type():
    """events_by_type groupe correctement les evenements."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port + 1000, flags="S.......")
        for host in range(1, 6)
        for port in range(1, 21)
    ]
    pkts.extend(
        make_pkt(src="192.168.1.200", dst=f"192.168.1.{(i % 2) + 1}", sport=50000 + i, dport=22, ts=float(i))
        for i in range(15)
    )
    result = detect_lateral_movement(pkts)
    by_type = result.events_by_type
    assert "port_scan" in by_type
    assert "brute_force" in by_type
    assert len(by_type["port_scan"]) == 1
    assert len(by_type["brute_force"]) == 1


def test_score_dans_intervalle_0_1():
    """Tous les scores sont dans [0, 1]."""
    pkts = [
        make_pkt(src="192.168.1.100", dst=f"192.168.1.{host}", dport=port + 1000, flags="S.......")
        for host in range(1, 6)
        for port in range(1, 21)
    ]
    result = detect_lateral_movement(pkts)
    for ev in result.events:
        assert 0.0 <= ev.score <= 1.0


# --- LateralMovementEvent dataclass ----------------------------------------


def test_lateral_movement_event_dataclass():
    """La dataclass serialise correctement."""
    ev = LateralMovementEvent(
        point="A",
        source="192.168.1.1",
        event_type="port_scan",
        details="test",
        score=0.5,
        targets=["192.168.1.2", "192.168.1.3"],
    )
    assert ev.point == "A"
    assert ev.event_type == "port_scan"
    assert ev.score == 0.5
    assert len(ev.targets) == 2
