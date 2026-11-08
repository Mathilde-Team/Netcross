# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #346 : comptages justes et attribues a un point pour les
mouvements lateraux et flow_stats."""

from __future__ import annotations

from netcross_core.security.flow_stats import analyze_flow_stats
from netcross_core.security.lateral_movement import detect_lateral_movement
from tests.conftest import make_pkt

ATTAQUANT = "10.0.0.66"
CIBLES = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]


def _sessions_ssh(point: str, n: int = 36, paquets_par_session: int = 4) -> list:
    """n sessions SSH (port source distinct), chacune de plusieurs paquets."""
    return [
        make_pkt(
            point=point,
            src=ATTAQUANT,
            dst=CIBLES[i % len(CIBLES)],
            sport=40000 + i,
            dport=22,
            proto="TCP",
            ts=float(i) + j * 0.01,
        )
        for i in range(n)
        for j in range(paquets_par_session)
    ]


def _brute_force(events):
    return [e for e in events if e.event_type == "brute_force"]


def test_36_sessions_donnent_36_tentatives():
    """Critere d'acceptation : 36 sessions injectees -> 36 tentatives."""
    events = _brute_force(detect_lateral_movement(_sessions_ssh("LAN")).events)
    assert len(events) == 1
    assert "36 tentatives vers 3 hotes" in events[0].details
    assert events[0].point == "LAN"


def test_meme_brute_force_sur_plusieurs_points_un_seul_evenement():
    """Un meme mouvement vu sur 3 points = UN evenement avec 3 points."""
    pkts = _sessions_ssh("LAN") + _sessions_ssh("WAN") + _sessions_ssh("DC")
    events = _brute_force(detect_lateral_movement(pkts).events)
    assert len(events) == 1
    ev = events[0]
    assert "36 tentatives" in ev.details
    assert ev.points == ("DC", "LAN", "WAN")
    assert ev.point == "DC"
    assert sorted(ev.targets) == CIBLES


def test_flow_stats_par_point_sans_double_comptage():
    """Un flux vu sur 2 points = 2 flux (un par point), chacun avec le bon
    nombre de paquets et son point renseigne."""
    pkts = _sessions_ssh("LAN", n=3, paquets_par_session=5) + _sessions_ssh("WAN", n=3, paquets_par_session=5)
    flows = analyze_flow_stats(pkts).flows
    par_point = {(f.points[0], f.src, f.dst): f.packet_count for f in flows}
    for point in ("LAN", "WAN"):
        for dst in CIBLES:
            assert par_point[(point, ATTAQUANT, dst)] == 5
    for f in flows:
        d = f.to_dict()
        assert d["point"] in ("LAN", "WAN")
        assert d["points"] == [d["point"]]
