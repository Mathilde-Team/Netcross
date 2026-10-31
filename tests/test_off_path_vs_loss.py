# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #352 : distinguer trafic hors chemin et pertes dans l'analyse croisee.

Scenario de l'issue, en miniature : trois points LAN -> WAN -> DC (ordre
connu, `--order`). Un scan local au LAN n'etait pas distingue d'une perte
(« 180 paquets manquants » a WAN et DC), et les paquets du sens retour
(DC -> LAN, TTL qui « augmente » de LAN a WAN) etaient comptes comme
« flux avec un nombre de sauts different ».
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate

POINTS = ["LAN", "WAN", "DC"]
CLIENT, SERVER = ("10.0.0.5", 40000), ("10.9.0.10", 443)


def _conversation(n: int, *, lost_at_dc: set[int] = frozenset(), t0: float = 0.0):
    """n aller-retours client<->serveur vus aux trois points, TTL coherents
    (un saut entre chaque point) ; les allers `lost_at_dc` disparaissent
    entre WAN et DC (perte reelle)."""
    pkts = []
    for i in range(n):
        ts = t0 + i * 0.1
        for idx, point in enumerate(POINTS):
            if not (point == "DC" and i in lost_at_dc):
                pkts.append(
                    make_pkt(
                        point=point,
                        ts=ts + idx * 0.001,
                        src=CLIENT[0],
                        sport=CLIENT[1],
                        dst=SERVER[0],
                        dport=SERVER[1],
                        ttl=64 - idx,
                        seq=1000 + i,
                        key_id=1000 + i,
                    )
                )
        for idx, point in enumerate(reversed(POINTS)):
            pkts.append(
                make_pkt(
                    point=point,
                    ts=ts + 0.05 + idx * 0.001,
                    src=SERVER[0],
                    sport=SERVER[1],
                    dst=CLIENT[0],
                    dport=CLIENT[1],
                    ttl=64 - idx,
                    seq=5000 + i,
                    key_id=5000 + i,
                    flags="...A...",
                )
            )
    return pkts


def _lan_scan(n: int):
    """Scan SYN d'un hote du LAN vers d'autres hotes du LAN : jamais vu a WAN ni DC."""
    return [
        make_pkt(
            point="LAN",
            ts=100.0 + i * 0.01,
            src="10.0.0.66",
            sport=50000,
            dst=f"10.0.0.{1 + i % 50}",
            dport=20 + i,
            flags="S......",
            seq=i,
            key_id=i,
        )
        for i in range(n)
    ]


def _run(pkts):
    flows = correlate(pkts)
    return analyse(flows, POINTS, pkts)


def test_scan_lan_seul_aucune_perte_a_wan_ni_dc():
    r = _run(_conversation(20) + _lan_scan(180))
    assert r.loss_count.get("WAN", 0) == 0
    assert r.loss_count.get("DC", 0) == 0
    assert r.off_path_count["WAN"] == 180
    assert r.off_path_count["DC"] == 180


def test_pertes_wan_dc_toujours_detectees():
    r = _run(_conversation(20, lost_at_dc={3, 7, 11}) + _lan_scan(180))
    assert r.loss_count.get("WAN", 0) == 0
    assert r.loss_count["DC"] == 3
    assert r.off_path_count["DC"] == 180  # le scan reste hors chemin, pas une perte


def test_perte_lan_wan_comptee_une_seule_fois():
    """Un paquet perdu entre LAN et WAN n'est pas recompte a DC."""
    pkts = [p for p in _conversation(10) if not (p.key_id == 1004 and p.point in ("WAN", "DC"))]
    r = _run(pkts)
    assert r.loss_count["WAN"] == 1
    assert r.loss_count.get("DC", 0) == 0
    assert r.off_path_count.get("WAN", 0) == 0


def test_sens_retour_ne_compte_pas_comme_nombre_de_sauts_different():
    r = _run(_conversation(30) + _lan_scan(50))
    assert r.hop_delta_outliers.get(("LAN", "WAN"), 0) == 0
    assert r.hop_delta_outliers.get(("WAN", "DC"), 0) == 0
    assert set(r.hop_delta[("LAN", "WAN")]) == {1}


def test_connexion_entierement_perdue_entre_hotes_connus_reste_une_perte():
    """SYN client -> serveur vu au LAN seulement, alors que ces deux hotes
    echangent par ailleurs au WAN : trou noir sur le chemin, pas hors chemin."""
    syn = make_pkt(
        point="LAN",
        ts=50.0,
        src=CLIENT[0],
        sport=41000,
        dst=SERVER[0],
        dport=SERVER[1],
        flags="S......",
        seq=1,
        key_id=1,
    )
    r = _run([*_conversation(5), syn])
    assert r.loss_count["WAN"] == 1
    assert r.off_path_count.get("WAN", 0) == 0


def test_vrai_changement_de_chemin_toujours_signale():
    """Un paquet dont le TTL baisse de 3 au lieu de 1 entre LAN et WAN
    (re-routage) reste un ecart au chemin majoritaire."""
    pkts = _conversation(10)
    for p in pkts:
        if p.key_id == 1002 and p.point == "WAN":
            p.ttl = 61
    r = _run(pkts)
    assert r.hop_delta_outliers[("LAN", "WAN")] == 1
