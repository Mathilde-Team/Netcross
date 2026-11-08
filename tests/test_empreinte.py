# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de netcross_core.empreinte (issue #1021) : empreinte compacte et
invariante d'un paquet, equivalente a l'appariement de correlate()."""

from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from netcross_core import empreinte as emp
from netcross_core.correlate import correlate, flow_key
from netcross_core.testing.synth import Configuration, generer
from tests.conftest import make_pkt

TSHARK = shutil.which("tshark")


def _trafic():
    """Petit trafic multi-points : TCP, UDP, ICMP, ARP/STP et un doublon."""
    paquets = []
    for point, ttl, ts in (("A", 64, 0.000), ("B", 63, 0.002), ("C", 62, 0.004)):
        paquets += [
            make_pkt(point=point, ts=ts, ttl=ttl, seq=1000, key_id=1000),
            make_pkt(point=point, ts=ts + 0.01, ttl=ttl, seq=1100, key_id=1100, payload_hash="aa"),
            make_pkt(point=point, ts=ts, ttl=ttl, proto="UDP", sport=5353, dport=53, seq=None, key_id=7, ip_id=7),
            make_pkt(point=point, ts=ts, ttl=ttl, proto="ICMP", sport=None, dport=None, seq=None, key_id=9, ip_id=9),
        ]
    # perte entre B et C
    paquets.append(make_pkt(point="A", ts=0.5, seq=2000, key_id=2000))
    paquets.append(make_pkt(point="B", ts=0.502, ttl=63, seq=2000, key_id=2000))
    # trafic local et doublon
    paquets.append(make_pkt(point="A", proto="ARP", sport=None, dport=None, key_id=None))
    paquets.append(make_pkt(point="B", proto="STP", sport=None, dport=None, key_id=None))
    paquets.append(make_pkt(point="C", ts=0.004, ttl=62, seq=1000, key_id=1000, is_duplicate=True))
    return paquets


# -- empreinte elle-meme -----------------------------------------------------------


def test_empreinte_tient_sur_64_bits_et_est_deterministe():
    pk = make_pkt()
    valeur = emp.empreinte(pk)
    assert 0 <= valeur < 2**64
    assert valeur == emp.empreinte(make_pkt())
    assert valeur == emp.empreinte_de_cle(flow_key(pk))


def test_empreinte_stable_entre_processus():
    """Pas de hash() Python : la valeur ne depend pas de PYTHONHASHSEED."""
    cle = ("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000)
    code = f"from netcross_core.empreinte import empreinte_de_cle;print(empreinte_de_cle({cle!r}))"
    sortie = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": "12345", "PATH": "", "PYTHONPATH": ":".join(sys.path)},
    ).stdout
    assert int(sortie.strip()) == emp.empreinte_de_cle(cle)


def test_empreinte_ignore_les_champs_modifies_a_chaque_saut():
    a = make_pkt(point="A", ttl=64, dscp=0, length=100, ts=0.0)
    b = make_pkt(point="B", ttl=12, dscp=46, length=104, ts=3.0, vlan_id=20)
    assert emp.empreinte(a) == emp.empreinte(b)


@pytest.mark.parametrize(
    "champ, valeur",
    [("proto", "UDP"), ("src", "10.9.9.9"), ("sport", 1), ("dst", "10.9.9.8"), ("dport", 80), ("key_id", 5)],
)
def test_empreinte_change_avec_chaque_champ_stable(champ, valeur):
    assert champ in emp.CHAMPS_STRICTS
    assert emp.empreinte(make_pkt(**{champ: valeur})) != emp.empreinte(make_pkt())


def test_none_distinct_de_chaine_vide_et_de_zero():
    base = ("UDP", "10.0.0.1", None, "10.0.0.2", None, 1)
    assert emp.empreinte_de_cle(base) != emp.empreinte_de_cle(("UDP", "10.0.0.1", 0, "10.0.0.2", None, 1))
    assert emp.empreinte_de_cle(base) != emp.empreinte_de_cle(("UDP", "10.0.0.1", "", "10.0.0.2", None, 1))


def test_taille_compacte_par_rapport_au_tuple():
    cle = flow_key(make_pkt())
    assert emp.TAILLE_OCTETS == 8
    assert sys.getsizeof(emp.empreinte_de_cle(cle)) < sys.getsizeof(cle) + sum(sys.getsizeof(c) for c in cle)


# -- filtre et appariement --------------------------------------------------------


def test_est_correlable_meme_filtre_que_correlate():
    assert emp.est_correlable(make_pkt())
    assert not emp.est_correlable(make_pkt(proto="ARP"))
    assert not emp.est_correlable(make_pkt(proto="STP"))
    assert emp.est_correlable(make_pkt(is_duplicate=True))
    assert not emp.est_correlable(make_pkt(is_duplicate=True), exclude_duplicates=True)


@pytest.mark.parametrize("exclude_duplicates", [False, True])
@pytest.mark.parametrize("nat_tolerant", [False, True])
def test_apparier_equivaut_a_correlate(nat_tolerant, exclude_duplicates):
    paquets = _trafic()
    reference = correlate(paquets, nat_tolerant=nat_tolerant, exclude_duplicates=exclude_duplicates)
    groupes = emp.apparier(paquets, nat_tolerant=nat_tolerant, exclude_duplicates=exclude_duplicates)
    rapport = emp.comparer_appariements(reference, groupes)
    assert rapport == {
        "groupes_cle": len(reference),
        "groupes_empreinte": len(reference),
        "collisions": 0,
        "identiques": True,
    }
    assert set(groupes) == {emp.empreinte_de_cle(cle) for cle in reference}


def test_apparier_accepte_un_generateur():
    groupes = emp.apparier(iter(_trafic()))
    assert len(groupes) == len(correlate(_trafic()))


def test_comparer_detecte_une_partition_differente():
    paquets = _trafic()
    reference = correlate(paquets)
    groupes = emp.apparier(paquets)
    # on fusionne deux groupes : la partition n'est plus la meme
    premier, second = list(groupes)[:2]
    fusion = dict(groupes)
    fusion[premier] = {p: groupes[premier].get(p, []) + groupes[second].get(p, []) for p in ("A", "B", "C")}
    del fusion[second]
    rapport = emp.comparer_appariements(reference, fusion)
    assert rapport["identiques"] is False
    assert rapport["groupes_empreinte"] == rapport["groupes_cle"] - 1


def test_collisions_signalees(monkeypatch):
    monkeypatch.setattr(emp, "empreinte_de_cle", lambda cle: 42)
    trouvees = emp.collisions([("a",), ("b",), ("a",)])
    assert trouvees == [(42, [("a",), ("b",)])]


def test_collisions_aucune_sur_cles_distinctes():
    cles = [("TCP", "10.0.0.1", p, "10.0.0.2", 443, s) for p in range(50) for s in range(50)]
    assert emp.collisions(cles) == []


# -- cas NAT ----------------------------------------------------------------------


def test_nat_empreinte_stricte_differe_tolerante_concorde():
    """Un NAT reecrit adresse et port : le mode strict ne rapproche pas les
    deux vues, le mode NAT-tolerant (hash du payload + fenetre) si."""
    avant = make_pkt(point="LAN", ts=1.000, src="192.168.1.10", sport=40000, payload_hash="cafe")
    apres = make_pkt(point="WAN", ts=1.001, src="203.0.113.5", sport=61000, payload_hash="cafe")
    assert emp.empreinte(avant) != emp.empreinte(apres)
    assert emp.empreinte(avant, nat_tolerant=True) == emp.empreinte(apres, nat_tolerant=True)
    for nat in (False, True):
        reference = correlate([avant, apres], nat_tolerant=nat)
        assert emp.comparer_appariements(reference, emp.apparier([avant, apres], nat_tolerant=nat))["identiques"]


def test_nat_tolerant_sans_payload_retombe_sur_le_mode_strict():
    syn = make_pkt(payload_hash=None)
    assert emp.empreinte(syn, nat_tolerant=True) == emp.empreinte(syn)


def test_nat_tolerant_hors_fenetre_ne_concorde_pas():
    a = make_pkt(point="LAN", ts=1.0, payload_hash="cafe")
    b = make_pkt(point="WAN", ts=1.5, payload_hash="cafe")
    assert emp.empreinte(a, nat_tolerant=True, nat_window_ms=200) != emp.empreinte(
        b, nat_tolerant=True, nat_window_ms=200
    )


# -- cas fragmentation ------------------------------------------------------------


def _fragments(point, ts, ttl):
    """Datagramme UDP en trois fragments : seul le premier porte les ports."""
    commun = {"point": point, "ttl": ttl, "proto": "UDP", "seq": None, "ip_id": 77, "key_id": 77, "is_fragment": True}
    return [
        make_pkt(ts=ts, sport=5000, dport=6000, **commun),
        make_pkt(ts=ts + 0.0001, sport=None, dport=None, **commun),
        make_pkt(ts=ts + 0.0002, sport=None, dport=None, **commun),
    ]


def test_fragmentation_meme_appariement_que_correlate():
    paquets = _fragments("A", 0.0, 64) + _fragments("B", 0.002, 63)
    reference = correlate(paquets)
    groupes = emp.apparier(paquets)
    assert emp.comparer_appariements(reference, groupes)["identiques"]
    # premier fragment (avec ports) et fragments suivants (sans ports)
    # forment deux groupes distincts, comme avec la cle tuple
    assert len(groupes) == 2
    tailles = sorted(sum(len(v) for v in par_point.values()) for par_point in groupes.values())
    assert tailles == [2, 4]


def test_fragmentation_en_route_cree_un_groupe_vu_seulement_en_aval():
    """Un routeur fragmente entre A et B : le premier fragment garde la
    cle du datagramme d'origine, les suivants n'existent qu'en aval."""
    origine = make_pkt(point="A", proto="UDP", seq=None, sport=5000, dport=6000, ip_id=88, key_id=88)
    aval = [
        make_pkt(point="B", proto="UDP", seq=None, sport=5000, dport=6000, ip_id=88, key_id=88, is_fragment=True),
        make_pkt(point="B", proto="UDP", seq=None, sport=None, dport=None, ip_id=88, key_id=88, is_fragment=True),
    ]
    groupes = emp.apparier([origine, *aval])
    assert sorted(sorted(par_point) for par_point in groupes.values()) == [["A", "B"], ["B"]]
    assert emp.comparer_appariements(correlate([origine, *aval]), groupes)["identiques"]


# -- jeux de reference du banc (synth + tshark) ------------------------------------


@pytest.mark.skipif(TSHARK is None, reason="tshark absent")
@pytest.mark.parametrize("nat_tolerant", [False, True])
def test_equivalence_sur_jeu_synthetique(tmp_path, nat_tolerant):
    from netcross_core.parsing import parse_capture

    verite = generer(Configuration(points=3, paquets=1500, graine=7, segment_perte=2, taux_perte=0.05), tmp_path)
    paquets = []
    for nom in verite["points"]:
        paquets += parse_capture(nom, str(tmp_path / f"{nom}.pcapng"), raise_on_error=True)
    assert paquets
    reference = correlate(paquets, nat_tolerant=nat_tolerant)
    rapport = emp.comparer_appariements(reference, emp.apparier(paquets, nat_tolerant=nat_tolerant))
    assert rapport["identiques"], rapport
    assert rapport["collisions"] == 0
    assert rapport["groupes_cle"] == rapport["groupes_empreinte"] > 100
