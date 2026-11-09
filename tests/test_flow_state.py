# SPDX-License-Identifier: GPL-3.0-or-later
"""État par flux avec expiration par protocole (issue #1023)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.flow_state import (
    DEFAULT_FLOW_TIMEOUTS,
    FlowTable,
    parse_flow_timeouts,
    run_flow_table,
)
from netcross_report.json_report import build_json_report_document

RACINE = Path(__file__).resolve().parent.parent
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"
EXEMPLES = RACINE / "docs" / "guide" / "exemples"
DOC = RACINE / "docs" / "etat-flux.md"
requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")

POINTS = ["CLIENT", "SERVEUR"]
DELAIS = {"TCP": 60.0, "UDP": 60.0, "ICMP": 60.0, "AUTRE": 60.0}

CONN = {"src": "10.0.0.1", "dst": "192.0.2.10", "sport": 40000, "dport": 443}


def _connexion(vu_en_aval=True, silence=100.0, reprise_vu_en_aval=False):
    """Connexion TCP vue aux deux points, éventuellement coupée : silence
    de ``silence`` secondes côté CLIENT, puis réveil jamais revu en aval."""
    paquets = []
    for i, t in enumerate([0.0, 1.0, 2.0]):
        paquets.append(make_pkt(point="CLIENT", ts=t, seq=100 + i, key_id=100 + i, **CONN))
        if vu_en_aval:
            paquets.append(make_pkt(point="SERVEUR", ts=t + 0.01, seq=100 + i, key_id=100 + i, **CONN))
    # réveil en amont après le silence
    paquets.append(make_pkt(point="CLIENT", ts=2.0 + silence, seq=900, key_id=900, **CONN))
    paquets.append(make_pkt(point="CLIENT", ts=2.0 + silence + 1.0, seq=901, key_id=901, **CONN))
    if reprise_vu_en_aval:
        paquets.append(make_pkt(point="SERVEUR", ts=2.0 + silence + 0.01, seq=900, key_id=900, **CONN))
    paquets.sort(key=lambda pk: pk.ts)
    return paquets


def _batch(paquets, order=POINTS):
    flows = correlate(paquets)
    return analyse(flows, order, paquets)


def _flux(paquets, order=POINTS, timeouts=DELAIS):
    sources = {p: [q for q in paquets if q.point == p] for p in order}
    return run_flow_table(sources.values(), order, timeouts=timeouts)


# -- délais configurables ------------------------------------------------------------------


def test_parse_flow_timeouts_defauts_et_specification():
    assert parse_flow_timeouts(None) == DEFAULT_FLOW_TIMEOUTS
    assert parse_flow_timeouts("tcp=30,UDP=15") == {"TCP": 30.0, "UDP": 15.0}
    assert parse_flow_timeouts(" TCP = 5 , ICMP=1.5, AUTRE=2 ") == {"TCP": 5.0, "ICMP": 1.5, "AUTRE": 2.0}


@pytest.mark.parametrize(
    "spec",
    ["TCP=0", "UDP=-1", "SMTP=30", "TCP=trente", "TCP=", "", "   ", "TCP30", "TCP;UDP"],
)
def test_parse_flow_timeouts_refuse_les_specifications_invalides(spec):
    with pytest.raises(ValueError):
        parse_flow_timeouts(spec)


# -- expiration / réouverture ---------------------------------------------------------------


def test_expiration_d_un_flux_inactif():
    table = FlowTable(POINTS, timeouts=DELAIS)
    table.feed(make_pkt(point="CLIENT", ts=0.0, **CONN))
    table.feed(make_pkt(point="SERVEUR", ts=0.01, **CONN))
    # un autre flux fait avancer le temps de 100 s : le premier expire
    table.feed(make_pkt(point="CLIENT", ts=100.0, src="10.0.0.9", dst="10.0.0.10", sport=2000, dport=80))
    assert table.expired == 1
    assert table.closed_at_end == 0
    table.finish()
    assert table.total_records == 2
    assert table.closed_at_end == 1
    assert table.records_by_proto["TCP"] == 2


def test_reouverture_d_un_flux_apres_expiration():
    table = FlowTable(["CLIENT"], timeouts=DELAIS)
    table.feed(make_pkt(point="CLIENT", ts=0.0, **CONN))
    table.feed(make_pkt(point="CLIENT", ts=1.0, **CONN))
    # silence de 100 s puis réveil : nouvel enregistrement, réouverture comptée
    table.feed(make_pkt(point="CLIENT", ts=101.0, **CONN))
    assert table.reopened["TCP"] == 1
    table.finish()
    assert table.total_records == 2
    assert table.expired == 1
    assert table.closed_at_end == 1


def test_memoire_bornee_par_les_flux_actifs():
    table = FlowTable(["CLIENT"], timeouts={"TCP": 1.0, "UDP": 1.0, "ICMP": 1.0, "AUTRE": 1.0})
    for i in range(500):
        base = {"src": f"10.0.{i}.1", "dst": "192.0.2.9", "sport": 10000 + i, "dport": 443}
        table.feed(make_pkt(point="CLIENT", ts=i * 10.0, **base))
        table.feed(make_pkt(point="CLIENT", ts=i * 10.0 + 0.5, **base))
    # 500 flux vus en tout, jamais plus de quelques états actifs à la fois
    assert table.peak_active <= 2
    table.finish()
    assert table.total_records == 500
    assert table.expired == 499
    assert table.closed_at_end == 1


# -- détecteur incrémental : mêmes constats que le mode actuel ------------------------------


def test_coupure_nat_incrementale_egale_le_mode_actuel():
    # réveil jamais revu en aval : le détecteur batch compte une coupure
    paquets = _connexion()
    r = _batch(paquets)
    assert r.idle_timeout_dropped[("CLIENT", "SERVEUR")] == 1
    table = _flux(paquets)
    assert table.nat_cutoffs[("CLIENT", "SERVEUR")] == 1
    assert table.cutoff_examples[("CLIENT", "SERVEUR")]


def test_pas_de_coupure_quand_le_reveil_est_revu_en_aval():
    paquets = _connexion(reprise_vu_en_aval=True)
    r = _batch(paquets)
    assert r.idle_timeout_dropped[("CLIENT", "SERVEUR")] == 0
    table = _flux(paquets)
    assert table.nat_cutoffs[("CLIENT", "SERVEUR")] == 0


def test_pas_de_coupure_quand_le_silence_est_plus_court_que_le_delai():
    paquets = _connexion(silence=10.0)
    r = _batch(paquets)
    assert r.idle_timeout_dropped[("CLIENT", "SERVEUR")] == 0
    table = _flux(paquets)
    assert table.nat_cutoffs[("CLIENT", "SERVEUR")] == 0
    assert table.reopened["TCP"] == 0


def test_pas_de_coupure_sur_un_flux_vu_d_un_seul_point():
    # jamais vu en aval avant le silence : pas ce scénario (cf. _analyse_idle_timeout)
    paquets = _connexion(vu_en_aval=False)
    r = _batch(paquets)
    assert r.idle_timeout_dropped[("CLIENT", "SERVEUR")] == 0
    table = _flux(paquets)
    assert table.nat_cutoffs[("CLIENT", "SERVEUR")] == 0


def test_une_seule_coupure_par_flux_et_par_segment():
    # deux silences coupés successifs : un seul constat, comme le mode batch
    paquets = _connexion()
    paquets.append(make_pkt(point="CLIENT", ts=300.0, seq=950, key_id=950, **CONN))
    paquets.append(make_pkt(point="CLIENT", ts=500.0, seq=980, key_id=980, **CONN))
    paquets.sort(key=lambda pk: pk.ts)
    r = _batch(paquets)
    assert r.idle_timeout_dropped[("CLIENT", "SERVEUR")] == 1
    table = _flux(paquets)
    assert table.nat_cutoffs[("CLIENT", "SERVEUR")] == 1


# -- rapport --------------------------------------------------------------------------------


def test_rapport_json_et_texte():
    table = _flux(_connexion(), timeouts={"TCP": 50.0, "UDP": 60.0, "ICMP": 60.0, "AUTRE": 60.0})
    doc = table.to_dict()
    assert doc["timeouts"]["TCP"] == 50.0
    assert doc["records"] == 2
    assert doc["expired"] == 1
    assert doc["nat_cutoffs"] == {"CLIENT -> SERVEUR": 1}
    lignes = table.summary_lines()
    assert any("État par flux" in ligne for ligne in lignes)
    assert any("COUPURE NAT/PARE-FEU" in ligne for ligne in lignes)


def test_section_flow_state_du_rapport_json():
    paquets = _connexion()
    r = _batch(paquets)
    doc = build_json_report_document(r)
    assert "flow_state" not in doc.get("streaming", {})  # sans --streaming, rien


# -- CLI ------------------------------------------------------------------------------------


@requires_tshark
def test_cli_flow_state(tmp_path):
    sortie = tmp_path / "r.json"
    env = dict(os.environ, PYTHONPATH=str(RACINE / "src"))
    res = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--capture",
            f"LAN={EXEMPLES / 'lan.pcap'}",
            "--capture",
            f"WAN={EXEMPLES / 'wan.pcap'}",
            "--order",
            "LAN,WAN",
            "--streaming",
            "--flow-timeouts",
            "TCP=1200,UDP=30,ICMP=30,AUTRE=30",
            "--json-report",
            str(sortie),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert "Correlation en flux" in res.stdout
    assert "État par flux" in res.stdout
    doc = json.loads(sortie.read_text(encoding="utf-8"))
    assert doc["streaming"]["flow_state"]["timeouts"] == {
        "TCP": 1200.0,
        "UDP": 30.0,
        "ICMP": 30.0,
        "AUTRE": 30.0,
    }
    assert doc["streaming"]["flow_state"]["records"] > 0
    assert "nat_cutoffs" in doc["streaming"]["flow_state"]


def test_documentation():
    doc = DOC.read_text(encoding="utf-8")
    for mot in ("--flow-timeouts", "expiration", "réouverture", "coupure", "Zeek", "flow_state"):
        assert mot in doc, mot


# -- branches restantes ---------------------------------------------------------------------


def test_specification_avec_virgule_finale():
    assert parse_flow_timeouts("TCP=30,") == {"TCP": 30.0}


def test_table_sans_point_refusee():
    with pytest.raises(ValueError):
        FlowTable([])


def test_fermeture_au_fil_de_leau_quand_le_point_aval_garde_letat_vivant():
    # le point aval voit le flux à t=50 : l'état n'expire pas en tâche de
    # fond (dernier paquet global récent), mais le silence côté CLIENT
    # (t=1 -> t=101) ferme l'état au fil de l'eau
    table = FlowTable(POINTS, timeouts=DELAIS)
    for t in (0.0, 1.0):
        table.feed(make_pkt(point="CLIENT", ts=t, **CONN))
        table.feed(make_pkt(point="SERVEUR", ts=t + 0.01, **CONN))
    table.feed(make_pkt(point="SERVEUR", ts=50.01, **CONN))
    assert table.total_records == 0  # rien de fermé : l'état est vivant
    table.feed(make_pkt(point="CLIENT", ts=101.0, **CONN))
    assert table.total_records == 1
    assert table.expired == 1
    table.finish()
    assert table.total_records == 2


def test_finish_est_idempotent():
    table = _flux(_connexion())
    table.finish()
    total = table.total_records
    table.finish()
    assert table.total_records == total


def test_eviction_des_cles_recentement_fermees(monkeypatch):
    import netcross_core.flow_state as fs

    monkeypatch.setattr(fs, "_SEEN_CAP", 2)
    table = FlowTable(["CLIENT"], timeouts={"TCP": 1.0, "UDP": 1.0, "ICMP": 1.0, "AUTRE": 1.0})
    for i in range(4):
        table.feed(make_pkt(point="CLIENT", ts=i * 10.0, src=f"10.0.{i}.1", dst="192.0.2.9", sport=10000 + i, dport=443))
    # les clés les plus anciennes sont oubliées : la réouverture n'est
    # comptée que pour la clé encore mémorisée
    table.feed(make_pkt(point="CLIENT", ts=100.0, src="10.0.3.1", dst="192.0.2.9", sport=10003, dport=443))
    assert table.reopened["TCP"] == 1


def test_coupure_sur_trois_points_un_seul_segment():
    points = ["CLIENT", "ROUTEUR", "SERVEUR"]
    paquets = []
    for t in (0.0, 1.0):
        for point in points:
            paquets.append(make_pkt(point=point, ts=t, **CONN))
    # réveil en CLIENT et ROUTEUR, jamais en SERVEUR : coupure (ROUTEUR, SERVEUR)
    for t in (101.0, 102.0):
        paquets.append(make_pkt(point="CLIENT", ts=t, **CONN))
        paquets.append(make_pkt(point="ROUTEUR", ts=t, **CONN))
    paquets.sort(key=lambda pk: pk.ts)
    table = _flux(paquets, order=points)
    assert table.nat_cutoffs[("ROUTEUR", "SERVEUR")] == 1
    assert table.nat_cutoffs[("CLIENT", "ROUTEUR")] == 0


def test_arp_stp_hors_table_de_flux():
    table = FlowTable(["A"], timeouts=DELAIS)
    table.feed(make_pkt(point="A", ts=0.0, proto="ARP", src="10.0.0.1", dst="10.0.0.2"))
    table.feed(make_pkt(point="A", ts=1.0, proto="STP", src="10.0.0.1", dst="10.0.0.2"))
    table.finish()
    assert table.total_records == 0


def test_lignes_resume_sans_reouverture_ni_coupure():
    table = FlowTable(["A"], timeouts=DELAIS)
    table.feed(make_pkt(point="A", ts=0.0, **CONN))
    # un autre flux fait expirer le premier : pas de réouverture (clé différente)
    table.feed(make_pkt(point="A", ts=100.0, src="10.0.0.2", dst="192.0.2.10", sport=40001, dport=443))
    table.finish()
    lignes = table.summary_lines()
    assert any("expiration(s) d'inactivité" in l for l in lignes)
    assert not any("réouverture" in l for l in lignes)
    assert not any("COUPURE" in l for l in lignes)


def test_lignes_resume_avec_reouverture_sans_coupure():
    table = FlowTable(["A"], timeouts=DELAIS)
    table.feed(make_pkt(point="A", ts=0.0, src="10.0.0.1", dst="192.0.2.10", sport=40000, dport=443))
    table.feed(make_pkt(point="A", ts=100.0, src="10.0.0.1", dst="192.0.2.10", sport=40000, dport=443))
    table.feed(make_pkt(point="A", ts=100.5, src="10.0.0.1", dst="192.0.2.10", sport=40000, dport=443))
    table.finish()
    lignes = table.summary_lines()
    assert any("réouverture(s) après expiration" in l for l in lignes)
    assert not any("COUPURE" in l for l in lignes)
