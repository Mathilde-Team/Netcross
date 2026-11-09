# SPDX-License-Identifier: GPL-3.0-or-later
"""Seconde passe ciblée en flux (issue #1025) : topologie déduite d'agrégats bornés."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core.analysis import _infer_topology
from netcross_core.correlate import correlate
from netcross_core.seconde_passe import run_seconde_passe
from netcross_core.streaming import sources_by_point

RACINE = Path(__file__).resolve().parent.parent
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"
EXEMPLES = RACINE / "docs" / "guide" / "exemples"
DOC = RACINE / "docs" / "seconde-passe.md"
requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")

POINTS = ["CLIENT", "ROUTEUR", "SERVEUR"]


def _trafic(seed=1, n=300, perte=0.05):
    """Paquets TCP/UDP traversant trois points (TTL décroissant le long du
    chemin : le signal de la topologie), avec pertes et flux hors chemin."""
    import random

    rnd = random.Random(seed)
    paquets = []
    for i in range(n):
        t0 = i * 0.01
        hote = f"10.0.{i % 7}.1"
        proto = "TCP" if i % 3 else "UDP"
        donnees = f"h{i}" if i % 2 else None
        base = {
            "proto": proto,
            "src": hote,
            "dst": "192.0.2.10",
            "sport": 40000 + i % 50,
            "dport": 443,
            "key_id": 1000 + i,
            "payload_hash": donnees,
        }
        t = t0
        for idx, point in enumerate(POINTS):
            if idx and rnd.random() < perte:
                break
            t += 0.001 * (idx + 1)
            paquets.append(make_pkt(point=point, ts=t, ttl=64 - idx, **base))
    # flux locaux : vus à un seul point (isolés de la topologie)
    paquets.extend(make_pkt(point="CLIENT", ts=i * 0.3, src="10.9.9.9", dst="10.9.9.8", key_id=i) for i in range(10))
    # ARP/STP : exclus de la corrélation comme du batch
    paquets.append(make_pkt(point="ROUTEUR", ts=1.0, proto="ARP", src="10.0.0.1", dst="10.0.0.2"))
    paquets.append(make_pkt(point="SERVEUR", ts=1.1, proto="STP", src="10.0.0.1", dst="10.0.0.2"))
    paquets.sort(key=lambda pk: pk.ts)
    return paquets


def _batch_topologie(paquets, points=POINTS):
    flows = correlate(paquets)
    return _infer_topology(flows, points)


def _assert_topologies_egales(passe, attendu):
    edges, ambiguous, isolated, branch, merge = attendu
    assert passe.topology_edges == edges
    assert passe.topology_ambiguous == ambiguous
    assert passe.topology_isolated == isolated
    assert passe.topology_branch_points == branch
    assert passe.topology_merge_points == merge


# -- equivalence avec le mode actuel -----------------------------------------------------


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_equivalence_topologie_avec_le_mode_batch(seed):
    paquets = _trafic(seed)
    attendu = _batch_topologie(paquets)
    passe = run_seconde_passe(sources_by_point(paquets), POINTS)
    _assert_topologies_egales(passe, attendu)


def test_equivalence_avec_debordement_sur_disque():
    # seuil minuscule : les agrégats partent sur disque et sont relus par
    # items() -- la topologie ne doit pas changer
    paquets = _trafic(4)
    attendu = _batch_topologie(paquets)
    passe = run_seconde_passe(sources_by_point(paquets), POINTS, spill_seuil=3)
    _assert_topologies_egales(passe, attendu)


def test_equivalence_sans_ordre():
    # sans --order : les points viennent des flux eux-mêmes, comme analyse()
    paquets = _trafic(5)
    points = sorted({pk.point for pk in paquets})
    attendu = _infer_topology(correlate(paquets), points)
    passe = run_seconde_passe(sources_by_point(paquets), points)
    _assert_topologies_egales(passe, attendu)


def test_arp_stp_hors_agregats():
    # les trames ARP/STP ne comptent pas comme présence de flux (même
    # exclusion que correlate) : elles ne gonflent ni les flux vus ni les
    # votes de TTL
    paquets = [
        make_pkt(point="CLIENT", ts=0.0, ttl=64, src="10.0.0.1", dst="192.0.2.9", key_id=1),
        make_pkt(point="SERVEUR", ts=0.01, ttl=63, src="10.0.0.1", dst="192.0.2.9", key_id=1),
        make_pkt(point="CLIENT", ts=0.02, proto="ARP", src="10.0.0.5", dst="10.0.0.6"),
        make_pkt(point="SERVEUR", ts=0.03, proto="STP", src="10.0.0.5", dst="10.0.0.6"),
    ]
    passe = run_seconde_passe(sources_by_point(paquets), ["CLIENT", "SERVEUR"])
    attendu = _infer_topology(correlate(paquets), ["CLIENT", "SERVEUR"])
    _assert_topologies_egales(passe, attendu)


def test_doublons_exclus():
    paquets = _trafic(6)
    paquets[0].is_duplicate = True
    avec_exclusion = run_seconde_passe(sources_by_point(paquets), POINTS, exclude_duplicates=True)
    # même exclusion que correlate(exclude_duplicates=True)
    flows = correlate(paquets, exclude_duplicates=True)
    attendu = _infer_topology(flows, POINTS)
    _assert_topologies_egales(avec_exclusion, attendu)


def test_finish_idempotent():
    paquets = _trafic(7)[:50]
    passe = run_seconde_passe(sources_by_point(paquets), POINTS)
    arretes = passe.topology_edges
    passe.finish()
    assert passe.topology_edges == arretes


def test_to_dict_seralise_les_tuples():
    paquets = _trafic(8)
    passe = run_seconde_passe(sources_by_point(paquets), POINTS)
    doc = passe.to_dict()
    assert doc["topology_edges"] == [[u, d, info] for u, d, info in passe.topology_edges]
    # sérialisable en JSON (clé streaming.seconde_passe du rapport)
    json.dumps(doc)


# -- exemples du guide (électronique, tshark requis) -------------------------------------


@requires_tshark
def test_equivalence_sur_les_exemples_du_guide():
    from netcross_core.parsing import parse_capture

    paquets = []
    for label, chemin in (("LAN", "lan.pcap"), ("WAN", "wan.pcap")):
        paquets.extend(parse_capture(label, str(EXEMPLES / chemin)))
    points = sorted({pk.point for pk in paquets})
    attendu = _infer_topology(correlate(paquets), points)
    passe = run_seconde_passe(sources_by_point(paquets), points)
    _assert_topologies_egales(passe, attendu)
    assert passe.topology_edges, "les exemples du guide doivent déduire au moins une arête"


@requires_tshark
def test_cli_streaming_seconde_passe_dans_le_rapport_json(tmp_path):
    sortie = tmp_path / "r.json"
    env = dict(
        __import__("os").environ,
        PYTHONPATH=str(RACINE / "src"),
    )
    res = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--capture",
            f"LAN={EXEMPLES / 'lan.pcap'}",
            "--capture",
            f"WAN={EXEMPLES / 'wan.pcap'}",
            "--streaming",
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
    doc = json.loads(sortie.read_text(encoding="utf-8"))
    assert doc["streaming"]["seconde_passe"]["topology_edges"], "la seconde passe doit déduire la topologie LAN -> WAN"


def test_documentation():
    texte = DOC.read_text(encoding="utf-8")
    for mot in ("seconde passe", "#1025", "topologie", "bornée"):
        assert mot in texte, mot
    assert "seconde-passe.md" in (RACINE / "mkdocs.yml").read_text(encoding="utf-8")
