# SPDX-License-Identifier: GPL-3.0-or-later
"""Correlation en flux par fenetre glissante (issue #1022)."""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.streaming import (
    DEFAULT_WINDOW_SECONDS,
    StreamingCorrelator,
    StreamingResult,
    correlate_streaming,
    merge_points,
    sources_by_point,
)
from netcross_report.json_report import build_json_report_document

RACINE = Path(__file__).resolve().parent.parent
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"
EXEMPLES = RACINE / "docs" / "guide" / "exemples"
DOC = RACINE / "docs" / "correlation-en-flux.md"
requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")

POINTS = ["CLIENT", "ROUTEUR", "SERVEUR"]


def _trafic(seed=1, n=400, perte=0.05, retrans=0.03, hors_chemin=True):
    """Paquets TCP/UDP traversant trois points, avec pertes, retransmissions,
    transit variable (donc desordre entre points) et un scan local au CLIENT."""
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
            t += rnd.uniform(0.0005, 0.05)
            paquets.append(make_pkt(point=point, ts=t, ttl=64 - idx, **base))
            if proto == "TCP" and rnd.random() < retrans:
                paquets.append(make_pkt(point=point, ts=t + 0.2, ttl=64 - idx, **base))
    if hors_chemin:
        paquets.extend(
            make_pkt(point="CLIENT", ts=i * 0.3, src="10.9.9.9", dst="10.9.9.8", key_id=i) for i in range(10)
        )
    paquets.append(make_pkt(point="ROUTEUR", ts=1.0, proto="ARP", src="10.0.0.1", dst="10.0.0.2"))
    paquets.sort(key=lambda pk: pk.ts)
    return paquets


def _batch(paquets, order=POINTS):
    flows = correlate(paquets)
    return analyse(flows, order, paquets)


def _assert_equivalents(res, r, points=POINTS):
    for p in points:
        assert res.packet_count[p] == r.packet_count[p], p
        assert res.seen_count[p] == r.seen_count[p], p
        assert res.retrans[p] == r.retrans[p], p
        assert res.dup_ack[p] == r.dup_ack[p], p
        assert res.loss_count[p] == r.loss_count[p], p
        assert res.off_path_count[p] == r.off_path_count[p], p
    for a, b in zip(points, points[1:], strict=False):
        batch = r.latency[(a, b)]
        assert res.latency_n[(a, b)] == len(batch)
        if batch:
            assert res.mean_latency_ms(a, b) == pytest.approx(sum(batch) / len(batch))


# -- equivalence avec le mode actuel -----------------------------------------------------


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_equivalence_des_compteurs_avec_le_mode_actuel(seed):
    paquets = _trafic(seed)
    res = correlate_streaming(sources_by_point(paquets), POINTS, window_seconds=1.0)
    r = _batch(paquets)
    _assert_equivalents(res, r)
    assert res.late_packets == 0
    assert not res.truncated
    assert sum(r.loss_count.values()) > 0
    assert r.off_path_count["ROUTEUR"] > 0
    assert sum(r.retrans.values()) > 0


def test_memoire_bornee_par_la_fenetre():
    paquets = _trafic(4, n=2000)
    res = correlate_streaming(sources_by_point(paquets), POINTS, window_seconds=0.5)
    assert res.groups >= 2000
    # ~100 groupes par seconde : une fenetre de 0,5 s n'en garde qu'une fraction
    assert res.peak_open_groups < res.groups / 10


def test_paquets_desordonnes_entre_points():
    # le SERVEUR voit le paquet 2 avant que le CLIENT ne voie le paquet 1
    p = [
        make_pkt(point="CLIENT", ts=0.0, key_id=1),
        make_pkt(point="SERVEUR", ts=0.05, key_id=2),
        make_pkt(point="CLIENT", ts=0.01, key_id=2),
        make_pkt(point="SERVEUR", ts=0.02, key_id=1),
    ]
    sources = {"CLIENT": [p[0], p[2]], "SERVEUR": [p[3], p[1]]}
    res = correlate_streaming(sources, ["CLIENT", "SERVEUR"], window_seconds=1.0)
    assert res.groups == 2
    assert res.loss_count["SERVEUR"] == 0
    assert res.mean_latency_ms("CLIENT", "SERVEUR") == pytest.approx(30.0)


def test_suite_localement_desordonnee_rattachee_dans_la_fenetre():
    sources = {
        "A": [make_pkt(point="A", ts=0.5, key_id=1), make_pkt(point="A", ts=0.4, key_id=2)],
        "B": [make_pkt(point="B", ts=0.6, key_id=1), make_pkt(point="B", ts=0.45, key_id=2)],
    }
    res = correlate_streaming(sources, ["A", "B"], window_seconds=1.0)
    assert res.out_of_order >= 1
    assert res.groups == 2
    assert res.seen_count["B"] == 2
    assert "desordonne" in "\n".join(res.summary_lines())


def test_flux_traversant_la_fin_de_fenetre_signale():
    # retransmission 3 s apres l'original : la fenetre de 1 s a deja ferme le groupe
    paquets = [
        make_pkt(point="A", ts=0.0, key_id=1, payload_hash="x"),
        make_pkt(point="B", ts=0.01, key_id=1, payload_hash="x"),
        make_pkt(point="A", ts=1.5, key_id=2),
        make_pkt(point="A", ts=3.0, key_id=1, payload_hash="x"),
        make_pkt(point="B", ts=3.01, key_id=1, payload_hash="x"),
    ]
    res = correlate_streaming(sources_by_point(paquets), ["A", "B"], window_seconds=1.0)
    assert res.late_packets == 1
    assert res.truncated
    texte = "\n".join(res.summary_lines())
    assert "TRONCATURE" in texte
    assert "--streaming-window" in texte
    assert res.to_dict()["truncated"] is True
    # une fenetre plus large rend le resultat exact
    large = correlate_streaming(sources_by_point(paquets), ["A", "B"], window_seconds=5.0)
    assert not large.truncated
    _assert_equivalents(large, _batch(paquets, ["A", "B"]), ["A", "B"])


def test_cle_fermee_oubliee_apres_deux_fenetres():
    paquets = [
        make_pkt(point="A", ts=0.0, key_id=1),
        make_pkt(point="A", ts=1.5, key_id=2),
        make_pkt(point="A", ts=5.0, key_id=3),
        make_pkt(point="A", ts=5.5, key_id=1),
    ]
    res = correlate_streaming({"A": paquets}, ["A"], window_seconds=1.0)
    assert res.late_packets == 0
    assert res.groups == 4


def test_groupes_ouverts_en_fin_de_capture():
    paquets = [make_pkt(point="A", ts=0.0, key_id=1), make_pkt(point="A", ts=0.1, key_id=2)]
    res = correlate_streaming({"A": paquets}, ["A"], window_seconds=1.0)
    assert res.open_at_end == 2
    assert "fin de capture" in "\n".join(res.summary_lines())


def test_sans_ordre_aucune_perte():
    paquets = _trafic(5, n=50)
    res = correlate_streaming(sources_by_point(paquets), None, window_seconds=1.0)
    assert res.points == sorted(POINTS)
    assert sum(res.loss_count.values()) == 0
    assert sum(res.off_path_count.values()) == 0


def test_mode_nat_tolerant_perte_sans_conversation():
    a = make_pkt(point="A", ts=0.0, payload_hash="p1", src="10.0.0.1")
    b = make_pkt(point="B", ts=0.01, payload_hash="p1", src="198.51.100.1")
    c = make_pkt(point="A", ts=0.02, payload_hash="p2", src="10.0.0.1")
    res = correlate_streaming({"A": [a, c], "B": [b]}, ["A", "B"], window_seconds=1.0, nat_tolerant=True)
    assert res.groups == 2
    assert res.loss_count["B"] == 1


def test_doublons_exclus():
    d = make_pkt(point="A", ts=0.0, key_id=1)
    d.is_duplicate = True
    res = correlate_streaming({"A": [d, make_pkt(point="A", ts=0.1, key_id=2)]}, ["A"], exclude_duplicates=True)
    assert res.packet_count["A"] == 1
    assert res.groups == 1


def test_perte_seulement_au_premier_point_manquant():
    paquets = [make_pkt(point="A", ts=0.0, src="10.0.0.1"), make_pkt(point="C", ts=0.0, src="10.0.0.1", key_id=9)]
    paquets += [make_pkt(point="B", ts=0.0, src="10.0.0.1", key_id=8)]
    res = correlate_streaming(sources_by_point(paquets), ["A", "B", "C"], window_seconds=1.0)
    _assert_equivalents(res, _batch(paquets, ["A", "B", "C"]), ["A", "B", "C"])


def test_merge_points_trie_par_temps():
    a = [make_pkt(point="A", ts=t) for t in (0.0, 0.2, 0.4)]
    b = [make_pkt(point="B", ts=t) for t in (0.1, 0.3)]
    assert [pk.ts for pk in merge_points([iter(a), iter(b)])] == [0.0, 0.1, 0.2, 0.3, 0.4]


def test_fenetre_invalide():
    with pytest.raises(ValueError, match="strictement positive"):
        StreamingCorrelator(["A"], window_seconds=0)


def test_finish_idempotent():
    c = StreamingCorrelator(["A"])
    c.feed(make_pkt(point="A", ts=0.0))
    premier = c.finish()
    assert c.finish() is premier
    assert premier.groups == 1


def test_resultat_vide():
    res = StreamingResult(window_seconds=DEFAULT_WINDOW_SECONDS, points=["A", "B"])
    assert res.mean_latency_ms("A", "B") is None
    doc = res.to_dict()
    assert doc["by_segment"] == {"A -> B": {"mean_latency_ms": None}}
    assert json.dumps(doc)


def test_cle_streaming_du_rapport_json():
    paquets = _trafic(6, n=30)
    r = _batch(paquets)
    assert "streaming" not in build_json_report_document(r)
    r.streaming = correlate_streaming(sources_by_point(paquets), POINTS).to_dict()
    doc = build_json_report_document(r)
    assert doc["streaming"]["by_point"]["CLIENT"]["packets"] == r.packet_count["CLIENT"]


# -- CLI ------------------------------------------------------------------------------------


@requires_tshark
def test_cli_streaming(tmp_path):
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
            "--streaming-window",
            "1.5",
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
    assert "Correlation en flux (fenetre 1.5 s)" in res.stdout
    doc = json.loads(sortie.read_text(encoding="utf-8"))
    assert doc["streaming"]["window_seconds"] == 1.5
    assert doc["streaming"]["by_point"]["WAN"]["flows"] == 121


def test_run_streaming_direct(capsys):
    sys.path.insert(0, str(RACINE / "src"))
    import cross_capture_analyzer_cli as cli

    class Args:
        streaming_window = 1.0
        nat_tolerant = False
        nat_window_ms = 200
        exclude_duplicates = False

    paquets = _trafic(7, n=20)
    r = _batch(paquets)
    cli._run_streaming(Args, paquets, POINTS, r)
    assert r.streaming["groups"] > 0
    assert "Correlation en flux" in capsys.readouterr().out


def test_documentation():
    doc = DOC.read_text(encoding="utf-8")
    for mot in ("--streaming", "--streaming-window", "TRONCATURE", "heapq.merge", "late_packets", "open_at_end"):
        assert mot in doc, mot
    assert "correlation-en-flux.md" in (RACINE / "mkdocs.yml").read_text(encoding="utf-8")
