# SPDX-License-Identifier: GPL-3.0-or-later
"""Vue « Chemin » du rapport HTML autonome (issue #1075).

Le JavaScript embarque est execute sans navigateur (``tests/js/rendu_headless.js``,
Node et un DOM minimal) : survol, focus, fleches du clavier et segment non
mesurable sont verifies sur le DOM produit, dont un rendu de l'exemple du guide
(``docs/guide/exemples/``).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core.models import Report
from netcross_report import html_report
from netcross_report.html_report import _labels, _static_value, render_html_report
from netcross_report.json_report import build_json_report_document

RACINE = Path(__file__).resolve().parent.parent
EXEMPLES = RACINE / "docs" / "guide" / "exemples"
RENDU = Path(__file__).resolve().parent / "js" / "rendu_headless.js"
NODE = shutil.which("node")
avec_node = pytest.mark.skipif(NODE is None, reason="node absent")
avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")


def _segment(amont, aval, **valeurs):
    seg = {
        "upstream": amont,
        "downstream": aval,
        "segment": f"{amont} -> {aval}",
        "measured": True,
        "samples": 10,
        "delay_avg_ms": 4.0,
        "delay_p50_ms": 4.0,
        "delay_p95_ms": 4.5,
        "delay_p99_ms": 4.9,
        "jitter_ms": 0.2,
        "loss_count": 1,
        "loss_pct": 10.0,
        "throughput_bps": 2_500_000.0,
        "clock_offset_ms": None,
        "clock_drift_ppm": None,
        "clock_ci_ms": None,
        "clock_samples": None,
        "clock_method": None,
        "dscp_changes": 0,
        "frag_new": 0,
        "pmtud_blackhole": 0,
        "retrans": 2,
        "hops": 1,
        "hop_outliers": 0,
    }
    seg.update(valeurs)
    return seg


NON_MESURE = {
    "measured": False,
    "samples": 0,
    "loss_count": 0,
    "delay_avg_ms": None,
    "delay_p50_ms": None,
    "delay_p95_ms": None,
    "delay_p99_ms": None,
    "jitter_ms": None,
    "loss_pct": None,
    "throughput_bps": None,
    "hops": None,
}


def _doc(segments):
    doc = build_json_report_document(Report(points=["A", "B", "C"]), title="T", findings=[])
    doc["path_metrics"] = segments
    return doc


def _rendre(page: str, actions=()):
    """Execute le script embarque de ``page`` dans Node ; renvoie (arbre, etats)."""
    elements = {
        "rapport": "",
        "netcross-data": _json_brut(page, "netcross-data"),
        "netcross-labels": _json_brut(page, "netcross-labels"),
    }
    script = re.findall(r"<script>(.*?)</script>", page, re.S)
    assert len(script) == 1
    entree = json.dumps({"script": script[0], "elements": elements, "actions": list(actions)})
    sortie = subprocess.run([NODE, str(RENDU)], input=entree, capture_output=True, text=True, check=True, timeout=60)
    resultat = json.loads(sortie.stdout)
    return resultat["rapport"], resultat["etats"]


def _json_brut(page: str, element_id: str) -> str:
    """Contenu brut (JSON echappe) d'une balise ``<script type="application/json">``."""
    m = re.search(rf'<script type="application/json" id="{element_id}">(.*?)</script>', page, re.S)
    assert m is not None
    return m.group(1)


def _noeuds(arbre, predicat):
    trouves = []

    def visiter(n):
        if predicat(n):
            trouves.append(n)
        for c in n["children"]:
            visiter(c)

    visiter(arbre)
    return trouves


def _texte(n) -> str:
    return n["text"] + "".join(_texte(c) for c in n["children"])


def _chemin(arbre):
    (liste,) = _noeuds(arbre, lambda n: n["attrs"].get("id") == "vue-chemin")
    return [
        ("segment" if c["children"] else "point", _texte(c), c["children"][0]["attrs"] if c["children"] else c["attrs"])
        for c in liste["children"]
    ]


# -- JSON du rapport ------------------------------------------------------------------------------


def test_path_metrics_dans_le_json_dans_l_ordre_du_chemin():
    r = Report(points=["A", "B", "C"])
    r.pairs = [("B", "C"), ("A", "B")]
    r.topology_edges = [("B", "C", {}), ("A", "B", {})]
    r.latency = {("A", "B"): [1.0, 3.0]}
    r.seen_count = {"B": 4}
    r.loss_count = {"B": 1}
    doc = build_json_report_document(r, findings=[])
    assert [s["segment"] for s in doc["path_metrics"]] == ["A -> B", "B -> C"]
    ab, bc = doc["path_metrics"]
    assert (ab["measured"], ab["samples"], ab["delay_avg_ms"], ab["loss_pct"]) == (True, 2, 2.0, 25.0)
    assert (bc["measured"], bc["samples"], bc["delay_avg_ms"], bc["loss_pct"]) == (False, 0, None, None)


def test_path_metrics_vide_sans_paire():
    assert build_json_report_document(Report(points=["A"]), findings=[])["path_metrics"] == []


# -- rendu sans JavaScript ------------------------------------------------------------------------


def test_noscript_tableau_des_segments():
    page = render_html_report(_doc([_segment("A", "B"), _segment("B", "C", **NON_MESURE)]))
    statique = re.search(r"<noscript>(.*)</noscript>", page, re.S).group(1)
    assert "Chemin observe" in statique and "Metriques par segment" in statique
    assert "<td>A -&gt; B</td><td>mesure</td><td>10</td><td>4,000 ms</td>" in statique
    assert "<td>B -&gt; C</td><td>non mesurable</td><td>0</td><td>non mesure</td>" in statique
    assert "2,50 Mbit/s" in statique


def test_noscript_sans_segment():
    statique = re.search(r"<noscript>(.*)</noscript>", render_html_report(_doc([])), re.S).group(1)
    assert "Aucun segment" in statique


@pytest.mark.parametrize(
    ("cle", "valeur", "attendu"),
    [
        ("throughput_bps", 2_500_000.0, "2,50 Mbit/s"),
        ("throughput_bps", 171_189.3, "171,2 kbit/s"),
        ("throughput_bps", None, "non mesure"),
        ("delay_p95_ms", 4.00018, "4,000 ms"),
        ("loss_pct", 4.1322, "4,13 %"),
        ("hops", 1, "1"),
        ("clock_drift_ppm", 12.345, "12,35 ppm"),
    ],
)
def test_format_des_valeurs(cle, valeur, attendu):
    labels = _labels()
    (champ,) = [c for c in labels["segment_fields"] if c["cle"] == cle]
    assert _static_value({cle: valeur}, champ, labels) == attendu


def test_champs_de_detail_couvrent_path_metrics():
    cles = {c["cle"] for c in html_report._SEGMENT_FIELDS}
    assert cles <= set(_segment("A", "B"))
    assert {"delay_avg_ms", "delay_p95_ms", "jitter_ms", "loss_pct", "throughput_bps", "hops"} <= cles


# -- rendu headless du JavaScript -----------------------------------------------------------------


@avec_node
def test_vue_chemin_points_et_segments():
    page = render_html_report(_doc([_segment("A", "B"), _segment("B", "C", **NON_MESURE)]))
    arbre, _ = _rendre(page)
    chemin = _chemin(arbre)
    assert [(t, txt) for t, txt, _ in chemin] == [
        ("point", "A"),
        ("segment", "4,00 ms / 10,0 % pertes"),
        ("point", "B"),
        ("segment", "non mesurable"),
        ("point", "C"),
    ]
    mesure, non_mesure = chemin[1][2], chemin[3][2]
    assert mesure["class"] == "segment" and non_mesure["class"] == "segment non-mesurable"
    assert non_mesure["aria-label"] == "Segment B -> C : non mesurable"
    assert all(a["type"] == "button" and a["aria-controls"] == "detail-segment" for a in (mesure, non_mesure))


@avec_node
def test_survol_affiche_le_detail():
    page = render_html_report(_doc([_segment("A", "B"), _segment("B", "C", **NON_MESURE)]))
    _, (survol, survol_nm) = _rendre(page, [{"type": "survol", "index": 0}, {"type": "survol", "index": 1}])
    assert survol["detail_segment"] == "A -> B"
    assert "Segment A -> B : mesure" in survol["detail"]
    for attendu in ("Delai moyen4,000 ms", "Delai P954,500 ms", "Gigue0,200 ms", "Taux de perte10,00 %"):
        assert attendu in survol["detail"]
    assert "Debit au point aval2,50 Mbit/s" in survol["detail"] and "Sauts IP1" in survol["detail"]
    assert survol_nm["detail_segment"] == "B -> C"
    assert "non mesurable" in survol_nm["detail"] and "inconnues, pas nulles" in survol_nm["detail"]
    assert "Delai moyennon mesure" in survol_nm["detail"] and "Echantillons0" in survol_nm["detail"]


@avec_node
def test_navigation_clavier():
    page = render_html_report(_doc([_segment("A", "B"), _segment("B", "C"), _segment("C", "D", **NON_MESURE)]))
    actions = [
        {"type": "focus", "index": 0},
        {"type": "touche", "index": 0, "key": "ArrowRight"},
        {"type": "touche", "index": 1, "key": "ArrowDown"},
        {"type": "touche", "index": 2, "key": "ArrowRight"},
        {"type": "touche", "index": 2, "key": "Home"},
        {"type": "touche", "index": 0, "key": "ArrowLeft"},
        {"type": "touche", "index": 0, "key": "End"},
        {"type": "touche", "index": 2, "key": "ArrowUp"},
        {"type": "touche", "index": 1, "key": "a"},
        {"type": "clic", "index": 0},
    ]
    _, etats = _rendre(page, actions)
    assert [e["actif"] for e in etats[:8]] == ["0", "1", "2", "2", "0", "0", "2", "1"]
    attendu = ["A -> B", "B -> C", "C -> D", "C -> D", "A -> B", "A -> B", "C -> D", "B -> C"]
    assert [e["detail_segment"] for e in etats[:8]] == attendu
    assert [e["empeche"] for e in etats[1:9]] == [True] * 7 + [False]
    assert etats[9]["detail_segment"] == "A -> B"


@avec_node
def test_chemin_ramifie_repete_le_point_amont():
    page = render_html_report(_doc([_segment("A", "B"), _segment("A", "C")]))
    arbre, _ = _rendre(page)
    assert [txt for t, txt, _ in _chemin(arbre) if t == "point"] == ["A", "B", "A", "C"]


@avec_node
def test_sans_segment_message_et_contenu_hostile():
    arbre, _ = _rendre(render_html_report(_doc([])))
    assert "Aucun segment" in _texte(arbre)
    hostile = '<img src=x onerror="alert(1)">'
    arbre, (etat,) = _rendre(render_html_report(_doc([_segment(hostile, "B")])), [{"type": "survol", "index": 0}])
    assert [txt for t, txt, _ in _chemin(arbre) if t == "point"] == [hostile, "B"]
    assert not _noeuds(arbre, lambda n: n["tag"] == "img")
    assert etat["detail_segment"] == f"{hostile} -> B"


@avec_node
@avec_tshark
def test_rendu_headless_de_l_exemple_du_guide(tmp_path, monkeypatch):
    sortie = tmp_path / "rapport.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            f"LAN={EXEMPLES / 'lan.pcap'}",
            "--capture",
            f"WAN={EXEMPLES / 'wan.pcap'}",
            "--json-report",
            str(sortie),
        ],
    )
    try:
        cli.main()
    except SystemExit as fin:
        assert fin.code in (0, None)
    doc = json.loads(sortie.read_text(encoding="utf-8"))
    (segment,) = doc["path_metrics"]
    assert (segment["segment"], segment["measured"], segment["loss_count"]) == ("LAN -> WAN", True, 5)
    page = render_html_report(doc)
    arbre, (etat,) = _rendre(page, [{"type": "survol", "index": 0}])
    assert [(t, txt) for t, txt, _ in _chemin(arbre)] == [
        ("point", "LAN"),
        ("segment", "4,00 ms / 4,1 % pertes"),
        ("point", "WAN"),
    ]
    assert "Segment LAN -> WAN : mesure" in etat["detail"] and "Paquets perdus5" in etat["detail"]
    assert "Delai moyen4,000 ms" in etat["detail"]
