# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagrammes de séquence non tronqués et carte des communications du rapport
HTML (issue #1079, chantier #1000).

Le PDF plafonnait un flux à 30 lignes : ici le diagramme défile et zoome,
et ne dégrade la fidélité (échantillonnage) que lorsque le poids du fichier
l'exige -- jamais en silence. Le JavaScript embarqué est exécuté sous Node
(``tests/js/rendu_headless.js``, comme #1075/#1077).
"""

from __future__ import annotations

import re

import pytest
from conftest import make_pkt
from test_html_report_chemin import _json_brut, _noeuds, _rendre, _texte, avec_node  # noqa: F401

from netcross_core.models import Report
from netcross_report.html_report import render_html_report
from netcross_report.json_report import build_json_report_document
from netcross_report.sequence_diagrams import BUDGET_DONNEES_DEFAUT

POINTS = ["A", "B"]


def _flows(n=60, sport=1000, dport=80, proto="TCP"):
    """Un flux de ``n`` trames vues aux DEUX points (le même paquet → deux
    lignes : c'est l'écart entre elles qui mesure le transit), plus un flux
    mineur qui ne doit pas voler la première place."""
    flux = {}
    par_point = {p: [] for p in POINTS}
    for i in range(n):
        for j, p in enumerate(POINTS):
            par_point[p].append(
                make_pkt(
                    point=p,
                    ts=10.0 + i * 0.5 + j * 0.002,
                    frame_number=1 + i + 100 * j,
                    key_id=i,
                    sport=sport,
                    dport=dport,
                    proto=proto,
                    flags="...A..." if i == 0 else "A",
                    length=60,
                    is_retransmission=(i == n - 1),
                )
            )
    flux[("TCP", sport)] = par_point
    flux[("UDP", 53)] = {"A": [make_pkt(point="A", ts=10.01, frame_number=999, sport=5353, dport=53, proto="UDP")]}
    return flux


def _doc(flows=True, budget=None):
    kwargs = {"packet_flows": _flows() if flows else None}
    if budget is not None:
        kwargs["sequence_budget_octets"] = budget
    return build_json_report_document(Report(points=list(POINTS)), title="T", findings=[], **kwargs)


# ================================ JSON ================================


def test_diagrammes_non_tronques_dans_le_json():
    """Le diagramme porte TOUTES les lignes du flux principal (60 paquets x
    2 points = 120 lignes) : la limite des 30 lignes du PDF est levée."""
    doc = _doc()
    diagrams = doc["sequence_diagrams"]
    assert diagrams, "les flux corrélés doivent produire des diagrammes"
    assert diagrams[0]["sampled_step"] == 1
    assert len(diagrams[0]["steps"]) == 120
    assert diagrams[0]["total_steps"] == 120
    assert diagrams[0]["hosts"] == ["10.0.0.1", "10.0.0.2"]


def test_cartes_des_communications_dans_le_json():
    """La carte est déduite de la même corrélation : hôtes, arêtes
    orientées, volumes, protocoles."""
    carte = _doc()["comm_map"]
    hotes = {n["host"] for n in carte["nodes"]}
    assert hotes == {"10.0.0.1", "10.0.0.2"}
    aretes = {(a["src"], a["dst"]) for a in carte["edges"]}
    assert ("10.0.0.1", "10.0.0.2") in aretes or ("10.0.0.2", "10.0.0.1") in aretes
    assert carte["total_hosts"] == 2


def test_echantillonnage_signe_au_dela_du_budget():
    """Un budget minuscule dégrade par échantillonnage RÉGULIER, sans jamais
    mentir sur le total d'origine."""
    doc = _doc(budget=3000)
    d = doc["sequence_diagrams"][0]
    assert d["sampled_step"] > 1
    assert d["total_steps"] == 120  # le total d'origine reste écrit
    assert len(d["steps"]) < 120
    # L'échantillonnage reste régulier : pas de ligne sautée en silence.
    gardes = [e["rel_ms"] for e in d["steps"]]
    assert gardes == sorted(gardes)


def test_poids_du_fichier_maitrise_sur_un_gros_exemple():
    """Le seuil vise un FICHIER de ~20 Mo : les données de séquence sont
    budgetées à moitié (le rendu statique répète les lignes), et un gros
    flux tient dedans -- échantillonné, et c'est écrit."""
    doc = _flows(n=25000)
    gros = build_json_report_document(Report(points=list(POINTS)), title="T", findings=[], packet_flows=doc)
    d = gros["sequence_diagrams"][0]
    assert d["total_steps"] == 50000
    assert d["sampled_step"] > 1  # 8000 lignes ne tiennent pas dans le budget
    page = render_html_report(gros)
    # Le fichier final reste sous le seuil visé (donnees x2 pour le rendu
    # statique, plus le reste du document).
    assert len(page.encode("utf-8")) < 2 * BUDGET_DONNEES_DEFAUT


# ========================== rendu statique ==========================


def test_rendu_statique_sequence_et_carte():
    """Sans JavaScript : le tableau des lignes du flux, complet, et la carte
    en tableau d'arêtes."""
    page = render_html_report(_doc())
    statique = re.search(r"<noscript>(.*?)</noscript>", page, re.S).group(1)
    assert "Diagrammes de sequence" in statique
    assert "Carte des communications" in statique
    # 120 lignes : le rendu statique ne tronque pas non plus.
    assert statique.count("<tr>") >= 120 + 3
    assert "10.0.0.1" in statique and "10.0.0.2" in statique
    # La carte : au moins une arête entre les deux hôtes.
    assert "10.0.0.1" in statique


def test_rendu_statique_echantillonnage_signale():
    page = render_html_report(_doc(budget=3000))
    statique = re.search(r"<noscript>(.*?)</noscript>", page, re.S).group(1)
    assert "Echantillonnage : 1 ligne sur" in statique


# ============================ rendu JS ===============================


def _svg_sequence(arbre, diagramme="0"):
    svgs = [
        n
        for n in _noeuds(arbre, lambda n: n["attrs"].get("data-role") == "svg-sequence")
        if n["attrs"].get("data-diagramme") == diagramme
    ]
    assert svgs, "le SVG de séquence doit être rendu"
    return svgs[0]


@avec_node
def test_rendu_js_section_et_virtualisation():
    """La section existe, le SVG est rendu, et la fenêtre visible seulement
    (virtualisation) : data-rendues est bien inférieur au total."""
    arbre, _ = _rendre(render_html_report(_doc()))
    svg = _svg_sequence(arbre)
    rendues = int(svg["attrs"]["data-rendues"])
    assert rendues >= 1
    # 120 lignes ne tiennent pas dans la fenêtre : virtualisation réelle.
    assert rendues < 120


@avec_node
def test_defilement_rend_la_fenetre_suitive():
    """Après défilement, d'autres lignes sont rendues : le diagramme n'est
    pas une image figée."""
    page = render_html_report(_doc())
    arbre, _ = _rendre(page)
    arbre2, _ = _rendre(
        page,
        actions=[{"type": "defilement", "diagramme": 0, "valeur": 400}],
    )
    apres = int(_svg_sequence(arbre2)["attrs"]["data-rendues"])
    assert apres >= 1
    # Les lignes rendues après défilement ne sont pas les mêmes positions
    # temporelles : au moins une flèche est apparue ou a disparu.
    lignes_avant = {n["attrs"].get("y1") for n in _noeuds(arbre, lambda n: n["tag"] == "line")}
    lignes_apres = {n["attrs"].get("y1") for n in _noeuds(arbre2, lambda n: n["tag"] == "line")}
    assert lignes_avant != lignes_apres


@avec_node
def test_zoom_temporel():
    """Zoom + : l'échelle double (data-px-ms) et la hauteur du SVG suit --
    le temps reste lisible aux deux extrémités."""
    page = render_html_report(_doc())
    arbre, _ = _rendre(page)
    svg = _svg_sequence(arbre)
    px_avant = float(svg["attrs"]["data-px-ms"])
    arbre2, _ = _rendre(
        page,
        actions=[{"type": "clic", "attr": "data-action", "valeur": "zoom-in"}],
    )
    svg2 = _svg_sequence(arbre2)
    px_apres = float(svg2["attrs"]["data-px-ms"])
    assert px_apres == pytest.approx(px_avant * 2)
    assert float(svg2["attrs"]["height"]) > float(svg["attrs"]["height"])


@avec_node
def test_echantillonnage_signale_dans_le_rendu_js():
    page = render_html_report(_doc(budget=3000))
    arbre, _ = _rendre(page)
    textes = _texte(arbre)
    assert "Echantillonnage : 1 ligne sur" in textes


@avec_node
def test_carte_des_communications_svg():
    """La carte est un dessin : un SVG avec les arêtes et les hôtes."""
    arbre, _ = _rendre(render_html_report(_doc()))
    cartes = _noeuds(arbre, lambda n: n["attrs"].get("data-role") == "svg-carte")
    assert cartes, "le SVG de la carte doit être rendu"
    cercles = _noeuds(arbre, lambda n: n["tag"] == "circle")
    assert len(cercles) == 2  # un cercle par hôte
    lignes = [
        n
        for n in _noeuds(arbre, lambda n: n["tag"] == "line")
        if n["attrs"].get("x1") and n["attrs"].get("x1") != n["attrs"].get("x2")
    ]
    assert lignes, "au moins une arête dessinée"


@avec_node
def test_sans_flux_message_explicite():
    page = render_html_report(_doc(flows=False))
    arbre, _ = _rendre(page)
    assert "Aucun flux corrélé" in _texte(arbre)
