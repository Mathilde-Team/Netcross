# SPDX-License-Identifier: GPL-3.0-or-later
"""Tableau de bord Grafana d'exemple (issue #1118).

Le JSON doit rester importable et surtout fidèle au catalogue figé de
#1110 : chaque métrique `netcross_*` référencée dans une requête ou une
variable doit exister dans `netcross_report.metrics_export.METRICS`, et
le guide doit documenter le même chemin d'import.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from netcross_report.metrics_export import METRICS

RACINE = Path(__file__).resolve().parents[1]
TABLEAU = RACINE / "docs" / "grafana" / "netcross-segments.json"
GUIDE = RACINE / "docs" / "grafana-dashboard.md"
NOMS_CATALOGUE = {spec.name for spec in METRICS}
_MOTIF_METRIQUE = re.compile(r"netcross_[a-z_]+")


def _expressions_valeur(objet):
    """Toutes les valeurs de clés 'expr'/'query'/'definition', récursivement."""
    if isinstance(objet, dict):
        for cle, valeur in objet.items():
            if cle in {"expr", "query", "definition"} and isinstance(valeur, str):
                yield valeur
            else:
                yield from _expressions_valeur(valeur)
    elif isinstance(objet, list):
        for element in objet:
            yield from _expressions_valeur(element)


def test_le_json_est_valide_et_importable():
    tableau = json.loads(TABLEAU.read_text(encoding="utf-8"))
    assert tableau["schemaVersion"] >= 39
    assert tableau["title"].startswith("Netcross")
    assert any(entree["name"] == "DS_PROMETHEUS" for entree in tableau["__inputs"])
    panneaux = [p for p in tableau["panels"] if p["type"] != "row"]
    assert len(panneaux) >= 8


def test_chaque_metrique_referencee_existe_au_catalogue():
    tableau = json.loads(TABLEAU.read_text(encoding="utf-8"))
    references = set()
    for expression in _expressions_valeur(tableau):
        references.update(_MOTIF_METRIQUE.findall(expression))
    assert references, "le tableau de bord doit référencer des métriques netcross_*"
    assert references <= NOMS_CATALOGUE, sorted(references - NOMS_CATALOGUE)


def test_variables_run_et_segment():
    tableau = json.loads(TABLEAU.read_text(encoding="utf-8"))
    variables = {v["name"]: v for v in tableau["templating"]["list"]}
    assert "run" in variables and "segment" in variables
    # les requêtes de variables passent aussi par le catalogue
    for variable in variables.values():
        for expression in _expressions_valeur(variable):
            for metrique in _MOTIF_METRIQUE.findall(expression):
                assert metrique in NOMS_CATALOGUE


def test_panneaux_par_segment_et_par_point():
    tableau = json.loads(TABLEAU.read_text(encoding="utf-8"))
    exprs = " ".join(e for e in _expressions_valeur(tableau))
    for attendu in (
        "netcross_segment_loss_ratio",
        "netcross_segment_delay_seconds",
        "netcross_segment_triage_score",
        "netcross_health_score",
        "netcross_point_packets_total",
        "netcross_point_lost_flows_total",
    ):
        assert attendu in exprs, f"panneau manquant pour {attendu}"
    # les panneaux segment sont filtrés par $segment
    assert 'segment=~"$segment"' in exprs


def test_le_guide_document_l_import_et_les_alertes():
    texte = GUIDE.read_text(encoding="utf-8")
    assert "netcross-segments.json" in texte
    assert "DS_PROMETHEUS" in texte
    assert "scrape_configs" in texte
    # exemples d'alertes : au moins perte de segment et délai p95
    assert "netcross_segment_loss_ratio > 0.10" in texte
    assert 'quantile="0.95"' in texte
