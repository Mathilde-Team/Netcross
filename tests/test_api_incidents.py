# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1095 : routes API du gel rétroactif et des incidents archivés
-- GET/PUT /gel/config, GET /incidents, GET /incidents/{id},
POST /incidents/{id}/analyse.

Mêmes conventions que test_issue_906_api_bpf_library : fichier de réglages
isolé par variable d'environnement (tmp_path), incidents réels construits
par les fonctions du chantier (#1087/#1090), analyse injectée (fausse)
pour le câblage et réelle (échec propre, 409) pour la panoplie complète :
ni tshark ni privilège requis."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi", reason="extra [api] non installé")

from fastapi.testclient import TestClient  # noqa: E402

api = importlib.import_module("netcross_api.app")
routes = importlib.import_module("netcross_api.incident_routes")
client = TestClient(api.app)


@pytest.fixture(autouse=True)
def fichier(tmp_path, monkeypatch):
    """Fichier de réglages isolé par test (même approche que bpf_routes)."""
    chemin = tmp_path / "gel_config.json"
    monkeypatch.setenv(routes.GEL_CONFIG_ENV, str(chemin))
    return chemin


@pytest.fixture
def archive(tmp_path):
    """Un incident archivé réel (gel -> manifeste signé) dans
    tmp_path/archives, pointé par les réglages."""
    from test_incident_analysis import _archive as _construire

    manifeste, _dossier = _construire(tmp_path)
    rep = client.put("/gel/config", json={"archives_dir": str(tmp_path / "archives")})
    assert rep.status_code == 200
    return manifeste


# --------------------------------------------------------------------------


def test_gel_config_défauts_puis_modification(fichier):
    """Fichier absent = défauts ; PUT partiel : les clés absentes gardent
    leur valeur courante, les invalides sont refusées (422)."""
    rep = client.get("/gel/config")
    assert rep.status_code == 200
    assert rep.json()["seconds_before"] == 60.0
    assert rep.json()["max_octets_archives"] is None

    rep = client.put("/gel/config", json={"seconds_before": 120})
    assert rep.status_code == 200
    corps = rep.json()
    assert corps["seconds_before"] == 120
    assert corps["seconds_after"] == 30.0  # inchangé
    assert json.loads(fichier.read_text(encoding="utf-8"))["seconds_before"] == 120

    # Clé inconnue / valeur hors bornes : refus, fichier inchangé.
    rep = client.put("/gel/config", json={"seconde_avant": 10})
    assert rep.status_code == 422
    rep = client.put("/gel/config", json={"seconds_before": 0})
    assert rep.status_code == 422
    rep = client.put("/gel/config", json={"min_severity": "critique"})
    assert rep.status_code == 422
    assert json.loads(fichier.read_text(encoding="utf-8"))["seconds_before"] == 120


def test_liste_et_détail_des_incidents(archive, tmp_path):
    """L'inventaire vient du répertoire des réglages (archives_dir) :
    alarme, points, segments, état des rapports ; le détail renvoie le
    manifeste complet (chaîne de preuve) et le rapport s'il existe."""
    rep = client.get("/incidents")
    assert rep.status_code == 200
    incidents = rep.json()["incidents"]
    assert len(incidents) == 1
    seul = incidents[0]
    assert seul["incident"] == archive.incident
    assert seul["alarme"]["rule_id"] == "loss_per_segment"
    assert seul["segments"] == len(archive.fichiers)
    assert seul["rapport_json"] is False  # pas encore analysé

    rep = client.get(f"/incidents/{archive.incident}")
    assert rep.status_code == 200
    detail = rep.json()
    assert detail["alarme"]["rule_id"] == "loss_per_segment"
    assert len(detail["fichiers"]) == len(archive.fichiers)
    assert all("empreinte" in f for f in detail["fichiers"])
    assert "rapport" not in detail

    # Inconnu : 404.
    rep = client.get("/incidents/gel-inconnu")
    assert rep.status_code == 404


def test_analyse_câblée(archive, monkeypatch):
    """POST /analyse : l'API câble les injections netcross_report (score,
    HTML, notification) et range le rapport dans l'archive — vérifié avec
    une analyse injectée (les mêmes injections que la GUI)."""
    appels = {}

    def faux_analyser_incident(manifeste, **kwargs):
        appels["manifeste"] = manifeste
        appels["kwargs"] = kwargs
        return SimpleNamespace(
            incident=manifeste.incident,
            dossier="/archives/gel-1/incident",
            chemin_rapport="/archives/gel-1/incident/rapport.json",
            chemin_html="/archives/gel-1/incident/rapport.html",
            points=("LAN", "WAN"),
            score=42,
            level="elevee",
            notifications=({"canal": "webhook", "statut": "livre"},),
        )

    import netcross_core.incident_analysis

    monkeypatch.setattr(netcross_core.incident_analysis, "analyser_incident", faux_analyser_incident)

    rep = client.post(f"/incidents/{archive.incident}/analyse")
    assert rep.status_code == 200
    corps = rep.json()
    assert corps["incident"] == archive.incident
    assert corps["rapport_json"].endswith("rapport.json")
    assert corps["rapport_html"].endswith("rapport.html")
    assert corps["score"] == 42
    assert corps["notifications"] == [{"canal": "webhook", "statut": "livre"}]
    # Le manifeste relu est bien celui de l'archive, et les injections
    # (évaluateur, HTML, configuration de notification) sont passées.
    assert appels["manifeste"].incident == archive.incident
    assert "evaluateur" in appels["kwargs"]
    assert "generateur_html" in appels["kwargs"]
    assert appels["kwargs"]["cfg_notification"] is not None

    # Inconnu : 404.
    rep = client.post("/incidents/gel-inconnu/analyse")
    assert rep.status_code == 404


def test_analyse_refusée_si_archive_indécodable(archive):
    """Panoplie complète SANS tshark : les segments de l'archive de test
    ne sont pas des pcap décodables, l'analyse réelle refuse proprement
    (409) au lieu de produire un rapport vide."""
    rep = client.post(f"/incidents/{archive.incident}/analyse")
    assert rep.status_code == 409
    assert "paquet" in rep.json()["detail"]
