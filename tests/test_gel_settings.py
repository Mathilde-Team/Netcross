# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_gel_settings.py -- réglages du gel et inventaire des
incidents archivés (issue #1095).

Le fichier de réglages est partagé GUI / API : les mêmes règles de
validation (clés inconnues, types, bornes, sévérités) doivent refuser à
l'ÉCRITURE, pas à la prochaine alarme. L'inventaire relit les manifestes
signés (#1090) et signale l'état des rapports (#1091).
"""

import json
from pathlib import Path

import pytest

from netcross_core.gel_settings import (
    ARCHIVES_DEFAUT,
    REGLAGES_DEFAUT,
    detail_incident,
    ecrire_reglages,
    lire_reglages,
    lister_incidents,
    valider_reglages,
    vers_gel_config,
)
from netcross_core.retro_capture import GelConfig

# --------------------------------------------------------------------------


def test_valeurs_par_defaut():
    """Fichier absent = réglages par défaut (rien à configurer n'est pas
    une erreur), identiques à GelConfig (#1087/#1093) + archives."""
    reglages = lire_reglages()
    assert reglages == REGLAGES_DEFAUT
    config, archives = vers_gel_config(reglages)
    assert config == GelConfig()
    assert archives == ARCHIVES_DEFAUT


def test_ecriture_puis_lecture(tmp_path):
    """Écriture atomique puis lecture : fusion (les clés absentes du
    fichier gardent leur valeur par défaut), pas remplacement."""
    chemin = tmp_path / "gel_config.json"
    valides = ecrire_reglages(
        {"seconds_before": 120, "max_octets_archives": 5_000_000_000},
        chemin,
    )
    assert valides["seconds_before"] == 120
    lus = lire_reglages(chemin)
    # Fusion : les clés non écrites gardent les défauts.
    assert lus["seconds_before"] == 120
    assert lus["max_octets_archives"] == 5_000_000_000
    assert lus["seconds_after"] == REGLAGES_DEFAUT["seconds_after"]
    assert json.loads(chemin.read_text(encoding="utf-8"))["seconds_before"] == 120


def test_validation_refuse_les_erreurs():
    """Mieux vaut un refus immédiat qu'un gel mal réglé : clé inconnue,
    mauvais type, durée nulle, sévérité hors hiérarchie, quota nul,
    répertoire vide."""
    with pytest.raises(ValueError, match="réglage inconnu"):
        valider_reglages({"seconde_avant": 10})
    with pytest.raises(ValueError, match="type invalide"):
        valider_reglages({"seconds_before": "beaucoup"})
    with pytest.raises(ValueError, match="strictement positive"):
        valider_reglages({"seconds_before": 0})
    with pytest.raises(ValueError, match="min_severity"):
        valider_reglages({"min_severity": "critique"})
    with pytest.raises(ValueError, match="max_octets_archives"):
        valider_reglages({"max_octets_archives": 0})
    with pytest.raises(ValueError, match="archives_dir"):
        valider_reglages({"archives_dir": "   "})
    # Un booléen n'est pas un int : refus explicite (piège isinstance).
    with pytest.raises(ValueError, match="type invalide"):
        valider_reglages({"seconds_before": True})


def test_fichier_illisible_erreur_explicite(tmp_path):
    """Un réglage silencieusement ignoré est pire qu'une erreur."""
    chemin = tmp_path / "gel_config.json"
    chemin.write_text("{pas du tout du json", encoding="utf-8")
    with pytest.raises(ValueError, match="illisibles"):
        lire_reglages(chemin)


# --------------------------------------------------------------------------


def _archive(tmp_path):
    """Un incident archivé complet : manifeste signé + segments, via les
    vraies fonctions du chantier (#1087/#1090), puis un rapport (#1091)."""
    from test_incident_analysis import _archive as _archive_complete

    manifeste, dossier = _archive_complete(tmp_path)
    return manifeste, dossier


def test_lister_incidents_vide_puis_present(tmp_path):
    """Répertoire d'archives absent = liste vide (pas une erreur) ; un
    incident archivé apparaît avec son alarme, ses points, ses segments
    et l'état de ses rapports."""
    assert lister_incidents(tmp_path / "ailleurs") == []

    manifeste, _dossier = _archive(tmp_path)
    incidents = lister_incidents(tmp_path / "archives")
    assert len(incidents) == 1
    seul = incidents[0]
    assert seul["incident"] == manifeste.incident
    assert seul["alarme"]["rule_id"] == "loss_per_segment"
    assert seul["segments"] == len(manifeste.fichiers)
    assert seul["points"]
    # Pas encore d'analyse : aucun rapport.
    assert seul["rapport_json"] is False
    assert seul["rapport_html"] is False
    assert seul["octets"] > 0

    # Après analyse (#1091), le rapport est signalé.
    (Path(_dossier) / "rapport.json").write_text("{}", encoding="utf-8")
    relus = lister_incidents(tmp_path / "archives")
    assert relus[0]["rapport_json"] is True
    assert relus[0]["rapport_html"] is False


def test_lister_incidents_signale_manifeste_illisible(tmp_path):
    """Un manifeste corrompu est SIGNALÉ (entrée erreur), pas caché :
    l'analyste doit savoir que l'archive existe même si elle est corrompue."""
    racine = tmp_path / "archives"
    (racine / "gel-x" / "incident").mkdir(parents=True)
    (racine / "gel-x" / "incident" / "manifeste.json").write_text("{casse", encoding="utf-8")
    incidents = lister_incidents(racine)
    assert len(incidents) == 1
    assert "erreur" in incidents[0]


def test_detail_incident(tmp_path):
    """Détail : manifeste complet (chaîne de preuve) et rapport PARSÉ si
    présent ; None si inconnu ou nom suspect (pas de traversée)."""
    manifeste, dossier = _archive(tmp_path)

    detail = detail_incident(tmp_path / "archives", manifeste.incident)
    assert detail is not None
    assert detail["alarme"]["rule_id"] == "loss_per_segment"
    assert len(detail["fichiers"]) == len(manifeste.fichiers)
    assert all("empreinte" in f for f in detail["fichiers"])
    assert "rapport" not in detail  # pas encore analysé

    # Rapport présent → inclus, parsé.
    (Path(dossier) / "rapport.json").write_text(json.dumps({"schema": "netcross.incident/1"}), encoding="utf-8")
    detail = detail_incident(tmp_path / "archives", manifeste.incident)
    assert detail["rapport"]["schema"] == "netcross.incident/1"

    # Inconnu / nom suspect : None, jamais d'exception.
    assert detail_incident(tmp_path / "archives", "gel-inconnu") is None
    assert detail_incident(tmp_path / "archives", "../archives") is None
