# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_incidents_panel.py -- décisions de l'onglet « Incidents »
(issue #1095), sans aucun objet GTK (même approche que test_bpf_panel) :
le résumé d'une ligne d'incident, l'état des rapports et la conversion
des champs saisis en réglages valides (mêmes règles que l'API)."""

import re

import pytest

from netcross_gtk4 import incidents_panel as panneau

# --------------------------------------------------------------------------


def test_formater_taille():
    """Unités lisibles : octets, Ko, Mo."""
    assert panneau.formater_taille(0) == "0 octets"
    assert panneau.formater_taille(512) == "512 octets"
    assert panneau.formater_taille(2048) == "2.0 Ko"
    assert panneau.formater_taille(1500000) == "1.4 Mo"


def test_texte_etat_rapport():
    """Ce que lit l'analyste d'un coup d'œil : aucun rapport tant que
    l'analyse (#1091) n'a pas tourné, puis JSON, puis JSON + HTML."""
    assert panneau.texte_etat_rapport(False, False) == panneau.MSG_RAPPORT_AUCUN
    assert panneau.texte_etat_rapport(True, False) == panneau.MSG_RAPPORT_JSON
    assert panneau.texte_etat_rapport(True, True) == panneau.MSG_RAPPORT_JSON_HTML


def test_texte_incident():
    """Le résumé se suffit à lui-même : identifiant, horodatage, règle,
    points, segments, état des rapports. Un manifeste illisible est
    signalé tel quel, pas masqué."""
    texte = panneau.texte_incident(
        {
            "incident": "gel-1",
            "alarme": {"rule_id": "loss_per_segment", "timestamp": 1000.0},
            "points": ["LAN", "WAN"],
            "segments": 2,
            "rapport_json": True,
            "rapport_html": False,
        }
    )
    assert "gel-1" in texte
    assert "loss_per_segment" in texte
    assert "LAN, WAN" in texte
    assert "2 segment(s)" in texte
    assert panneau.MSG_RAPPORT_JSON in texte
    # Sans horodatage : « ? », pas de crash.
    assert "?" in panneau.texte_incident({"incident": "gel-2", "alarme": {}})
    # Manifeste illisible : l'erreur est dans la ligne.
    texte_casse = panneau.texte_incident({"incident": "gel-3", "alarme": {}, "erreur": "JSON invalide"})
    assert "illisible" in texte_casse
    assert "JSON invalide" in texte_casse


def test_reglages_depuis_saisie_valides():
    """Champs saisis → réglages valides (référentiel : le cœur, mêmes
    règles que l'API). Virgule décimale acceptée, quota « 0 » ou vide =
    illimité."""
    valides = panneau.reglages_depuis_saisie(
        seconds_before="120",
        seconds_after="30",
        min_severity="a_surveiller",
        min_delay_between_gels="45",
        max_octets="0",
        archives_dir="/tmp/incidents",
    )
    assert valides["seconds_before"] == 120.0
    assert valides["min_severity"] == "a_surveiller"
    assert valides["max_octets_archives"] is None
    assert valides["archives_dir"] == "/tmp/incidents"

    avec_virgule = panneau.reglages_depuis_saisie(
        seconds_before="90,5",
        seconds_after="30",
        min_severity="anomalie",
        min_delay_between_gels="30",
        max_octets="",
        archives_dir="  /tmp/x  ",
    )
    assert avec_virgule["seconds_before"] == 90.5
    assert avec_virgule["max_octets_archives"] is None
    assert avec_virgule["archives_dir"] == "/tmp/x"  # espaces de bordure retirés


def test_reglages_depuis_saisie_refuse_avec_un_message():
    """Un refus au clic sur « Enregistrer », avec un message en français
    vérifié : ce sont eux que l'utilisateur lit."""
    base = {
        "seconds_before": "60",
        "seconds_after": "30",
        "min_severity": "anomalie",
        "min_delay_between_gels": "30",
        "max_octets": "0",
        "archives_dir": "/tmp/incidents",
    }
    with pytest.raises(ValueError, match=re.escape(panneau.MSG_ARCHIVES_VIDE)):
        panneau.reglages_depuis_saisie(**{**base, "archives_dir": "   "})
    with pytest.raises(ValueError, match=re.escape(panneau.MSG_DUREE_INVALIDE)):
        panneau.reglages_depuis_saisie(**{**base, "seconds_before": "bientôt"})
    with pytest.raises(ValueError, match=re.escape(panneau.MSG_QUOTA_INVALIDE)):
        panneau.reglages_depuis_saisie(**{**base, "max_octets": "plein"})
    # Valeur REFUSÉE par le cœur (sévérité hors hiérarchie du gel) : le
    # message du cœur remonte, même source de vérité que l'API.
    with pytest.raises(ValueError, match="min_severity"):
        panneau.reglages_depuis_saisie(**{**base, "min_severity": "critique"})


def test_fonctions_partages_via_le_panneau(tmp_path):
    """Les fonctions « partagées » du panneau délèguent au cœur : la GUI
    ne choisit pas le chemin (c'est le fichier par défaut), mais les tests
    vérifient la délégation avec le chemin explicite du cœur."""
    chemin = tmp_path / "gel_config.json"
    valides = panneau.ecrire_reglages_partages({"seconds_before": 90}, chemin)
    assert valides["seconds_before"] == 90
    lus = panneau.lire_reglages_partages(chemin)
    assert lus["seconds_before"] == 90
    incidents = panneau.lister_incidents_depuis_reglages(lus)
    assert isinstance(incidents, list)
