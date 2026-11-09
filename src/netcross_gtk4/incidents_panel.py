# SPDX-License-Identifier: GPL-3.0-or-later
"""
Décisions de l'onglet « Incidents » (issue #1095, chantier #1001), sorties
de ``netcross_gtk4/app.py``.

Comme ``bpf_panel``, ce module ne touche AUCUN objet GTK : il porte les
règles qui décident ce que l'utilisateur VOIT et ce qu'il SAUVEGARDE —
le format d'une ligne d'incident (le résumé que l'analyste lit en
survolant la liste), l'état des rapports (présent / absent), et la
conversion des champs saisis en réglages valides (mêmes règles que
l'API, ``netcross_core.gel_settings``).

Un réglage refusé doit l'être ICI, au clic sur « Enregistrer », avec un
message en français — pas à la prochaine alarme, quand il est trop tard
pour corriger.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from netcross_core.gel_settings import (
    ecrire_reglages,
    lire_reglages,
    lister_incidents,
    valider_reglages,
)
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


def lire_reglages_partages(chemin=None) -> dict[str, Any]:
    """Réglages lus depuis le fichier partagé avec l'API (défaut
    ``~/.netcross/gel_config.json``) : la GUI ne choisit PAS le chemin,
    contrairement à l'administrateur de l'API (variable d'environnement
    serveur). Fichier absent = défauts. ``chemin`` : pour les tests."""
    logger.debug("lire_reglages_partages: entrée (chemin={})", chemin)
    reglages = lire_reglages(chemin)
    logger.debug("lire_reglages_partages: retour dictionnaire")
    return reglages


def ecrire_reglages_partages(reglages: Mapping[str, Any], chemin=None) -> dict[str, Any]:
    """Écrit les réglages dans le fichier partagé (même fichier que
    l'API lit : un réglage saisi dans la GUI vaut pour les deux).
    ``chemin`` : pour les tests."""
    logger.debug("ecrire_reglages_partages: entrée ({})", summarize(reglages, "reglages"))
    valides = ecrire_reglages(reglages, chemin)
    logger.debug("ecrire_reglages_partages: retour dictionnaire")
    return valides


def lister_incidents_depuis_reglages(reglages: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Inventaire des incidents depuis le répertoire d'archives des
    réglages : c'est LE réglage qui configure la consultation."""
    logger.debug("lister_incidents_depuis_reglages: entrée ({})", summarize(reglages, "reglages"))
    incidents = lister_incidents(str(reglages["archives_dir"]))
    logger.debug("lister_incidents_depuis_reglages: retour liste")
    return incidents


# Sévérités du gel (hiérarchie #1087), de la plus grave à la plus faible :
# l'ordre du menu déroulant suit la hiérarchie, pas l'ordre de saisie.
SEVERITES_MENU = ("anomalie", "a_surveiller", "info")

# Messages de saisie. Affichés tels quels à l'utilisateur, donc vérifiés
# par les tests : un message changé par inadvertance est une régression
# fonctionnelle, pas un détail de forme.
MSG_ARCHIVES_VIDE = "Le répertoire d'archives ne peut pas être vide."
MSG_QUOTA_INVALIDE = "Le quota doit être un nombre entier positif (0 = illimité)."
MSG_DUREE_INVALIDE = "Les durées doivent être des nombres positifs (secondes)."

# État des rapports (issue #1091) : ce que lit l'analyste d'un coup d'œil.
MSG_RAPPORT_AUCUN = "aucun rapport"
MSG_RAPPORT_JSON = "rapport JSON"
MSG_RAPPORT_JSON_HTML = "rapport JSON + HTML"


def formater_taille(octets: int) -> str:
    """Formate un nombre d'octets en unité lisible (Ko/Mo), même
    convention que ``stats_view.format_bytes`` — recopié ici pour garder
    ce module sans import GTK."""
    logger.debug("formater_taille: entrée (octets={})", octets)
    if octets < 1024:
        texte = f"{octets} octets"
    elif octets < 1024 * 1024:
        texte = f"{octets / 1024:.1f} Ko"
    else:
        texte = f"{octets / (1024 * 1024):.1f} Mo"
    logger.debug("formater_taille: retour texte")
    return texte


def texte_etat_rapport(rapport_json: bool, rapport_html: bool) -> str:
    """État des rapports d'un incident : « aucun rapport » tant que
    l'analyse (#1091) n'a pas tourné, « rapport JSON » ensuite, « rapport
    JSON + HTML » si le rendu HTML est disponible."""
    logger.debug(
        "texte_etat_rapport: entrée (rapport_json={}, rapport_html={})",
        rapport_json,
        rapport_html,
    )
    if rapport_json and rapport_html:
        texte = MSG_RAPPORT_JSON_HTML
    elif rapport_json:
        texte = MSG_RAPPORT_JSON
    else:
        texte = MSG_RAPPORT_AUCUN
    logger.debug("texte_etat_rapport: retour texte")
    return texte


def texte_incident(incident: Mapping[str, Any]) -> str:
    """Le résumé d'une ligne d'incident : horodatage de l'alarme, règle,
    points, segments et état des rapports. Lu en premier par l'analyste,
    il doit se suffire à lui-même sans ouvrir le détail."""
    logger.debug("texte_incident: entrée ({})", summarize(incident, "incident"))
    alarme = incident.get("alarme") or {}
    horodatage = alarme.get("timestamp")
    quand = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(horodatage))) if horodatage is not None else "?"
    regle = str(alarme.get("rule_id") or "?")
    points = ", ".join(str(p) for p in (incident.get("points") or [])) or "?"
    segments = incident.get("segments")
    etat = texte_etat_rapport(bool(incident.get("rapport_json")), bool(incident.get("rapport_html")))
    if isinstance(incident.get("erreur"), str):
        texte = f"{incident.get('incident', '?')} : manifeste illisible ({incident['erreur']})"
    else:
        texte = (
            f"{incident.get('incident', '?')} — {quand} — règle {regle} — "
            f"points {points} — {segments if segments is not None else '?'} segment(s) — {etat}"
        )
    logger.debug("texte_incident: retour texte")
    return texte


def reglages_depuis_saisie(
    *,
    seconds_before: str,
    seconds_after: str,
    min_severity: str,
    min_delay_between_gels: str,
    max_octets: str,
    archives_dir: str,
) -> dict[str, Any]:
    """Convertit les champs saisis en réglages valides (référentiel :
    ``netcross_core.gel_settings.valider_reglages``, les mêmes règles que
    l'API). Lève ValueError avec un message en français — c'est lui que
    la GUI affiche au clic sur « Enregistrer ».

    ``max_octets`` : « 0 » ou vide = illimité (None)."""
    logger.debug(
        "reglages_depuis_saisie: entrée (seconds_before={} ... archives_dir={})",
        seconds_before,
        archives_dir,
    )
    if not archives_dir.strip():
        logger.debug("reglages_depuis_saisie: si archives_dir vide -> levée ValueError")
        raise ValueError(MSG_ARCHIVES_VIDE)
    try:
        reglages: dict[str, Any] = {
            "seconds_before": float(seconds_before.replace(",", ".")),
            "seconds_after": float(seconds_after.replace(",", ".")),
            "min_severity": min_severity,
            "min_delay_between_gels": float(min_delay_between_gels.replace(",", ".")),
            "archives_dir": archives_dir.strip(),
        }
    except ValueError:
        logger.debug("reglages_depuis_saisie: si durée indécodable -> levée ValueError")
        raise ValueError(MSG_DUREE_INVALIDE) from None
    if max_octets.strip() in ("", "0"):
        reglages["max_octets_archives"] = None
    else:
        try:
            reglages["max_octets_archives"] = int(max_octets)
        except ValueError:
            logger.debug("reglages_depuis_saisie: si quota indécodable -> levée ValueError")
            raise ValueError(MSG_QUOTA_INVALIDE) from None
    valides = valider_reglages(reglages)
    logger.debug("reglages_depuis_saisie: retour dictionnaire")
    return valides
