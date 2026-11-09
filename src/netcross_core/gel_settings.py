# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.gel_settings -- réglages du gel rétroactif et inventaire des
incidents archivés (issue #1095, chantier #1001).

Le gel (#1087), l'archivage (#1090), le quota (#1093) et l'analyse
(#1091) sont livrés ; il reste à les RÉGLER et à CONSULTER les incidents
depuis l'API et la GUI. Ce module fournit les deux briques partagées :

1. un fichier de réglages JSON (défaut ``~/.netcross/gel_config.json``,
   overridable par l'appelant) : mêmes rôles que
   ``netcross_core.bpf_filters`` pour les filtres BPF -- un seul fichier
   lu et écrit par la CLI, l'API et la GUI, pour qu'un réglage saisi dans
   une surface vaille dans les autres. Champs = ceux de ``GelConfig``
   (#1087, #1093) plus ``archives_dir`` (où les gels écrivent, lu aussi
   par la liste des incidents) ;

2. l'inventaire des incidents archivés : chaque gel écrit
   ``<archives_dir>/<gel>/incident/manifeste.json`` (#1090) — ce module
   les relit, signale la présence des rapports (``rapport.json`` /
   ``rapport.html``, #1091) et agrège la taille de l'archive. L'API
   (``incident_routes``) et la GUI (onglet Incidents) consomment ces
   fonctions : pas de duplication de la logique de parcours.

Ce module vit dans netcross_core : il n'importe ni netcross_report ni
netcross_api/netcross_gtk4. L'analyse proprement dite (injections
netcross_report) reste à la charge de l'appelant — voir
``incident_analysis.analyser_incident``.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger, summarize
from netcross_core.retro_capture import SEVERITES, GelConfig, ManifesteIncident

logger = get_logger(__name__)

#: Fichier de réglages par défaut (même convention que bpf_filters :
#: ``~/.netcross``). L'API peut le surcharger (variable d'environnement
#: réservée à l'administrateur du serveur), la GUI écrit le même fichier.
CHEMIN_DEFAUT = Path("~/.netcross/gel_config.json").expanduser()

#: Répertoire d'archives par défaut (là où GelManager écrit les gels).
ARCHIVES_DEFAUT = str(Path("~/.netcross/incidents").expanduser())

#: Réglages par défaut : ceux de GelConfig (#1087, #1093) + archives_dir.
REGLAGES_DEFAUT: dict[str, Any] = {
    "seconds_before": 60.0,
    "seconds_after": 30.0,
    "min_severity": "anomalie",
    "min_delay_between_gels": 30.0,
    "max_octets_archives": None,
    "archives_dir": ARCHIVES_DEFAUT,
}

#: Champs autorisés (typés) : tout autre champ est refusé — une faute de
#: frappe dans un réglage doit échouer maintenant, pas à la prochaine alarme.
_TYPES_CHAMPS: dict[str, tuple[type, ...]] = {
    "seconds_before": (int, float),
    "seconds_after": (int, float),
    "min_severity": (str,),
    "min_delay_between_gels": (int, float),
    "max_octets_archives": (int, type(None)),
    "archives_dir": (str,),
}


def valider_reglages(demande: Mapping[str, Any]) -> dict[str, Any]:
    """Valide des réglages de gel (typés, bornés) et renvoie la version
    nettoyée. Refuse les clés inconnues, les valeurs hors bornes et les
    sévérités hors hiérarchie : mieux vaut un refus immédiat qu'un gel
    qui ne se déclenchera pas (ou videra le disque) à la prochaine alarme.
    """
    logger.debug("valider_reglages: entrée ({})", summarize(demande, "demande"))
    if not isinstance(demande, Mapping):
        logger.debug("valider_reglages: si not isinstance(demande, Mapping) -> levée ValueError")
        raise ValueError("réglages du gel : un objet JSON (dictionnaire) est attendu")
    resultats: dict[str, Any] = {}
    for cle, valeur in demande.items():
        if cle not in _TYPES_CHAMPS:
            logger.debug("valider_reglages: si cle not in _TYPES_CHAMPS -> levée ValueError")
            raise ValueError(f"réglage inconnu : {cle!r} (attendus : {', '.join(sorted(_TYPES_CHAMPS))})")
        if isinstance(valeur, bool) or not isinstance(valeur, _TYPES_CHAMPS[cle]):
            logger.debug("valider_reglages: si mauvais type -> levée ValueError")
            raise ValueError(f"réglage {cle!r} : type invalide ({type(valeur).__name__})")
        resultats[cle] = valeur
    for cle in _TYPES_CHAMPS:
        if cle not in resultats:
            continue
        if cle == "min_severity" and resultats[cle] not in SEVERITES:
            logger.debug("valider_reglages: si min_severity hors SEVERITES -> levée ValueError")
            raise ValueError(f"min_severity : {resultats[cle]!r} (attendues : {', '.join(SEVERITES)})")
        if cle == "archives_dir" and not str(resultats[cle]).strip():
            logger.debug("valider_reglages: si archives_dir vide -> levée ValueError")
            raise ValueError("archives_dir : un chemin non vide est attendu")
        if cle in ("seconds_before", "seconds_after", "min_delay_between_gels") and float(resultats[cle]) <= 0:
            logger.debug("valider_reglages: si valeur <= 0 -> levée ValueError")
            raise ValueError(f"{cle} : une durée strictement positive est attendue")
        if cle == "max_octets_archives" and resultats[cle] is not None and int(resultats[cle]) <= 0:
            logger.debug("valider_reglages: si max_octets_archives <= 0 -> levée ValueError")
            raise ValueError("max_octets_archives : un entier strictement positif (ou null)")
    logger.debug("valider_reglages: retour dictionnaire")
    return resultats


def lire_reglages(chemin: Path | None = None) -> dict[str, Any]:
    """Réglages EFFECTIFS : défauts fusionnés avec le fichier (partiel :
    chaque clé absente garde sa valeur par défaut). Fichier absent =
    défauts (rien à configurer n'est pas une erreur) ; fichier illisible
    ou invalide = ValueError (un réglage silencieusement ignoré est pire).
    """
    logger.debug("lire_reglages: entrée (chemin={})", chemin)
    cible = (chemin or CHEMIN_DEFAUT).expanduser()
    reglages = dict(REGLAGES_DEFAUT)
    if cible.exists():
        try:
            charge = json.loads(cible.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.debug("lire_reglages: si fichier illisible -> levée ValueError")
            raise ValueError(f"réglages du gel illisibles ({cible}) : {exc}") from exc
        reglages.update(valider_reglages(charge))
    logger.debug("lire_reglages: retour dictionnaire")
    return reglages


def ecrire_reglages(reglages: Mapping[str, Any], chemin: Path | None = None) -> dict[str, Any]:
    """Valide puis écrit les réglages (écriture atomique, répertoire
    parent créé au besoin). Renvoie les réglages validés."""
    logger.debug("ecrire_reglages: entrée ({})", summarize(reglages, "reglages"))
    valides = valider_reglages(reglages)
    cible = (chemin or CHEMIN_DEFAUT).expanduser()
    cible.parent.mkdir(parents=True, exist_ok=True)
    charge = json.dumps(valides, indent=2, sort_keys=True, ensure_ascii=False)
    fd, tmp = tempfile.mkstemp(dir=str(cible.parent), prefix=f".{cible.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fic:
            fic.write(charge)
        os.chmod(tmp, 0o644)
        os.replace(tmp, str(cible))
    except BaseException:
        logger.exception("ecrire_reglages: erreur: BaseException")
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        logger.debug("ecrire_reglages: except BaseException -> relance de l'exception en cours")
        raise
    logger.debug("ecrire_reglages: retour dictionnaire")
    return valides


def vers_gel_config(reglages: Mapping[str, Any]) -> tuple[GelConfig, str]:
    """Sépare les réglages en (GelConfig pour GelManager, archives_dir) :
    ce que consomme le moteur du gel d'un côté, où chercher les incidents
    de l'autre. Les clés absentes prennent les valeurs par défaut."""
    logger.debug("vers_gel_config: entrée ({})", summarize(reglages, "reglages"))
    complets = dict(REGLAGES_DEFAUT)
    complets.update(valider_reglages(reglages))
    config = GelConfig(
        seconds_before=float(complets["seconds_before"]),
        seconds_after=float(complets["seconds_after"]),
        min_severity=str(complets["min_severity"]),
        min_delay_between_gels=float(complets["min_delay_between_gels"]),
        max_octets_archives=complets["max_octets_archives"],
    )
    logger.debug("vers_gel_config: retour tuple de 2")
    return config, str(complets["archives_dir"])


def _taille_octets(dossier: Path) -> int:
    """Taille totale (octets) des fichiers d'un répertoire, récursive.
    Les incidents sont petits mais le quota (#1093) se joue sur ces
    octets : la liste doit montrer la même unité."""
    logger.debug("_taille_octets: entrée (dossier={})", dossier)
    total = 0
    for racine, _dirs, fichiers in os.walk(dossier):
        for nom in fichiers:
            with contextlib.suppress(OSError):
                total += os.path.getsize(os.path.join(racine, nom))
    logger.debug("_taille_octets: retour {}", total)
    return total


def lister_incidents(archives_dir: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Inventaire des incidents archivés (issue #1090) : chaque sous-
    répertoire de ``archives_dir`` portant un ``incident/manifeste.json``.
    Pour chaque incident : l'alarme, la fenêtre, les points, le nombre de
    segments, la taille de l'archive et l'état des rapports (#1091 :
    ``rapport.json`` toujours attendu, ``rapport.html`` si disponible).
    Un manifeste illisible est signalé (entrée ``erreur``), pas caché :
    l'analyste doit savoir qu'une archive existe même si elle est corrompue.
    """
    logger.debug("lister_incidents: entrée (archives_dir={})", archives_dir)
    incidents: list[dict[str, Any]] = []
    racine = Path(archives_dir).expanduser()
    if not racine.is_dir():
        logger.debug("lister_incidents: si racine inexistante -> retour liste vide")
        return incidents
    for entree in sorted(p for p in racine.iterdir() if p.is_dir()):
        chemin_manifeste = entree / "incident" / "manifeste.json"
        if not chemin_manifeste.is_file():
            continue
        base = {
            "incident": entree.name,
            "dossier": str(entree),
            "octets": _taille_octets(entree / "incident"),
            "rapport_json": (entree / "incident" / "rapport.json").is_file(),
            "rapport_html": (entree / "incident" / "rapport.html").is_file(),
        }
        try:
            manifeste = ManifesteIncident.depuis_json(chemin_manifeste.read_text(encoding="utf-8"))
        except (OSError, KeyError, ValueError) as exc:
            logger.warning("incident {} : manifeste illisible ({})", entree.name, exc)
            incidents.append({**base, "erreur": str(exc)})
            continue
        points = sorted({f.point for f in manifeste.fichiers})
        incidents.append(
            {
                **base,
                "alarme": dict(manifeste.alarme),
                "fenetre": {"debut": manifeste.fenetre[0], "fin": manifeste.fenetre[1]},
                "points": points,
                "segments": len(manifeste.fichiers),
            }
        )
    logger.debug("lister_incidents: retour liste")
    return incidents


def detail_incident(archives_dir: str | os.PathLike[str], incident: str) -> dict[str, Any] | None:
    """Détail d'un incident archivé : le manifeste complet (chaîne de
    preuve, #1090) et le rapport d'analyse s'il existe (#1091). ``None``
    si l'incident est inconnu. Le rapport JSON est renvoyé PARSÉ (clé
    ``rapport``) pour que l'API comme la GUI l'affichent sans relire le
    fichier deux fois."""
    logger.debug("detail_incident: entrée (archives_dir={}, incident={})", archives_dir, incident)
    if not incident or "/" in incident or ".." in incident:
        logger.debug("detail_incident: si nom suspect -> retour None")
        return None
    chemin_manifeste = Path(archives_dir).expanduser() / incident / "incident" / "manifeste.json"
    if not chemin_manifeste.is_file():
        logger.debug("detail_incident: si manifeste absent -> retour None")
        return None
    try:
        manifeste = ManifesteIncident.depuis_json(chemin_manifeste.read_text(encoding="utf-8"))
    except (OSError, KeyError, ValueError) as exc:
        logger.warning("incident {} : manifeste illisible ({})", incident, exc)
        logger.debug("detail_incident: si manifeste illisible -> retour None")
        return None
    detail: dict[str, Any] = {
        "incident": manifeste.incident,
        "dossier": str(chemin_manifeste.parent.parent),
        "alarme": dict(manifeste.alarme),
        "fenetre": {"debut": manifeste.fenetre[0], "fin": manifeste.fenetre[1]},
        "fichiers": [{"point": f.point, "segment": f.segment, "empreinte": f.empreinte} for f in manifeste.fichiers],
        "rapport_json": (chemin_manifeste.parent / "rapport.json").is_file(),
        "rapport_html": (chemin_manifeste.parent / "rapport.html").is_file(),
    }
    chemin_rapport = chemin_manifeste.parent / "rapport.json"
    if chemin_rapport.is_file():
        with contextlib.suppress(OSError, ValueError):
            detail["rapport"] = json.loads(chemin_rapport.read_text(encoding="utf-8"))
    logger.debug("detail_incident: retour dictionnaire")
    return detail
