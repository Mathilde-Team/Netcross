# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.incident_analysis — analyse multi-points de la fenêtre gelée
(issue #1091, chantier #1001 : enregistrement rétroactif déclenché par alarme).

Après le gel (#1087), la découpe et l'archivage avec manifeste (#1090), il
reste à exploiter l'archive : l'analyste doit recevoir « alarme + rapport
qui localise le segment + pcap de preuve » sans rien relancer à la main.

Ce module orchestre la chaîne complète sur les segments d'un incident
archivé :

1. vérification de la chaîne de preuve (verifier_manifeste, issue #1090) —
   on n'analyse pas une archive dont les empreintes ne correspondent plus ;
2. analyse multi-points : chaque segment est décodé avec le label de son
   point de capture (parseur injectable), puis correlate() + analyse() +
   apply_security_findings() — le même socle que la CLI, sur les données
   garanties du gel ;
3. rapport JSON rangé AVEC les segments (schéma « netcross.incident/1 »,
   écriture atomique) et rapport HTML si un générateur est injecté ;
4. notification enrichie : build_summary() (résumé + sévérités) avec le
   CHEMIN DE L'ARCHIVE comme report_path, passée à run_notifications()
   (ou à un notificateur injecté pour les tests).

Contrat de couches (netcross_gtk4 -> netcross_report -> netcross_core ->
pcap_parser) : ce module vit dans netcross_core et n'importe JAMAIS
netcross_report. Le score/level du tableau de bord de sécurité
(netcross_report.security_report) et le rendu HTML (netcross_report.
html_report) sont donc INJECTÉS par l'appelant — même raison d'être que
le render_html injecté de live_report. Le CVE-2 (scan d'exploits sur la
charge utile brute) exige de relire les fichiers : le scanner est injecté
aussi (défaut : aucun scan).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Callable

from netcross_core.analysis import Report, analyse
from netcross_core.config import NotifyConfig
from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger, summarize
from netcross_core.notify import build_summary, run_notifications
from netcross_core.notify.dispatch import DeliveryResult
from netcross_core.notify.summary import NotificationSummary
from netcross_core.parsing import parse_capture
from netcross_core.retro_capture import ManifesteIncident, verifier_manifeste
from netcross_core.security.findings import apply_security_findings

logger = get_logger(__name__)

# Signature du rapport d'incident écrit dans l'archive (à côté du
# manifeste.json et des segments) — versionné pour les consommateurs
# machine (GUI #1095, intégrations).
SCHEMA_RAPPORT = "netcross.incident/1"


@dataclass(frozen=True)
class RapportIncident:
    """Résultat de l'analyse d'un incident archivé : chemins du rapport
    (JSON obligatoire, HTML si générateur injecté), points analysés,
    score/level si évaluateur injecté, et résultats de notification."""

    incident: str
    dossier: str
    chemin_rapport: str
    chemin_html: str | None = None
    points: tuple[str, ...] = ()
    score: int = 0
    level: str | None = None
    notifications: tuple[Any, ...] = ()


def _ecrire_atomique(chemin: str, texte: str) -> None:
    """Écriture atomique (fichier temporaire puis os.replace) : un lecteur
    ne voit jamais un rapport à moitié écrit, même si le processus meurt
    en cours d'écriture. Même motif que live_report._atomic_write."""
    logger.debug("_ecrire_atomique: entrée (chemin={})", chemin)
    dossier = os.path.dirname(chemin)
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix=f".{os.path.basename(chemin)}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fic:
            fic.write(texte)
        os.chmod(tmp, 0o644)
        os.replace(tmp, chemin)
    except BaseException:
        logger.exception("_ecrire_atomique: erreur: BaseException")
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        logger.debug("_ecrire_atomique: except BaseException -> relance de l'exception en cours")
        raise
    logger.debug("_ecrire_atomique: retour None")


def _notifier_defaut(resume: NotificationSummary, cfg: NotifyConfig) -> list[DeliveryResult]:
    """Notificateur par défaut : build_summary a déjà validé le seuil, on
    passe le résumé tel quel à run_notifications (canaux issus de la
    configuration — aucun canal configuré, aucune notification, aucune
    erreur : un incident sans canal n'est pas un échec d'analyse)."""
    logger.debug("_notifier_defaut: entrée (resume={}, cfg={})", summarize(resume, "resume"), summarize(cfg, "cfg"))
    resultats = run_notifications(lambda seuil: resume, threshold=resume.threshold, cfg=cfg)
    logger.debug("_notifier_defaut: retour liste de DeliveryResult")
    return resultats


def analyser_incident(
    manifeste: ManifesteIncident,
    dossier_incident: str | None = None,
    *,
    parseur: Callable[[str, str], list[Any]] | None = None,
    scanner: Callable[[str, str], Sequence[Any]] | None = None,
    evaluateur: Callable[[Report], tuple[int, str | None]] | None = None,
    generateur_html: Callable[[Report, str], str | None] | None = None,
    seuil_notification: str = "elevee",
    notificateur: Callable[[NotificationSummary], Sequence[Any]] | None = None,
    cfg_notification: NotifyConfig | None = None,
) -> RapportIncident:
    """Analyse multi-points d'un incident archivé et notifie (issue #1091).

    ``manifeste`` : sorti de archiver_incident (issue #1090). La chaîne de
    preuve est vérifiée d'abord (verifier_manifeste) : une archive dont un
    segment ne correspond plus à son empreinte n'est PAS analysée — un
    rapport bâti sur des preuves altérées serait pire que pas de rapport.

    ``dossier_incident`` : répertoire de l'archive (celui du manifeste.json).
    Défaut : parent du répertoire du premier segment (l'archive vit dans
    ``<gel>/incident/<point>/``, donc ce parent est ``<gel>/incident``).

    Dépendances injectables (contrat de couches et tests) :
    - ``parseur(point, chemin) -> list[Pkt]`` — défaut parsing.parse_capture
      (tshark). En direct comme en différé, le label du point est attaché
      à chaque paquet : c'est lui qui permet à l'analyse de localiser le
      segment fautif ;
    - ``scanner(point, chemin) -> detections`` — scan d'exploits (CVE-2)
      sur la charge utile brute, None par défaut (aucune relecture) ;
    - ``evaluateur(report) -> (score, level)`` — tableau de bord du rapport
      de sécurité (netcross_report.security_report) ; None par défaut
      (score 0, level None) car netcross_core ne peut pas l'importer ;
    - ``generateur_html(report, dossier) -> chemin`` — rendu HTML
      (netcross_report.html_report) rangé avec le JSON ; None par défaut ;
    - ``notificateur(resume) -> résultats`` — défaut : run_notifications
      avec ``cfg_notification`` (NotifyConfig() si None).

    Écrit ``<dossier_incident>/rapport.json`` (schéma SCHEMA_RAPPORT,
    écriture atomique) et renvoie un RapportIncident. Lève ValueError si
    l'archive est vide, non conforme, ou si aucun paquet n'est décodé.
    """
    logger.debug(
        "analyser_incident: entrée (manifeste={}, dossier_incident={})",
        summarize(manifeste, "manifeste"),
        summarize(dossier_incident, "dossier_incident"),
    )
    if not manifeste.fichiers:
        logger.debug("analyser_incident: si not manifeste.fichiers -> levée ValueError")
        raise ValueError("analyser_incident : manifeste sans fichier — rien à analyser")
    non_conformes = verifier_manifeste(manifeste)
    if non_conformes:
        logger.debug("analyser_incident: si non_conformes -> levée ValueError")
        raise ValueError(
            "analyser_incident : segments non conformes au manifeste "
            f"({len(non_conformes)} écart(s), ex : {non_conformes[0]}) — archive altérée, analyse refusée"
        )
    if dossier_incident is None:
        dossier_incident = os.path.dirname(os.path.dirname(manifeste.fichiers[0].segment))

    # 1. Analyse multi-points : chaque segment décodé avec le label de son
    # point, puis le socle standard (correlate + analyse + constats).
    points: list[str] = []
    paquets: list[Any] = []
    for fichier in manifeste.fichiers:
        if fichier.point not in points:
            points.append(fichier.point)
        paquets.extend((parseur or parse_capture)(fichier.point, fichier.segment))
    if not paquets:
        logger.debug("analyser_incident: si not paquets -> levée ValueError")
        raise ValueError("analyser_incident : aucun paquet décodé depuis les segments de l'incident")
    detections: list[Any] = []
    if scanner is not None:
        for fichier in manifeste.fichiers:
            detections.extend(scanner(fichier.point, fichier.segment))
    flux = correlate(paquets)
    from netcross_core.link_speed import resolve_link_speeds

    rapport = analyse(
        flux,
        tuple(points),
        paquets,
        link_speeds=resolve_link_speeds([(f.point, f.segment) for f in manifeste.fichiers]),
    )
    apply_security_findings(rapport, paquets, detections=detections)

    # 2. Score/level du tableau de bord (injecté — netcross_report).
    score: int
    level: str | None
    if evaluateur is not None:
        score, level = evaluateur(rapport)
    else:
        score, level = 0, None

    # 3. Rapport JSON rangé avec les segments : l'analyste reçoit
    # « alarme + rapport + pcap de preuve » dans UN seul répertoire.
    charge: dict[str, Any] = {
        "schema": SCHEMA_RAPPORT,
        "incident": manifeste.incident,
        "alarme": dict(manifeste.alarme),
        "fenetre": {"debut": manifeste.fenetre[0], "fin": manifeste.fenetre[1]},
        "points": [
            {
                "point": point,
                "segments": [
                    {"segment": f.segment, "empreinte": f.empreinte} for f in manifeste.fichiers if f.point == point
                ],
            }
            for point in points
        ],
        "score": score,
        "level": level,
        "constats": list(rapport.security_findings or []),
    }
    chemin_rapport = os.path.join(dossier_incident, "rapport.json")
    os.makedirs(dossier_incident, exist_ok=True)
    _ecrire_atomique(chemin_rapport, json.dumps(charge, indent=2, sort_keys=True, ensure_ascii=False))

    # 4. HTML si un générateur est injecté (netcross_report).
    chemin_html: str | None = None
    if generateur_html is not None:
        chemin_html = generateur_html(rapport, dossier_incident)

    # 5. Notification enrichie : résumé + CHEMIN DE L'ARCHIVE.
    resume = build_summary(
        rapport.security_findings or [],
        score=score,
        level=level,
        threshold=seuil_notification,
        report_path=dossier_incident,
    )
    if notificateur is None:
        cfg = cfg_notification if cfg_notification is not None else NotifyConfig()
        resultats_bruts: Sequence[Any] | None = _notifier_defaut(resume, cfg)
    else:
        # Un notificateur qui ne renvoie rien (effet de bord seul) est admis.
        resultats_bruts = notificateur(resume) or ()
    notifications = tuple(r.to_dict() if hasattr(r, "to_dict") else r for r in (resultats_bruts or ()))

    resultat = RapportIncident(
        incident=manifeste.incident,
        dossier=dossier_incident,
        chemin_rapport=chemin_rapport,
        chemin_html=chemin_html,
        points=tuple(points),
        score=score,
        level=level,
        notifications=notifications,
    )
    logger.info(
        "Incident {} analysé : {} point(s), {} constat(s), rapport {}",
        manifeste.incident,
        len(points),
        len(rapport.security_findings or []),
        chemin_rapport,
    )
    logger.debug("analyser_incident: retour RapportIncident")
    return resultat
