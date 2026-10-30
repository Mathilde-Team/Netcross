"""Fichiers de clés TLS (SSLKEYLOGFILE) par point de capture (issue #1040, chantier #997).

``--tls-keylog FICHIER`` vaut pour tous les points, ``--tls-keylog NOM=FICHIER``
pour un seul point (prioritaire sur la forme globale). Le fichier est passé à
tshark (``-o tls.keylog_file:FICHIER``) pour la lecture principale des
captures ; tshark déchiffre alors les sessions TLS dont les secrets y figurent.

Même règles sur toutes les surfaces (CLI d'analyse, CLI de différentiel, API,
interface graphique) :

- le fichier doit exister et être lisible (refus avant toute lecture de capture) ;
- un nom de point inconnu, deux fichiers pour un même point ou deux fichiers
  globaux sont refusés ;
- refus explicite avec ``--redact`` tant que l'interaction entre déchiffrement
  et anonymisation n'est pas définie.

Le contenu du fichier (les secrets) n'est jamais lu ni journalisé ici : seuls
les chemins et les noms de points circulent.
"""

from __future__ import annotations

import os
from collections.abc import Collection, Iterable, Mapping, Sequence

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

OPTION = "--tls-keylog"

MESSAGE_REDACT = (
    f"{OPTION} n'est pas disponible avec --redact : l'interaction entre le déchiffrement TLS "
    "et l'anonymisation des adresses n'est pas encore définie (chantier #997)."
)

MESSAGE_SANS_CAPTURE = f"{OPTION} s'applique aux fichiers de capture (--capture) : sans objet en direct (--live)."


class TlsKeylogError(ValueError):
    """Fichier de clés TLS refusé, message destiné à l'utilisateur."""


def _verifier_fichier(chemin: str, spec: str) -> None:
    """Refuse un fichier absent ou illisible (sans en lire le contenu)."""
    logger.debug("_verifier_fichier: entrée")
    if not chemin:
        logger.debug("_verifier_fichier: refus, chemin vide")
        raise TlsKeylogError(f"{OPTION} {spec} : chemin vide (attendu FICHIER ou NOM=FICHIER)")
    if not os.path.isfile(chemin):
        logger.debug("_verifier_fichier: refus, fichier introuvable")
        raise TlsKeylogError(f"{OPTION} : fichier introuvable : {chemin}")
    if not os.access(chemin, os.R_OK):
        logger.debug("_verifier_fichier: refus, fichier illisible")
        raise TlsKeylogError(f"{OPTION} : fichier illisible (droits) : {chemin}")
    logger.debug("_verifier_fichier: retour")


def _decouper(spec: str, points: Sequence[str]) -> tuple[str | None, str]:
    """``FICHIER`` -> (None, FICHIER) ; ``NOM=FICHIER`` -> (NOM, FICHIER).

    Un ``=`` dans un chemin existant (sans point de ce nom) reste un chemin global.
    """
    logger.debug("_decouper: entrée")
    if "=" in spec:
        nom, chemin = spec.split("=", 1)
        nom = nom.strip()
        if nom in points:
            logger.debug("_decouper: retour, fichier du point {}", nom)
            return nom, chemin.strip()
        if not os.path.isfile(spec):
            logger.debug("_decouper: refus, point inconnu")
            raise TlsKeylogError(f"{OPTION} : point inconnu « {nom} » (points : {', '.join(points) or 'aucun'})")
    logger.debug("_decouper: retour, fichier global")
    return None, spec.strip()


def resoudre_keylogs(specs: Iterable[str] | None, points: Sequence[str]) -> dict[str, str]:
    """Fichier de clés de chaque point : ``{point: chemin}`` (points sans fichier absents).

    ``specs`` : valeurs de ``--tls-keylog`` ; ``points`` : noms des points de capture.
    Lève ``TlsKeylogError`` (message pour l'utilisateur) sur une spécification invalide.
    """
    specs = list(specs or ())
    logger.debug("resoudre_keylogs: entrée ({} spécification(s), {} point(s))", len(specs), len(points))
    points = list(dict.fromkeys(points))
    global_: str | None = None
    par_point: dict[str, str] = {}
    for spec in specs:
        nom, chemin = _decouper(spec, points)
        _verifier_fichier(chemin, spec)
        if nom is None:
            if global_ is not None:
                logger.debug("resoudre_keylogs: refus, deux fichiers globaux")
                raise TlsKeylogError(f"{OPTION} : un seul fichier pour tous les points (sinon NOM=FICHIER)")
            global_ = chemin
        elif nom in par_point:
            logger.debug("resoudre_keylogs: refus, point en double")
            raise TlsKeylogError(f"{OPTION} : plusieurs fichiers pour le point {nom}")
        else:
            par_point[nom] = chemin
    resolution: dict[str, str] = {}
    for point in points:
        chemin_point = par_point.get(point, global_)
        if chemin_point:
            resolution[point] = chemin_point
    logger.debug("resoudre_keylogs: retour, {} point(s) avec fichier de clés", len(resolution))
    return resolution


def verifier_compatibilite(keylogs: Collection[object] | None, *, redact: bool) -> None:
    """Refus de ``--tls-keylog`` combiné à ``--redact`` (critère d'acceptation de #1040)."""
    logger.debug("verifier_compatibilite: entrée")
    if keylogs and redact:
        logger.debug("verifier_compatibilite: refus, --redact")
        raise TlsKeylogError(MESSAGE_REDACT)
    logger.debug("verifier_compatibilite: retour")


def resume_keylogs(keylogs: Mapping[str, str]) -> str:
    """Ligne d'information sans chemin complet : ``« P1, P2 »`` ou ``« aucun »``."""
    logger.debug("resume_keylogs: entrée")
    texte = ", ".join(sorted(keylogs)) if keylogs else "aucun"
    logger.debug("resume_keylogs: retour")
    return texte


def fichier_du_point(keylogs: Mapping[str, str], point: str) -> str | None:
    """Fichier de clés d'un point ; un point issu de ``--split-interfaces``
    (``NOM:interface``) hérite de celui de ``NOM``."""
    logger.debug("fichier_du_point: entrée")
    chemin = keylogs.get(point)
    if chemin is None and ":" in point:
        chemin = keylogs.get(point.split(":", 1)[0])
    logger.debug("fichier_du_point: retour")
    return chemin


def options_lecture_parallele(
    keylogs: Mapping[str, str], captures: Sequence[tuple[str, str]]
) -> dict[str, dict[str, str]]:
    """Arguments nommés de ``parse_captures_parallel`` : ``{}`` sans fichier de clés
    (appel strictement identique à l'existant)."""
    logger.debug("options_lecture_parallele: entrée")
    par_point: dict[str, str] = {}
    for label, _ in captures:
        chemin = fichier_du_point(keylogs, label)
        if chemin:
            par_point[label] = chemin
    options = {"tls_keylogs": par_point} if par_point else {}
    logger.debug("options_lecture_parallele: retour")
    return options


def options_lecture(keylogs: Mapping[str, str], point: str) -> dict[str, str]:
    """Arguments nommés de ``parse_capture`` pour un point : ``{}`` s'il n'a pas de fichier."""
    logger.debug("options_lecture: entrée")
    chemin = fichier_du_point(keylogs, point)
    options = {"tls_keylog": chemin} if chemin else {}
    logger.debug("options_lecture: retour")
    return options
