# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_api.incident_routes -- gel rétroactif et incidents archivés
(issue #1095, chantier #1001) : configurer le gel, consulter les
incidents, lancer leur analyse.

- ``GET /gel/config`` : réglages effectifs (défauts fusionnés avec le
  fichier de réglages, chaque clé absente garde sa valeur par défaut) ;
- ``PUT /gel/config`` : remplace les réglages fournis (validation stricte :
  clés inconnues, types, bornes et sévérités refusés), les absentes
  gardent leur valeur courante ;
- ``GET /incidents`` : inventaire des incidents archivés (manifestes
  #1090) avec état des rapports (#1091) ;
- ``GET /incidents/{incident}`` : manifeste complet et rapport d'analyse
  s'il existe ;
- ``POST /incidents/{incident}/analyse`` : lance l'analyse multi-points
  de la fenêtre gelée (#1091) et range le rapport dans l'archive.
  Synchrone : la fenêtre d'un incident est courte (défaut 60 s avant,
  30 s après), l'analyse est rapide ; une archive altérée (empreintes
  SHA-256 non conformes) est refusée.

Mêmes conventions que bpf_routes : le fichier de réglages est celui du
SERVEUR (``$NETCROSS_API_GEL_CONFIG``, sinon ``~/.netcross/gel_config.json``
— le même que la GUI écrit), choisi par l'administrateur, jamais par le
client ; les réglages sont partagés avec la GUI (onglet Incidents) et la
liste des incidents vient du répertoire d'archives des réglages
(``archives_dir``).

L'analyse injecte les briques netcross_report (score/level du tableau de
bord, rendu HTML) : netcross_core ne peut pas les importer (contrat de
couches), l'API est au-dessus et fait le câblage.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from netcross_core.gel_settings import (
    detail_incident,
    ecrire_reglages,
    lire_reglages,
    lister_incidents,
)
from netcross_core.logging_config import get_logger, summarize
from netcross_core.retro_capture import ManifesteIncident

logger = get_logger(__name__)

#: Variable d'environnement : fichier de réglages côté serveur.
GEL_CONFIG_ENV = "NETCROSS_API_GEL_CONFIG"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Incident inconnu (pas de manifeste à ce nom)"},
    409: {"description": "Archive altérée (empreintes non conformes) ou indécodable"},
    422: {"description": "Réglages invalides (clé inconnue, type, borne, sévérité)"},
    500: {"description": "Échec de l'analyse (segments illisibles, tshark absent...)"},
}


class GelConfigBody(BaseModel):
    """Corps de ``PUT /gel/config`` : champs TOUS optionnels (les
    absents gardent leur valeur courante), validés par le cœur. Les clés
    inconnues sont REFUSÉES (422) : une faute de frappe ne doit pas passer
    en silence, le réglage visé resterait inchangé."""

    model_config = ConfigDict(extra="forbid")

    seconds_before: float | None = Field(None, gt=0, description="Secondes conservées AVANT l'alarme")
    seconds_after: float | None = Field(None, gt=0, description="Secondes conservées APRÈS l'alarme")
    min_severity: str | None = Field(
        None, description="Sévérité minimale qui déclenche le gel (anomalie, a_surveiller, info)"
    )
    min_delay_between_gels: float | None = Field(None, gt=0, description="Délai minimal (s) entre deux gels")
    max_octets_archives: int | None = Field(None, gt=0, description="Quota d'archives (octets) ; null = illimité")
    archives_dir: str | None = Field(None, min_length=1, description="Répertoire où les gels écrivent leurs archives")


def gel_config_path() -> Path | None:
    """Fichier de réglages utilisé : ``$NETCROSS_API_GEL_CONFIG`` ou
    ``None`` (défaut du cœur, ``~/.netcross/gel_config.json``)."""
    logger.debug("gel_config_path: entrée")
    valeur = os.environ.get(GEL_CONFIG_ENV, "").strip()
    chemin = Path(valeur).expanduser() if valeur else None
    logger.debug("gel_config_path: retour Path | None")
    return chemin


def _get_gel_config() -> dict[str, Any]:
    logger.debug("_get_gel_config: entrée")
    try:
        reglages = lire_reglages(gel_config_path())
    except ValueError as exc:
        logger.warning("gel/config : fichier de réglages invalide ({})", exc)
        logger.debug("_get_gel_config: si ValueError -> levée HTTPException(500)")
        raise HTTPException(status_code=500, detail=f"Réglages du gel illisibles : {exc}") from exc
    logger.debug("_get_gel_config: retour dictionnaire")
    return reglages


def _put_gel_config(corps: GelConfigBody) -> dict[str, Any]:
    logger.debug("_put_gel_config: entrée ({})", summarize(corps, "corps"))
    courants = _get_gel_config()
    demandes = {cle: valeur for cle, valeur in corps.model_dump().items() if valeur is not None}
    if demandes:
        try:
            ecrire_reglages({**courants, **demandes}, gel_config_path())
        except ValueError as exc:
            logger.warning("gel/config : réglages refusés ({})", exc)
            logger.debug("_put_gel_config: si ValueError -> levée HTTPException(422)")
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OSError as exc:
            logger.warning("gel/config : écriture impossible ({})", exc)
            logger.debug("_put_gel_config: si OSError -> levée HTTPException(500)")
            raise HTTPException(status_code=500, detail=f"Écriture impossible : {exc}") from exc
    logger.debug("_put_gel_config: retour dictionnaire")
    return _get_gel_config()


def _get_incidents() -> dict[str, Any]:
    """Inventaire des incidents archivés, depuis le répertoire des
    réglages (``archives_dir``) : le réglage configure la consultation."""
    logger.debug("_get_incidents: entrée")
    reglages = _get_gel_config()
    incidents = lister_incidents(str(reglages["archives_dir"]))
    logger.debug("_get_incidents: retour dictionnaire")
    return {"incidents": incidents}


def _get_incident(incident: str) -> dict[str, Any]:
    logger.debug("_get_incident: entrée (incident={})", incident)
    reglages = _get_gel_config()
    detail = detail_incident(str(reglages["archives_dir"]), incident)
    if detail is None:
        logger.debug("_get_incident: si detail is None -> levée HTTPException(404)")
        raise HTTPException(status_code=404, detail=f"Incident inconnu : {incident}")
    logger.debug("_get_incident: retour dictionnaire")
    return detail


def _post_analyse(incident: str) -> dict[str, Any]:
    """Lance l'analyse de la fenêtre gelée (issue #1091) et range le
    rapport avec les segments. Les injections netcross_report (score,
    HTML) sont câblées ici : l'API est au-dessus des deux couches."""
    logger.debug("_post_analyse: entrée (incident={})", incident)
    from netcross_core.incident_analysis import analyser_incident
    from netcross_report.html_report import generate_html_report
    from netcross_report.security_report import build_security_report

    reglages = _get_gel_config()
    archives_dir = str(reglages["archives_dir"])
    detail = detail_incident(archives_dir, incident)
    if detail is None:
        logger.debug("_post_analyse: si detail is None -> levée HTTPException(404)")
        raise HTTPException(status_code=404, detail=f"Incident inconnu : {incident}")
    chemin_manifeste = Path(archives_dir).expanduser() / incident / "incident" / "manifeste.json"

    def evaluateur(rapport: Any) -> tuple[int, str | None]:
        logger.debug("evaluateur: entrée")
        tableau = build_security_report(rapport).dashboard
        logger.debug("evaluateur: retour (score, niveau)")
        return tableau.score, tableau.level

    def generateur_html(rapport: Any, dossier: str) -> str | None:
        logger.debug("generateur_html: entrée")
        chemin = generate_html_report(
            rapport,
            os.path.join(dossier, "rapport.html"),
            title=f"Incident {incident}",
        )
        logger.debug("generateur_html: retour chemin")
        return chemin

    try:
        manifeste = ManifesteIncident.depuis_json(chemin_manifeste.read_text(encoding="utf-8"))
        from netcross_core.config import load_config

        resultat = analyser_incident(
            manifeste,
            evaluateur=evaluateur,
            generateur_html=generateur_html,
            seuil_notification="elevee",
            cfg_notification=load_config().notify,
        )
    except ValueError as exc:
        logger.warning("analyse de l'incident {} refusée ({})", incident, exc)
        logger.debug("_post_analyse: si ValueError -> levée HTTPException(409)")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 -- l'analyse ne doit pas faire planter l'API
        logger.exception("analyse de l'incident {} en échec", incident)
        logger.debug("_post_analyse: si Exception -> levée HTTPException(500)")
        raise HTTPException(status_code=500, detail=f"Analyse impossible : {exc}") from exc
    reponse = {
        "incident": resultat.incident,
        "dossier": resultat.dossier,
        "rapport_json": resultat.chemin_rapport,
        "rapport_html": resultat.chemin_html,
        "points": list(resultat.points),
        "score": resultat.score,
        "level": resultat.level,
        "notifications": list(resultat.notifications),
    }
    logger.debug("_post_analyse: retour dictionnaire")
    return reponse


def register(app: FastAPI, verify: Callable[..., None]) -> None:
    """Déclare les routes sur ``app`` avec l'authentification ``verify``."""
    logger.debug("register: entrée")
    deps = [Depends(verify)]
    app.add_api_route(
        "/gel/config",
        _get_gel_config,
        methods=["GET"],
        tags=["gel"],
        responses={500: _RESPONSES[500]},
        dependencies=deps,
    )
    app.add_api_route(
        "/gel/config",
        _put_gel_config,
        methods=["PUT"],
        tags=["gel"],
        responses={422: _RESPONSES[422], 500: _RESPONSES[500]},
        dependencies=deps,
    )
    app.add_api_route(
        "/incidents",
        _get_incidents,
        methods=["GET"],
        tags=["incidents"],
        dependencies=deps,
    )
    app.add_api_route(
        "/incidents/{incident}",
        _get_incident,
        methods=["GET"],
        tags=["incidents"],
        responses={404: _RESPONSES[404], 500: _RESPONSES[500]},
        dependencies=deps,
    )
    app.add_api_route(
        "/incidents/{incident}/analyse",
        _post_analyse,
        methods=["POST"],
        tags=["incidents"],
        responses={404: _RESPONSES[404], 409: _RESPONSES[409], 500: _RESPONSES[500]},
        dependencies=deps,
    )
    logger.debug("register: fin")
