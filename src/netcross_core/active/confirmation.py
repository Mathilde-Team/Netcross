# SPDX-License-Identifier: GPL-3.0-or-later
"""Exécution bornée et exclusivement explicite des propositions (#1068)."""

from __future__ import annotations

import ipaddress
import shlex
from collections import defaultdict

from netcross_core.active import paris_traceroute, twamp
from netcross_core.active.planner import PARIS_TRACEROUTE, plan_measurements
from netcross_core.i18n import _
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
MAX_MESURES = 8


def _cible_twamp(proposition) -> tuple[str, int]:
    """Jamais de résolution DNS ni de cible multicast/broadcast."""
    logger.debug("_cible_twamp: entrée")
    cible, port = twamp.cible_de_proposition(proposition)
    adresse = ipaddress.ip_address(cible)
    if adresse.is_multicast or adresse.is_unspecified or "%" in cible or cible == "255.255.255.255":
        logger.debug("_cible_twamp: adresse refusée")
        raise ValueError(_("cible TWAMP unicast littérale requise"))
    logger.debug("_cible_twamp: retour")
    return str(adresse), port


def _commande(proposition) -> list[str]:
    """Commande reproductible, sans exécution ni recherche de binaire."""
    logger.debug("_commande: entrée")
    if proposition.kind == PARIS_TRACEROUTE:
        commande = paris_traceroute.commande(proposition.five_tuple)
    else:
        cible, port = _cible_twamp(proposition)
        code = (
            "import json; from netcross_core.active.twamp import mesurer; "
            f"print(json.dumps(mesurer({cible!r}, port={port}, nombre=10, "
            "intervalle=0.1, timeout=1.0).to_dict(), ensure_ascii=False))"
        )
        commande = ["python3", "-c", code]
    logger.debug("_commande: retour")
    return commande


def _sauts(resultat: dict) -> list[dict]:
    """Réponses natives par TTL ; un silence ICMP n'est pas une perte prouvée."""
    logger.debug("_sauts: entrée")
    donnees = resultat.get("donnees") or {}
    reponses: dict[int, list[dict]] = defaultdict(list)
    for hop in donnees.get("hops", []):
        reponses[hop["probe_ttl"]].append({"adresse": hop.get("addr"), "rtt_ms": hop.get("rtt")})
    # Le backend utilise exactement une tentative par TTL, sans parallélisme.
    # Sans nombre natif vérifié (échec partiel), aucune perte n'est inventée.
    compte = resultat.get("envoyees")
    ttls = range(1, compte + 1) if type(compte) is int else sorted(reponses)
    sauts = [
        {
            "ttl": ttl,
            "reponses": reponses[ttl],
            "non_reponse_pct": (0.0 if reponses[ttl] else 100.0) if type(compte) is int else None,
        }
        for ttl in ttls
    ]
    logger.debug("_sauts: retour {} saut(s)", len(sauts))
    return sauts


def _divergence(proposition, resultat: dict) -> str:
    """Divergence possible, jamais une réfutation du diagnostic historique."""
    logger.debug("_divergence: entrée")
    stats = resultat.get("statistiques") or {}
    perte_passive = any("loss" in regle or "retransmission" in regle for regle in proposition.rule_ids)
    if perte_passive and stats.get("recues", 0) > 0 and stats.get("pertes") == 0:
        message = _(
            "Divergence possible : aucune perte active observée. Cette mesure postérieure, "
            "vers un réflecteur, ne réfute pas les pertes de la capture."
        )
    else:
        message = _(
            "Indéterminée : une mesure active postérieure ne prouve ni la cause ni "
            "l'état historique du segment. Les RTT ne sont pas des latences aller simple."
        )
    logger.debug("_divergence: retour")
    return message


def confirmer(events, *, enabled: bool = False, dry_run: bool = False) -> dict:
    """Aucune préparation ni émission par défaut ; la simulation a priorité.

    Au plus huit propositions, séquentielles, avec les budgets des backends
    (Paris : 30 TTL, 1 tentative, au plus 10 sondes/s ; TWAMP : 10 sondes).
    Les erreurs ne permettent jamais de prétendre qu'aucune sonde n'est partie.
    """
    logger.debug("confirmer: entrée enabled={} dry_run={}", enabled, dry_run)
    document: dict = {"enabled": enabled, "dry_run": dry_run, "omitted": 0, "measurements": []}
    if not enabled and not dry_run:
        logger.debug("confirmer: retour désactivé")
        return document
    propositions = plan_measurements(events)
    document["omitted"] = max(0, len(propositions) - MAX_MESURES)
    for proposition in propositions[:MAX_MESURES]:
        ligne = {"proposal": proposition.to_dict(), "status": "simulation", "result": None, "command": None}
        try:
            ligne["command"] = shlex.join(_commande(proposition))
            if not dry_run:
                if proposition.kind == PARIS_TRACEROUTE:
                    resultat = paris_traceroute.mesurer_proposition(proposition).to_dict()
                    resultat["sauts"] = _sauts(resultat)
                    ligne["status"] = resultat["statut"]
                else:
                    cible, port = _cible_twamp(proposition)
                    resultat = twamp.mesurer(cible, port, nombre=10, intervalle=0.1, timeout=1.0).to_dict()
                    ligne["status"] = "ok" if resultat["reflecteur_present"] else "sans_reflecteur"
                ligne["result"] = resultat
                ligne["divergence"] = _divergence(proposition, resultat)
        except (ValueError, OSError) as exc:
            logger.warning("confirmer: mesure refusée ou interrompue : {}", exc)
            ligne["status"] = "erreur"
            ligne["error"] = str(exc)
            ligne["sent"] = None
        document["measurements"].append(ligne)
    logger.debug("confirmer: retour {} mesure(s)", len(document["measurements"]))
    return document
