# SPDX-License-Identifier: GPL-3.0-or-later
"""Traceroute Paris optionnel via Scamper, sans émission à l'import (#1065).

TCP/UDP gardent les adresses et ports du flux ; ICMP-Paris garde son
checksum. L'appel explicite à mesurer() émet : il appartient à l'appelant
d'obtenir l'autorisation. Aucun sudo, setcap ou repli vers un autre flux.
"""

from __future__ import annotations

import ipaddress
import json
import math
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import NoReturn

from netcross_core.active.planner import PARIS_TRACEROUTE, FiveTuple, ProposedMeasurement
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
_METHODS = {"TCP": "tcp", "UDP": "udp-paris", "ICMP": "icmp-paris", "ICMPV6": "icmp-paris"}


class ParisError(ValueError):
    """Paramètre invalide ou sortie native impossible à vérifier."""


def _refuser(message: str) -> NoReturn:
    logger.debug("_refuser: entrée puis levée ParisError : {}", message)
    raise ParisError(message)


@dataclass(frozen=True)
class Parametres:
    """Budget par mesure ; délai natif en secondes, silence en sauts consécutifs."""

    max_ttl: int = 30
    tentatives: int = 1
    debit_max: int = 10
    timeout: int = 1
    silence_max: int = 3

    def __post_init__(self) -> None:
        logger.debug("Parametres.__post_init__: entrée")
        for name, value, low, high in (
            ("max_ttl", self.max_ttl, 1, 255),
            ("tentatives", self.tentatives, 1, 3),
            ("debit_max", self.debit_max, 1, 10),
            ("timeout", self.timeout, 1, 10),
            ("silence_max", self.silence_max, 2, 20),
        ):
            if type(value) is not int or not low <= value <= high:
                _refuser(f"{name} doit être un entier entre {low} et {high}")
        logger.debug("Parametres.__post_init__: sortie")


@dataclass
class ResultatParis:
    """Mesure native conservée ; nombre émis inconnu en cas d'échec du processus."""

    flux: FiveTuple
    debut: str
    statut: str
    message: str
    envoyees: int | None = None
    donnees: dict | None = None

    def to_dict(self) -> dict:
        logger.debug("ResultatParis.to_dict: entrée")
        result = {"type": PARIS_TRACEROUTE, **asdict(self)}
        logger.debug("ResultatParis.to_dict: retour")
        return result


def _normaliser_flux(flux: FiveTuple) -> FiveTuple:
    logger.debug("_normaliser_flux: entrée")
    proto = flux.proto.upper()
    if proto not in _METHODS:
        _refuser("protocole attendu : TCP, UDP, ICMP ou ICMPv6")
    try:
        source, target = ipaddress.ip_address(flux.src), ipaddress.ip_address(flux.dst)
    except ValueError as exc:
        logger.warning("_normaliser_flux: adresse invalide")
        logger.debug("_normaliser_flux: levée ParisError")
        raise ParisError("adresses IP littérales requises, sans résolution DNS") from exc
    if source.version != target.version:
        _refuser("les deux adresses doivent utiliser la même famille IP")
    for address in (source, target):
        if address.is_multicast or address.is_unspecified or "%" in str(address) or str(address) == "255.255.255.255":
            _refuser("adresse non unicast, non spécifiée ou à zone IPv6 non prise en charge")
    if proto in {"ICMP", "ICMPV6"}:
        if (proto == "ICMPV6") != (source.version == 6) or flux.sport is not None or flux.dport is not None:
            _refuser("ICMP/ICMPv6 doit correspondre à la famille IP, sans ports")
    elif any(type(port) is not int or not 1 <= port <= 65535 for port in (flux.sport, flux.dport)):
        _refuser("ports TCP/UDP requis, entiers entre 1 et 65535")
    normalized = FiveTuple(proto, str(source), flux.sport, str(target), flux.dport)
    logger.debug("_normaliser_flux: retour")
    return normalized


def _commande(flux: FiveTuple, parameters: Parametres, executable: str) -> list[str]:
    logger.debug("_commande: entrée")
    # -p est un objectif global, -W un minimum natif entre sondes, en 10 ms.
    # Une unité supplémentaire évite de viser exactement la frontière 100 ms.
    wait_probe = math.ceil(100 / parameters.debit_max) + 1
    sport = flux.sport if flux.sport is not None else 33436
    dport = flux.dport if flux.dport is not None else 33435
    trace = (
        f"trace -P {_METHODS[flux.proto]} -S {flux.src} -s {sport} -d {dport} "
        f"-f 1 -m {parameters.max_ttl} -q {parameters.tentatives} "
        f"-N 1 -g {parameters.silence_max} -G 1 -w {parameters.timeout} -W {wait_probe} {flux.dst}"
    )
    command = [executable, "-p", str(parameters.debit_max), "-O", "json", "-I", trace]
    logger.debug("_commande: retour")
    return command


def _lire_sortie(text: str, flux: FiveTuple, parameters: Parametres) -> dict:
    logger.debug("_lire_sortie: entrée")
    records = [json.loads(line, parse_constant=_refuser) for line in text.splitlines() if line.strip()]
    traces = [record for record in records if isinstance(record, dict) and record.get("type") == "trace"]
    if len(traces) != 1:
        _refuser("une unique mesure trace JSON native est requise")
    trace = traces[0]
    if trace.get("src") != flux.src or trace.get("dst") != flux.dst:
        _refuser("les adresses mesurées ne correspondent pas au flux demandé")
    if str(trace.get("method", "")).lower() != _METHODS[flux.proto]:
        _refuser("la méthode native ne correspond pas au protocole demandé")
    if flux.sport is not None and (trace.get("sport") != flux.sport or trace.get("dport") != flux.dport):
        _refuser("les ports mesurés ne correspondent pas au flux demandé")
    count = trace.get("probe_count")
    if type(count) is not int or not 0 <= count <= parameters.max_ttl * parameters.tentatives:
        _refuser("nombre de sondes natif absent ou hors budget")
    if not isinstance(trace.get("stop_reason"), str) or not isinstance(trace.get("hops", []), list):
        _refuser("motif d'arrêt ou sauts natifs invalides")
    for hop in trace.get("hops", []):
        if (
            not isinstance(hop, dict)
            or type(hop.get("probe_ttl")) is not int
            or not 1 <= hop["probe_ttl"] <= parameters.max_ttl
        ):
            _refuser("TTL natif absent ou hors budget")
    logger.debug("_lire_sortie: retour")
    return trace


def mesurer(flux: FiveTuple, parametres: Parametres | None = None, *, binaire: str = "scamper") -> ResultatParis:
    """Exécute une seule mesure explicitement autorisée par l'appelant.

    Pas de résolution DNS, de substitution de source ni d'élévation de
    privilège. La source doit être locale au point d'exécution. Le backend
    doit disposer des droits requis par sa compilation (CAP_NET_RAW/root).
    Les erreurs de processus ne sont jamais présentées comme zéro sonde.
    """
    logger.debug("mesurer: entrée")
    flux = _normaliser_flux(flux)
    parameters = parametres if parametres is not None else Parametres()
    debut = datetime.now(UTC).isoformat()
    logger.info("Paris début={} cible={} budget_sondes={}", debut, flux.dst, parameters.max_ttl * parameters.tentatives)
    executable = shutil.which(binaire)
    if executable is None:
        result = ResultatParis(
            flux, debut, "indisponible", "Scamper absent : installer le binaire optionnel scamper.", 0
        )
    else:
        # Budget maximal, démarrage inclus ; aucune attente illimitée.
        deadline = parameters.max_ttl * parameters.tentatives * (parameters.timeout + 1.1) + 30
        try:
            completed = subprocess.run(
                _commande(flux, parameters, executable),
                capture_output=True,
                text=True,
                timeout=deadline,
                check=False,
                shell=False,
            )
            if completed.returncode:
                logger.warning("mesurer: backend en échec, code {}", completed.returncode)
                result = ResultatParis(
                    flux,
                    debut,
                    "erreur",
                    "Scamper a échoué : vérifier la source locale et les droits du binaire "
                    "(CAP_NET_RAW/root selon sa compilation). " + completed.stderr.strip()[:400],
                )
            else:
                trace = _lire_sortie(completed.stdout, flux, parameters)
                if trace["stop_reason"] == "ERROR":
                    result = ResultatParis(
                        flux,
                        debut,
                        "erreur",
                        "Erreur native Scamper : vérifier la source locale et CAP_NET_RAW/root.",
                        trace["probe_count"],
                        trace,
                    )
                else:
                    result = ResultatParis(flux, debut, "ok", trace["stop_reason"], trace["probe_count"], trace)
        except subprocess.TimeoutExpired:
            logger.warning("mesurer: budget de temps du processus dépassé")
            result = ResultatParis(flux, debut, "timeout", "Scamper a dépassé le budget de temps ; mesure interrompue.")
        except OSError as exc:
            logger.warning("mesurer: exécution impossible : {}", exc)
            result = ResultatParis(
                flux, debut, "erreur", "Scamper inexécutable : vérifier le binaire et CAP_NET_RAW/root. " + str(exc)
            )
        except (ValueError, TypeError) as exc:
            logger.warning("mesurer: sortie native refusée : {}", exc)
            result = ResultatParis(flux, debut, "erreur", "Sortie Scamper non vérifiable : " + str(exc))
    logger.info(
        "Paris fin début={} cible={} sondes_envoyees={} statut={}", debut, flux.dst, result.envoyees, result.statut
    )
    logger.debug("mesurer: retour")
    return result


def mesurer_proposition(proposition: ProposedMeasurement, **kwargs) -> ResultatParis:
    """Exécution explicite d'une proposition du planificateur, jamais automatique."""
    logger.debug("mesurer_proposition: entrée")
    if proposition.kind != PARIS_TRACEROUTE:
        _refuser("la proposition n'est pas un traceroute Paris")
    result = mesurer(proposition.five_tuple, **kwargs)
    logger.debug("mesurer_proposition: retour")
    return result
