"""Vitesse de lien et resolution d'horodatage par point (issue #1132).

Premiere brique du chantier microrafales (#1005) : pour chaque point de
capture, la vitesse de l'interface vient de l'option pcapng ``if_speed`` de
ses blocs IDB, sinon de ``--link-speed POINT=1G`` ; la resolution
d'horodatage vient de ``if_tsresol`` (ou du magic d'un pcap classique).
La source de chaque valeur est toujours exposee (``speed_source``), pour ne
jamais presenter une vitesse saisie comme une vitesse mesuree.
"""

from __future__ import annotations

import re
import struct

from netcross_core.logging_config import get_logger
from pcap_parser.capfile import read_structure

logger = get_logger(__name__)

SOURCE_IF_SPEED = "if_speed"
SOURCE_OPTION = "--link-speed"

_SPEED_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)(?:bps|bit/s|b/s)?\s*$")
_MULTIPLIERS = {"": 1, "k": 10**3, "m": 10**6, "g": 10**9, "t": 10**12}


def parse_link_speed(text: str) -> int:
    """Vitesse en bit/s depuis ``1G``, ``2.5G``, ``100M``, ``10k`` ou un
    entier brut (multiplicateurs decimaux, comme if_speed). Leve
    ValueError sur une valeur illisible ou nulle."""
    logger.debug("parse_link_speed: {!r}", text)
    match = _SPEED_RE.match(text)
    if not match:
        logger.debug("parse_link_speed: levée ValueError (format)")
        raise ValueError(f"vitesse de lien illisible : {text!r} (attendu par exemple 1G, 100M, 2.5G)")
    value = round(float(match[1]) * _MULTIPLIERS[match[2].lower()])
    if value <= 0:
        logger.debug("parse_link_speed: levée ValueError (nulle)")
        raise ValueError(f"vitesse de lien nulle : {text!r}")
    logger.debug("parse_link_speed: retour {} bit/s", value)
    return value


def parse_link_speed_specs(specs: list[str] | None, points: list[str]) -> dict[str, int]:
    """``["A=1G", "B=100M"]`` -> ``{"A": 10**9, "B": 10**8}``. Leve
    ValueError si une entree n'a pas la forme POINT=VITESSE, designe un
    point inconnu ou est repetee."""
    logger.debug("parse_link_speed_specs: {} entrée(s)", len(specs or []))
    result: dict[str, int] = {}
    for spec in specs or []:
        point, sep, speed = spec.partition("=")
        point = point.strip()
        if not sep or not point:
            logger.debug("parse_link_speed_specs: levée ValueError (forme)")
            raise ValueError(f"--link-speed attend POINT=VITESSE, reçu {spec!r}")
        if point not in points:
            logger.debug("parse_link_speed_specs: levée ValueError (point inconnu)")
            raise ValueError(f"--link-speed : point inconnu {point!r} (points : {', '.join(points)})")
        if point in result:
            logger.debug("parse_link_speed_specs: levée ValueError (doublon)")
            raise ValueError(f"--link-speed : point {point!r} donné plusieurs fois")
        result[point] = parse_link_speed(speed)
    logger.debug("parse_link_speed_specs: retour {}", result)
    return result


def resolve_link_speeds(captures, overrides: dict[str, int] | None = None) -> dict[str, dict]:
    """Une fiche par point : ``speed_bps``/``speed_source`` (if_speed de la
    premiere interface qui le porte, sinon --link-speed, sinon None),
    ``ts_resolution`` (la plus fine des interfaces, en s) et le detail par
    interface. Une capture illisible (fichier absent, format inconnu ou
    compresse) garde la seule valeur --link-speed eventuelle."""
    logger.debug("resolve_link_speeds: {} capture(s)", len(captures))
    overrides = overrides or {}
    result: dict[str, dict] = {}
    for label, path in captures:
        interfaces: list[dict] = []
        try:
            structure = read_structure(path)
        except (OSError, ValueError, struct.error) as exc:
            logger.debug("resolve_link_speeds: structure illisible pour {} ({})", label, type(exc).__name__)
            structure = None
        if structure is not None:
            interfaces = [
                {"index": i.index, "name": i.name, "speed_bps": i.speed_bps, "ts_resolution": i.ts_resolution}
                for i in structure.interfaces
            ]
        measured = [i["speed_bps"] for i in interfaces if i["speed_bps"]]
        if len(set(measured)) > 1:
            logger.debug("resolve_link_speeds: {} interfaces de vitesses différentes sur {}", len(measured), label)
        if measured:
            speed, source = measured[0], SOURCE_IF_SPEED
            if label in overrides and overrides[label] != speed:
                logger.debug("resolve_link_speeds: --link-speed ignoré pour {} (if_speed présent)", label)
        elif label in overrides:
            speed, source = overrides[label], SOURCE_OPTION
        else:
            speed, source = None, None
        result[label] = {
            "speed_bps": speed,
            "speed_source": source,
            "ts_resolution": min((i["ts_resolution"] for i in interfaces), default=None),
            "interfaces": interfaces,
        }
    logger.debug("resolve_link_speeds: retour {} point(s)", len(result))
    return result


def format_speed(bps: int) -> str:
    """``1000000000`` -> ``1 Gbit/s`` ; ``2500000000`` -> ``2.5 Gbit/s``."""
    logger.debug("format_speed: {}", bps)
    for factor, unit in ((10**12, "Tbit/s"), (10**9, "Gbit/s"), (10**6, "Mbit/s"), (10**3, "kbit/s")):
        if bps >= factor:
            text = f"{bps / factor:.3f}".rstrip("0").rstrip(".")
            logger.debug("format_speed: retour {} {}", text, unit)
            return f"{text} {unit}"
    logger.debug("format_speed: retour {} bit/s", bps)
    return f"{bps} bit/s"
