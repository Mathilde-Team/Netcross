# SPDX-License-Identifier: GPL-3.0-or-later
"""Preuves cliquables du rapport HTML : trame de preuve vue a chaque point
(issue #1077, sous-issue 3/6 du chantier #1000).

Une preuve de constat (``evidence`` du JSON) designe une trame d'UN point
(``point`` + ``frame_number``). Pour la rendre verifiable depuis le
navigateur, ce module retrouve la meme trame aux autres points grace a la
correlation (``correlate()`` : cle de paquet -> {point: [Pkt]}) et produit,
par preuve, un petit diagramme centre sur elle :

- ``rows`` : la trame de preuve et ses voisines de la meme conversation au
  point de la preuve (``context`` avant et apres), chacune avec sa trame et
  sa date relative a chaque point ou elle a ete vue ;
- ``transits`` : pour la trame de preuve, temps de transit entre points
  consecutifs du chemin, corrige du decalage d'horloge estime quand il
  existe (meme correction que ``analysis`` pour la latence, #996).

Les dates sont en ms relatives a la trame de preuve, a son point : le
diagramme reste lisible quelle que soit l'heure absolue. Une preuve sans
trame correlee (``frame_number`` inconnu du jeu de paquets) est listee avec
``found: False`` : jamais de diagramme invente. Une preuve de segment
``A -> B`` designe une trame du point amont ``A`` (``capture_point``).
"""

from __future__ import annotations

import re
from collections import defaultdict

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_CONTEXT = 3
DEFAULT_LIMIT = 200

# Protocole affiche (et filtrable) par categorie de constat ; une categorie
# transverse (pertes, QoS, saturation...) vaut pour tout le trafic IP.
CATEGORY_PROTOCOLS = {
    "ARP": "ARP",
    "DHCP": "DHCP",
    "DNS": "DNS",
    "HTTP": "HTTP",
    "SIP": "SIP",
    "STP": "STP",
    "TCP": "TCP",
    "TLS": "TLS",
    "QUIC": "QUIC",
    "VLAN": "802.1Q",
    "RTP/Voix": "RTP",
    "PMTUD": "ICMP",
}
GENERIC_PROTOCOL = "IP"
SEGMENT_SEPARATOR = " -> "


def finding_protocol(category: str | None) -> str:
    """Protocole d'un constat d'apres sa categorie (``IP`` si transverse)."""
    logger.debug("finding_protocol: {}", category)
    proto = CATEGORY_PROTOCOLS.get(category or "", GENERIC_PROTOCOL)
    logger.debug("finding_protocol: retour {}", proto)
    return proto


def evidence_ref(point: str, frame_number: int) -> str:
    """Identifiant stable d'une preuve, partage par le JSON et le HTML."""
    logger.debug("evidence_ref: {} #{}", point, frame_number)
    ref = f"{point}#{frame_number}"
    logger.debug("evidence_ref: retour {}", ref)
    return ref


def evidence_anchor(point: str, frame_number: int) -> str:
    """Ancre HTML (``id``) d'une preuve : ``preuve-<point>-<trame>``, tout
    caractere hors ``[A-Za-z0-9_-]`` du point remplace par ``_``."""
    logger.debug("evidence_anchor: {} #{}", point, frame_number)
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", point)
    anchor = f"preuve-{slug}-{frame_number}"
    logger.debug("evidence_anchor: retour {}", anchor)
    return anchor


def capture_point(point: str) -> str:
    """Point dont la capture porte la trame : une preuve de segment
    ``A -> B`` (PMTUD, inactivite) designe une trame du point amont."""
    logger.debug("capture_point: {}", point)
    amont = point.split(SEGMENT_SEPARATOR)[0] if SEGMENT_SEPARATOR in point else point
    logger.debug("capture_point: retour {}", amont)
    return amont


def _conversation(pk) -> tuple:
    """Conversation non orientee (proto, extremites triees)."""
    logger.debug("_conversation: debut")
    a, b = (pk.src, pk.sport), (pk.dst, pk.dport)
    ends = (a, b) if str(a) <= str(b) else (b, a)
    logger.debug("_conversation: retour")
    return (pk.proto, ends)


def _index(packet_flows):
    """(point, trame) -> (cle, paquet) et (point, conversation) -> paquets."""
    logger.debug("_index: {} cle(s)", len(packet_flows))
    by_ref: dict[tuple[str, int], tuple] = {}
    by_conv: dict[tuple[str, tuple], list] = defaultdict(list)
    for key, per_point in packet_flows.items():
        for point, pkts in per_point.items():
            for pk in pkts:
                if pk.frame_number is None:
                    continue
                by_ref.setdefault((point, pk.frame_number), (key, pk))
                by_conv[(point, _conversation(pk))].append(pk)
    for pkts in by_conv.values():
        pkts.sort(key=lambda p: (p.ts, p.frame_number))
    logger.debug("_index: retour {} trame(s)", len(by_ref))
    return by_ref, by_conv


def _sightings(per_point: dict, points: list[str]) -> dict:
    """Premiere occurrence de la trame a chaque point ou elle a ete vue."""
    logger.debug("_sightings: debut")
    seen = {}
    for p in points:
        numbered = [pk for pk in per_point.get(p) or [] if pk.frame_number is not None]
        if numbered:
            seen[p] = min(numbered, key=lambda pk: pk.ts)
    logger.debug("_sightings: retour {} point(s)", len(seen))
    return seen


def _summary(pk) -> str:
    """Resume d'une ligne : protocole, extremites, drapeaux TCP, taille."""
    logger.debug("_summary: debut")
    src = f"{pk.src}:{pk.sport}" if pk.sport is not None else str(pk.src)
    dst = f"{pk.dst}:{pk.dport}" if pk.dport is not None else str(pk.dst)
    flags = f" [{pk.flags}]" if pk.proto == "TCP" and pk.flags and set(pk.flags) != {"."} else ""
    text = f"{pk.proto} {src} -> {dst}{flags} {pk.length} o"
    logger.debug("_summary: retour")
    return text


def _transits(seen: dict, points: list[str], clock_offsets: dict) -> list[dict]:
    """Transit entre points consecutifs (dans l'ordre du chemin) ayant vu la trame."""
    logger.debug("_transits: debut")
    present = [p for p in points if p in seen]
    rows = []
    for a, b in zip(present, present[1:]):  # noqa: RUF007 (Python 3.9)
        ts_a = seen[a].ts
        raw_ms = (seen[b].ts - ts_a) * 1000.0
        estimate = clock_offsets.get((a, b))
        corrected = estimate is not None
        transit = raw_ms - estimate.decalage_a(ts_a) if estimate is not None else raw_ms
        rows.append(
            {
                "segment": f"{a} -> {b}",
                "transit_ms": round(transit, 3),
                "raw_ms": round(raw_ms, 3),
                "corrected": corrected,
            }
        )
    logger.debug("_transits: retour {} segment(s)", len(rows))
    return rows


def build_evidence_frames(
    findings: list[dict],
    packet_flows,
    points: list[str],
    clock_offsets: dict | None = None,
    context: int = DEFAULT_CONTEXT,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """Une entree par preuve distincte (``point`` + ``frame_number``) des
    ``findings`` (dicts du JSON), au plus ``limit`` ; voir la docstring de
    module pour le contenu."""
    logger.debug("build_evidence_frames: {} constat(s), {} point(s)", len(findings), len(points))
    clock_offsets = clock_offsets or {}
    refs: list[tuple[str, int]] = []
    for f in findings:
        for ev in f.get("evidence") or []:
            if ev.get("frame_number") is None or ev.get("point") is None:
                continue
            ref = (ev["point"], ev["frame_number"])
            if ref not in refs:
                refs.append(ref)
    truncated = max(0, len(refs) - limit)
    refs = refs[:limit]
    by_ref, by_conv = _index(packet_flows) if refs else ({}, {})
    out = []
    for ev_point, frame in refs:
        point = capture_point(ev_point)
        entry: dict = {
            "ref": evidence_ref(ev_point, frame),
            "anchor": evidence_anchor(ev_point, frame),
            "point": point,
            "frame_number": frame,
        }
        hit = by_ref.get((point, frame))
        if hit is None:
            entry["found"] = False
            out.append(entry)
            continue
        key, pk = hit
        origin = pk.ts
        convo = by_conv[(point, _conversation(pk))]
        pos = next(i for i, p in enumerate(convo) if p is pk)
        window = convo[max(0, pos - context) : pos + context + 1]
        rows = []
        for neighbour in window:
            nkey = by_ref.get((point, neighbour.frame_number), (None, None))[0]
            per_point = packet_flows.get(nkey, {}) if nkey is not None else {point: [neighbour]}
            seen = _sightings(per_point, points)
            rows.append(
                {
                    "frame_number": neighbour.frame_number,
                    "evidence": neighbour is pk,
                    "summary": _summary(neighbour),
                    "cells": {
                        p: {"frame_number": s.frame_number, "rel_ms": round((s.ts - origin) * 1000.0, 3)}
                        for p, s in seen.items()
                    },
                }
            )
        seen = _sightings(packet_flows[key], points)
        entry.update(
            {
                "found": True,
                "proto": pk.proto,
                "summary": _summary(pk),
                "points": [p for p in points if p in seen] or [point],
                "rows": rows,
                "transits": _transits(seen, points, clock_offsets),
            }
        )
        out.append(entry)
    if truncated:
        logger.debug("build_evidence_frames: {} preuve(s) au-dela de la limite", truncated)
    logger.debug("build_evidence_frames: retour {} preuve(s)", len(out))
    return out
