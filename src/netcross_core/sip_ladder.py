# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.sip_ladder -- diagramme d'echelle SIP multi-points
(issue #1125, sous-issue 4/6 du chantier VoIP #1004).

Pour chaque appel (Call-ID), une ligne par message SIP (methode ou ligne
de statut + CSeq) et une colonne par point de capture. Chaque cellule dit
si le message a ete vu a ce point, quand (ms depuis le premier message de
l'appel), combien de fois, et s'il y differe du premier point ou il a ete
vu. Trois constats sont mis en evidence :

- **perdu** : le message est vu a au moins un point et absent d'un autre.
  Les reponses provisoires ``100 Trying`` sont produites saut par saut
  (RFC 3261, 16.2) : leur absence a un point n'est pas une perte, elles
  sont marquees ``hop_by_hop`` et jamais comptees comme perdues ;
- **retransmis** : le meme message vu plusieurs fois au meme point
  (retransmission UDP, timers A/E/G de la RFC 3261, 17) ;
- **reecrit** : le SDP (adresses et ports media, issue #1120), le premier
  ``Via`` ou le ``Contact`` different de ceux du premier point ou le
  message a ete vu -- signature d'un ALG ou d'un SBC. Un proxy SIP ajoute
  legitimement son propre ``Via`` : un ``Via`` change est donc un indice,
  pas une anomalie a lui seul.

Aucun seuil, aucun verdict de gravite : le module decrit, les rapports
(PDF, HTML, JSON) affichent. Les appels qui portent au moins un constat
passent en tete, puis l'ordre chronologique.
"""

from __future__ import annotations

from collections import defaultdict

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

MAX_CALLS = 20
"""Nombre d'appels conserves : au-dela, l'echelle n'est plus lisible et le
detail reste disponible dans ``sip_missing``/``sip_failed_calls``."""

MAX_MESSAGES = 40
"""Nombre de messages conserves par appel (les premiers : etablissement et
fin d'appel portent le diagnostic)."""

CALL_ID_MAX_LEN = 80

REWRITE_FIELDS = ("sdp", "via", "contact")


def _is_hop_by_hop(message: str) -> bool:
    """Vrai pour une reponse ``100`` (Trying), generee a chaque saut."""
    logger.debug("_is_hop_by_hop: retour message.startswith('100')")
    return message.split(" ", 1)[0] == "100"


def _fields(pk) -> dict:
    """Valeurs comparees d'un point a l'autre pour reperer une reecriture."""
    logger.debug("_fields: retour dictionnaire")
    return {
        "sdp": tuple(getattr(pk, "sip_sdp_media", ()) or ()),
        "via": getattr(pk, "sip_via", None),
        "contact": getattr(pk, "sip_contact", None),
    }


def _rewritten(reference: dict, other: dict) -> list[str]:
    """Champs reecrits entre la premiere observation (``reference``) et une
    autre. Le SDP est compare des qu'un des deux en porte un (un SDP
    supprime est une reecriture) ; Via et Contact seulement s'ils sont
    connus des deux cotes (un en-tete absent du parseur n'est pas une
    preuve de reecriture)."""
    logger.debug("_rewritten: reference={} other={}", summarize(reference, "reference"), summarize(other, "other"))
    champs = []
    if (reference["sdp"] or other["sdp"]) and set(reference["sdp"]) != set(other["sdp"]):
        champs.append("sdp")
    champs.extend(
        nom
        for nom in ("via", "contact")
        if reference[nom] is not None and other[nom] is not None and reference[nom] != other[nom]
    )
    logger.debug("_rewritten: retour {} champ(s)", len(champs))
    return champs


def _ordered_points(per_point: dict, points) -> list[str]:
    """Points ou l'appel a ete vu, dans l'ordre du chemin s'il est connu,
    sinon dans l'ordre de premiere observation. Un point qui n'a vu aucun
    message de l'appel n'est pas sur son chemin de signalisation (capture
    du seul media, autre lien) : il n'a pas de colonne, et aucun message
    n'y est donc declare perdu."""
    logger.debug("_ordered_points: entrée")
    if points:
        ordre = [p for p in points if p in per_point]
        logger.debug("_ordered_points: si points -> retour ordre du chemin")
        return ordre
    ordre = sorted(per_point, key=lambda p: (min(pk.ts for pk in per_point[p]), p))
    logger.debug("_ordered_points: retour ordre d'observation")
    return ordre


def _build_call(call_id: str, packets: list, points) -> dict:
    """Echelle d'un appel : ``packets`` sont tous ses messages, tous points
    confondus."""
    logger.debug("_build_call: call_id={} packets={}", summarize(call_id, "call_id"), len(packets))
    per_point: defaultdict[str, list] = defaultdict(list)
    for pk in packets:
        per_point[pk.point].append(pk)
    ordre = _ordered_points(per_point, points)
    origin = min(pk.ts for pk in packets)

    # message -> point -> [Pkt] ; la cle garde l'ordre de premiere vue.
    messages: dict[tuple[str, str], dict[str, list]] = {}
    for pk in sorted(packets, key=lambda p: (p.ts, p.point, p.frame_number or 0)):
        cle = (pk.sip_msg_type, pk.sip_cseq or "")
        messages.setdefault(cle, defaultdict(list))[pk.point].append(pk)

    lignes = []
    for (message, cseq), vus in messages.items():
        presents = [p for p in ordre if vus.get(p)]
        reference = _fields(vus[presents[0]][0]) if presents else None
        cellules = {}
        reecrits = []
        for p in presents:
            premier = vus[p][0]
            champs = _rewritten(reference, _fields(premier)) if reference is not None else []
            cellules[p] = {
                "count": len(vus[p]),
                "rel_ms": round((premier.ts - origin) * 1000.0, 3),
                "frame_number": premier.frame_number,
                "rewritten": champs,
            }
            if champs:
                reecrits.append({"point": p, "fields": champs})
        hop = _is_hop_by_hop(message)
        lignes.append(
            {
                "message": message,
                "cseq": cseq,
                "hop_by_hop": hop,
                "cells": cellules,
                "lost_at": [] if hop else [p for p in ordre if p not in cellules],
                "retransmitted_at": [p for p in presents if len(vus[p]) > 1],
                "rewritten": reecrits,
            }
        )

    retenues = lignes[:MAX_MESSAGES]
    echelle = {
        "call_id": call_id[:CALL_ID_MAX_LEN],
        "points": ordre,
        "messages": retenues,
        "total_messages": len(lignes),
        "truncated": len(lignes) - len(retenues),
        "lost": sum(1 for m in lignes if m["lost_at"]),
        "retransmitted": sum(1 for m in lignes if m["retransmitted_at"]),
        "rewritten": sum(1 for m in lignes if m["rewritten"]),
        "_start": origin,
    }
    logger.debug("_build_call: retour echelle ({} message(s))", len(lignes))
    return echelle


def build_sip_ladders(all_packets, points=None, max_calls: int = MAX_CALLS) -> list[dict]:
    """Echelles SIP de la capture : une par Call-ID vu, ``max_calls`` au plus.

    ``points`` : ordre du chemin (colonnes) ; ``None`` = ordre de premiere
    observation de chaque appel. Les appels avec un constat (message perdu,
    retransmis ou reecrit) passent en tete. Liste vide sans SIP."""
    logger.debug(
        "build_sip_ladders: all_packets={} points={} max_calls={}",
        summarize(all_packets, "all_packets"),
        summarize(points, "points"),
        max_calls,
    )
    appels: defaultdict[str, list] = defaultdict(list)
    for pk in all_packets or []:
        if pk.sip_call_id and pk.sip_msg_type:
            appels[pk.sip_call_id].append(pk)
    if not appels:
        logger.debug("build_sip_ladders: si aucun message SIP -> retour liste vide")
        return []
    echelles = [_build_call(cid, pkts, points) for cid, pkts in appels.items()]
    echelles.sort(
        key=lambda e: (
            0 if (e["lost"] or e["retransmitted"] or e["rewritten"]) else 1,
            e["_start"],
            e["call_id"],
        )
    )
    retenues = echelles[: max(max_calls, 0)]
    for e in retenues:
        del e["_start"]
    logger.debug("build_sip_ladders: retour {} echelle(s) sur {} appel(s)", len(retenues), len(echelles))
    return retenues
