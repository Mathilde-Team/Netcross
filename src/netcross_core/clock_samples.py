# SPDX-License-Identifier: GPL-3.0-or-later
"""Échantillons d'horloge UDP conservateurs, sans identifiant DNS global.

DNS fournit quatre observations d'un échange complet. RTP/RTCP fournit
deux datagrammes de sens opposés, chacun observé aux deux points : leur
demi-somme estime le décalage sous la même hypothèse de symétrie que NTP.
Un flux unidirectionnel ne permet pas de séparer délai et décalage.
"""

from __future__ import annotations

import math
from collections import defaultdict

from netcross_core.clock_sync import EchantillonHorloge
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)
MAX_MEDIA_SEPARATION_S = 1.0


def _sample(q_a: Pkt, q_b: Pkt, r_b: Pkt, r_a: Pkt, source: str) -> EchantillonHorloge:
    """Quatre horodatages ; l'ancre moyenne évite de dater un couple média à tort."""
    logger.debug("_sample: source {}", source)
    forward, backward = q_b.ts - q_a.ts, r_b.ts - r_a.ts
    result = EchantillonHorloge(
        t=(q_a.ts + r_a.ts) / 2,
        decalage_ms=(forward + backward) * 500,
        delai_ms=abs(forward - backward) * 1000,
        source=source,
    )
    logger.debug("_sample: retour échantillon {}", source)
    return result


def _dns_name(packet: Pkt) -> str:
    logger.debug("_dns_name: retour nom normalisé")
    return (packet.dns_qry_name or "").casefold().rstrip(".")


def _dns_exchanges(packets: list[Pkt], nat_tolerant: bool) -> dict:
    """Un seul échange par clé locale ; IDs réutilisés et collisions restent ambigus."""
    logger.debug("_dns_exchanges: {} paquet(s), NAT {}", len(packets), nat_tolerant)
    local: dict[tuple, list[Pkt]] = defaultdict(list)
    for packet in packets:
        if packet.dns_txn_id is None:
            continue
        client, server = (packet.dst, packet.src) if packet.dns_is_response else (packet.src, packet.dst)
        cport, sport = (packet.dport, packet.sport) if packet.dns_is_response else (packet.sport, packet.dport)
        local[(packet.point, client, server, cport, sport, packet.dns_txn_id)].append(packet)
    exchanges: dict[tuple, dict[str, list[tuple[Pkt, Pkt]]]] = defaultdict(lambda: defaultdict(list))
    for key, group in local.items():
        names = {_dns_name(packet) for packet in group} - {""}
        buckets: dict[str, list[Pkt]] = defaultdict(list)
        for packet in group:
            name = _dns_name(packet)
            if not name and len(names) > 1:
                continue
            buckets[name or next(iter(names), "")].append(packet)
        for name, same_query in buckets.items():
            requests = [packet for packet in same_query if not packet.dns_is_response]
            replies = [packet for packet in same_query if packet.dns_is_response]
            if len(requests) != 1 or len(replies) != 1 or replies[0].ts < requests[0].ts:
                continue
            point, *endpoints, txn_id = key
            request, reply = requests[0], replies[0]
            if nat_tolerant and name and request.payload_hash and reply.payload_hash:
                signature = (txn_id, name, request.payload_hash, reply.payload_hash)
            else:
                signature = (txn_id, name, *endpoints)
            exchanges[signature][point].append((requests[0], replies[0]))
    logger.debug("_dns_exchanges: retour {} signature(s)", len(exchanges))
    return exchanges


def _dns_samples(packets: list[Pkt], pairs: list[tuple[str, str]], nat_tolerant: bool) -> dict:
    logger.debug("_dns_samples: {} paquet(s), {} paire(s)", len(packets), len(pairs))
    result: dict[tuple[str, str], list[EchantillonHorloge]] = defaultdict(list)
    for per_point in _dns_exchanges(packets, nat_tolerant).values():
        for a, b in pairs:
            at_a, at_b = per_point.get(a, []), per_point.get(b, [])
            if len(at_a) != 1 or len(at_b) != 1:
                continue
            q_a, r_a = at_a[0]
            q_b, r_b = at_b[0]
            result[(a, b)].append(_sample(q_a, q_b, r_b, r_a, "DNS"))
    logger.debug("_dns_samples: retour {} paire(s)", len(result))
    return result


def _media_identity(packet: Pkt) -> tuple | None:
    logger.debug("_media_identity: entrée")
    if packet.rtcp_hash:
        logger.debug("_media_identity: retour empreinte RTCP")
        return ("RTCP", packet.rtcp_hash, packet.length)
    if packet.is_rtp and None not in (packet.rtp_ssrc, packet.rtp_seq, packet.rtp_ts):
        logger.debug("_media_identity: retour identité RTP")
        return ("RTP", packet.rtp_ssrc, packet.rtp_seq, packet.rtp_ts, packet.length, packet.payload_hash)
    logger.debug("_media_identity: retour None")
    return None


def _endpoints(packet: Pkt) -> tuple:
    logger.debug("_endpoints: retour extrémités")
    return ((packet.src, packet.sport), (packet.dst, packet.dport))


def _media_samples(packets: list[Pkt], pairs: list[tuple[str, str]]) -> dict:
    """Paquets uniques aux deux points, connexions cohérentes dans les deux sens."""
    logger.debug("_media_samples: {} paquet(s), {} paire(s)", len(packets), len(pairs))
    observations: dict[tuple, dict[str, list[Pkt]]] = defaultdict(lambda: defaultdict(list))
    for packet in packets:
        if packet.dns_txn_id is not None or packet.sport is None or packet.dport is None:
            continue
        identity = _media_identity(packet)
        if identity is not None:
            observations[identity][packet.point].append(packet)
    result: dict[tuple[str, str], list[EchantillonHorloge]] = defaultdict(list)
    for a, b in pairs:
        channels: dict[tuple, tuple[list, list]] = defaultdict(lambda: ([], []))
        for identity, per_point in observations.items():
            at_a, at_b = per_point.get(a, []), per_point.get(b, [])
            if len(at_a) != 1 or len(at_b) != 1:
                continue
            packet_a, packet_b = at_a[0], at_b[0]
            endpoints_a, endpoints_b = _endpoints(packet_a), _endpoints(packet_b)
            connection_a, connection_b = tuple(sorted(endpoints_a)), tuple(sorted(endpoints_b))
            direction = int(endpoints_a != connection_a)
            orientation = direction ^ int(endpoints_b != connection_b)
            channels[(identity[0], connection_a, connection_b, orientation)][direction].append((packet_a, packet_b))
        for (kind, _a, _b, _orientation), (forward, backward) in channels.items():
            forward.sort(key=lambda observation: observation[0].ts)
            backward.sort(key=lambda observation: observation[0].ts)
            i = j = 0
            while i < len(forward) and j < len(backward):
                q_a, q_b = forward[i]
                r_a, r_b = backward[j]
                if q_a.ts < r_a.ts - MAX_MEDIA_SEPARATION_S:
                    i += 1
                    continue
                if r_a.ts < q_a.ts - MAX_MEDIA_SEPARATION_S:
                    j += 1
                    continue
                if abs(q_b.ts - r_b.ts) <= MAX_MEDIA_SEPARATION_S:
                    result[(a, b)].append(_sample(q_a, q_b, r_b, r_a, kind))
                i += 1
                j += 1
    logger.debug("_media_samples: retour {} paire(s)", len(result))
    return result


def collect_udp_samples(packets, pairs, nat_tolerant: bool = False) -> dict:
    """Sources DNS et média ; aucune mesure d'horloge sur un seul sens."""
    logger.debug("collect_udp_samples: {} paire(s), NAT {}", len(pairs), nat_tolerant)
    valid = [packet for packet in packets if packet.proto == "UDP" and math.isfinite(packet.ts)]
    result = _dns_samples(valid, pairs, nat_tolerant)
    for pair, samples in _media_samples(valid, pairs).items():
        result[pair].extend(samples)
    logger.debug("collect_udp_samples: retour {} paire(s)", len(result))
    return result
