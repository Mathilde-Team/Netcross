# SPDX-License-Identifier: GPL-3.0-or-later
"""Qualité de transport entre jambes RTP appariées, sans lire le contenu."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from netcross_core.logging_config import get_logger
from netcross_core.rtp_match import SEQ_MOD, TS_MOD
from pcap_parser.protocols import compute_mos

logger = get_logger(__name__)

TRANSPORT_NOTE = (
    "Transport uniquement (RTP/SRTP), contenu non analysé. "
    "Note indicative : E-model simplifié avec hypothèse G.711, pas une qualité perçue. "
    "Une différence de visibilité peut aussi provenir de pertes de capture."
)


def _key(value):
    logger.debug("_key: retour identité d'une jambe RTP")
    return tuple(value[k] for k in ("point", "src", "sport", "dst", "dport", "ssrc"))


def _samples(packets, leg):
    """Déduplique les couples normalisés, en gardant la première arrivée."""
    logger.debug("_samples: entrée n={}", len(packets))
    samples = {}
    for packet in sorted(packets, key=lambda p: p.ts):
        pair = (
            (packet.rtp_seq - leg["seq_offset"]) % SEQ_MOD,
            (packet.rtp_ts - leg["ts_offset"]) % TS_MOD,
        )
        samples.setdefault(pair, packet)
    logger.debug("_samples: retour n={}", len(samples))
    return samples


def _jitter(packets, clock_rate):
    """Interarrival jitter RFC 3550 ; horodatage RTP 32 bits déroulé."""
    logger.debug("_jitter: entrée n={}", len(packets))
    jitter = 0.0
    for previous, current in zip(packets, packets[1:]):
        ticks = (current.rtp_ts - previous.rtp_ts + TS_MOD // 2) % TS_MOD - TS_MOD // 2
        difference = (current.ts - previous.ts) - ticks / clock_rate
        jitter += (abs(difference) - jitter) / 16
    logger.debug("_jitter: retour gigue={}", jitter * 1000)
    return jitter * 1000


def _timing(a, b, common, estimates, point_a, point_b):
    """Delta signé corrigé, et borne conservatrice d'incertitude au temps réel."""
    logger.debug("_timing: entrée n={}", len(common))
    estimate = estimates.get((point_a, point_b))
    reverse = estimate is None
    if reverse:
        estimate = estimates.get((point_b, point_a))
    deltas = []
    uncertainties = []
    for pair in common:
        first, second = a[pair], b[pair]
        delta = (second.ts - first.ts) * 1000
        if estimate is not None:
            anchor = second.ts if reverse else first.ts
            correction = estimate.decalage_a(anchor)
            delta -= -correction if reverse else correction
            uncertainties.append(estimate.ic_decalage_ms + abs(anchor - estimate.t0) * estimate.ic_derive_ppm / 1000)
        deltas.append(delta)
    signed = statistics.median(deltas)
    uncertainty = max(uncertainties) if uncertainties else None
    measurable = uncertainty is not None and abs(signed) > uncertainty
    logger.debug("_timing: retour mesurable={}", measurable)
    return signed, uncertainty, measurable


def _segment(group, leg_a, leg_b, a, b, estimates, clock_rate):
    logger.debug("_segment: entrée {} / {}", leg_a["point"], leg_b["point"])
    common = a.keys() & b.keys()
    if len(common) < 2:
        logger.debug("_segment: retour None, recouvrement insuffisant")
        return None
    signed, uncertainty, measurable = _timing(a, b, common, estimates, leg_a["point"], leg_b["point"])
    # Le chemin fourni reste le nom canonique du segment ; le sens média
    # ne s'infère des horloges que si l'incertitude le permet.
    if measurable and signed < 0:
        a, b = b, a
        upstream, downstream = leg_b["point"], leg_a["point"]
    else:
        upstream, downstream = leg_a["point"], leg_b["point"]
    ordered_a = list(a)
    positions = [n for n, pair in enumerate(ordered_a) if pair in common]
    window = ordered_a[positions[0] : positions[-1] + 1]
    missing = [pair for pair in window if pair not in b]
    selected_a = [a[pair] for pair in window]
    selected_b = sorted((b[pair] for pair in common), key=lambda p: p.ts)
    # Comparer les mêmes paquets reçus évite qu'une perte fabrique à elle
    # seule une différence de gigue d'échantillonnage entre les deux points.
    jitter_a = _jitter(sorted((a[pair] for pair in common), key=lambda p: p.ts), clock_rate)
    jitter_b = _jitter(selected_b, clock_rate)
    added_jitter = max(0.0, jitter_b - jitter_a)
    loss_pct = 100 * len(missing) / len(window)
    delay = abs(signed) if measurable else None
    baseline, _ = compute_mos(20.0, 0.0)
    factor, _ = compute_mos(20.0 + 2 * added_jitter + (delay or 0.0), loss_pct)
    degradation = min(100.0, max(0.0, (baseline - factor) / baseline * 100))
    result = {
        "label": group["label"],
        "segment": f"{leg_a['point']} -> {leg_b['point']}",
        "upstream": upstream,
        "downstream": downstream,
        "direction_confirmed": measurable,
        "sample_count": len(selected_a),
        "matched_packets": len(common),
        "lost": len(missing),
        "loss_pct": loss_pct,
        "jitter_upstream_ms": jitter_a,
        "jitter_downstream_ms": jitter_b,
        "added_jitter_ms": added_jitter,
        "signed_delta_ms": signed,
        "delay_ms": delay,
        "clock_uncertainty_ms": uncertainty,
        "degradation": degradation,
        "transport_quality": 100 - degradation,
        "degraded": bool(missing) or added_jitter >= 5.0 or (delay is not None and delay >= 150.0),
        "scope": "transport",
        "note": TRANSPORT_NOTE,
    }
    logger.debug("_segment: retour pertes={}", len(missing))
    return result


def analyse_rtp_segments(packets, matches, estimates, *, ordered, clock_rate=8000):
    """Mesures par segment ; aucun sens physique déduit sans ordre fourni.

    Les pertes sont comptées seulement entre le premier et le dernier paquet
    commun, après normalisation NAT/SBC. Sans horloge exploitable, les comptes
    suivent l'ordre fourni ; le délai est nul au sens JSON (``None``), jamais
    présenté comme une mesure physique. Le sens reste explicitement non confirmé.
    """
    logger.debug("analyse_rtp_segments: entrée groupes={}", len(matches))
    if not math.isfinite(clock_rate) or clock_rate <= 0:
        logger.debug("analyse_rtp_segments: levée ValueError, horloge RTP invalide")
        raise ValueError("l'horloge RTP doit être strictement positive et finie")
    if not ordered:
        logger.debug("analyse_rtp_segments: retour vide, chemin non ordonné")
        return []
    index = defaultdict(list)
    for packet in packets:
        if packet.proto == "UDP" and packet.is_rtp and packet.rtp_seq is not None and packet.rtp_ts is not None:
            index[(packet.point, packet.src, packet.sport, packet.dst, packet.dport, packet.rtp_ssrc)].append(packet)
    segments = []
    for group in matches:
        legs = group["legs"]
        samples = [_samples(index[_key(leg)], leg) for leg in legs]
        for n, (leg_a, leg_b) in enumerate(zip(legs, legs[1:])):
            segment = _segment(group, leg_a, leg_b, samples[n], samples[n + 1], estimates, clock_rate)
            if segment is not None:
                segments.append(segment)
    logger.debug("analyse_rtp_segments: retour n={}", len(segments))
    return segments
