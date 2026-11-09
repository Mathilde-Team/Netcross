# SPDX-License-Identifier: GPL-3.0-or-later
"""Microrafales par point, fenêtres glissantes exactes et référence relative.

La médiane des tranches NON VIDES de chaque échelle estime le trafic de
fond sans allouer les périodes de silence. Un pic doit la dépasser d'un
facteur quatre ; avec une vitesse connue, il doit aussi occuper au moins
80 % du lien. Ce sont des indices de concentration, pas des preuves de perte.
"""

from __future__ import annotations

import math
import statistics
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.multiscale import DEFAULT_SCALES, ScaleTooFineError, SlidingWindowPeak, check_scale

logger = get_logger(__name__)

MIN_PEAK_MEDIAN_RATIO = 4.0
MIN_UTILISATION_PCT = 80.0
MIN_WINDOW_PACKETS = 2
_NS = 1_000_000_000
_PEAK_FIELDS = ("peak_bps", "scale_s", "baseline_bps", "peak_median_ratio")


def _merge_episode(episodes: list[dict], candidate: dict) -> None:
    """Fusionne une fenêtre chevauchante ; conserve la crête et sa référence."""
    logger.debug("_merge_episode: {} épisode(s)", len(episodes))
    if not episodes or candidate["start_ns"] > episodes[-1]["end_ns"]:
        episodes.append(dict(candidate))
        logger.debug("_merge_episode: nouvel épisode")
        return
    previous = episodes[-1]
    previous["end_ns"] = max(previous["end_ns"], candidate["end_ns"])
    if candidate["peak_bps"] > previous["peak_bps"]:
        for key in _PEAK_FIELDS:
            previous[key] = candidate[key]
    logger.debug("_merge_episode: fenêtre fusionnée")


def _scale_candidates(ticks: list[int], packets: list[Pkt], scale: float, speed: int | None) -> list[dict]:
    """Référence par tranches fixes, puis test des fenêtres glissantes exactes."""
    logger.debug("_scale_candidates: {} paquet(s), échelle {} s", len(packets), scale)
    width = round(scale * _NS)
    buckets: Counter[int] = Counter()
    for tick, packet in zip(ticks, packets):
        buckets[tick // width] += packet.length
    baseline_bps = statistics.median(buckets.values()) * 8 / scale
    window = SlidingWindowPeak(scale)
    episodes: list[dict] = []
    for tick, packet in zip(ticks, packets):
        window.update(tick, packet.length)
        peak_bps = window.current_bytes * 8 / scale
        ratio = peak_bps / baseline_bps
        if window.current_packets < MIN_WINDOW_PACKETS or ratio < MIN_PEAK_MEDIAN_RATIO:
            continue
        if speed and 100 * peak_bps / speed < MIN_UTILISATION_PCT:
            continue
        _merge_episode(
            episodes,
            {
                "start_ns": max(0, tick - width),
                "end_ns": tick,
                "peak_bps": peak_bps,
                "scale_s": scale,
                "baseline_bps": baseline_bps,
                "peak_median_ratio": ratio,
            },
        )
    logger.debug("_scale_candidates: retour {} épisode(s)", len(episodes))
    return episodes


def _detect_point(point: str, packets: list[Pkt], metadata: dict) -> dict:
    """Respecte le quantum du point ; ne crée jamais un axe temporel dense."""
    logger.debug("_detect_point: {} paquet(s)", len(packets))
    ordered = sorted(packets, key=lambda p: p.ts)
    origin = ordered[0].ts
    resolution = metadata.get("ts_resolution")
    speed = metadata.get("speed_bps") or None
    quantum = max(1_000, round((resolution or 0) * _NS))
    ticks = [round((p.ts - origin) * _NS / quantum) * quantum for p in ordered]
    candidates: list[dict] = []
    refused = []
    accepted = []
    for scale in DEFAULT_SCALES:
        try:
            check_scale(scale, resolution, point)
        except ScaleTooFineError as exc:
            logger.debug("_detect_point: échelle refusée ({})", exc)
            refused.append(str(exc))
            continue
        accepted.append(scale)
        candidates.extend(_scale_candidates(ticks, ordered, scale, speed))
    merged: list[dict] = []
    for candidate in sorted(candidates, key=lambda e: (e["start_ns"], e["end_ns"])):
        _merge_episode(merged, candidate)
    events = []
    for episode in merged:
        start_ns, end_ns = episode.pop("start_ns"), episode.pop("end_ns")
        first, last = bisect_left(ticks, start_ns), bisect_right(ticks, end_ns)
        senders: Counter[str] = Counter()
        for packet in ordered[first:last]:
            senders[packet.src or "indéterminé"] += packet.length
        total = sum(senders.values())
        events.append(
            {
                **episode,
                "point": point,
                "start": origin + start_ns / _NS,
                "end": origin + end_ns / _NS,
                "duration_s": (end_ns - start_ns) / _NS,
                "speed_bps": speed,
                "utilisation_pct": 100 * episode["peak_bps"] / speed if speed else None,
                "threshold_kind": "utilisation_and_relative" if speed else "relative",
                "baseline_kind": "median_nonempty_windows",
                "packets": last - first,
                "bytes": total,
                "top_senders": [
                    {"src": src, "bytes": size, "share_pct": 100 * size / total} for src, size in senders.most_common(5)
                ],
            }
        )
    result = {
        "events": events,
        "refused": refused,
        "scales_s": accepted,
        "ts_resolution": resolution,
        "speed_bps": speed,
    }
    logger.debug("_detect_point: retour {} événement(s), {} refus", len(events), len(refused))
    return result


def detect_microbursts(packets, link_speeds: dict[str, dict] | None = None) -> dict[str, dict]:
    """Détection automatique ; sans métadonnées, seuil relatif explicite.

    Les fenêtres chevauchantes sont réunies en épisodes conservateurs :
    leurs bornes couvrent les fenêtres de détection, pas un début physique
    exact de congestion. Les émetteurs proviennent des mêmes paquets que
    l'analyse, donc sont déjà pseudonymisés si l'appelant utilise --redact.
    """
    logger.debug("detect_microbursts: type {}, métadonnées {} point(s)", type(packets).__name__, len(link_speeds or {}))
    grouped: dict[str, list[Pkt]] = defaultdict(list)
    invalid = 0
    for packet in packets:
        if not math.isfinite(packet.ts) or packet.length <= 0:
            invalid += 1
            continue
        grouped[packet.point].append(packet)
    if invalid:
        logger.debug("detect_microbursts: {} paquet(s) invalides ignorés", invalid)
    metadata = link_speeds or {}
    result = {point: _detect_point(point, group, metadata.get(point, {})) for point, group in grouped.items()}
    logger.debug("detect_microbursts: retour {} point(s)", len(result))
    return result


def format_microburst(event: dict) -> str:
    """Même explication vérifiable pour le texte et les constats structurés."""
    logger.debug("format_microburst: {} paquet(s)", event["packets"])
    if event["utilisation_pct"] is None:
        threshold = "vitesse inconnue, seuil relatif"
    else:
        threshold = f"{event['utilisation_pct']:.1f} % de la vitesse d'interface"
    senders = ", ".join(f"{s['src']} ({s['share_pct']:.1f} %)" for s in event["top_senders"])
    text = (
        f"point {event['point']}, début {event['start']:.6f} s, "
        f"durée de fenêtre {event['duration_s'] * 1000:.3f} ms : "
        f"crête {event['peak_bps'] / 1e6:.3f} Mbit/s, {threshold} ; "
        f"pic / médiane des tranches non vides = {event['peak_median_ratio']:.2f} ; "
        f"principaux émetteurs : {senders}"
    )
    logger.debug("format_microburst: retour du résumé")
    return text
