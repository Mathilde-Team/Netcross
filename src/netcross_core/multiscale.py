# SPDX-License-Identifier: GPL-3.0-or-later
"""Debit crete multi-echelle en fenetre glissante (issue #1133).

Deuxieme brique du chantier microrafales (#1005). Pour chaque echelle
(par defaut 100 us, 1 ms et 10 ms), on cherche la fenetre de cette duree,
placee n'importe ou dans le temps, qui contient le plus d'octets.

Le calcul est exact et incremental :

- les paquets arrivent un par un (``update``), dans l'ordre chronologique,
  ce qui le rend compatible avec le pipeline en flux ;
- seule la fenetre courante est gardee en memoire (une file par echelle),
  la memoire est donc bornee par le nombre de paquets d'une fenetre de la
  plus grande echelle, jamais par la taille de la capture ;
- le maximum d'une somme glissante sur un processus ponctuel est atteint
  par une fenetre ``]t - echelle, t]`` dont le bord droit est un paquet :
  evaluer la fenetre a chaque arrivee suffit pour avoir la valeur exacte ;
- les horodatages sont convertis en nanosecondes entieres relatives au
  premier paquet puis arrondis au quantum d'horodatage (``if_tsresol`` du
  point, 1 us au minimum), pour que les bords de fenetre ne dependent pas
  des arrondis des flottants : un horodatage epoch en ``float`` n'a
  qu'environ 0,24 us de granularite, d'ou aussi le refus de toute echelle
  inferieure a 1 us (``MIN_SCALE``).

Une echelle plus fine que la resolution d'horodatage du point
(``if_tsresol``, fournie par ``link_speed.resolve_link_speeds``) n'a pas de
sens : deux paquets distincts peuvent porter le meme horodatage. Elle est
refusee explicitement (``ScaleTooFineError``), ou listee dans ``refused``
avec la raison par ``multiscale_peaks``.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_SCALES: tuple[float, ...] = (100e-6, 1e-3, 10e-3)
MIN_SCALE = 1e-6
_NS = 1_000_000_000
_MIN_QUANTUM_NS = 1_000
# tolerance relative pour comparer une echelle a une resolution binaire (2^-n)
_RES_TOLERANCE = 1e-9


class ScaleTooFineError(ValueError):
    """Echelle plus fine que la resolution d'horodatage du point."""


def format_scale(seconds: float) -> str:
    """``0.0001`` -> ``100 µs`` ; ``0.001`` -> ``1 ms`` ; ``2`` -> ``2 s``."""
    logger.debug("format_scale: {}", seconds)
    for factor, unit in ((1.0, "s"), (1e-3, "ms"), (1e-6, "µs")):
        if seconds >= factor:
            text = f"{seconds / factor:.3f}".rstrip("0").rstrip(".")
            logger.debug("format_scale: retour {} {}", text, unit)
            return f"{text} {unit}"
    text = f"{seconds * 1e9:.3f}".rstrip("0").rstrip(".")
    logger.debug("format_scale: retour {} ns", text)
    return f"{text} ns"


def check_scale(scale: float, ts_resolution: float | None, point: str = "") -> None:
    """Leve ValueError pour une echelle nulle ou negative et
    ScaleTooFineError pour une echelle plus fine que ``ts_resolution``
    (resolution inconnue : aucune verification)."""
    logger.debug("check_scale: {} s (résolution {}) point {!r}", scale, ts_resolution, point)
    if not scale > 0:
        logger.debug("check_scale: levée ValueError (échelle non positive)")
        raise ValueError(f"échelle de fenêtre non positive : {scale!r}")
    if scale < MIN_SCALE * (1 - _RES_TOLERANCE):
        logger.debug("check_scale: levée ScaleTooFineError (sous 1 µs)")
        raise ScaleTooFineError(
            f"échelle {format_scale(scale)} refusée : plus fine que la précision des "
            f"horodatages en virgule flottante ({format_scale(MIN_SCALE)} au minimum)"
        )
    if ts_resolution and scale < ts_resolution * (1 - _RES_TOLERANCE):
        where = f" du point {point}" if point else ""
        logger.debug("check_scale: levée ScaleTooFineError")
        raise ScaleTooFineError(
            f"échelle {format_scale(scale)} refusée : plus fine que la résolution "
            f"d'horodatage{where} ({format_scale(ts_resolution)}, if_tsresol)"
        )
    logger.debug("check_scale: échelle acceptée")


class SlidingWindowPeak:
    """Fenetre glissante d'une echelle : somme courante et crete exacte."""

    def __init__(self, scale: float) -> None:
        logger.debug("SlidingWindowPeak.__init__: échelle {} s", scale)
        if not scale > 0:
            logger.debug("SlidingWindowPeak.__init__: levée ValueError")
            raise ValueError(f"échelle de fenêtre non positive : {scale!r}")
        self.scale = scale
        self._scale_ns = max(1, round(scale * _NS))
        self._window: deque[tuple[int, int]] = deque()
        self._bytes = 0
        self.max_window_packets = 0
        self.peak_bytes = 0
        self.peak_packets = 0
        self.peak_start_ns = 0
        self.peak_end_ns = 0
        logger.debug("SlidingWindowPeak.__init__: {} ns", self._scale_ns)

    def update(self, ts_ns: int, length: int) -> None:
        """Ajoute un paquet (``ts_ns`` croissant) et met a jour la crete."""
        logger.debug("SlidingWindowPeak.update: {} ns, {} o", ts_ns, length)
        window = self._window
        window.append((ts_ns, length))
        self._bytes += length
        limit = ts_ns - self._scale_ns
        while window[0][0] <= limit:
            self._bytes -= window.popleft()[1]
        self.max_window_packets = max(self.max_window_packets, len(window))
        if self._bytes > self.peak_bytes:
            self.peak_bytes = self._bytes
            self.peak_packets = len(window)
            self.peak_start_ns = window[0][0]
            self.peak_end_ns = ts_ns
        logger.debug("SlidingWindowPeak.update: fenêtre {} o / {} paquet(s)", self._bytes, len(window))


class MultiScaleRates:
    """Cretes de debit d'un point a plusieurs echelles, paquet par paquet.

    ``ts_resolution`` (s) refuse a la construction toute echelle plus fine ;
    ``link_speed_bps`` ajoute le taux d'occupation de l'interface."""

    def __init__(
        self,
        scales: Iterable[float] = DEFAULT_SCALES,
        ts_resolution: float | None = None,
        link_speed_bps: int | None = None,
        point: str = "",
    ) -> None:
        logger.debug("MultiScaleRates.__init__: point {!r}", point)
        ordered = sorted(set(scales))
        if not ordered:
            logger.debug("MultiScaleRates.__init__: levée ValueError (aucune échelle)")
            raise ValueError("au moins une échelle de fenêtre est requise")
        for scale in ordered:
            check_scale(scale, ts_resolution, point)
        self.point = point
        self.ts_resolution = ts_resolution
        self.link_speed_bps = link_speed_bps
        self._windows = [SlidingWindowPeak(s) for s in ordered]
        self._quantum_ns = max(_MIN_QUANTUM_NS, round((ts_resolution or 0) * _NS))
        self._origin: float | None = None
        self._last_ns = 0
        self.packets = 0
        self.bytes = 0
        self.reordered = 0
        self.first_ts: float | None = None
        logger.debug("MultiScaleRates.__init__: {} échelle(s)", len(ordered))

    def update(self, ts: float, length: int) -> None:
        """Ajoute un paquet (horodatage en s, taille en octets). Un paquet
        legerement en retard (reordonnancement de capture) est compte au
        dernier instant vu, pour garder des fenetres coherentes."""
        logger.debug("MultiScaleRates.update: {} s, {} o", ts, length)
        if self._origin is None:
            self._origin = ts
            self.first_ts = ts
        quantum = self._quantum_ns
        ts_ns = round((ts - self._origin) * _NS / quantum) * quantum
        if ts_ns < self._last_ns:
            self.reordered += 1
            ts_ns = self._last_ns
        self._last_ns = ts_ns
        self.packets += 1
        self.bytes += length
        for window in self._windows:
            window.update(ts_ns, length)
        logger.debug("MultiScaleRates.update: {} paquet(s)", self.packets)

    def results(self) -> list[dict]:
        """Une fiche par echelle, de la plus fine a la plus large."""
        logger.debug("MultiScaleRates.results: point {!r}", self.point)
        origin = self.first_ts or 0.0
        rows = []
        for w in self._windows:
            peak_bps = w.peak_bytes * 8 / w.scale
            row = {
                "scale_s": w.scale,
                "scale": format_scale(w.scale),
                "peak_bytes": w.peak_bytes,
                "peak_packets": w.peak_packets,
                "peak_bps": peak_bps,
                "peak_start": origin + w.peak_start_ns / _NS if w.peak_packets else None,
                "peak_end": origin + w.peak_end_ns / _NS if w.peak_packets else None,
                "max_window_packets": w.max_window_packets,
                "utilisation_pct": (round(100 * peak_bps / self.link_speed_bps, 2) if self.link_speed_bps else None),
            }
            rows.append(row)
        logger.debug("MultiScaleRates.results: retour {} fiche(s)", len(rows))
        return rows


def _refusal(scale: float, resolution: float | None, point: str) -> str | None:
    """Raison du refus d'une echelle pour ce point, ou None si acceptee."""
    logger.debug("_refusal: {} s point {!r}", scale, point)
    try:
        check_scale(scale, resolution, point)
    except ScaleTooFineError as exc:
        logger.debug("_refusal: retour refus ({})", exc)
        return str(exc)
    logger.debug("_refusal: retour None (acceptée)")
    return None


def multiscale_peaks(
    packets_by_point: dict[str, Iterable],
    link_speeds: dict[str, dict] | None = None,
    scales: Iterable[float] = DEFAULT_SCALES,
) -> dict[str, dict]:
    """Cretes multi-echelles de chaque point. ``packets_by_point`` donne,
    par point, des paquets tries portant ``ts`` et ``length`` ;
    ``link_speeds`` est le resultat de ``resolve_link_speeds``. Les echelles
    trop fines pour la resolution du point sont listees dans ``refused``
    avec la raison, jamais calculees en silence."""
    logger.debug("multiscale_peaks: {} point(s)", len(packets_by_point))
    link_speeds = link_speeds or {}
    wanted = sorted(set(scales))
    result: dict[str, dict] = {}
    for point, packets in packets_by_point.items():
        fiche = link_speeds.get(point, {})
        resolution = fiche.get("ts_resolution")
        accepted, refused = [], []
        for scale in wanted:
            reason = _refusal(scale, resolution, point)
            if reason:
                refused.append({"scale_s": scale, "scale": format_scale(scale), "reason": reason})
            else:
                accepted.append(scale)
        rates = None
        if accepted:
            rates = MultiScaleRates(accepted, resolution, fiche.get("speed_bps"), point)
            for pkt in packets:
                rates.update(pkt.ts, pkt.length)
        result[point] = {
            "ts_resolution": resolution,
            "speed_bps": fiche.get("speed_bps"),
            "packets": rates.packets if rates else 0,
            "reordered": rates.reordered if rates else 0,
            "scales": rates.results() if rates else [],
            "refused": refused,
        }
    logger.debug("multiscale_peaks: retour {} point(s)", len(result))
    return result
