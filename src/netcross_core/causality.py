# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.causality -- moteur de correlation causale (Session 3 de la
section 13.3 de FEATURES.md, Job 4/issue #4).

Fusionne les evenements elementaires (perte + retransmissions + hausse RTT +
anomalie segment) en evenements corroles avec CAUSE PROBABLE et IMPACT,
en remplissant les champs `ExpertEvent.cause` / `ExpertEvent.impact` et
`Diagnosis.cause` / `Diagnosis.impact` qui restent TOUJOURS `None` dans les
passes precedentes (voir `expert_model.ExpertEvent` et
`expert_model.Diagnosis`).

Approche : correlation par SEGMENT (pas par flux -- `ExpertEvent.flow_keys`
reste vide cote source "netcross" aujourd'hui, voir `expert_model` ; la
correlation par flux depend du Job 8/9, hors perimetre ici). Pour chaque
segment, le moteur examine l'ensemble des `rule_id` presents et cherche
des PATTERNS de co-occurrence qui suggerent une cause commune :

1. **Congestion / saturation** : perte de paquets + retransmission TCP +
   bufferbloat ou saturation sur le meme segment -> cause probable
   "congestion", impact "pertes + latence + debit effondre".
2. **PMTUD / MTU insuffisant** : PMTUD black hole + fragmentation ou
   ICMP Fragmentation Needed -> cause probable "MTU insuffisant",
   impact "connexions TCP qui stagnent".
3. **Ralentissement applicatif** : temps de traitement serveur dominant +
   reponse HTTP lente ou timeout -> cause probable "ralentissement
   applicatif cote serveur", impact "lenteur percue par l'utilisateur
   -- pas un probleme reseau".

Chaque pattern ne renseigne `cause`/`impact` que sur les ExpertEvent dont
le `rule_id` participe au pattern (pas sur tous les evenements du segment
-- un `dns_nxdomain` sur un segment congeste ne doit pas heriter de la
cause "congestion"). Les objets existants sont MUTES en place (meme
liste retournee, ordre preserve, `evidence` inchange).

CORRELATION PAR SEGMENT UNIQUEMENT : les ExpertEvent de source "netcross"
ne portent pas `flow_keys` (vide, voir `expert_model`), et `Finding.segment`
n'est pas toujours un nom de point -- `rtp_quality_mos` utilise une
etiquette de flux, `dns_slow_resolution`/`http_slow_response`/`server_
processing_dominant` utilisent "global". Les patterns ci-dessus ne se
declenchent donc que sur des segments PARTAGES par plusieurs symptomes,
ce qui correspond aux cas ou la correlation est structurellement fiable
(pertes + retransmissions + bufferbloat sur le MEME point de capture).
La correlation par flux (quand `flow_keys` sera peuple) est un chantier
futur, explicitement hors perimetre de ce job -- voir Job 8/9.
"""

from __future__ import annotations

import math
import os
from bisect import bisect_left, bisect_right

from netcross_core.expert_model import Diagnosis, ExpertEvent
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt, Report

logger = get_logger(__name__)


class MicroburstCorrelator:
    """Associe des impacts localisés aux épisodes, sans affirmer leur cause physique.

    Les pertes proviennent exclusivement du détecteur existant, après sa garde
    hors chemin. Les bornes de paquets communs excluent les bords de capture.
    Les preuves sont limitées à dix par épisode et segment, pas les compteurs.
    """

    def __init__(self, report: Report, flows, ordered: bool, window_ms: float | None = None):
        logger.debug("MicroburstCorrelator: entrée ordre={}, points={}", ordered, len(report.points))
        value = os.environ.get("NETCROSS_MICROBURST_WINDOW_MS", "50") if window_ms is None else window_ms
        try:
            self.window_ms = float(value)
        except (TypeError, ValueError) as exc:
            logger.error("Fenêtre de corrélation microrafales non numérique")
            raise ValueError("La fenêtre microrafales doit être un nombre fini strictement positif") from exc
        if isinstance(value, bool) or not math.isfinite(self.window_ms) or self.window_ms <= 0:
            logger.error("Fenêtre de corrélation microrafales non positive ou non finie")
            raise ValueError("La fenêtre microrafales doit être un nombre fini strictement positif")
        self.report = report
        self.index: dict[str, tuple[list[float], list[float], list[dict]]] = {}
        self.records: dict[tuple[str, str, int], dict] = {}
        self.bounds: dict[tuple[str, str], tuple[float, float]] = {}
        if ordered:
            for point, record in report.microbursts.items():
                events = sorted(record["events"], key=lambda event: event["end"])
                self.index[point] = (
                    [event["end"] for event in events],
                    [event["end"] + self.window_ms / 1000 for event in events],
                    events,
                )
            for a, b in report.pairs:
                if a not in self.index or not self.index[a][0]:
                    continue
                for per_point in flows.values():
                    if a not in per_point or b not in per_point:
                        continue
                    ts = min(packet.ts for packet in per_point[a])
                    if not math.isfinite(ts):
                        continue
                    low, high = self.bounds.get((a, b), (ts, ts))
                    self.bounds[(a, b)] = (min(low, ts), max(high, ts))
        logger.debug("MicroburstCorrelator: sortie segments encadrés={}", len(self.bounds))

    def _record(self, a: str, b: str, packet: Pkt, ts: float, kind: str, uncertainty_ms: float = 0):
        logger.debug("MicroburstCorrelator._record: entrée type={}", kind)
        bounds = self.bounds.get((a, b))
        uncertainty = uncertainty_ms / 1000
        if bounds is None or not math.isfinite(ts) or not bounds[0] < ts - uncertainty <= ts + uncertainty < bounds[1]:
            logger.debug("MicroburstCorrelator._record: sortie sans encadrement")
            return
        ends, deadlines, events = self.index[a]
        # Tout l'intervalle d'incertitude doit tenir après la fin de l'épisode,
        # dans la fenêtre configurée. Les bornes temporelles sont inclusives.
        first = bisect_left(deadlines, ts + uncertainty)
        last = bisect_right(ends, ts - uncertainty)
        for i in range(first, last):
            event = events[i]
            key = (a, b, i)
            if key not in self.records:
                self.records[key] = {
                    "upstream": a,
                    "downstream": b,
                    "burst_start": event["start"],
                    "burst_end": event["end"],
                    "window_ms": self.window_ms,
                    "losses": 0,
                    "retransmissions": 0,
                    "association": "temporal",
                    "physical_cause_proven": False,
                    "evidence": [],
                }
            record = self.records[key]
            record[kind] += 1
            if len(record["evidence"]) < 10:
                record["evidence"].append(
                    {
                        "kind": kind,
                        "point": packet.point,
                        "frame_number": packet.frame_number,
                        "ts": packet.ts,
                        "upstream_ts": ts,
                        "clock_uncertainty_ms": uncertainty_ms,
                    }
                )
        logger.debug("MicroburstCorrelator._record: sortie épisodes associés={}", last - first)

    def add_loss(self, a: str, b: str, packet: Pkt):
        """Enregistre un paquet déjà déclaré absent au premier point aval."""
        logger.debug("MicroburstCorrelator.add_loss: entrée")
        self._record(a, b, packet, packet.ts, "losses")
        logger.debug("MicroburstCorrelator.add_loss: sortie")

    def add_retransmissions(self, per_point):
        """Ne retient que les copies TCP supplémentaires propres au point aval."""
        logger.debug("MicroburstCorrelator.add_retransmissions: entrée")
        for a, b in self.bounds:
            if a not in per_point or b not in per_point:
                continue
            estimation = self.report.clock_offset_estimate.get((a, b))
            if estimation is None:
                continue
            upstream = [
                p for p in per_point[a] if p.proto == "TCP" and p.payload_hash is not None and not p.is_duplicate
            ]
            downstream = [
                p for p in per_point[b] if p.proto == "TCP" and p.payload_hash is not None and not p.is_duplicate
            ]
            extra = len(downstream) - len(upstream)
            if not upstream or extra <= 0:
                continue
            retransmissions = sorted(
                (
                    p
                    for p in downstream
                    if p.is_retransmission or p.is_fast_retransmission or p.is_spurious_retransmission
                ),
                key=lambda p: p.ts,
            )
            # Inversion exacte du modèle affine B = A + offset(A), avec dérive.
            slope = 1 + estimation.derive_ppm * 1e-6
            if not math.isfinite(slope) or slope <= 0:
                continue
            for packet in retransmissions[-extra:]:
                ts = estimation.t0 + (packet.ts - estimation.t0 - estimation.decalage_a(estimation.t0) / 1000) / slope
                uncertainty = (
                    estimation.ic_decalage_ms + abs(ts - estimation.t0) * estimation.ic_derive_ppm * 1e-3
                ) / slope
                if not math.isfinite(uncertainty) or uncertainty < 0:
                    continue
                self._record(a, b, packet, ts, "retransmissions", uncertainty)
        logger.debug("MicroburstCorrelator.add_retransmissions: sortie")

    def results(self) -> list[dict]:
        """Restitue les associations dans un ordre déterministe."""
        logger.debug("MicroburstCorrelator.results: entrée")
        result = [self.records[key] for key in sorted(self.records)]
        logger.debug("MicroburstCorrelator.results: sortie associations={}", len(result))
        return result


def format_microburst_correlation(record: dict) -> str:
    """Texte commun aux constats et au rapport console, sans surinterprétation."""
    logger.debug("format_microburst_correlation: entrée")
    a, b = record["upstream"], record["downstream"]
    text = (
        f"Après la rafale à {a} terminée à {record['burst_end']:.6f} s : "
        f"{record['losses']} perte(s) inférée(s) et "
        f"{record['retransmissions']} retransmission(s) supplémentaire(s) sur {a} -> {b}, "
        f"dans une fenêtre de {record['window_ms']:g} ms. "
        "Association temporelle établie, congestion possible mais cause physique non prouvée ; "
        "vérifier les files et les pertes de capture."
    )
    logger.debug("format_microburst_correlation: sortie")
    return text


# -- Patterns de correlation ----------------------------------------------
#
# Chaque pattern est un tuple :
#   (rule_ids_a_matcher, rule_ids_a_enrichir, cause, impact)
#
# - `rule_ids_to_match` : ensemble de rule_id dont la CO-OCCURRENCE
#   (au moins un de chaque) sur un meme segment declenche le pattern.
#   Chaque element de l'ensemble est un sous-ensemble alternatif
#   (ex: {"tcp_retransmission_rto", "tcp_retransmission_fast"} = l'un
#   OU l'autre suffit).
# - `rule_ids_to_enrich` : ensemble des rule_id qui doivent recevoir
#   cause/impact si le pattern declenche (pas tous les evenements du
#   segment -- voir docstring de module).

_CorrelationPattern = tuple[
    list[set[str]],  # groupes de rule_id a matcher (au moins 1 de chaque groupe)
    set[str],  # rule_id a enrichir
    str,  # cause
    str,  # impact
]

_PATTERNS: list[_CorrelationPattern] = [
    # 1. Congestion / saturation
    (
        [
            {"loss_per_segment"},
            {"tcp_retransmission_rto", "tcp_retransmission_fast"},
            {"bufferbloat", "saturation"},
        ],
        {"loss_per_segment", "tcp_retransmission_rto", "tcp_retransmission_fast", "bufferbloat", "saturation"},
        "Congestion probable sur ce segment : pertes + retransmissions TCP + "
        "signaux de saturation/bufferbloat co-occurrent",
        "Degradation de bout en bout : latence elevee, taux de perte, debit effondre",
    ),
    # 2. PMTUD / MTU insuffisant
    (
        [
            {"pmtud_blackhole"},
            {"fragmentation_new", "icmp_fragmentation_needed"},
        ],
        {"pmtud_blackhole", "fragmentation_new", "icmp_fragmentation_needed"},
        "MTU insuffisant sur ce segment : PMTUD black hole + fragmentation/ICMP Fragmentation Needed co-occurrent",
        "Connexions TCP qui stagnent sans progresser (segments retransmis sans reduction de MSS)",
    ),
    # 3. Ralentissement applicatif cote serveur
    (
        [
            {"server_processing_dominant"},
            {"http_slow_response", "http_timeout"},
        ],
        {"server_processing_dominant", "http_slow_response", "http_timeout"},
        "Ralentissement applicatif cote serveur : temps de traitement serveur dominant + reponse HTTP lente/timeout",
        "Lenteur percue par l'utilisateur -- la cause est applicative, pas un probleme de transport reseau",
    ),
]


def _match_pattern(
    pattern: _CorrelationPattern,
    rule_ids_by_segment: set[str],
) -> bool:
    """Verifie si un pattern declenche : au moins un rule_id de CHAQUE
    groupe de `rule_ids_to_match` doit etre present dans
    `rule_ids_by_segment`."""
    groups_to_match, _, _, _ = pattern
    logger.debug("_match_pattern: retour all(…)")
    return all(group & rule_ids_by_segment for group in groups_to_match)


def correlate_event_causes(events: list[ExpertEvent]) -> list[ExpertEvent]:
    """Enrichit les `ExpertEvent` passes en argument avec `cause` et
    `impact` en correlant les symptomes co-occurrents sur un meme segment.

    Mute les objets en place (meme liste retournee, ordre preserve,
    `evidence` inchange). Un `ExpertEvent` dont le `rule_id` ne participe
    a aucun pattern declenche garde `cause`/`impact` a `None`.

    See module docstring for the three correlation patterns and the
    segment-only scope (flow-level correlation is future work, Job 8/9).
    """
    # Grouper les rule_id par segment
    rule_ids_by_segment: dict[str, set[str]] = {}
    for ev in events:
        if ev.rule_id:
            rule_ids_by_segment.setdefault(ev.segment, set()).add(ev.rule_id)

    # Pour chaque segment, trouver les patterns qui declenchent
    patterns_by_segment: dict[str, list[_CorrelationPattern]] = {}
    for segment, rule_ids in rule_ids_by_segment.items():
        matched = [p for p in _PATTERNS if _match_pattern(p, rule_ids)]
        if matched:
            patterns_by_segment[segment] = matched

    # Enrichir les ExpertEvent dont le rule_id participe a un pattern
    for ev in events:
        segment_patterns = patterns_by_segment.get(ev.segment)
        if not segment_patterns or not ev.rule_id:
            continue
        for pattern in segment_patterns:
            _, enrich_ids, cause, impact = pattern
            if ev.rule_id in enrich_ids and ev.cause is None:
                ev.cause = cause
                ev.impact = impact
                break  # un seul pattern par evenement (priorite : ordre _PATTERNS)

    logger.debug(
        "correlate_event_causes: {} événement(s), {} segment(s) avec motif, {} cause(s) attribuée(s)",
        len(events),
        len(patterns_by_segment),
        sum(1 for ev in events if ev.cause is not None),
    )
    return events


def correlate_diagnosis_causes(diagnoses: list[Diagnosis]) -> list[Diagnosis]:
    """Derive `Diagnosis.cause` et `Diagnosis.impact` a partir des
    `ExpertEvent` deja enrichis par `correlate_event_causes()`.

    Un `Diagnosis` recoit la cause/impact du PREMIER pattern declenche
    parmi ses evenements (priorite : ordre de `_PATTERNS`). Si aucun
    evenement du diagnostic n'a de cause, le diagnostic garde
    `cause`/`impact` a `None`.
    """
    for diag in diagnoses:
        for ev in diag.events:
            if ev.cause is not None:
                diag.cause = ev.cause
                diag.impact = ev.impact
                break
    logger.debug(
        "correlate_diagnosis_causes: {} diagnostic(s), {} avec cause",
        len(diagnoses),
        sum(1 for d in diagnoses if d.cause is not None),
    )
    return diagnoses
