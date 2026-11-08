# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.tshark_stats.models -- modele commun des statistiques tshark
(Job 19 / issue #20, section 6.19 de features-backlog.md).

Les sorties ``tshark -z`` sont des statistiques AGREGEES (compteurs par
conversation / endpoint / protocole / intervalle temporel), sans paquet ni
point de capture complet ni evidence -- elles ne se confondent donc pas
avec les objets ``Flow`` / ``Conversation`` / ``ExpertEvent`` du moteur
(per-paquet). Ce module definit le modele commun dedie.

Toutes les records sont des dataclasses gelees (``slots=True``) ; chaque
record porte un champ ``raw_fields`` pour absorber les variations de format
entre versions de tshark sans perte d'information.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class MetricPoint:
    """Un point d'une serie temporelle (ex: intervalle I/O)."""

    start: float | None
    end: float | None
    #: Valeurs nommees de l'intervalle (frames, bytes, bits/s...).
    values: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MetricSeries:
    """Serie temporelle normalisee (ex: ``tshark -z io,stat``)."""

    name: str
    points: tuple[MetricPoint, ...] = ()
    #: Etiquettes descriptives (filtre, unite, protocole...).
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _BaseStat:
    """Champ commun a toutes les stats : trace brute des colonnes inconnues."""

    raw_fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ConversationStat(_BaseStat):
    """Une conversation agregee (``tshark -z conv,<proto>``)."""

    protocol: str = ""
    endpoint_a: str = ""
    endpoint_b: str = ""
    packets_total: int | None = None
    bytes_total: int | None = None
    packets_ab: int | None = None
    bytes_ab: int | None = None
    packets_ba: int | None = None
    bytes_ba: int | None = None
    rel_start: float | None = None
    duration: float | None = None
    bits_per_second: float | None = None


@dataclass(frozen=True, slots=True)
class EndpointStat(_BaseStat):
    """Un endpoint agrege (``tshark -z endpoints,<proto>``)."""

    protocol: str = ""
    address: str = ""
    packets_total: int | None = None
    bytes_total: int | None = None
    packets_out: int | None = None
    bytes_out: int | None = None
    packets_in: int | None = None
    bytes_in: int | None = None
    bits_per_second: float | None = None


@dataclass(frozen=True, slots=True)
class ProtocolHierarchyStat(_BaseStat):
    """Un noeud de la hierarchie protocolaire (``tshark -z io,phs``)."""

    protocol: str = ""
    depth: int = 0
    frame_count: int | None = None
    byte_count: int | None = None
    percent_packets: float | None = None
    percent_bytes: float | None = None


@dataclass(frozen=True, slots=True)
class ApplicationStat(_BaseStat):
    """Statistique applicative generique (HTTP, DNS...) -- ``tshark -z``.

    Les sorties ``http,stat`` / ``dns,tree`` et similaires varient fort
    entre versions ; ce record normalise les metriques nommees sans
    pretendre couvrir toutes les variantes. ``labels`` decrit la categorie
    (methode HTTP, code de retour, type de requete DNS...).
    """

    application: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResponseTimeStat(_BaseStat):
    """Temps de reponse applicatif (``tshark -z http,rtt`` etc.)."""

    application: str = ""
    count: int | None = None
    min_ms: float | None = None
    max_ms: float | None = None
    mean_ms: float | None = None
    median_ms: float | None = None
