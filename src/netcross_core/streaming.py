# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.streaming -- correlation des points en flux, par fenetre
glissante (issue #1022, sous-issue 3/6 du chantier #995).

``correlate()`` garde en memoire tous les paquets de tous les points avant de
les grouper par cle. Ici, les points sont lus comme des suites triees par
temps et fusionnees en k voies (``heapq.merge``). Un groupe (une cle
``correlate.flow_key()``, donc en pratique un paquet vu a plusieurs points)
reste ouvert tant que le temps courant n'a pas depasse son dernier paquet de
plus de ``window_seconds`` ; il est alors ferme et ne laisse que des
compteurs. La memoire depend du nombre de groupes ouverts dans la fenetre,
pas du nombre total de paquets.

Ce qui n'est jamais silencieux :

- paquet desordonne : un paquet plus ancien que le temps courant reste
  rattache a son groupe tant que ce dernier est ouvert (compte dans
  ``out_of_order``) ;
- paquet tardif : un paquet dont le groupe a deja ete ferme par la fenetre
  (retransmission apres un long delai, transit plus long que la fenetre)
  ouvre un second groupe ; il est compte dans ``late_packets`` et les
  compteurs peuvent alors differer du mode actuel ;
- groupes ouverts en fin de capture : fermes a la fin, comptes dans
  ``open_at_end`` (un point manquant peut venir de la fin de capture).

Avec ``points_order``, une perte n'est comptee qu'au premier point manquant
(meme regle que ``analysis.analyse``). La distinction perte / hors chemin
(#352) depend de tout le trafic d'un couple d'hotes : elle est differee a la
fin, avec une memoire proportionnelle au nombre de couples d'hotes.
"""

from __future__ import annotations

import heapq
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

from netcross_core.analysis import _conversation_key
from netcross_core.correlate import flow_key
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

DEFAULT_WINDOW_SECONDS = 2.0


@dataclass
class StreamingResult:
    """Compteurs de la correlation en flux (memes noms que ``Report``)."""

    window_seconds: float
    points: list[str]
    packet_count: Counter = field(default_factory=Counter)
    seen_count: Counter = field(default_factory=Counter)
    retrans: Counter = field(default_factory=Counter)
    dup_ack: Counter = field(default_factory=Counter)
    loss_count: Counter = field(default_factory=Counter)
    off_path_count: Counter = field(default_factory=Counter)
    latency_sum_ms: dict = field(default_factory=lambda: defaultdict(float))
    latency_n: Counter = field(default_factory=Counter)
    groups: int = 0
    out_of_order: int = 0
    late_packets: int = 0
    open_at_end: int = 0
    peak_open_groups: int = 0

    @property
    def truncated(self) -> bool:
        """Vrai si la fenetre a coupe au moins un groupe (paquet tardif)."""
        logger.debug("StreamingResult.truncated: retour bool")
        return self.late_packets > 0

    def mean_latency_ms(self, a: str, b: str) -> float | None:
        """Latence moyenne du segment ``a -> b`` (None si aucun appariement)."""
        logger.debug("StreamingResult.mean_latency_ms: entrée ({} -> {})", a, b)
        n = self.latency_n.get((a, b), 0)
        if not n:
            logger.debug("StreamingResult.mean_latency_ms: si aucun appariement -> retour None")
            return None
        logger.debug("StreamingResult.mean_latency_ms: retour moyenne")
        return self.latency_sum_ms[(a, b)] / n

    def to_dict(self) -> dict:
        """Forme JSON (cle ``streaming`` de ``--json-report``)."""
        logger.debug("StreamingResult.to_dict: entrée")
        pairs = list(zip(self.points, self.points[1:], strict=False))
        doc = {
            "window_seconds": self.window_seconds,
            "groups": self.groups,
            "peak_open_groups": self.peak_open_groups,
            "out_of_order": self.out_of_order,
            "late_packets": self.late_packets,
            "open_at_end": self.open_at_end,
            "truncated": self.truncated,
            "by_point": {
                p: {
                    "packets": self.packet_count[p],
                    "flows": self.seen_count[p],
                    "retrans": self.retrans[p],
                    "dup_ack": self.dup_ack[p],
                    "lost_flows": self.loss_count[p],
                    "off_path": self.off_path_count[p],
                }
                for p in self.points
            },
            "by_segment": {f"{a} -> {b}": {"mean_latency_ms": self.mean_latency_ms(a, b)} for a, b in pairs},
        }
        logger.debug("StreamingResult.to_dict: retour dict")
        return doc

    def summary_lines(self) -> list[str]:
        """Lignes du rapport texte ; la troncature y est toujours explicite."""
        logger.debug("StreamingResult.summary_lines: entrée")
        lignes = [
            f"Correlation en flux (fenetre {self.window_seconds:g} s) : {self.groups} groupe(s), "
            f"au plus {self.peak_open_groups} ouvert(s) a la fois",
        ]
        lignes.extend(
            f"  {p} : {self.packet_count[p]} paquet(s), {self.seen_count[p]} flux, "
            f"{self.loss_count[p]} perdu(s), {self.retrans[p]} retransmission(s)"
            for p in self.points
        )
        if self.out_of_order:
            lignes.append(f"  {self.out_of_order} paquet(s) desordonne(s) rattache(s) dans la fenetre")
        if self.truncated:
            lignes.append(
                f"  TRONCATURE : {self.late_packets} paquet(s) arrive(s) apres la fermeture de leur groupe "
                "par la fenetre ; compteurs approches, elargir --streaming-window"
            )
        if self.open_at_end:
            lignes.append(f"  {self.open_at_end} groupe(s) encore ouvert(s) en fin de capture, fermes a la fin")
        logger.debug("StreamingResult.summary_lines: retour {} ligne(s)", len(lignes))
        return lignes


def merge_points(sources: Iterable[Iterable[Pkt]]) -> Iterator[Pkt]:
    """Fusion k voies de suites de paquets (une par point) triees par temps.

    Ne lit qu'un paquet d'avance par point. Une suite localement desordonnee
    est acceptee : la sortie suit alors l'ordre d'arrivee de la fusion, et la
    fenetre de ``StreamingCorrelator`` absorbe le desordre.
    """
    logger.debug("merge_points: retour iterateur fusionne")
    return heapq.merge(*sources, key=lambda pk: pk.ts)


class _Group:
    """Groupe ouvert : compteurs par point, sans garder les paquets."""

    __slots__ = ("first", "last_ts", "n_ctrl", "n_data")

    def __init__(self) -> None:
        logger.debug("_Group.__init__: entrée")
        self.first: dict[str, Pkt] = {}
        self.n_data: Counter = Counter()
        self.n_ctrl: Counter = Counter()
        self.last_ts = float("-inf")
        logger.debug("_Group.__init__: fin")


class StreamingCorrelator:
    """Correlation incrementale : ``feed()`` paquet par paquet, puis ``finish()``."""

    def __init__(
        self,
        points: list[str],
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        points_order: bool = True,
        nat_tolerant: bool = False,
        nat_window_ms: int = 200,
        exclude_duplicates: bool = False,
    ) -> None:
        logger.debug("StreamingCorrelator.__init__: entrée (fenetre={} s, {} point(s))", window_seconds, len(points))
        if window_seconds <= 0:
            logger.debug("StreamingCorrelator.__init__: si fenetre <= 0 -> ValueError")
            raise ValueError("la fenetre doit etre strictement positive")
        self.result = StreamingResult(window_seconds=window_seconds, points=list(points))
        self._points_order = points_order
        self._nat_tolerant = nat_tolerant
        self._nat_window_ms = nat_window_ms
        self._exclude_duplicates = exclude_duplicates
        self._open: OrderedDict[tuple, _Group] = OrderedDict()
        self._closed: OrderedDict[tuple, float] = OrderedDict()
        self._now = float("-inf")
        self._conversations: dict[tuple, set[str]] = defaultdict(set)
        self._pending: Counter = Counter()  # (conversation, point, precedent vu) -> a trancher
        self._finished = False
        logger.debug("StreamingCorrelator.__init__: fin")

    def feed(self, pk: Pkt) -> None:
        """Ajoute un paquet (dans l'ordre de ``merge_points``)."""
        logger.debug("StreamingCorrelator.feed: entrée")
        res = self.result
        if self._exclude_duplicates and pk.is_duplicate:
            logger.debug("StreamingCorrelator.feed: doublon exclu -> retour")
            return
        res.packet_count[pk.point] += 1
        if pk.proto in ("ARP", "STP"):
            logger.debug("StreamingCorrelator.feed: ARP/STP hors correlation -> retour")
            return
        if pk.ts < self._now:
            res.out_of_order += 1
        else:
            self._now = pk.ts
            self._expire()
        key = flow_key(pk, self._nat_tolerant, self._nat_window_ms)
        group = self._open.get(key)
        if group is None:
            if key in self._closed:
                res.late_packets += 1
            group = _Group()
            self._open[key] = group
            res.peak_open_groups = max(res.peak_open_groups, len(self._open))
        else:
            self._open.move_to_end(key)
        group.last_ts = max(group.last_ts, pk.ts)
        premier = group.first.get(pk.point)
        if premier is None or pk.ts < premier.ts:
            group.first[pk.point] = pk
        if pk.payload_hash is not None:
            group.n_data[pk.point] += 1
        else:
            group.n_ctrl[pk.point] += 1
        logger.debug("StreamingCorrelator.feed: retour None")

    def _expire(self) -> None:
        """Ferme les groupes sortis de la fenetre ; oublie les cles fermees
        depuis plus de deux fenetres (detection des paquets tardifs)."""
        logger.debug("StreamingCorrelator._expire: entrée")
        limite = self._now - self.result.window_seconds
        while self._open:
            key, group = next(iter(self._open.items()))
            if group.last_ts >= limite:
                break
            del self._open[key]
            self._close(key, group)
            self._closed[key] = self._now
        oubli = self._now - 2 * self.result.window_seconds
        while self._closed and next(iter(self._closed.values())) < oubli:
            self._closed.popitem(last=False)
        logger.debug("StreamingCorrelator._expire: retour None")

    def _close(self, key: tuple, group: _Group) -> None:
        """Compteurs d'un groupe ferme (memes regles que ``analyse``)."""
        logger.debug("StreamingCorrelator._close: entrée")
        res = self.result
        res.groups += 1
        points = res.points
        present = [p for p in points if p in group.first]
        is_tcp = key[0] == "TCP"
        conversation = _conversation_key(key)
        if conversation is not None:
            self._conversations[conversation].update(group.first)
        for p in present:
            res.seen_count[p] += 1
            if is_tcp:
                res.retrans[p] += max(group.n_data[p] - 1, 0)
                res.dup_ack[p] += max(group.n_ctrl[p] - 1, 0)
        if self._points_order and present:
            premier = points.index(present[0])
            for idx in range(premier + 1, len(points)):
                p = points[idx]
                if p in group.first:
                    continue
                precedent_vu = points[idx - 1] in group.first
                if conversation is not None:
                    self._pending[(conversation, p, precedent_vu)] += 1
                elif precedent_vu:
                    res.loss_count[p] += 1
        for a, b in zip(points, points[1:], strict=False):
            if a in group.first and b in group.first:
                res.latency_sum_ms[(a, b)] += (group.first[b].ts - group.first[a].ts) * 1000.0
                res.latency_n[(a, b)] += 1
        logger.debug("StreamingCorrelator._close: retour None")

    def finish(self) -> StreamingResult:
        """Ferme les groupes restants et tranche perte / hors chemin."""
        logger.debug("StreamingCorrelator.finish: entrée")
        res = self.result
        if self._finished:
            logger.debug("StreamingCorrelator.finish: si deja termine -> retour resultat")
            return res
        res.open_at_end = len(self._open)
        while self._open:
            key, group = self._open.popitem(last=False)
            self._close(key, group)
        for (conversation, p, precedent_vu), n in self._pending.items():
            if p not in self._conversations[conversation]:
                res.off_path_count[p] += n
            elif precedent_vu:
                res.loss_count[p] += n
        self._pending.clear()
        self._closed.clear()
        self._finished = True
        logger.debug("StreamingCorrelator.finish: retour ({} groupe(s), {} tardif(s))", res.groups, res.late_packets)
        return res


def correlate_streaming(
    sources: Mapping[str, Iterable[Pkt]],
    points_order: list[str] | None = None,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    nat_tolerant: bool = False,
    nat_window_ms: int = 200,
    exclude_duplicates: bool = False,
) -> StreamingResult:
    """Correle en flux des suites de paquets par point (``{point: iterable}``).

    ``points_order`` : ordre du chemin (pertes au premier point manquant) ;
    sans lui, les points sont tries par nom et aucune perte n'est comptee.
    """
    logger.debug("correlate_streaming: entrée ({} point(s))", len(sources))
    points = list(points_order) if points_order else sorted(sources)
    correlator = StreamingCorrelator(
        points,
        window_seconds=window_seconds,
        points_order=bool(points_order),
        nat_tolerant=nat_tolerant,
        nat_window_ms=nat_window_ms,
        exclude_duplicates=exclude_duplicates,
    )
    for pk in merge_points(sources.values()):
        correlator.feed(pk)
    resultat = correlator.finish()
    logger.debug("correlate_streaming: retour resultat")
    return resultat


def sources_by_point(all_packets: Iterable[Pkt]) -> dict[str, list[Pkt]]:
    """Regroupe une liste deja chargee par point, dans l'ordre de lecture
    (passerelle pour la CLI tant que la lecture tshark n'est pas en flux)."""
    logger.debug("sources_by_point: entrée")
    sources: dict[str, list[Pkt]] = defaultdict(list)
    for pk in all_packets:
        sources[pk.point].append(pk)
    logger.debug("sources_by_point: retour {} point(s)", len(sources))
    return dict(sources)
