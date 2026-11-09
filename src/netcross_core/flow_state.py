# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.flow_state -- etat par flux actif, expire par protocole
(issue #1023, sous-issue 4/6 du chantier #995 : pipeline a empreinte
memoire bornee).

Inspiré de la table de connexions de Zeek : chaque flux (conversation
directionnelle, cle ``(proto, src, sport, dst, dport)``) garde un état
compact tant qu'il est actif, et le libère à l'expiration. La mémoire
dépend du nombre de flux ACTIFS, pas du nombre total de paquets ni de
flux vus pendant la capture.

Expiration, deux mécanismes complémentaires :

- au fil de l'eau : un paquet qui arrive plus de ``timeout`` secondes
  après le dernier paquet du même flux au même point ferme l'état
  courant (raison ``expiration``) et ouvre un nouvel enregistrement --
  c'est le silence mesuré au point amont, exactement la règle du
  détecteur batch ``_analyse_idle_timeout`` ;
- en tâche de fond : à chaque paquet, les états silencieux depuis plus
  de ``timeout`` secondes (dernier paquet, tous points confondus) sont
  fermés, pour borner la mémoire même sans trafic sur le flux.

Détecteur incrémental branché sur cet état : la coupure NAT/pare-feu
silencieuse (équivalent flux de ``_analyse_idle_timeout``). Un
enregistrement TCP vu aux deux points d'un segment, fermé par
expiration, dont le réveil n'est jamais revu au point aval, compte une
coupure pour ce segment -- mêmes règles, mêmes compteurs que le mode
batch (un seul silence retenu par flux et par segment, au moins deux
paquets en amont pour mesurer un silence).

Ce qui n'est jamais silencieux :

- ``reopened`` : un nouvel enregistrement ouvert pour une clé déjà vue
  (le flux s'est réveillé après expiration) ;
- ``nat_cutoffs`` : les coupures NAT/pare-feu ci-dessus, par segment.

Mémoire, bornes assumées et documentées :

- les états ouverts : proportionnels aux flux actifs ;
- ``_tcp_prev`` (résumé du dernier enregistrement TCP vu à plusieurs
  points, pour le détecteur de coupure) : proportionnel au nombre de
  conversations TCP multipoints, comme ``_conversations`` de la
  corrélation en flux (#1022) ;
- ``_seen`` (clés récemment fermées, pour compter ``reopened``) : au
  plus ``_SEEN_CAP`` entrées, la plus ancienne est oubliée.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from collections.abc import Iterable

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

# Delais d'expiration par protocole, en secondes d'inactivite (meme
# ordre de grandeur que Zeek : TCP 1 h, UDP/ICMP 1 min). "AUTRE" sert
# pour tout protocole sans delai explicite.
DEFAULT_FLOW_TIMEOUTS: dict[str, float] = {
    "TCP": 3600.0,
    "UDP": 60.0,
    "ICMP": 60.0,
    "AUTRE": 60.0,
}

# Cles recemment fermees memorisees pour compter les reouvertures.
_SEEN_CAP = 65536


def parse_flow_timeouts(spec: str | None) -> dict[str, float]:
    """Analyse ``"TCP=3600,UDP=30"`` en délais par protocole.

    Sans spécification (None) : les défauts. Les protocoles inconnus et
    les délais non positifs sont refusés explicitement.
    """
    logger.debug("parse_flow_timeouts: entrée (spec={!r})", spec)
    if spec is None:
        logger.debug("parse_flow_timeouts: retour défauts")
        return dict(DEFAULT_FLOW_TIMEOUTS)
    delais: dict[str, float] = {}
    for morceau in spec.split(","):
        morceau = morceau.strip()
        if not morceau:
            continue
        if "=" not in morceau:
            logger.debug("parse_flow_timeouts: morceau sans '=' -> ValueError")
            raise ValueError(f"délai de flux invalide : {morceau!r} (attendu « PROTO=SECONDES »)")
        proto, _, valeur = morceau.partition("=")
        proto = proto.strip().upper()
        try:
            secondes = float(valeur)
        except ValueError as exc:
            logger.debug("parse_flow_timeouts: valeur non numérique -> ValueError")
            raise ValueError(f"délai de flux invalide : {morceau!r} (valeur non numérique)") from exc
        if proto not in DEFAULT_FLOW_TIMEOUTS:
            logger.debug("parse_flow_timeouts: protocole inconnu -> ValueError")
            raise ValueError(
                f"protocole inconnu dans --flow-timeouts : {proto!r} "
                f"(choisir parmi {', '.join(sorted(DEFAULT_FLOW_TIMEOUTS))})"
            )
        if secondes <= 0:
            logger.debug("parse_flow_timeouts: délai non positif -> ValueError")
            raise ValueError(f"délai de flux invalide : {morceau!r} (le délai doit être strictement positif)")
        delais[proto] = secondes
    if not delais:
        logger.debug("parse_flow_timeouts: spécification vide -> ValueError")
        raise ValueError("--flow-timeouts vide : au moins un délai « PROTO=SECONDES » est requis")
    logger.debug("parse_flow_timeouts: retour {} délai(s)", len(delais))
    return delais


class _EtatFlux:
    """État ouvert d'un flux : compteurs compacts, sans garder les paquets."""

    __slots__ = ("last_ts", "last_ts_point", "octets", "packets", "start_ts")

    def __init__(self, start_ts: float) -> None:
        logger.debug("_EtatFlux.__init__: entrée")
        self.start_ts = start_ts
        self.last_ts = start_ts
        self.last_ts_point: dict[str, float] = {}
        self.packets: Counter = Counter()
        self.octets: Counter = Counter()
        logger.debug("_EtatFlux.__init__: fin")


class _ResumeTcp:
    """Résumé du dernier enregistrement TCP d'une clé (pour le détecteur
    de coupure NAT) : points vus, paquets par point, raison de fermeture."""

    __slots__ = ("packets", "points", "raison")

    def __init__(self, points: frozenset[str], packets: dict[str, int], raison: str) -> None:
        logger.debug("_ResumeTcp.__init__: entrée ({} point(s))", len(points))
        self.points = points
        self.packets = packets
        self.raison = raison
        logger.debug("_ResumeTcp.__init__: fin")


class FlowTable:
    """Table des flux actifs : ``feed()`` paquet par paquet, puis ``finish()``.

    La mémoire est bornée par le nombre de flux actifs : un état fermé ne
    laisse que des compteurs (et, pour TCP, le résumé compact du dernier
    enregistrement multipoint).
    """

    def __init__(
        self,
        points: list[str],
        timeouts: dict[str, float] | None = None,
    ) -> None:
        logger.debug("FlowTable.__init__: entrée ({} point(s))", len(points))
        if not points:
            logger.debug("FlowTable.__init__: sans points -> ValueError")
            raise ValueError("la table de flux exige au moins un point de capture")
        self.points = list(points)
        self.pairs = list(zip(self.points, self.points[1:], strict=False))
        self.timeouts = dict(timeouts) if timeouts else dict(DEFAULT_FLOW_TIMEOUTS)
        self._open: OrderedDict[tuple, _EtatFlux] = OrderedDict()
        self._now = float("-inf")
        # compteurs
        self.total_records = 0
        self.expired = 0
        self.closed_at_end = 0
        self.peak_active = 0
        self.reopened: Counter = Counter()  # par protocole
        self.records_by_proto: Counter = Counter()
        self.nat_cutoffs: Counter = Counter()  # (a, b) -> coupures
        self.cutoff_examples: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.examples: list[str] = []
        # memoires bornees, voir docstring du module
        self._tcp_prev: dict[tuple, _ResumeTcp] = {}
        self._cutoff_seen: set[tuple[tuple, tuple[str, str]]] = set()
        self._seen: OrderedDict[tuple, None] = OrderedDict()
        self._finished = False
        logger.debug("FlowTable.__init__: fin")

    # -- alimentation ----------------------------------------------------------------

    def feed(self, pk: Pkt) -> None:
        """Ajoute un paquet (fusion k voies : ordre de temps croissant)."""
        logger.debug("FlowTable.feed: entrée")
        if pk.proto in ("ARP", "STP"):
            logger.debug("FlowTable.feed: ARP/STP hors table de flux -> retour")
            return
        self._now = max(self._now, pk.ts)
        self._expire()
        key = (pk.proto, pk.src, pk.sport, pk.dst, pk.dport)
        etat = self._open.get(key)
        timeout = self.timeouts.get(pk.proto, self.timeouts.get("AUTRE", 60.0))
        precedent_ts = etat.last_ts_point.get(pk.point) if etat is not None else None
        if precedent_ts is not None and pk.ts - precedent_ts >= timeout:
            # silence au point courant au moins egal au delai : l'etat
            # precedent se ferme (raison expiration), un nouvel
            # enregistrement s'ouvre -- meme regle que le plus grand
            # silence du detecteur batch.
            logger.debug("FlowTable.feed: silence >= délai -> fermeture puis nouvel état")
            self._close(key, etat, "expiration")
            etat = None
        if etat is None:
            etat = _EtatFlux(pk.ts)
            self._open[key] = etat
            self.peak_active = max(self.peak_active, len(self._open))
            if key in self._seen:
                self.reopened[pk.proto] += 1
        else:
            self._open.move_to_end(key)
        etat.last_ts = max(etat.last_ts, pk.ts)
        etat.last_ts_point[pk.point] = pk.ts
        etat.packets[pk.point] += 1
        etat.octets[pk.point] += pk.length
        logger.debug("FlowTable.feed: retour None")

    def _expire(self) -> None:
        """Ferme les états silencieux depuis plus de leur délai (tous
        points confondus), pour borner la mémoire sans trafic sur le flux.

        Les états sont ordonnés par dernière activité (``move_to_end`` à
        chaque mise à jour) : on s'arrête au premier état encore actif.
        Un paquet légèrement désordonné peut retarder une expiration, il
        ne l'empêche jamais -- la fermeture au fil de l'eau (``feed``)
        reste le mécanisme d'équivalence avec le détecteur batch."""
        logger.debug("FlowTable._expire: entrée")
        while self._open:
            key, etat = next(iter(self._open.items()))
            timeout = self.timeouts.get(key[0], self.timeouts.get("AUTRE", 60.0))
            if self._now - etat.last_ts < timeout:
                break
            del self._open[key]
            self._close(key, etat, "expiration")
        logger.debug("FlowTable._expire: retour None")

    def _close(self, key: tuple, etat: _EtatFlux, raison: str) -> None:
        """Compte la fermeture d'un enregistrement ; branche le détecteur
        incrémental de coupure NAT sur le résumé TCP précédent."""
        logger.debug("FlowTable._close: entrée (raison={})", raison)
        self.total_records += 1
        if raison == "expiration":
            self.expired += 1
        else:
            self.closed_at_end += 1
        self.records_by_proto[key[0]] += 1
        points = frozenset(etat.last_ts_point)
        if len(self.examples) < 5:
            duree = etat.last_ts - etat.start_ts
            self.examples.append(
                f"{key[1]}:{key[2]} -> {key[3]}:{key[4]} ({key[0]}, {sorted(points)}, "
                f"{sum(etat.packets.values())} paquet(s), {duree:.3f} s, fermeture : {raison})"
            )
        if key[0] == "TCP":
            precedent = self._tcp_prev.get(key)
            if precedent is not None and precedent.raison == "expiration" and len(precedent.points) >= 2:
                for a, b in self.pairs:
                    if (
                        a in precedent.points
                        and b in precedent.points
                        and b not in points
                        and precedent.packets.get(a, 0) >= 2
                        and (key, (a, b)) not in self._cutoff_seen
                    ):
                        self._cutoff_seen.add((key, (a, b)))
                        self.nat_cutoffs[(a, b)] += 1
                        if len(self.cutoff_examples[(a, b)]) < 5:
                            self.cutoff_examples[(a, b)].append(
                                f"{key[1]}:{key[2]} -> {key[3]}:{key[4]} (réveil en {a} "
                                f"jamais revu en {b} après expiration)"
                            )
            self._tcp_prev[key] = _ResumeTcp(points, dict(etat.packets), raison)
        self._seen[key] = None
        if len(self._seen) > _SEEN_CAP:
            self._seen.popitem(last=False)
        logger.debug("FlowTable._close: retour None")

    def finish(self) -> None:
        """Ferme les états restants (raison ``fin``) ; idempotent."""
        logger.debug("FlowTable.finish: entrée")
        if self._finished:
            logger.debug("FlowTable.finish: déjà terminé -> retour")
            return
        while self._open:
            key, etat = self._open.popitem(last=False)
            self._close(key, etat, "fin")
        self._finished = True
        logger.debug(
            "FlowTable.finish: retour ({} enregistrement(s), {} expiration(s), {} coupure(s) NAT)",
            self.total_records,
            self.expired,
            sum(self.nat_cutoffs.values()),
        )

    # -- restitution -----------------------------------------------------------------

    def to_dict(self) -> dict:
        """Forme JSON (clé ``flow_state`` de la section ``streaming``)."""
        logger.debug("FlowTable.to_dict: entrée")
        doc = {
            "timeouts": dict(self.timeouts),
            "records": self.total_records,
            "expired": self.expired,
            "closed_at_end": self.closed_at_end,
            "peak_active": self.peak_active,
            "records_by_proto": dict(self.records_by_proto),
            "reopened": dict(self.reopened),
            "examples": list(self.examples),
            "nat_cutoffs": {f"{a} -> {b}": n for (a, b), n in sorted(self.nat_cutoffs.items())},
            "cutoff_examples": {f"{a} -> {b}": list(v) for (a, b), v in sorted(self.cutoff_examples.items())},
        }
        logger.debug("FlowTable.to_dict: retour dict")
        return doc

    def summary_lines(self) -> list[str]:
        """Lignes du rapport texte ; les coupures NAT y sont toujours explicites."""
        logger.debug("FlowTable.summary_lines: entrée")
        lignes = [
            f"État par flux (délais {', '.join(f'{p}={t:g} s' for p, t in sorted(self.timeouts.items()))}) : "
            f"{self.total_records} enregistrement(s), au plus {self.peak_active} actif(s) à la fois"
        ]
        if self.expired:
            lignes.append(
                f"  {self.expired} expiration(s) d'inactivité, {self.closed_at_end} fermeture(s) en fin de capture"
            )
        if sum(self.reopened.values()):
            lignes.append(
                "  "
                + ", ".join(f"{p} : {n}" for p, n in sorted(self.reopened.items()))
                + " réouverture(s) après expiration"
            )
        for (a, b), n in sorted(self.nat_cutoffs.items()):
            lignes.append(
                f"  COUPURE NAT/PARE-FEU ({a} -> {b}) : {n} flux réveillé(s) en {a} jamais revu(s) en {b} "
                "(équivalent flux du détecteur d'expiration silencieuse)"
            )
        logger.debug("FlowTable.summary_lines: retour {} ligne(s)", len(lignes))
        return lignes


def run_flow_table(
    sources: Iterable[Iterable[Pkt]],
    points: list[str],
    timeouts: dict[str, float] | None = None,
) -> FlowTable:
    """Alimente une table de flux depuis des suites par point fusionnées
    en k voies (``streaming.merge_points``), puis la ferme."""
    logger.debug("run_flow_table: entrée ({} point(s))", len(points))
    from netcross_core.streaming import merge_points

    table = FlowTable(points, timeouts=timeouts)
    for pk in merge_points(sources):
        table.feed(pk)
    table.finish()
    logger.debug("run_flow_table: retour table fermée")
    return table
