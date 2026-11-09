# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.seconde_passe -- seconde passe ciblée du mode en flux
(issue #1025, sous-issue 6/6 du chantier #995 : pipeline en flux à
empreinte mémoire bornée).

L'inventaire des détecteurs (#1020) classe ``infer_topology`` en
« seconde passe » : sa décision dépend d'agrégats couvrant la capture
entière (flux vus par paire de points, votes de TTL entre premiers
paquets). Ce module calcule ces agrégats AU FIL DE L'EAU -- un enregistrement
compact par (flux, point) : l'horodatage et le TTL du premier paquet --
puis déduit la topologie à la fermeture, en réutilisant exactement la
déduction du mode batch (``_stats_topologie`` / ``_deduire_topologie`` de
``netcross_core.analysis``) : mêmes agrégats, même déduction, mêmes
arêtes/ambiguïtés/isolés/branchements/fusions.

Mémoire : proportionnelle au nombre de flux vus (un enregistrement par
(flux, point)), pas au nombre de paquets -- et, au-delà du seuil de
débordement, déportée sur disque (SQLite temporaire, #1024, module
``netcross_core.spill``).

Restent hors de cette première passe ciblée (voir l'issue #1025) : les
deux autres détecteurs classés seconde passe (``clock_sync``,
``detect_microbursts``) et l'équivalence complète du rapport.
"""

from __future__ import annotations

import json
from itertools import combinations

from netcross_core.analysis import _deduire_topologie
from netcross_core.correlate import flow_key
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt
from netcross_core.spill import SpillDict, cle_json

logger = get_logger(__name__)

# Défaut : sans débordement (tout en RAM), comme FlowTable.
DEFAUT_SPILL_SEUIL = 0


class SecondePasse:
    """Seconde passe ciblée en flux : topologie déduite d'agrégats bornés.

    ``feed()`` paquet par paquet (fusion k voies : ordre de temps
    croissant), puis ``finish()``. Les résultats bruts (tuples, comme le
    mode batch) sont exposés en attributs, ``to_dict()`` les sérialise
    pour la clé ``streaming.seconde_passe`` du rapport JSON.
    """

    def __init__(
        self,
        points: list[str],
        nat_tolerant: bool = False,
        nat_window_ms: float = 200.0,
        exclude_duplicates: bool = False,
        spill_seuil: int | None = None,
    ) -> None:
        logger.debug("SecondePasse.__init__: entrée ({} point(s))", len(points))
        self._points = list(points)
        self._nat_tolerant = nat_tolerant
        self._nat_window_ms = nat_window_ms
        self._exclude_duplicates = exclude_duplicates
        self.spill_seuil = max(0, int(spill_seuil)) if spill_seuil else DEFAUT_SPILL_SEUIL
        # un enregistrement par (flux, point) : premier paquet (ts, ttl) --
        # exactement ce que compare _stats_topologie (min de ts par point).
        self._premiers: SpillDict[tuple, dict] = SpillDict(
            self.spill_seuil,
            cle_json,
            _dump_premiers,
            _load_premiers,
            nom="seconde_passe_premiers",
        )
        self._finished = False
        # résultats (finish)
        self.topology_edges: list = []
        self.topology_ambiguous: list = []
        self.topology_isolated: list = []
        self.topology_branch_points: list = []
        self.topology_merge_points: list = []
        logger.debug("SecondePasse.__init__: fin")

    def feed(self, pk: Pkt) -> None:
        """Agrège un paquet : premier (ts, ttl) du flux au point courant."""
        logger.debug("SecondePasse.feed: entrée")
        if pk.proto in ("ARP", "STP"):
            # mêmes exclusions que correlate() : ni l'un ni l'autre n'est
            # relayé par un routeur, les compter fausserait le
            # recouvrement de flux (voir correlate.py).
            logger.debug("SecondePasse.feed: ARP/STP ignoré -> retour")
            return
        if self._exclude_duplicates and pk.is_duplicate:
            logger.debug("SecondePasse.feed: doublon exclu -> retour")
            return
        cle = flow_key(pk, self._nat_tolerant, self._nat_window_ms)
        vu = self._premiers.get(cle)
        if vu is None:
            vu = {}
            self._premiers.put(cle, vu)
        precedent = vu.get(pk.point)
        if precedent is None or pk.ts < precedent[0]:
            vu[pk.point] = [pk.ts, pk.ttl]
        logger.debug("SecondePasse.feed: retour None")

    def finish(self) -> None:
        """Déduit la topologie des agrégats ; idempotent.

        Même boucle d'agrégation que ``_stats_topologie`` (le min de ts
        par (flux, point) a été collecté au fil de l'eau), puis la même
        déduction ``_deduire_topologie`` que le mode batch.
        """
        logger.debug("SecondePasse.finish: entrée")
        if self._finished:
            logger.debug("SecondePasse.finish: déjà terminé -> retour")
            return
        total_flows_at: dict[str, int] = {}
        pair_stats: dict = {}
        for vu in self._premiers.values():
            pts_here = list(vu.keys())
            for p in pts_here:
                total_flows_at[p] = total_flows_at.get(p, 0) + 1
            for x, y in combinations(sorted(pts_here), 2):
                stats = pair_stats.setdefault(
                    (x, y),
                    {"common": 0, "x_gt_y": 0, "y_gt_x": 0, "eq": 0, "compared": 0},
                )
                stats["common"] += 1
                _ts_x, ttl_x = vu[x]
                _ts_y, ttl_y = vu[y]
                if ttl_x is not None and ttl_y is not None:
                    stats["compared"] += 1
                    if ttl_x > ttl_y:
                        stats["x_gt_y"] += 1
                    elif ttl_y > ttl_x:
                        stats["y_gt_x"] += 1
                    else:
                        stats["eq"] += 1
        (
            self.topology_edges,
            self.topology_ambiguous,
            self.topology_isolated,
            self.topology_branch_points,
            self.topology_merge_points,
        ) = _deduire_topologie(total_flows_at, pair_stats, self._points)
        self._finished = True
        self._premiers.close()
        logger.debug(
            "SecondePasse.finish: retour ({} arête(s))",
            len(self.topology_edges),
        )

    def to_dict(self) -> dict:
        """Forme JSON (clé ``seconde_passe`` de la section ``streaming``).

        Les listes de tuples du mode batch deviennent des listes de listes,
        comme le reste du rapport JSON.
        """
        logger.debug("SecondePasse.to_dict: entrée")
        doc = {
            "topology_edges": [[u, d, info] for u, d, info in self.topology_edges],
            "topology_ambiguous": [list(a) for a in self.topology_ambiguous],
            "topology_isolated": list(self.topology_isolated),
            "topology_branch_points": list(self.topology_branch_points),
            "topology_merge_points": list(self.topology_merge_points),
        }
        logger.debug("SecondePasse.to_dict: retour dict")
        return doc


def _dump_premiers(vu: dict) -> str:
    """Sérialise les premiers paquets d'un flux : {point: [ts, ttl]}."""
    logger.debug("_dump_premiers: entrée ({} point(s))", len(vu))
    texte = json.dumps(vu, separators=(",", ":"), ensure_ascii=False)
    logger.debug("_dump_premiers: retour")
    return texte


def _load_premiers(texte: str) -> dict:
    """Reconstruit les premiers paquets sérialisés par ``_dump_premiers``."""
    logger.debug("_load_premiers: entrée")
    vu = json.loads(texte)
    logger.debug("_load_premiers: retour ({} point(s))", len(vu))
    return vu


def run_seconde_passe(
    sources,
    points: list[str],
    nat_tolerant: bool = False,
    nat_window_ms: float = 200.0,
    exclude_duplicates: bool = False,
    spill_seuil: int | None = None,
) -> SecondePasse:
    """Alimente la seconde passe depuis des suites par point (le dictionnaire
    de ``streaming.sources_by_point``, ou directement ses valeurs) fusionnées
    en k voies (``streaming.merge_points``), puis la ferme."""
    logger.debug("run_seconde_passe: entrée ({} point(s))", len(points))
    from netcross_core.streaming import merge_points

    passe = SecondePasse(
        points,
        nat_tolerant=nat_tolerant,
        nat_window_ms=nat_window_ms,
        exclude_duplicates=exclude_duplicates,
        spill_seuil=spill_seuil,
    )
    suites = list(sources.values()) if hasattr(sources, "values") else list(sources)
    for pk in merge_points(suites):
        passe.feed(pk)
    passe.finish()
    logger.debug("run_seconde_passe: retour passe fermée")
    return passe
