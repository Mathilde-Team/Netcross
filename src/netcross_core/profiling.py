"""Mesure par étape du pipeline d'analyse (issue #1016, banc #994).

Chronomètre « au tour » : :meth:`MesuresPipeline.etape` clôt l'étape en
cours et ouvre la suivante, avec la même lecture d'horloge. Les étapes
sont donc contiguës et leur somme vaut exactement la durée totale
mesurée ; une étape rouverte plus tard (par exemple ``detecteurs`` après
un premier rendu) cumule ses passages.

Mémoire, relevée à chaque fin d'étape :

- ``rss_max_ko`` : RSS maximale du processus depuis son démarrage
  (``resource.getrusage(RUSAGE_SELF).ru_maxrss``, en Kio sous Linux) --
  valeur monotone, la croissance d'une étape à l'autre situe le pic ;
- ``rss_max_enfants_ko`` : idem pour les sous-processus terminés (tshark) ;
- ``pic_tracemalloc_ko`` (option) : pic des allocations Python pendant
  l'étape seule (``tracemalloc``, remis à zéro à chaque étape). Coûteux :
  ralentit nettement l'analyse, à réserver au diagnostic.

Désactivé par défaut : :func:`creer_mesures` renvoie ``None`` et
:func:`marquer` ne fait alors qu'un test ``is None`` -- aucun objet de
mesures n'est créé, aucune horloge n'est lue.
"""

from __future__ import annotations

import json
import resource
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

ETAPES_STANDARD = ("lecture", "correlation", "detecteurs", "rapport")


def _rss_ko() -> tuple[int, int]:
    """(RSS max du processus, RSS max des enfants terminés), en Kio."""
    logger.debug("_rss_ko: entrée")
    soi = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    enfants = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    logger.debug("_rss_ko: retour")
    return soi, enfants


class MesuresPipeline:
    """Durées et mémoire par étape d'une analyse."""

    def __init__(self, tracemalloc_actif: bool = False, horloge: Callable[[], float] = time.perf_counter):
        logger.debug("MesuresPipeline.__init__: entrée (tracemalloc={})", tracemalloc_actif)
        self._horloge = horloge
        self.tracemalloc_actif = tracemalloc_actif
        self._tracemalloc_lance = False
        if tracemalloc_actif and not tracemalloc.is_tracing():
            tracemalloc.start()
            self._tracemalloc_lance = True
        self._debut: float | None = None
        self._courante: str | None = None
        self._debut_courante = 0.0
        self.total_s = 0.0
        self.etapes: dict[str, dict] = {}
        self.termine = False
        logger.debug("MesuresPipeline.__init__: retour")

    def _clore(self, maintenant: float) -> None:
        """Comptabilise l'étape courante jusqu'à ``maintenant``."""
        logger.debug("MesuresPipeline._clore: entrée")
        if self._courante is None:
            logger.debug("MesuresPipeline._clore: aucune étape ouverte -> retour")
            return
        soi, enfants = _rss_ko()
        entree = self.etapes.setdefault(
            self._courante,
            {"secondes": 0.0, "passages": 0, "rss_max_ko": 0, "rss_max_enfants_ko": 0},
        )
        entree["secondes"] += maintenant - self._debut_courante
        entree["passages"] += 1
        entree["rss_max_ko"] = max(entree["rss_max_ko"], soi)
        entree["rss_max_enfants_ko"] = max(entree["rss_max_enfants_ko"], enfants)
        if self.tracemalloc_actif and tracemalloc.is_tracing():
            _actuel, pic = tracemalloc.get_traced_memory()
            entree["pic_tracemalloc_ko"] = max(entree.get("pic_tracemalloc_ko", 0), pic // 1024)
            tracemalloc.reset_peak()
        logger.debug("MesuresPipeline._clore: retour")

    def etape(self, nom: str) -> None:
        """Clôt l'étape en cours (s'il y en a une) et ouvre ``nom``."""
        logger.debug("MesuresPipeline.etape: entrée ({})", nom)
        if self.termine:
            logger.warning("mesures déjà terminées : étape {} ignorée", nom)
            logger.debug("MesuresPipeline.etape: déjà terminé -> retour")
            return
        maintenant = self._horloge()
        if self._debut is None:
            self._debut = maintenant
        self._clore(maintenant)
        self._courante = nom
        self._debut_courante = maintenant
        logger.debug("MesuresPipeline.etape: retour")

    def terminer(self) -> dict:
        """Clôt la dernière étape, arrête tracemalloc s'il a été lancé ici ; renvoie :meth:`en_dict`."""
        logger.debug("MesuresPipeline.terminer: entrée")
        if not self.termine:
            maintenant = self._horloge()
            self._clore(maintenant)
            self.total_s = maintenant - self._debut if self._debut is not None else 0.0
            self._courante = None
            self.termine = True
            if self._tracemalloc_lance:
                tracemalloc.stop()
                self._tracemalloc_lance = False
        logger.debug("MesuresPipeline.terminer: retour")
        return self.en_dict()

    def en_dict(self) -> dict:
        """Mesures sérialisables (JSON) ; durées arrondies à la microseconde."""
        logger.debug("MesuresPipeline.en_dict: entrée")
        etapes = {nom: {**v, "secondes": round(v["secondes"], 6)} for nom, v in self.etapes.items()}
        soi, enfants = _rss_ko()
        resultat = {
            "format": 1,
            "total_s": round(self.total_s, 6),
            "etapes": etapes,
            "rss_max_ko": soi,
            "rss_max_enfants_ko": enfants,
            "tracemalloc": self.tracemalloc_actif,
        }
        logger.debug("MesuresPipeline.en_dict: retour")
        return resultat

    def ecrire_json(self, chemin: str | Path) -> dict:
        """Termine les mesures et les écrit en JSON dans ``chemin``."""
        logger.debug("MesuresPipeline.ecrire_json: entrée")
        donnees = self.terminer()
        Path(chemin).write_text(json.dumps(donnees, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        logger.debug("MesuresPipeline.ecrire_json: retour")
        return donnees

    def resume(self) -> str:
        """Tableau texte : une ligne par étape (durée, part du total, RSS max)."""
        logger.debug("MesuresPipeline.resume: entrée")
        lignes = [f"Mesures par étape (total {self.total_s:.3f} s) :"]
        for nom, v in self.etapes.items():
            part = 100.0 * v["secondes"] / self.total_s if self.total_s else 0.0
            ligne = f"  {nom:<12} {v['secondes']:>9.3f} s {part:5.1f} %  RSS max {v['rss_max_ko'] / 1024:.1f} Mio"
            if "pic_tracemalloc_ko" in v:
                ligne += f"  pic Python {v['pic_tracemalloc_ko'] / 1024:.1f} Mio"
            lignes.append(ligne)
        logger.debug("MesuresPipeline.resume: retour")
        return "\n".join(lignes)


def creer_mesures(actif: bool, tracemalloc_actif: bool = False) -> MesuresPipeline | None:
    """Objet de mesures si ``actif``, sinon ``None`` (aucun coût)."""
    logger.debug("creer_mesures: entrée (actif={})", actif)
    if not actif:
        logger.debug("creer_mesures: désactivé -> retour None")
        return None
    mesures = MesuresPipeline(tracemalloc_actif=tracemalloc_actif)
    logger.debug("creer_mesures: retour")
    return mesures


def marquer(mesures: MesuresPipeline | None, nom: str) -> None:
    """Ouvre l'étape ``nom`` si les mesures sont actives ; sinon ne fait rien."""
    logger.debug("marquer: entrée")
    if mesures is not None:
        mesures.etape(nom)
    logger.debug("marquer: retour")
