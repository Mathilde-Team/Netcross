"""Estimation du décalage d'horloge entre points de capture (issue #1026, chantier #996).

Extrait tel quel de ``analysis._analyse_handshake`` pour pouvoir le tester
sur des listes d'échantillons, sans paquet ni tshark, puis le remplacer par
un estimateur robuste (#1027 : filtre au délai minimal, régression
décalage + dérive ; #1033 : intervalle de confiance).

Estimateur actuel :

- **échantillon** : pour un SYN et son SYN-ACK vus tous deux aux points
  ``a`` (amont) et ``b`` (aval), formule NTP classique
  ``offset = ((t2 - t1) - (t4 - t3)) / 2`` avec ``t1`` = SYN vu en ``a``,
  ``t2`` = SYN vu en ``b``, ``t3`` = SYN-ACK vu en ``b``, ``t4`` = SYN-ACK
  vu en ``a`` ; résultat en millisecondes, positif si l'horloge de ``b``
  avance sur celle de ``a`` (à délais aller et retour égaux) ;
- **estimation** : moyenne arithmétique des échantillons, écart-type de
  population (``statistics.pstdev``, 0.0 pour un seul échantillon) et
  nombre d'échantillons.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Mapping, Sequence

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

Estimation = tuple[float, float, int]


def echantillon_ntp_ms(t1: float, t2: float, t3: float, t4: float) -> float:
    """Décalage (ms) de l'horloge aval sur l'horloge amont pour un aller-retour vu aux deux points.

    ``t1`` / ``t4`` : départ de la requête / arrivée de la réponse au point amont ;
    ``t2`` / ``t3`` : arrivée de la requête / départ de la réponse au point aval ; en secondes.
    """
    logger.debug("echantillon_ntp_ms: entrée")
    offset_ms = ((t2 - t1) - (t4 - t3)) / 2 * 1000.0
    logger.debug("echantillon_ntp_ms: retour")
    return offset_ms


def estimer_decalage(echantillons: Sequence[float]) -> Estimation:
    """(moyenne, écart-type de population, nombre) des échantillons, en ms.

    ``statistics.StatisticsError`` sur une liste vide, comme avant l'extraction
    (l'appelant n'estime que les paires ayant au moins un échantillon).
    """
    logger.debug("estimer_decalage: entrée ({} échantillon(s))", len(echantillons))
    moyenne = statistics.mean(echantillons)
    ecart = statistics.pstdev(echantillons) if len(echantillons) > 1 else 0.0
    logger.debug("estimer_decalage: retour")
    return moyenne, ecart, len(echantillons)


def estimer_decalages(echantillons_par_paire: Mapping[tuple[str, str], Iterable[float]]) -> dict:
    """Estimation par paire de points : ``{(a, b): (moyenne, écart-type, n)}``."""
    logger.debug("estimer_decalages: entrée ({} paire(s))", len(echantillons_par_paire))
    estimations = {paire: estimer_decalage(list(ech)) for paire, ech in echantillons_par_paire.items()}
    logger.debug("estimer_decalages: retour")
    return estimations
