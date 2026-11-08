# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.clock_sync -- estimation robuste du decalage et de la derive
d'horloge entre deux points de capture (issue #996).

L'ancienne implementation (`analysis.py::_analyse_handshake`) faisait la
moyenne des decalages NTP observes par handshake TCP : un echantillon dont
un seul des deux sens a subi une file d'attente biaise la moyenne (formule
NTP suppose des delais aller/retour symetriques), la derive n'etait pas
modelelee, et aucune incertitude n'etait publiee.

Ce module isole l'estimateur (zero dependance : ni GTK, ni tshark, ni meme
le reste de netcross_core) pour qu'il soit testable sur des jeux
synthetiques :

- **filtre au delai minimal** : parmi les derniers echantillons, NTP ne
  garde que ceux dont le delai aller-retour apparent est le plus faible,
  car ce sont ceux qui ont le moins subi de files d'attente (RFC 5905
  §10). Ici : le decalage observable est `offset = ((t2-t1)-(t4-t3))/2`
  et le delai apparent `delay = (t4-t1)-(t3-t2)` ; on ne garde, par
  fenetre temporelle egale, que l'echantillon au delai minimal ;
- **regression Theil-Sen** (mediane des pentes par paires) du decalage
  en fonction du temps : robuste aux valeurs aberrantes (jusqu'a ~29 %
  de points aberrants sans borne sur leur amplitude), elle fournit le
  decalage a t0 ET la derive (ppm) ;
- **intervalle de confiance** : demi-largeur 95 % calculee a partir de
  la deviation absolue mediane (MAD) des residus, methode robuste
  documentee ici meme -- pas un test statistique exact, un ordre de
  grandeur honnete du bruit d'estimation.

Sources d'echantillons (choisies par l'appelant) : handshakes TCP (SYN +
SYN-ACK vus aux deux points) et couples requete/reponse UDP apparies
(DNS par dns.id) ; l'ancien chemin ne connaissait que les handshakes.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

#: Nombre de fenetres temporelles du filtre au delai minimal (RFC 5905
#: garde les 8 meilleurs des 16 derniers echantillons ; ici le reglage
#: par defaut retient au plus 8 echantillons, un par fenetre).
FENETRES_DELAIS_MINIMAUX = 8

#: Motif d'une specification manuelle de decalage : ``A:B=+12.5ms``.
_MOTIF_DECALAGE_MANUEL = re.compile(
    r"^(?P<amont>[^:=\s]+):(?P<aval>[^:=\s]+)=(?P<valeur>[+-]?\d+(?:\.\d+)?)\s*(?P<unite>ms|us|s)?$"
)


@dataclass(frozen=True)
class EchantillonHorloge:
    """Un couple requete/reponse vu aux deux points d'une paire.

    Args:
        t (float): Instant de la requete vu au point amont (secondes,
            horloge du point amont) -- ancre temporelle de l'echantillon.
        decalage_ms (float): Decalage NTP ``b - a`` estime sur cet
            echange (millisecondes).
        delai_ms (float): Delai aller-retour apparent ``(t4-t1)-(t3-t2)``
            (millisecondes) -- plus il est faible, moins l'echantillon a
            subi de files d'attente, plus il est digne de confiance.
    """

    t: float
    decalage_ms: float
    delai_ms: float


@dataclass
class EstimationHorloge:
    """Resultat de l'estimation robuste pour une paire de points.

    Args:
        decalage_ms (float): Decalage ``b - a`` estime a l'instant
            ``t0`` (millisecondes).
        t0 (float): Instant de reference de ``decalage_ms`` (secondes,
            horloge du point amont) -- le decalage est ensuite extrapole
            par la derive.
        derive_ppm (float): Demeure de l'horloge aval relativement a
            l'amont, en parties par million (un echantillon de 20 ppm
            decale de 72 ms en une heure).
        ic_decalage_ms (float): Demi-largeur de l'intervalle de
            confiance 95 % autour de ``decalage_ms`` (methode MAD des
            residus, voir le module).
        ic_derive_ppm (float): Demi-largeur de l'intervalle de
            confiance 95 % autour de ``derive_ppm``.
        n_echantillons (int): Echantillons recus par l'estimateur.
        n_conserves (int): Echantillons conserves par le filtre au
            delai minimal.
        methode (str): Methode annoncee dans le rapport (texte court,
            lisible par un operateur).
        manuel (bool): Vrai si la valeur a ete imposeee via l'option
            ``--clock-offset`` (aucune estimation, derive et intervalle
            nuls).
    """

    decalage_ms: float
    t0: float = 0.0
    derive_ppm: float = 0.0
    ic_decalage_ms: float = 0.0
    ic_derive_ppm: float = 0.0
    n_echantillons: int = 0
    n_conserves: int = 0
    methode: str = ""
    manuel: bool = False

    def decalage_a(self, t: float) -> float:
        """Decalage extrapole au temps ``t`` (correction par paquet).

        Args:
            t (float): Instant (secondes, horloge du point amont) auquel
                corriger une mesure de latence.

        Returns:
            float: Decalage ``b - a`` a cet instant (millisecondes) --
            decalage a t0 plus derive x duree ecoulee.
        """
        logger.debug("EstimationHorloge.decalage_a: entrée t={}", t)
        valeur = self.decalage_ms + self.derive_ppm * 1e-6 * (t - self.t0) * 1000.0
        logger.debug("EstimationHorloge.decalage_a: sortie valeur={}", valeur)
        return valeur


def _mediane(valeurs: list[float]) -> float:
    """Mediane d'une liste de nombres.

    Args:
        valeurs (list[float]): Valeurs (au moins une -- les appelsants
            garantissent une liste non vide).

    Returns:
        float: Mediane ; 0.0 pour une liste vide (valeur neutre).
    """
    logger.debug("_mediane: entrée n={}", len(valeurs))
    if not valeurs:
        logger.debug("_mediane: sortie 0.0 (liste vide)")
        return 0.0
    resultat = float(statistics.median(valeurs))
    logger.debug("_mediane: sortie resultat={}", resultat)
    return resultat


def _filtre_delais_minimaux(echantillons: list[EchantillonHorloge]) -> list[EchantillonHorloge]:
    """Filtre au delai minimal, par fenetre temporelle egale.

    Reproduit l'esprit du filtre d'horloge NTP (RFC 5905 §10) : parmi
    des echanges proches dans le temps, seul celui dont le delai
    aller-retour apparent est le plus faible a probablement evite les
    files d'attente, et c'est lui qui porte l'information la moins
    biaisee. On decoupe la duree observee en fenetres de duree egale
    (au plus ``FENETRES_DELAIS_MINIMAUX``, moins s'il y a moins
    d'echantillons) et l'on garde, par fenetre, l'echantillon au delai
    minimal. Les echantillons qui tombent hors de toute fenetre (avant
    le premier ou apres le dernier) restent eligibles dans leur fenetre
    tronquee.

    Args:
        echantillons (list[EchantillonHorloge]): Echantillons tries ou
            non (au moins un).

    Returns:
        list[EchantillonHorloge]: Au plus un echantillon par fenetre,
        celui au delai minimal ; l'ordre d'origine est preserve.
    """
    logger.debug("_filtre_delais_minimaux: entrée n={}", len(echantillons))
    triees = sorted(echantillons, key=lambda e: e.t)
    n_fenetres = min(FENETRES_DELAIS_MINIMAUX, len(triees))
    if n_fenetres <= 0:
        logger.debug("_filtre_delais_minimaux: sortie (aucun échantillon)")
        return []
    t_min, t_max = triees[0].t, triees[-1].t
    if t_max <= t_min:
        # Tous les echantillons au meme instant : une seule fenetre, le
        # delai minimal (la derive ne peut pas etre estimee, la
        # regression Theil-Sen s'en chargera).
        meilleure = min(triees, key=lambda e: e.delai_ms)
        logger.debug("_filtre_delais_minimaux: sortie n=1 (même instant)")
        return [meilleure]
    duree_fenetre = (t_max - t_min) / n_fenetres
    meilleures: dict[int, EchantillonHorloge] = {}
    for echantillon in triees:
        index = min(int((echantillon.t - t_min) / duree_fenetre), n_fenetres - 1)
        precedente = meilleures.get(index)
        if precedente is None or echantillon.delai_ms < precedente.delai_ms:
            meilleures[index] = echantillon
    conserves = [e for e in triees if e in meilleures.values()]
    logger.debug("_filtre_delais_minimaux: sortie n={}", len(conserves))
    return conserves


def _theil_sen(conserves: list[EchantillonHorloge], t0: float) -> tuple[float, float]:
    """Regression Theil-Sen du decalage en fonction du temps.

    La pente de chaque paire d'echantillons (i, j), i < j en temps, est
    ``(d_j - d_i) / (t_j - t_i)`` ; la pente Theil-Sen est la MEDIANE de
    ces pentes, insensible aux valeurs aberrantes (rupture de pointe
    ~29 % sans hypothese d'amplitude). L'ordonnee a l'origine est la
    mediane des ``d_i - pente * t_i`` recentree sur ``t0``.

    Args:
        conserves (list[EchantillonHorloge]): Echantillons conserves par
            le filtre (au moins un).
        t0 (float): Instant de reference de l'ordonnee a l'origine.

    Returns:
        tuple[float, float]: ``(decalage_a_t0_ms, derive_ppm)``.
    """
    logger.debug("_theil_sen: entrée n={} t0={}", len(conserves), t0)
    if len(conserves) == 1:
        unique = conserves[0]
        logger.debug("_theil_sen: sortie (échantillon unique)")
        return unique.decalage_ms - 0.0, 0.0
    pentes: list[float] = []
    for i in range(len(conserves)):
        for j in range(i + 1, len(conserves)):
            dt = conserves[j].t - conserves[i].t
            if dt > 0.0:
                pentes.append((conserves[j].decalage_ms - conserves[i].decalage_ms) / dt)
    if not pentes:
        # Tous les echantillons au meme instant : pas de derive
        # estimable, le decalage est la mediane des decalages.
        logger.debug("_theil_sen: sortie (instants identiques)")
        return _mediane([e.decalage_ms for e in conserves]), 0.0
    pente_ms_par_s = _mediane(pentes)
    derive_ppm = pente_ms_par_s * 1000.0  # 1 ms/s == 1000 ppm
    ordonnees = [e.decalage_ms - pente_ms_par_s * (e.t - t0) for e in conserves]
    decalage_t0 = _mediane(ordonnees)
    logger.debug("_theil_sen: sortie decalage_t0={} derive_ppm={}", decalage_t0, derive_ppm)
    return decalage_t0, derive_ppm


def _ecart_mad(valeurs: list[float]) -> float:
    """Deviation robuste (MAD x 1.4826, echelle d'une loi normale).

    Args:
        valeurs (list[float]): Residus ou pentes (au moins deux).

    Returns:
        float: Estimation robuste de l'ecart-type ; 0.0 si toutes les
        valeurs sont identiques (aucune bruit d'estimation mesurable).
    """
    logger.debug("_ecart_mad: entrée n={}", len(valeurs))
    if len(valeurs) < 2:
        logger.debug("_ecart_mad: sortie 0.0 (moins de deux valeurs)")
        return 0.0
    centre = _mediane(valeurs)
    ecarts = [abs(v - centre) for v in valeurs]
    ecart = 1.4826 * _mediane(ecarts)
    logger.debug("_ecart_mad: sortie ecart={}", ecart)
    return ecart


def _theil_sen_ic(conserves: list[EchantillonHorloge]) -> tuple[float, float]:
    """Intervalles de confiance 95 % robustes (ecart MAD) pour une estimation.

    Args:
        conserves: Echantillons conserves par le filtre au delai minimal.

    Returns:
        tuple: (demi-largeur du decalage en ms, demi-largeur de la derive en
        ppm). Pentes nulles (instants identiques) : derive non estimable,
        demi-largeur 0.
    """
    ic_decalage = 1.96 * _ecart_mad([e.decalage_ms for e in conserves]) / max(len(conserves) ** 0.5, 1.0)
    pentes_paires: list[float] = []
    for i in range(len(conserves)):
        for j in range(i + 1, len(conserves)):
            dt = conserves[j].t - conserves[i].t
            if dt > 0.0:
                pentes_paires.append((conserves[j].decalage_ms - conserves[i].decalage_ms) / dt * 1000.0)
    ic_derive = 1.96 * _ecart_mad(pentes_paires) / max(len(pentes_paires) ** 0.5, 1.0)
    logger.debug("_theil_sen_ic: sortie ic_decalage={} ic_derive={}", ic_decalage, ic_derive)
    return ic_decalage, ic_derive


def estimer_decalage(echantillons: list[EchantillonHorloge]) -> EstimationHorloge | None:
    """Estime decalage a t0, derive et intervalles d'une paire de points.

    Args:
        echantillons (list[EchantillonHorloge]): Echantillons de la paire
            (handshakes TCP et/ou couples requete/reponse UDP) ; une
            liste vide renvoie ``None`` (paire sans mesure possible).

    Returns:
        Optional[EstimationHorloge]: Estimation (methode
        « filtre au delai minimal + Theil-Sen »), ``None`` si aucun
        echantillon.
    """
    logger.debug("estimer_decalage: entrée n={}", len(echantillons))
    if not echantillons:
        logger.debug("estimer_decalage: sortie None (aucun échantillon)")
        return None
    t0 = min(e.t for e in echantillons)
    conserves = _filtre_delais_minimaux(echantillons)
    decalage_t0, derive_ppm = _theil_sen(conserves, t0)
    # Intervalles 95 % : 1,96 x ecart robuste / sqrt(n). Hypothese
    # documentee (module) : residus approximativement gaussiens une fois
    # les files d'attente filtrees ; avec peu d'echantillons l'intervalle
    # est volontairement large, c'est le but -- il DOIT refleter
    # l'incertitude honnetement pour que le rapport puisse marquer « non
    # mesurable ».
    ic_decalage, ic_derive = _theil_sen_ic(conserves)
    estimation = EstimationHorloge(
        decalage_ms=decalage_t0,
        t0=t0,
        derive_ppm=derive_ppm,
        ic_decalage_ms=ic_decalage,
        ic_derive_ppm=ic_derive,
        n_echantillons=len(echantillons),
        n_conserves=len(conserves),
        methode="filtre au délai minimal + Theil-Sen",
    )
    logger.debug("estimer_decalage: sortie {}", estimation)
    return estimation


def estimation_manuelle(decalage_ms: float, t0: float = 0.0) -> EstimationHorloge:
    """Estimation imposee par l'option ``--clock-offset`` (cas PTP).

    Args:
        decalage_ms (float): Decalage connu, imposé pour toute la paire.
        t0 (float): Instant de reference (secondes).

    Returns:
        EstimationHorloge: Estimation marquee ``manuel=True`` : derive et
        intervalles nuls, methode annoncant la valeur imposee dans le
        rapport.
    """
    logger.debug("estimation_manuelle: entrée decalage_ms={} t0={}", decalage_ms, t0)
    estimation = EstimationHorloge(
        decalage_ms=decalage_ms,
        t0=t0,
        methode="valeur imposée (--clock-offset)",
        manuel=True,
    )
    logger.debug("estimation_manuelle: sortie {}", estimation)
    return estimation


def _vers_ms(valeur: float, unite: str | None) -> float:
    """Convertit une valeur et son unite en millisecondes.

    Args:
        valeur (float): Valeur numerique telle que saisie.
        unite (str | None): Unite saisie (``ms``, ``us``, ``s`` ou
            absente -- l'option ``--clock-offset`` de l'issue documente
            ``+12.5ms`` ; l'unite par defaut reste la milliseconde).

    Returns:
        float: Valeur en millisecondes.

    Raises:
        ValueError: Unite inconnue.
    """
    logger.debug("_vers_ms: entrée valeur={} unite={}", valeur, unite)
    facteurs = {"ms": 1.0, None: 1.0, "us": 0.001, "s": 1000.0}
    if unite not in facteurs:
        message = f"unité inconnue « {unite} » (attendu : ms, us ou s)"
        logger.debug("_vers_ms: sortie erreur {}", message)
        raise ValueError(message)
    resultat = valeur * facteurs[unite]
    logger.debug("_vers_ms: sortie resultat={}", resultat)
    return resultat


def analyser_decalages_manuels(specifications: list[str]) -> dict[tuple[str, str], float]:
    """Analyse les valeurs ``--clock-offset A:B=+12.5ms``.

    Args:
        specifications (list[str]): Valeurs brutes de l'option (une par
            paire, repetables).

    Returns:
        dict[tuple[str, str], float]: Decalages imposes, cles
        ``(amont, aval)`` (paire orientee amont -> aval, telle que
        saisie), valeurs en millisecondes.

    Raises:
        ValueError: Une specification ne respecte pas le motif attendu.
    """
    logger.debug("analyser_decalages_manuels: entrée n={}", len(specifications))
    decalages: dict[tuple[str, str], float] = {}
    for specification in specifications:
        correspondance = _MOTIF_DECALAGE_MANUEL.match(specification.strip())
        if correspondance is None:
            message = f"spécification « {specification} » invalide : attendu POINT:POINT=+12.5ms (ex. LAN:WAN=+12.5ms)"
            logger.debug("analyser_decalages_manuels: sortie erreur {}", message)
            raise ValueError(message)
        decalages[(correspondance["amont"], correspondance["aval"])] = _vers_ms(
            float(correspondance["valeur"]), correspondance["unite"]
        )
    logger.debug("analyser_decalages_manuels: sortie {} paire(s)", len(decalages))
    return decalages
