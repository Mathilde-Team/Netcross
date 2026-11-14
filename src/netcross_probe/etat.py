# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_probe.etat -- pertes de capture et état d'horloge de la sonde
(issue #1103, sous-issue 4/6 du chantier #1002).

Distinguer « le réseau a perdu » de « la sonde a perdu » : la sonde
déclare, pour la fenêtre extraite, ce que l'outil de capture a admis
perdre (blocs ISB pcapng : ``ifdrop``/``osdrop``) et l'état de
synchronisation horaire de la machine au moment de l'extraction (chrony
ou systemd-timesyncd). Ces métadonnées suivent la fenêtre (contrat v1 :
``Window.capture_loss`` et ``Window.clock``) jusqu'au rapport.

Limites assumées, documentées : ``ntpd`` et PTP (``ptp4l``/``phc2sys``)
ne sont pas interrogés — la source est alors ``unknown``, jamais
inventée ; les pertes déclarées sont celles des blocs ISB des fichiers
du tampon qui couvrent la fenêtre (dumpcap les écrit, editcap et tcpdump
non — sans ISB, la métadonnée vaut ``None``, pas 0).
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from loguru import logger

from pcap_parser.capfile import read_structure

__all__ = [
    "EtatHorloge",
    "PertesCapture",
    "lire_etat_horloge",
    "lire_pertes_capture",
]


@dataclass(frozen=True)
class PertesCapture:
    """Pertes déclarées par les blocs ISB des fichiers du tampon couvrant
    la fenêtre (contrat v1 : ``CaptureLoss``). ``None`` = aucune
    statistique lue (fichier sans ISB), à ne pas confondre avec 0."""

    packets_received: int
    ifdrop: int
    osdrop: int

    @property
    def packets_dropped(self) -> int:
        logger.debug("PertesCapture.packets_dropped: retour ifdrop + osdrop")
        return self.ifdrop + self.osdrop

    def vers_dict(self) -> dict:
        """Miroir du schéma ``CaptureLoss`` du contrat v1."""
        logger.debug("PertesCapture.vers_dict: entrée")
        dico = {
            "packets_received": self.packets_received,
            "packets_dropped": self.packets_dropped,
            "ifdrop": self.ifdrop,
            "osdrop": self.osdrop,
        }
        logger.debug("PertesCapture.vers_dict: retour")
        return dico


@dataclass(frozen=True)
class EtatHorloge:
    """État de synchronisation horaire au moment de la mesure (contrat
    v1 : ``ClockStatus``). ``source`` : ``chrony``/``systemd-timesyncd``/
    ``unknown`` ; les valeurs annoncées sont celles du démon, jamais
    mesurées ici."""

    source: str
    synchronized: bool
    offset_ms: float | None
    dispersion_ms: float | None
    reference: str | None
    measured_at: float

    def vers_dict(self) -> dict:
        """Miroir du schéma ``ClockStatus`` du contrat v1."""
        logger.debug("EtatHorloge.vers_dict: entrée")
        dico = {
            "source": self.source,
            "synchronized": self.synchronized,
            "offset_ms": self.offset_ms,
            "dispersion_ms": self.dispersion_ms,
            "reference": self.reference,
            "measured_at": self.measured_at,
        }
        logger.debug("EtatHorloge.vers_dict: retour")
        return dico


def lire_pertes_capture(chemins: Sequence[str]) -> PertesCapture | None:
    """Somme les statistiques ISB (reçus, ``ifdrop``, ``osdrop``) des
    fichiers donnés. Renvoie None si aucun ne porte d'ISB exploitable."""
    logger.debug("lire_pertes_capture: entrée ({} fichier(s))", len(chemins))
    recus: int | None = None
    ifdrop: int | None = None
    osdrop: int | None = None
    for chemin in chemins:
        try:
            structure = read_structure(chemin)
        except OSError:
            # Fichier tourné/disparu entre l'inventaire et la lecture : la
            # sonde ne crashe pas, elle déclare ce qu'elle a pu lire.
            logger.debug("lire_pertes_capture: {} illisible -> ignoré", chemin)
            continue
        if structure is None:
            continue
        for interface in structure.interfaces:
            if interface.received is not None:
                recus = (recus or 0) + interface.received
            if interface.dropped_by_interface is not None:
                ifdrop = (ifdrop or 0) + interface.dropped_by_interface
            if interface.dropped_by_os is not None:
                osdrop = (osdrop or 0) + interface.dropped_by_os
    if recus is None and ifdrop is None and osdrop is None:
        logger.debug("lire_pertes_capture: aucun ISB -> retour None")
        return None
    pertes = PertesCapture(
        packets_received=recus or 0,
        ifdrop=ifdrop or 0,
        osdrop=osdrop or 0,
    )
    logger.debug("lire_pertes_capture: retour {}", pertes)
    return pertes


def _lancer(nom: str, arguments: Sequence[str]) -> str | None:
    """Sortie standard d'une commande, None si absent ou en échec."""
    logger.debug("_lancer: entrée ({} {})", nom, list(arguments))
    try:
        resultat = subprocess.run(
            [nom, *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        logger.debug("_lancer: {} indisponible -> retour None", nom)
        return None
    if resultat.returncode != 0:
        logger.debug("_lancer: code {} -> retour None", nom, resultat.returncode)
        return None
    logger.debug("_lancer: retour sortie de {} ({} octet(s))", nom, len(resultat.stdout))
    return resultat.stdout


def _secondes_vers_ms(texte: str | None) -> float | None:
    """«+0.000000123 seconds» -> millisecondes ; None si non analysable."""
    logger.debug("_secondes_vers_ms: entrée ({!r})", texte)
    if texte is None:
        logger.debug("_secondes_vers_ms: None -> retour None")
        return None
    cherche = re.search(r"[-+]?\d+(?:\.\d+)?", texte)
    if cherche is None:
        logger.debug("_secondes_vers_ms: aucun nombre -> retour None")
        return None
    valeur = float(cherche.group()) * 1000.0
    logger.debug("_secondes_vers_ms: retour {} ms", valeur)
    return valeur


def _lire_chrony(lancer: Callable[..., str | None]) -> EtatHorloge | None:
    """État depuis ``chronyc -n tracking`` ; None si chrony absent."""
    logger.debug("_lire_chrony: entrée")
    sortie = lancer("chronyc", ["-n", "tracking"])
    if sortie is None:
        logger.debug("_lire_chrony: chronyc indisponible -> retour None")
        return None
    lignes = {}
    for ligne in sortie.splitlines():
        if ":" in ligne:
            cle, valeur = ligne.split(":", 1)
            lignes[cle.strip()] = valeur.strip()
    reference = lignes.get("Reference ID")
    if reference:
        # « C0A80001 (192.168.0.1) » -> garder l'adresse lisible.
        entre_parentheses = re.search(r"\(([^)]+)\)", reference)
        if entre_parentheses:
            reference = entre_parentheses.group(1)
    etat = EtatHorloge(
        source="chrony",
        synchronized=lignes.get("Leap status", "").lower().startswith("normal"),
        offset_ms=_secondes_vers_ms(lignes.get("Last offset")),
        dispersion_ms=_secondes_vers_ms(lignes.get("RMS offset")),
        reference=reference or None,
        measured_at=time.time(),
    )
    logger.debug("_lire_chrony: retour {}", etat)
    return etat


def _lire_timesyncd(lancer: Callable[..., str | None]) -> EtatHorloge | None:
    """État depuis ``timedatectl show-timesync`` ; None si absent."""
    logger.debug("_lire_timesyncd: entrée")
    sortie = lancer("timedatectl", ["show-timesync"])
    if sortie is None:
        logger.debug("_lire_timesyncd: indisponible -> retour None")
        return None
    proprietes = {}
    for ligne in sortie.splitlines():
        if "=" in ligne:
            cle, valeur = ligne.split("=", 1)
            proprietes[cle.strip()] = valeur.strip()
    synchronise = lancer("timedatectl", ["show", "-p", "NTPSynchronized", "--value"])
    etat = EtatHorloge(
        source="systemd-timesyncd",
        synchronized=(synchronise or "").strip().lower() == "yes",
        offset_ms=_secondes_vers_ms(proprietes.get("Offset")),
        dispersion_ms=_secondes_vers_ms(proprietes.get("RootDistance")),
        reference=proprietes.get("ServerName") or None,
        measured_at=time.time(),
    )
    logger.debug("_lire_timesyncd: retour {}", etat)
    return etat


def lire_etat_horloge(lancer: Callable[..., str | None] = _lancer) -> EtatHorloge:
    """État d'horloge de la machine : chrony d'abord, systemd-timesyncd
    sinon, ``unknown`` (jamais inventé) en dernier recours."""
    logger.debug("lire_etat_horloge: entrée")
    for lecteur in (_lire_chrony, _lire_timesyncd):
        etat = lecteur(lancer)
        if etat is not None:
            logger.debug("lire_etat_horloge: retour via {}", lecteur.__name__)
            return etat
    etat = EtatHorloge(
        source="unknown",
        synchronized=False,
        offset_ms=None,
        dispersion_ms=None,
        reference=None,
        measured_at=time.time(),
    )
    logger.debug("lire_etat_horloge: retour unknown")
    return etat
