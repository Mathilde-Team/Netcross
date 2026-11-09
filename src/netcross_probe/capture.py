# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture locale de la sonde ``netcross-probe`` en tampon circulaire.

Issue #1099 (sous-issue 2/6 du chantier sondes distribuées #1002) : la
sonde capture en local via l'enregistreur en ring buffer existant
(``pcap_parser.capture`` -- tshark/dumpcap, ``ring_recorder_args``) : une
coupure du lien d'administration ne fait perdre aucun paquet au point de
mesure, le collecteur ne tirera que les fenêtres utiles (extraction dans
``netcross_probe.fenetres``).

Ce module ne fait qu'habiller l'enregistreur existant avec les réglages
de la sonde : interface, dossier du tampon, nombre de fichiers, durée par
fichier et filtre BPF éventuel appliqué dès la capture. Sans GTK, sans
dépendance lourde : tshark/dumpcap seul côté capture.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from loguru import logger

from pcap_parser.capture import RingFile, ring_inventory, start_ring_recorder, stop_ring_recorder

__all__ = ["AgentCapture", "ReglagesCapture"]


@dataclass(frozen=True)
class ReglagesCapture:
    """Réglages du tampon circulaire de la sonde.

    ``interface`` : interface à capturer (ou toute source acceptée par
    ``ring_recorder_args``, hors ``pipe://``). ``nb_fichiers`` multiplie
    ``duree_par_fichier`` fixe la profondeur du tampon ; au-delà, tshark
    supprime le plus ancien fichier. ``filtre_bpf`` : filtre de capture
    optionnel (syntaxe pcap-filter), appliqué par dumpcap lui-même.
    """

    interface: str
    dossier: str
    nb_fichiers: int = 5
    duree_par_fichier: float = 60.0
    prefixe: str = "probe"
    filtre_bpf: str | None = None


class AgentCapture:
    """Gestion de la capture locale en tampon circulaire (issue #1099).

    Un seul enregistreur à la fois : ``demarrer`` lève si une capture est
    déjà en cours. L'enregistreur est un processus tshark séparé, arrêté
    proprement par ``arreter`` (SIGTERM puis SIGKILL : le fichier en cours
    reste lisible).
    """

    def __init__(self, reglages: ReglagesCapture) -> None:
        logger.debug("AgentCapture.__init__: entrée")
        self.reglages = reglages
        self._processus: subprocess.Popen | None = None
        logger.debug("AgentCapture.__init__: fin")

    @property
    def en_cours(self) -> bool:
        """True si l'enregistreur tourne encore."""
        logger.debug("AgentCapture.en_cours: retour bool")
        return self._processus is not None and self._processus.poll() is None

    def demarrer(self) -> None:
        """Lance l'enregistrement en ring buffer (idempotent : refuse si déjà lancé)."""
        logger.debug("AgentCapture.demarrer: entrée ({})", self.reglages.interface)
        if self.en_cours:
            logger.warning("AgentCapture.demarrer: capture déjà en cours -> refus")
            raise RuntimeError("une capture est déjà en cours sur cette sonde")
        self._processus = start_ring_recorder(
            self.reglages.interface,
            self.reglages.dossier,
            max_files=self.reglages.nb_fichiers,
            max_duration_per_file=self.reglages.duree_par_fichier,
            prefix=self.reglages.prefixe,
            bpf_filter=self.reglages.filtre_bpf,
        )
        logger.debug("AgentCapture.demarrer: fin (pid {})", self._processus.pid)

    def arreter(self) -> str:
        """Arrête l'enregistreur ; renvoie son stderr (vide si tout va bien)."""
        logger.debug("AgentCapture.arreter: entrée")
        if self._processus is None:
            logger.debug("AgentCapture.arreter: aucun processus -> retour ''")
            return ""
        stderr = stop_ring_recorder(self._processus)
        self._processus = None
        logger.debug("AgentCapture.arreter: fin")
        return stderr

    def inventaire(self) -> list[RingFile]:
        """Inventaire horodaté du tampon circulaire (fichiers présents sur disque)."""
        logger.debug("AgentCapture.inventaire: entrée")
        fichiers = ring_inventory(self.reglages.dossier, prefix=self.reglages.prefixe)
        logger.debug("AgentCapture.inventaire: retour {} fichier(s)", len(fichiers))
        return fichiers
