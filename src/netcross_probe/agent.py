# SPDX-License-Identifier: GPL-3.0-or-later
"""L'agent ``netcross-probe`` : capture locale + extraction de fenêtres.

Issue #1099 (sous-issue 2/6 du chantier #1002). :class:`AgentProbe`
compose les deux briques de la sonde :

- la capture en tampon circulaire (``netcross_probe.capture``) ;
- l'extraction d'une fenêtre [t1, t2] filtrée BPF vers un pcapng
  (``netcross_probe.fenetres``).

Les fenêtres extraites sont retenues dans un registre en mémoire avec
expiration (contrat v1 : une fenêtre non libérée expire), et l'extraction
va au tampon ACTUEL de l'agent. La couche réseau (mTLS, #1101) et le
collecteur (#1105) viendront se brancher sur cette classe sans la
réécrire.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from loguru import logger

from netcross_probe.capture import AgentCapture, ReglagesCapture
from netcross_probe.fenetres import FenetreResultat, extraire_fenetre

__all__ = ["EXPIRATION_FENETRES_DEFAUT", "AgentProbe"]

EXPIRATION_FENETRES_DEFAUT = 3600.0


@dataclass
class _FenetreMemoire:
    """Une fenêtre extraite retenue par l'agent, avec son échéance."""

    resultat: FenetreResultat
    expire_a: float


class AgentProbe:
    """Sonde locale : capture en anneau + fenêtres extraites à la demande.

    ``expiration_fenetres`` : durée de vie (secondes) d'une fenêtre
    extraite non libérée (contrat v1 : ``expires_at``).
    """

    def __init__(
        self,
        reglages_capture: ReglagesCapture,
        dossier_fenetres: str,
        expiration_fenetres: float = EXPIRATION_FENETRES_DEFAUT,
    ) -> None:
        logger.debug("AgentProbe.__init__: entrée")
        self.capture = AgentCapture(reglages_capture)
        self.dossier_fenetres = dossier_fenetres
        self.expiration_fenetres = expiration_fenetres
        self._fenetres: dict[str, _FenetreMemoire] = {}
        logger.debug("AgentProbe.__init__: fin")

    def extraire(
        self,
        debut: float,
        fin: float,
        filtre_bpf: str | None = None,
        inclure_inconnus: bool = False,
        max_octets: int | None = None,
    ) -> FenetreResultat:
        """Extrait une fenêtre du tampon courant et la retient jusqu'à expiration."""
        logger.debug("AgentProbe.extraire: entrée ([{}, {}], filtre {!r})", debut, fin, filtre_bpf)
        resultat = extraire_fenetre(
            self.capture.reglages.dossier,
            debut,
            fin,
            prefixe=self.capture.reglages.prefixe,
            filtre_bpf=filtre_bpf,
            inclure_inconnus=inclure_inconnus,
            dossier_sortie=self.dossier_fenetres,
            max_octets=max_octets,
        )
        self._nettoyer_expirees()
        self._fenetres[resultat.identifiant] = _FenetreMemoire(
            resultat=resultat, expire_a=time.time() + self.expiration_fenetres
        )
        logger.debug("AgentProbe.extraire: retour fenêtre {}", resultat.identifiant)
        return resultat

    def fenetre(self, identifiant: str) -> FenetreResultat | None:
        """Fenêtre retenue si elle n'a pas expiré ; None sinon (contrat v1 : 404)."""
        logger.debug("AgentProbe.fenetre: entrée ({})", identifiant)
        self._nettoyer_expirees()
        memoire = self._fenetres.get(identifiant)
        if memoire is None:
            logger.debug("AgentProbe.fenetre: inconnue ou expirée -> retour None")
            return None
        logger.debug("AgentProbe.fenetre: retour fenêtre {}", identifiant)
        return memoire.resultat

    def liberer(self, identifiant: str) -> bool:
        """Libère une fenêtre (contrat v1 : DELETE). True si elle existait."""
        logger.debug("AgentProbe.liberer: entrée ({})", identifiant)
        self._nettoyer_expirees()
        memoire = self._fenetres.pop(identifiant, None)
        logger.debug("AgentProbe.liberer: retour {}", memoire is not None)
        return memoire is not None

    def _nettoyer_expirees(self) -> None:
        """Retire les fenêtres expirées du registre (le pcapng reste sur disque)."""
        logger.debug("AgentProbe._nettoyer_expirees: entrée")
        maintenant = time.time()
        expires = [k for k, m in self._fenetres.items() if m.expire_a <= maintenant]
        for cle in expires:
            del self._fenetres[cle]
        logger.debug("AgentProbe._nettoyer_expirees: {} fenêtre(s) expirée(s) retirée(s)", len(expires))
