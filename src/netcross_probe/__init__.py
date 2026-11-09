# SPDX-License-Identifier: GPL-3.0-or-later
"""Sonde distribuée ``netcross-probe`` (chantier #1002, sous-issue #1099).

Agent léger de capture : tampon circulaire local (dumpcap/tshark) et
extraction de fenêtres [t1, t2] filtrées BPF vers un pcapng, sans GTK ni
dépendance lourde. Le contrat avec le collecteur est figé dans
``docs/probe-api-v1.yaml`` (v1) ; la sécurité (mTLS, #1101), la remontée
pertes/horloge (#1103), le collecteur et le schéma ``probe://`` (#1105)
et les paquets de déploiement (#1107) complèteront la sonde.
"""

from netcross_probe.agent import AgentProbe
from netcross_probe.bpf import FiltreBpfInvalideError, LibpcapIndisponibleError, valider_filtre
from netcross_probe.capture import AgentCapture, ReglagesCapture
from netcross_probe.fenetres import (
    FenetreInvalideError,
    FenetreResultat,
    FenetreTropGrandeError,
    FenetreVideError,
    extraire_fenetre,
)

__all__ = [
    "AgentCapture",
    "AgentProbe",
    "FenetreInvalideError",
    "FenetreResultat",
    "FenetreTropGrandeError",
    "FenetreVideError",
    "FiltreBpfInvalideError",
    "LibpcapIndisponibleError",
    "ReglagesCapture",
    "extraire_fenetre",
    "valider_filtre",
]
