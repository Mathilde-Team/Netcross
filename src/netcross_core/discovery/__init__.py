# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.discovery -- decouverte et cartographie passive des actifs
reseau (SCENARIO-5, issue #151, parent #141).

100% passif, comme le reste de netcross_core : aucune sonde n'est
emise, tout provient des paquets deja captures. Deux sous-modules :

- `os_detect` : hypothese d'OS par empreinte TTL/options TCP (type
  p0f), independante de tout hote -- fonctions pures sur des valeurs
  scalaires.
- `assets` : inventaire structure des hotes vus dans une capture (IP,
  MAC, premiere/derniere vue, ports exposes, hypothese d'OS), avec
  comparaison optionnelle a une baseline d'hotes connus pour signaler
  les nouveaux hotes.

Difference avec l'existant deja documentee dans l'issue : netcross_core.
analysis produit deja une topologie deduite (Report.topology_edges) et
des compteurs PAR POINT ; ce module produit un inventaire PAR HOTE,
orthogonal et complementaire, consommable tel quel pour une integration
SIEM (voir AssetInventory.to_records dans `assets`).
"""

from __future__ import annotations

from netcross_core.discovery.assets import (
    AssetInventory,
    ExposedService,
    HostAsset,
    build_asset_inventory,
    load_baseline_hosts,
)
from netcross_core.discovery.os_detect import OsGuess, guess_initial_ttl, guess_os_from_ttl, refine_with_tcp_options
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

__all__ = [
    "AssetInventory",
    "ExposedService",
    "HostAsset",
    "OsGuess",
    "build_asset_inventory",
    "guess_initial_ttl",
    "guess_os_from_ttl",
    "load_baseline_hosts",
    "refine_with_tcp_options",
]
