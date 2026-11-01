# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.plugins -- detecteurs et sorties tierces (issue #284).
Voir docs/plugins.md : contrat, schema des constats, limites de securite.
"""

from netcross_core.logging_config import get_logger
from netcross_core.plugins.api import (
    SEVERITIES,
    Detector,
    DetectorContext,
    Exporter,
    InvalidFindingError,
    PluginAccessError,
    ReadOnlyView,
    validate_finding,
)
from netcross_core.plugins.loader import (
    GROUPS,
    LoadedPlugins,
    PluginInfo,
    PluginLoadError,
    discover_installed,
    forbidden_imports,
    list_plugins,
    load_plugins,
)
from netcross_core.plugins.runner import load_error_runs, run_detectors, run_exporters, run_line

logger = get_logger(__name__)

__all__ = [
    "GROUPS",
    "SEVERITIES",
    "Detector",
    "DetectorContext",
    "Exporter",
    "InvalidFindingError",
    "LoadedPlugins",
    "PluginAccessError",
    "PluginInfo",
    "PluginLoadError",
    "ReadOnlyView",
    "discover_installed",
    "forbidden_imports",
    "list_plugins",
    "load_error_runs",
    "load_plugins",
    "run_detectors",
    "run_exporters",
    "run_line",
    "validate_finding",
]
