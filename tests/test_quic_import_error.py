# SPDX-License-Identifier: GPL-3.0-or-later
"""Test du repli ImportError de quic_diagnostics (lines 55-62).

Le module quic_diagnostics importe cryptography au niveau module. Si
cryptography est absent, il doit lever ImportError avec un message
clair plutot que de planter silencieusement. Ce test simule l'absence
de cryptography en manipulant sys.modules.
"""

from __future__ import annotations

import importlib
import sys


def test_quic_diagnostics_import_error_sans_cryptography(monkeypatch):
    """Lines 55-62 : ImportError quand cryptography est absent."""
    # Retire cryptography et ses sous-modules de sys.modules
    for mod in list(sys.modules):
        if mod == "cryptography" or mod.startswith("cryptography."):
            monkeypatch.delitem(sys.modules, mod, raising=False)

    # Empeche l'import de cryptography
    # Protocole moderne (find_spec) : depuis Python 3.12, sys.meta_path
    # n'appelle plus find_module/load_module -- un bloqueur a l'ancienne
    # est ignore et cryptography s'importerait normalement.
    class _BlockCryptography:
        def find_spec(self, name, path=None, target=None):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError(f"blocked: {name}")
            return None

    blocker = _BlockCryptography()
    # Insere le blocker au debut de sys.meta_path
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    # Retire quic_diagnostics de sys.modules pour forcer le reimport
    monkeypatch.delitem(sys.modules, "netcross_core.quic_diagnostics", raising=False)

    with __import__("pytest").raises(ImportError, match="cryptography"):
        importlib.import_module("netcross_core.quic_diagnostics")
