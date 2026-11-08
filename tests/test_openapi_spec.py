# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de la generation et du controle de fraicheur de docs/openapi.yaml
(issue #209, dernieres cases : script + verification en CI).

Meme discipline que tests/test_class_diagram.py : la spec est un artefact
DERIVE du code, donc une spec non regeneree est un bug que la CI doit
attraper, pas une divergence silencieuse.

Le module est saute si l'extra ``api`` n'est pas installe (fastapi absent) :
la spec ne peut pas etre derivee sans l'application.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="extra [api] non installe")

RACINE = Path(__file__).resolve().parent.parent
SCRIPT = RACINE / "scripts" / "generate_openapi.py"


def _charger_script():
    """Importe le script comme un module (il n'est pas dans un package)."""
    sys.path.insert(0, str(RACINE / "src"))
    spec = importlib.util.spec_from_file_location("generate_openapi", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_le_script_existe():
    assert SCRIPT.is_file()


def test_render_produit_un_chemin_et_un_contenu_non_vide():
    module = _charger_script()
    chemin, contenu = module._render()
    assert chemin.name in {"openapi.yaml", "openapi.json"}
    assert contenu.strip()


def test_la_spec_versionnee_est_a_jour():
    """Echoue si docs/openapi.yaml ne correspond plus au code de
    netcross_api -- c'est exactement le controle que la CI execute."""
    module = _charger_script()
    assert module.main(["--check"]) == 0


def test_check_signale_une_spec_obsolete(tmp_path, monkeypatch):
    module = _charger_script()
    faux = tmp_path / "openapi.yaml"
    faux.write_text("openapi: 3.0.0\npaths: {}\n", encoding="utf-8")
    monkeypatch.setattr(module, "_render", lambda: (faux, "contenu different\n"))
    assert module.main(["--check"]) == 1


def test_check_signale_une_spec_absente(tmp_path, monkeypatch):
    module = _charger_script()
    absent = tmp_path / "jamais-ecrit.yaml"
    monkeypatch.setattr(module, "_render", lambda: (absent, "peu importe\n"))
    assert module.main(["--check"]) == 1


def test_generation_ecrit_le_fichier(tmp_path, monkeypatch):
    module = _charger_script()
    cible = tmp_path / "sous-dossier" / "openapi.yaml"
    monkeypatch.setattr(module, "_render", lambda: (cible, "openapi: 3.1.0\n"))
    assert module.main([]) == 0
    assert cible.read_text(encoding="utf-8") == "openapi: 3.1.0\n"


def test_la_spec_declare_les_routes_attendues():
    """La spec doit decrire les endpoints de l'issue #209."""
    contenu = (RACINE / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    for route in ("/health", "/captures", "/analyses/"):
        assert route in contenu, f"route absente de la spec : {route}"
