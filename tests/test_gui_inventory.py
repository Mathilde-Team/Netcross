# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests du script d'inventaire de app.py (issue #285)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gui_inventory.py"
_spec = importlib.util.spec_from_file_location("gui_inventory", SCRIPT)
assert _spec is not None and _spec.loader is not None
gui_inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gui_inventory)

SOURCE = """
class Fenetre:
    def __init__(self):
        self.x = 1

    def construit(self):
        bouton = Gtk.Button()
        bouton.show()

    def decide(self, n):
        if n > 1:
            return "ok"
        return "non"

def hors_classe():
    return Gtk.Label()
"""


def test_classe_les_methodes_et_compte_les_instructions():
    inv = gui_inventory.inventaire(SOURCE)
    assert inv["gtk"] == [(2, "Fenetre.construit"), (1, "Fenetre.__init__")]
    assert inv["sans_gtk"] == [(3, "Fenetre.decide")]
    assert inv["lignes"] == len(SOURCE.splitlines())


def test_main_sur_app_py(capsys):
    assert gui_inventory.main(["--top", "3"]) == 0
    sortie = capsys.readouterr().out
    assert "Methodes touchant GTK ou __init__" in sortie
    assert "MainWindow." in sortie


def test_main_sur_un_fichier(tmp_path, capsys):
    fichier = tmp_path / "app.py"
    fichier.write_text(SOURCE, encoding="utf-8")
    assert gui_inventory.main([str(fichier), "--top", "1"]) == 0
    assert "Fenetre.decide" in capsys.readouterr().out
