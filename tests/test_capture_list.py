# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de l'enumeration, de l'ordre et du retrait des lignes des panneaux de
captures (`netcross_gtk4.capture_list`, issue #285, cinquieme lot).

L'ordre des lignes est le chemin physique du reseau quand la deduction de
topologie est desactivee : une erreur ici change le resultat de l'analyse
sans lever d'exception. Les objets GTK sont remplaces par des factices qui
reproduisent le seul contrat utilise -- ``get_row_at_index`` renvoie
``None`` apres la derniere ligne, et ``insert`` au-dela de la longueur
ajoute en fin (comportement de ``Gtk.ListBox``, celui qui masquait la borne
manquante a la descente).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from netcross_gtk4 import capture_list
from netcross_gtk4.capture_list import (
    PREFIXE_POINT,
    captures_fichiers,
    captures_live,
    deplacer_ligne,
    lignes,
    nom_de_point,
    nom_par_defaut_fichier,
    nom_par_defaut_live,
    nombre_de_lignes,
    retirer_ligne,
)

APP_PY = Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"


# -- factices GTK ---------------------------------------------------------------


class FauxListBox:
    def __init__(self, contenus=()):
        self.rows: list[FauxRow] = []
        self.selection = None
        self.operations: list[str] = []
        for contenu in contenus:
            self.append(FauxRow(contenu))

    def append(self, row):
        row.parent = self
        self.rows.append(row)

    def get_row_at_index(self, index):
        return self.rows[index] if 0 <= index < len(self.rows) else None

    def remove(self, row):
        self.operations.append("remove")
        self.rows.remove(row)
        row.parent = None

    def insert(self, row, position):
        self.operations.append(f"insert:{position}")
        row.parent = self
        if position < 0 or position >= len(self.rows):
            self.rows.append(row)
        else:
            self.rows.insert(position, row)

    def select_row(self, row):
        self.selection = row

    def contenus(self):
        return [row.get_child() for row in self.rows]


class FauxRow:
    def __init__(self, contenu, parent=None):
        self.contenu = contenu
        self.parent = parent

    def get_child(self):
        return self.contenu

    def get_parent(self):
        return self.parent

    def get_index(self):
        return self.parent.rows.index(self) if self.parent is not None else -1


@dataclass
class LigneFichier:
    label: str
    path: str


@dataclass
class LigneLive:
    label: str
    interface: str
    bpf_filter: str | None


# -- enumeration ----------------------------------------------------------------


def test_nombre_de_lignes_liste_vide():
    assert nombre_de_lignes(FauxListBox()) == 0


def test_nombre_de_lignes_compte_jusqu_au_premier_none():
    assert nombre_de_lignes(FauxListBox("abc")) == 3


def test_lignes_renvoie_les_contenus_dans_l_ordre_visuel():
    assert lignes(FauxListBox(["LAN", "WAN", "DC"])) == ["LAN", "WAN", "DC"]


def test_lignes_liste_vide():
    assert lignes(FauxListBox()) == []


# -- noms -----------------------------------------------------------------------


def test_nom_de_point_garde_le_nom_saisi():
    assert nom_de_point("LAN", 4) == "LAN"


@pytest.mark.parametrize(("index", "attendu"), [(0, "POINT1"), (1, "POINT2"), (9, "POINT10")])
def test_nom_de_point_numerote_a_partir_de_un(index, attendu):
    assert nom_de_point("", index) == attendu
    assert attendu.startswith(PREFIXE_POINT)


@pytest.mark.parametrize(
    ("chemin", "attendu"),
    [
        ("/tmp/lan-a.pcapng", "LAN-A"),
        ("wan.pcap", "WAN"),
        ("/data/capture.v2.pcap", "CAPTURE.V2"),
        ("/data/sans_extension", "SANS_EXTENSION"),
    ],
)
def test_nom_par_defaut_fichier(chemin, attendu):
    assert nom_par_defaut_fichier(chemin) == attendu


def test_nom_par_defaut_live_suit_le_nombre_de_lignes():
    assert nom_par_defaut_live(0) == "POINT1"
    assert nom_par_defaut_live(2) == "POINT3"


# -- captures -------------------------------------------------------------------


def test_captures_fichiers_ordre_et_noms_par_defaut():
    contenus = [LigneFichier("LAN", "/a.pcap"), LigneFichier("", "/b.pcap"), LigneFichier("DC", "/c.pcap")]
    assert captures_fichiers(contenus) == [("LAN", "/a.pcap"), ("POINT2", "/b.pcap"), ("DC", "/c.pcap")]


def test_captures_fichiers_numerote_par_position_et_non_par_rang_des_vides():
    """Le numero par defaut est la POSITION de la ligne : deux lignes sans nom
    en 1re et 3e position deviennent POINT1 et POINT3, jamais POINT1/POINT2,
    pour que le nom affiche corresponde a la place dans le chemin."""
    contenus = [LigneFichier("", "/a"), LigneFichier("WAN", "/b"), LigneFichier("", "/c")]
    assert [nom for nom, _ in captures_fichiers(contenus)] == ["POINT1", "WAN", "POINT3"]


def test_captures_live_conserve_interface_brute_et_filtre():
    contenus = [LigneLive("GW", "eth0, eth1", "tcp port 443"), LigneLive("", "wlan0", None)]
    assert captures_live(contenus) == [("GW", "eth0, eth1", "tcp port 443"), ("POINT2", "wlan0", None)]


def test_captures_vides():
    assert captures_fichiers([]) == []
    assert captures_live([]) == []


# -- deplacement ----------------------------------------------------------------


def test_monter_une_ligne():
    listbox = FauxListBox(["A", "B", "C"])
    row = listbox.rows[1]
    assert deplacer_ligne(row, vers_le_haut=True) is True
    assert listbox.contenus() == ["B", "A", "C"]
    assert listbox.selection is row


def test_descendre_une_ligne():
    listbox = FauxListBox(["A", "B", "C"])
    row = listbox.rows[1]
    assert deplacer_ligne(row, vers_le_haut=False) is True
    assert listbox.contenus() == ["A", "C", "B"]
    assert listbox.selection is row


def test_monter_la_premiere_ligne_ne_touche_pas_la_liste():
    listbox = FauxListBox(["A", "B"])
    assert deplacer_ligne(listbox.rows[0], vers_le_haut=True) is False
    assert listbox.operations == []
    assert listbox.selection is None


def test_descendre_la_derniere_ligne_ne_touche_pas_la_liste():
    """Borne qui manquait aux lignes live : l'ancien code retirait puis
    reinserait a ``idx + 1``, et seul l'ajout en fin de GTK gardait la
    ligne en place -- avec un clignotement de selection a chaque clic."""
    listbox = FauxListBox(["A", "B"])
    assert deplacer_ligne(listbox.rows[1], vers_le_haut=False) is False
    assert listbox.operations == []
    assert listbox.contenus() == ["A", "B"]


def test_deplacer_une_ligne_seule():
    listbox = FauxListBox(["A"])
    assert deplacer_ligne(listbox.rows[0], vers_le_haut=True) is False
    assert deplacer_ligne(listbox.rows[0], vers_le_haut=False) is False
    assert listbox.operations == []


def test_deplacer_une_ligne_detachee():
    assert deplacer_ligne(FauxRow("A"), vers_le_haut=True) is False


def test_allers_retours_restaurent_l_ordre():
    listbox = FauxListBox(["A", "B", "C", "D"])
    row = listbox.rows[0]
    for _ in range(5):  # descend jusqu'en bas, puis bute
        deplacer_ligne(row, vers_le_haut=False)
    assert listbox.contenus() == ["B", "C", "D", "A"]
    for _ in range(5):
        deplacer_ligne(row, vers_le_haut=True)
    assert listbox.contenus() == ["A", "B", "C", "D"]


# -- retrait --------------------------------------------------------------------


def test_retirer_previent_la_fenetre():
    """Correctif du lot : sans ce rappel, le bouton Lancer gardait l'etat
    calcule avant le retrait (actif avec une seule capture en comparaison)."""
    listbox = FauxListBox(["A", "B"])
    appels = []
    assert retirer_ligne(listbox.rows[0], lambda: appels.append(nombre_de_lignes(listbox))) is True
    assert listbox.contenus() == ["B"]
    assert appels == [1], "on_change doit etre appele APRES le retrait"


def test_retirer_sans_rappel():
    listbox = FauxListBox(["A"])
    assert retirer_ligne(listbox.rows[0]) is True
    assert listbox.contenus() == []


def test_retirer_une_ligne_detachee_ne_previent_personne():
    appels = []
    assert retirer_ligne(FauxRow("A"), lambda: appels.append(1)) is False
    assert appels == []


# -- garde-fous sur app.py (non importable en CI : PyGObject absent) ----------


def _appels_capture_list():
    arbre = ast.parse(APP_PY.read_text(encoding="utf-8"))
    return {
        noeud.attr
        for noeud in ast.walk(arbre)
        if isinstance(noeud, ast.Attribute) and isinstance(noeud.value, ast.Name) and noeud.value.id == "capture_list"
    }


def test_app_py_n_appelle_que_des_fonctions_existantes():
    """Une faute de frappe dans app.py ne casserait qu'au lancement de la GUI,
    qu'aucun test de la CI n'execute : ce test la voit a la place."""
    appels = _appels_capture_list()
    assert appels, "app.py devrait deleguer a capture_list"
    manquantes = {nom for nom in appels if not hasattr(capture_list, nom)}
    assert not manquantes, manquantes


def test_app_py_delegue_enumeration_deplacement_et_retrait():
    attendues = {
        "lignes",
        "captures_fichiers",
        "captures_live",
        "nom_par_defaut_fichier",
        "nom_par_defaut_live",
        "deplacer_ligne",
        "retirer_ligne",
    }
    assert attendues <= _appels_capture_list()


def test_les_deux_types_de_ligne_previennent_au_retrait():
    """Les deux ``_on_remove`` de app.py passent leur ``_on_change`` a
    ``retirer_ligne`` : c'est la condition du correctif, et la seule partie
    que les tests ci-dessus ne peuvent pas executer."""
    arbre = ast.parse(APP_PY.read_text(encoding="utf-8"))
    classes = {n.name: n for n in arbre.body if isinstance(n, ast.ClassDef)}
    for nom_classe in ("CaptureRow", "LiveCaptureRow"):
        methodes = {m.name: m for m in classes[nom_classe].body if isinstance(m, ast.FunctionDef)}
        appels = [
            n
            for n in ast.walk(methodes["_on_remove"])
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "retirer_ligne"
        ]
        assert len(appels) == 1, nom_classe
        assert ast.unparse(appels[0].args[1]) == "self._on_change", nom_classe
