# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests app.py -- onglet Incidents (issue #1095, chantier #1001).

Périmètre : la quatrième page de la pile (« Incidents »), son formulaire de
configuration du gel rétroactif et sa liste d'incidents archivés. La logique
pure (validation, sérialisation, inventaire) est couverte sans GTK par
``tests/test_incidents_panel.py`` : on vérifie ici le câblage de la vraie
fenêtre -- saisie sauvegardée dans le fichier partagé, liste alimentée depuis
les archives, analyse lancée en thread.

Même garde-fou que les autres lots (#285/#421) : aucun test n'exige GTK4 en
CI ; le module saute proprement sans pygobject, GTK4 ou affichage.

Le fichier de réglages partagé (~/.netcross/gel_config.json) n'est PAS
touché : chaque test redirige ``CHEMIN_DEFAUT`` vers son tmp.
"""

import json
from pathlib import Path

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

from netcross_core import gel_settings  # noqa: E402
from netcross_gtk4 import incidents_panel as panel  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402


@pytest.fixture
def tmp_home(monkeypatch, tmp_path):
    """Réglages partagés redirigés vers le tmp du test."""
    cible = tmp_path / ".netcross" / "gel_config.json"
    monkeypatch.setattr(gel_settings, "CHEMIN_DEFAUT", cible)
    return tmp_path


@pytest.fixture
def journal(monkeypatch, window):
    """Capte les messages de la fenêtre au lieu de les afficher."""
    messages = []
    monkeypatch.setattr(window, "_log", messages.append)
    return messages


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test1095")
    app.register(None)
    return MainWindow(app)


def _archive(archives: Path, incident: str) -> Path:
    """Crée l'archive d'un incident : ``<archives>/<incident>/incident/``
    avec son manifeste complet (même format que ``archiver_incident``) --
    l'alarme, la fenêtre et les fichiers, sinon le manifeste est jugé
    illisible et la ligne ne montre pas l'état des rapports."""
    dossier_incident = archives / incident / "incident"
    dossier_incident.mkdir(parents=True)
    (dossier_incident / "manifeste.json").write_text(
        json.dumps(
            {
                "incident": incident,
                "alarme": {"timestamp": 1119600000, "rule_id": "AlarmeRSSI"},
                "fenetre": {"debut": 1119599940.0, "fin": 1119600030.0},
                "fichiers": [
                    {
                        "point": "LAN",
                        "source": "capture.pcapng",
                        "segment": "segment.pcapng",
                        "empreinte": "aa",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return dossier_incident


# ============ page présente dans la pile, saisie sauvegardée ============


def test_pile_contient_la_page_incidents(window):
    assert window.stack.get_child_by_name("incidents") is not None


def test_saisie_sauvergardee_dans_le_fichier_partage(window, tmp_home, journal):
    archives = tmp_home / ".netcross" / "incidents"

    window.gel_seconds_before_spin.set_value(90)
    window.gel_seconds_after_spin.set_value(45)
    window.gel_min_delay_spin.set_value(20)
    window.gel_quota_spin.set_value(0)
    window.gel_severity_dropdown.set_selected(1)  # a_surveiller
    window.gel_archives_entry.set_text(str(archives))

    window._on_gel_save(None)

    attendu = tmp_home / ".netcross" / "gel_config.json"
    assert attendu.is_file(), "la sauvegarde doit écrire le fichier partagé"
    ecrits = json.loads(attendu.read_text(encoding="utf-8"))
    assert ecrits["seconds_before"] == 90
    assert ecrits["seconds_after"] == 45
    assert ecrits["min_delay_between_gels"] == 20
    assert ecrits["min_severity"] == "a_surveiller"
    assert ecrits["max_octets_archives"] is None
    assert ecrits["archives_dir"] == str(archives)
    assert any("Réglages du gel enregistrés" in m for m in journal)


def test_saisie_invalide_refusee_sans_ecriture(window, tmp_home, journal):
    # Le répertoire d'archives vide est refusé : le message doit le dire,
    # et rien ne doit être écrit (l'ancien réglage reste intact).
    window.gel_archives_entry.set_text("   ")
    window._on_gel_save(None)
    attendu = tmp_home / ".netcross" / "gel_config.json"
    assert not attendu.exists(), "une saisie invalide ne doit rien écrire"
    assert any("Réglages refusés" in m for m in journal)


def test_rechargement_depuis_le_fichier(window, tmp_home):
    ecrire = dict(gel_settings.REGLAGES_DEFAUT)
    ecrire["seconds_before"] = 120
    panel.ecrire_reglages_partages(ecrire)
    window._charge_reglages_gel()
    assert window.gel_seconds_before_spin.get_value() == 120


# ===================== liste des incidents archivés =====================


def test_liste_vide_message_explicite(window, tmp_home):
    window._refresh_incidents()
    etiquette = window.incidents_list.get_first_child()
    assert etiquette is not None, "la liste doit toujours montrer quelque chose"
    assert "Aucun incident archivé" in etiquette.get_child().get_label()


def test_liste_incidents_alimentee(window, tmp_home):
    _archive(tmp_home / ".netcross" / "incidents", "incident-6f4d9e")
    panel.ecrire_reglages_partages(
        {**gel_settings.REGLAGES_DEFAUT, "archives_dir": str(tmp_home / ".netcross" / "incidents")}
    )

    window._refresh_incidents()

    ligne = window.incidents_list.get_first_child()
    assert ligne is not None, "l'incident archivé doit apparaître dans la liste"
    texte = ligne.get_child().get_first_child().get_label()
    assert "incident-6f4d9e" in texte
    assert "aucun rapport" in texte  # pas encore analysé
    # La ligne porte son bouton « Analyser » : c'est lui qui lance #1091.
    assert ligne.get_last_child() is not None


def test_analyse_lancee_dans_un_thread(window, tmp_home, monkeypatch):
    # Le clic « Analyser » doit démarrer le worker de fond (thread démon :
    # il ne doit pas retenir la fermeture de l'application), pas bloquer la
    # boucle GTK ; l'analyse réelle (#1091) est couverte par ses propres
    # tests, on vérifie ici la transmission du nom d'incident.
    captures = []

    class _FauxThread:
        def __init__(self, *args, **kwargs):
            captures.append(kwargs)

        def start(self):
            captures.append("start")

    monkeypatch.setattr("netcross_gtk4.app.threading.Thread", _FauxThread)

    window._on_analyser_incident("incident-6f4d9e")

    assert captures[0]["args"] == ("incident-6f4d9e",)
    assert captures[0]["daemon"] is True
    assert captures[0]["target"] == window._analyser_incident_worker
    assert captures[1] == "start"
