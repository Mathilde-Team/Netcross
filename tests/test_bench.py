# SPDX-License-Identifier: GPL-3.0-or-later
"""Banc de performance ``netcross_core.testing.bench`` (issue #1017).

Les tests unitaires remplacent l'analyse par un exécuteur factice qui écrit
le fichier ``--profile-steps`` attendu ; un test d'intégration (tshark requis)
lance le vrai banc sur le mini-jeu et vérifie le schéma du JSON produit.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from netcross_core.testing import bench
from netcross_core.testing.synth import Configuration, generer

TSHARK = shutil.which("tshark")


def _mesures(total: float) -> dict:
    """Contenu ``--profile-steps`` minimal (format 1 de #1016)."""
    part = total / 4
    return {
        "format": 1,
        "total_s": total,
        "etapes": {nom: {"secondes": part, "passages": 1} for nom in bench.ETAPES_STANDARD},
        "rss_max_ko": 102_400,
        "rss_max_enfants_ko": 51_200,
        "tracemalloc": False,
    }


class Executeur:
    """Faux exécuteur : écrit des mesures de durées données, garde les commandes."""

    def __init__(self, durees=(1.0,), code=0, ecrire=True):
        self.durees = list(durees)
        self.code = code
        self.ecrire = ecrire
        self.commandes = []

    def __call__(self, cmd):
        self.commandes.append(cmd)
        if self.ecrire:
            fichier = Path(cmd[cmd.index("--profile-steps") + 1])
            duree = self.durees[(len(self.commandes) - 1) % len(self.durees)]
            fichier.write_text(json.dumps(_mesures(duree)), encoding="utf-8")
        return self.code


@pytest.fixture
def jeu(tmp_path):
    """Petit jeu synthétique de 3 points (sans tshark)."""
    dossier = tmp_path / "p3-n300-g2"
    generer(Configuration(points=3, paquets=300, graine=2), dossier)
    return dossier


ENV = dict.fromkeys(bench.CLES_ENVIRONNEMENT, "x") | {"ram_mio": None, "tshark": None}


# -- environnement -------------------------------------------------------------


def test_lire_fichier_absent(tmp_path):
    assert bench._lire(str(tmp_path / "absent")) == ""


def test_modele_cpu_depuis_cpuinfo():
    assert bench.modele_cpu("processor : 0\nmodel name\t: Xeon test\n") == "Xeon test"
    assert bench.modele_cpu("Hardware : BCM2835\n") == "BCM2835"


def test_modele_cpu_repli_platform(monkeypatch):
    monkeypatch.setattr(bench.platform, "processor", lambda: "")
    monkeypatch.setattr(bench.platform, "machine", lambda: "riscv64")
    assert bench.modele_cpu("model name :\n") == "riscv64"
    monkeypatch.setattr(bench.platform, "machine", lambda: "")
    assert bench.modele_cpu("") == "inconnu"


def test_modele_cpu_lit_proc_par_defaut(monkeypatch):
    monkeypatch.setattr(bench, "_lire", lambda chemin: "model name : lu dans " + chemin)
    assert bench.modele_cpu() == "lu dans /proc/cpuinfo"


def test_ram_mio():
    assert bench.ram_mio("MemTotal:       8148244 kB\n") == 7957
    assert bench.ram_mio("MemTotal: inconnu\n") is None
    assert bench.ram_mio("MemTotal:\n") is None
    assert bench.ram_mio("") is None
    assert isinstance(bench.ram_mio(), (int, type(None)))


def test_coeurs_utilisables(monkeypatch):
    assert bench.coeurs_utilisables(lambda _pid: {0, 1, 2}) == 3
    monkeypatch.setattr(bench.os, "cpu_count", lambda: None)
    assert bench.coeurs_utilisables(None) == 1
    assert bench.coeurs_utilisables() >= 1


def test_version_tshark_absent(monkeypatch):
    monkeypatch.setattr(bench.shutil, "which", lambda _nom: None)
    assert bench.version_tshark() is None


def _faux_binaire(tmp_path, script):
    chemin = tmp_path / "faux-tshark"
    chemin.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    chemin.chmod(0o755)
    return str(chemin)


def test_version_tshark_lue(tmp_path):
    assert bench.version_tshark(_faux_binaire(tmp_path, "echo 'TShark 9.9'\necho suite\n")) == "TShark 9.9"


def test_version_tshark_sortie_vide(tmp_path):
    assert bench.version_tshark(_faux_binaire(tmp_path, "exit 0\n")) is None


def test_version_tshark_echec_lancement(tmp_path):
    assert bench.version_tshark(str(tmp_path / "inexistant")) is None


def test_version_netcross(monkeypatch):
    assert bench.version_netcross()

    def absent(_nom):
        raise metadata.PackageNotFoundError("netcross")

    monkeypatch.setattr(metadata, "version", absent)
    assert bench.version_netcross() == "inconnue"


def test_environnement_complet():
    env = bench.environnement()
    assert set(bench.CLES_ENVIRONNEMENT) <= set(env)
    assert env["coeurs_utilisables"] <= env["coeurs_logiques"]


# -- jeux ----------------------------------------------------------------------


def test_trouver_jeux_unique_et_matrice(jeu, tmp_path):
    assert bench.trouver_jeux(jeu) == [jeu]
    autre = tmp_path / "p2-n100-g1"
    generer(Configuration(points=2, paquets=100), autre)
    (tmp_path / "vide").mkdir()
    assert bench.trouver_jeux(tmp_path) == [autre, jeu]


def test_trouver_jeux_aucun(tmp_path):
    with pytest.raises(bench.BancError, match="aucun jeu"):
        bench.trouver_jeux(tmp_path)
    with pytest.raises(bench.BancError):
        bench.trouver_jeux(tmp_path / "absent")


def test_lire_verite_fichier_manquant(jeu):
    (jeu / "P2.pcapng").unlink()
    with pytest.raises(bench.BancError, match="P2"):
        bench.lire_verite(jeu)


# -- exécution -----------------------------------------------------------------


def test_commande_analyse(jeu, tmp_path):
    verite = bench.lire_verite(jeu)
    seq = bench.commande_analyse(jeu, verite, 1, tmp_path / "m.json", python="py")
    assert seq[:2] == ["py", str(bench.CLI)]
    assert seq.count("--capture") == 3
    assert f"P2={jeu / 'P2.pcapng'}" in seq
    assert seq[seq.index("--order") + 1] == "P1,P2,P3"
    assert "--parallel" not in seq
    par = bench.commande_analyse(jeu, verite, 4, tmp_path / "m.json")
    assert par[-3:] == ["--parallel", "--parallel-workers", "4"]


def test_executer_renvoie_le_code():
    assert bench.executer([sys.executable, "-c", "print('ignoré')"]) == 0
    assert bench.executer([sys.executable, "-c", "raise SystemExit(3)"]) == 3


def test_mesurer_essai_median(jeu):
    executeur = Executeur(durees=(3.0, 1.0, 2.0))
    horloge = iter(range(100)).__next__
    essai = bench.mesurer(jeu, 2, repetitions=3, executeur=executeur, horloge=horloge)
    assert essai["total_s"] == 2.0
    assert essai["durees_totales_s"] == [3.0, 1.0, 2.0]
    assert essai["mur_s"] == 1
    assert essai["points"] == 3
    assert essai["paquets"] == sum(bench.lire_verite(jeu)["paquets_par_point"].values())
    assert essai["paquets_par_s"] == round(essai["paquets"] / 2.0)
    assert essai["rss_max_mio"] == 100.0
    assert essai["rss_max_enfants_mio"] == 50.0
    assert set(essai["etapes_s"]) == set(bench.ETAPES_STANDARD)
    assert len(executeur.commandes) == 3


def test_mesurer_total_nul(jeu):
    assert bench.mesurer(jeu, 1, executeur=Executeur(durees=(0.0,)))["paquets_par_s"] is None


@pytest.mark.parametrize("executeur", [Executeur(code=1), Executeur(ecrire=False)], ids=["code", "sans-mesures"])
def test_mesurer_analyse_en_echec(jeu, executeur):
    with pytest.raises(bench.BancError, match="en échec"):
        bench.mesurer(jeu, 1, executeur=executeur)


def test_lancer_jeux_par_paralleles(jeu):
    resultat = bench.lancer([jeu], [1, 2], executeur=Executeur(), env=ENV)
    assert [e["parallele"] for e in resultat["essais"]] == [1, 2]
    assert bench.valider(resultat) == []
    complet = bench.lancer([jeu], [1], executeur=Executeur())
    assert set(bench.CLES_ENVIRONNEMENT) <= set(complet["environnement"])


# -- schéma et rendu -----------------------------------------------------------


def test_valider_signale_les_ecarts(jeu):
    assert bench.valider({}) == [
        "schema différent de netcross-bench",
        "version différente de 1",
        "date absente",
        "environnement absent",
        "aucun essai",
    ]
    resultat = bench.lancer([jeu], [1], executeur=Executeur(), env=ENV)
    del resultat["environnement"]["cpu"]
    essai = resultat["essais"][0]
    del essai["mur_s"]
    del essai["etapes_s"]["rapport"]
    essai["total_s"] = 0
    assert bench.valider(resultat) == [
        "environnement.cpu absent",
        "essais[0].mur_s absent",
        "essais[0].etapes_s.rapport absent",
        "essais[0].total_s non positif",
    ]


def test_en_markdown(jeu):
    resultat = bench.lancer([jeu], [1], executeur=Executeur(durees=(0.0,)), env=ENV)
    texte = bench.en_markdown(resultat)
    assert "tshark absent" in texte
    assert "RAM : n/d Mio" in texte
    ligne = texte.strip().splitlines()[-1]
    assert ligne.startswith("| p3-n300-g2 | 3 |")
    assert ligne.endswith("| 100.0 | 50.0 | n/d |")
    assert texte.count("| lecture (s) |") == 1


# -- ligne de commande --------------------------------------------------------


def test_liste_paralleles():
    assert bench._liste_paralleles("1, 2,4,") == [1, 2, 4]
    for faux in ("", "0,1", "un"):
        with pytest.raises(argparse.ArgumentTypeError):
            bench._liste_paralleles(faux)


def test_main_jeux_ecrit_json_et_markdown(jeu, tmp_path, capsys):
    sortie_json = tmp_path / "banc.json"
    sortie_md = tmp_path / "banc.md"
    code = bench.main(
        ["--jeux", str(jeu), "--parallel", "1,2", "--json", str(sortie_json), "--markdown", str(sortie_md)],
        executeur=Executeur(),
    )
    assert code == 0
    resultat = json.loads(sortie_json.read_text(encoding="utf-8"))
    assert bench.valider(resultat) == []
    assert sortie_md.read_text(encoding="utf-8") == capsys.readouterr().out


def test_main_mini(capsys):
    executeur = Executeur()
    assert bench.main(["--mini"], executeur=executeur) == 0
    assert "| mini | 2 | " in capsys.readouterr().out
    assert executeur.commandes[0].count("--capture") == 2


def test_main_jeu_absent(tmp_path, capsys):
    assert bench.main(["--jeux", str(tmp_path)], executeur=Executeur()) == 2
    assert "aucun jeu" in capsys.readouterr().err


def test_main_refuse_les_options_invalides(capsys):
    with pytest.raises(SystemExit):
        bench.main(["--mini", "--repetitions", "0"])
    with pytest.raises(SystemExit):
        bench.main([])
    assert "--repetitions" in capsys.readouterr().err


def test_script_enveloppe():
    sortie = subprocess.run(
        [sys.executable, str(bench.RACINE / "scripts" / "bench.py"), "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--parallel" in sortie.stdout


# -- intégration (vraie analyse) -----------------------------------------------


@pytest.mark.skipif(TSHARK is None, reason="tshark absent")
def test_banc_mini_produit_le_schema_attendu(tmp_path):
    sortie = tmp_path / "banc.json"
    assert bench.main(["--mini", "--json", str(sortie)]) == 0
    resultat = json.loads(sortie.read_text(encoding="utf-8"))
    assert bench.valider(resultat) == []
    essai = resultat["essais"][0]
    assert essai["jeu"] == "mini"
    assert essai["paquets"] == 4_000
    assert essai["paquets_par_s"] > 0
    assert resultat["environnement"]["tshark"].startswith("TShark")
