# SPDX-License-Identifier: GPL-3.0-or-later
"""Non-régression de performance (issue #1019) : comparateur de
``netcross_core.testing.bench``, référence versionnée et workflow."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import pytest
import yaml

from netcross_core.testing import bench

RACINE = bench.RACINE
REFERENCE = RACINE / "benchmarks" / "reference.json"
WORKFLOW = RACINE / ".github" / "workflows" / "bench.yml"

ENV = dict.fromkeys(bench.CLES_ENVIRONNEMENT, "x") | {"cpu": "Xeon test", "coeurs_utilisables": 4}


def _essai(jeu="p3-n100000-g1", parallele=1, total=10.0, rss=500.0, rss_enfants=600.0):
    return {
        "jeu": jeu,
        "points": 3,
        "paquets": 300_000,
        "parallele": parallele,
        "repetitions": 3,
        "total_s": total,
        "durees_totales_s": [total],
        "mur_s": total + 1,
        "etapes_s": dict.fromkeys(bench.ETAPES_STANDARD, total / 4),
        "rss_max_mio": rss,
        "rss_max_enfants_mio": rss_enfants,
        "paquets_par_s": round(300_000 / total),
    }


def _resultat(*essais, env=None):
    return {
        "schema": bench.SCHEMA,
        "version": bench.VERSION_SCHEMA,
        "date": "2026-11-08T00:00:00Z",
        "environnement": dict(ENV if env is None else env),
        "essais": list(essais) or [_essai()],
    }


# -- comparer ------------------------------------------------------------------


def test_regression_de_duree_simulee_echoue():
    reference = _resultat(_essai(total=10.0))
    comparaison = bench.comparer(_resultat(_essai(total=12.5)), reference)
    assert comparaison["statut"] == "regression"
    ligne = next(ligne for ligne in comparaison["lignes"] if ligne["mesure"] == "total_s")
    assert ligne == {
        "jeu": "p3-n100000-g1",
        "parallele": 1,
        "mesure": "total_s",
        "reference": 10.0,
        "actuel": 12.5,
        "ecart_pct": 25.0,
        "seuil_pct": 20.0,
        "regression": True,
    }


@pytest.mark.parametrize("mesure", ["rss_max_mio", "rss_max_enfants_mio"])
def test_regression_memoire_simulee_echoue(mesure):
    actuel = _essai()
    actuel[mesure] *= 1.5
    comparaison = bench.comparer(_resultat(actuel), _resultat(_essai()))
    assert comparaison["statut"] == "regression"
    assert [ligne["mesure"] for ligne in comparaison["lignes"] if ligne["regression"]] == [mesure]


def test_amelioration_ou_ecart_sous_le_seuil_reussit():
    reference = _resultat(_essai(total=10.0), _essai(parallele=2, total=8.0))
    actuel = _resultat(_essai(total=6.0, rss=300.0), _essai(parallele=2, total=9.5, rss=590.0))
    comparaison = bench.comparer(actuel, reference)
    assert comparaison["statut"] == "ok"
    assert not any(ligne["regression"] for ligne in comparaison["lignes"])
    assert len(comparaison["lignes"]) == 6


def test_ecart_exactement_au_seuil_reussit():
    assert bench.comparer(_resultat(_essai(total=12.0)), _resultat(_essai(total=10.0)))["statut"] == "ok"


def test_seuils_configurables():
    reference, actuel = _resultat(_essai(total=10.0)), _resultat(_essai(total=11.0))
    assert bench.comparer(actuel, reference, seuil_duree_pct=5)["statut"] == "regression"
    assert bench.comparer(actuel, reference, seuil_duree_pct=50)["statut"] == "ok"
    memoire = _resultat(_essai(rss=550.0))
    assert bench.comparer(memoire, _resultat(_essai()), seuil_memoire_pct=5)["statut"] == "regression"


def test_environnement_different_non_compare():
    autre = ENV | {"cpu": "AMD EPYC"}
    comparaison = bench.comparer(_resultat(_essai(total=99.0), env=autre), _resultat(_essai()))
    assert comparaison["statut"] == "environnement_different"
    assert comparaison["environnement"] == [{"cle": "cpu", "reference": "Xeon test", "actuel": "AMD EPYC"}]
    assert comparaison["lignes"] == []


def test_essai_absent_incomparable():
    reference = _resultat(_essai(), _essai(parallele=2))
    comparaison = bench.comparer(_resultat(_essai()), reference)
    assert comparaison["statut"] == "incomparable"
    assert comparaison["manquants"] == [{"jeu": "p3-n100000-g1", "parallele": 2}]


def test_mesure_absente_ou_reference_nulle_ignoree():
    reference = _essai(rss=None, total=10.0)
    reference["rss_max_enfants_mio"] = 0.0
    comparaison = bench.comparer(_resultat(_essai()), _resultat(reference))
    assert comparaison["statut"] == "ok"
    mesures = {ligne["mesure"]: ligne for ligne in comparaison["lignes"]}
    assert set(mesures) == {"total_s", "rss_max_enfants_mio"}
    assert mesures["rss_max_enfants_mio"]["ecart_pct"] is None


def test_ecart_pct():
    assert bench._ecart_pct(12.0, 10.0) == 20.0
    assert bench._ecart_pct(5.0, 10.0) == -50.0
    assert bench._ecart_pct(1.0, 0) is None


# -- rendu Markdown --------------------------------------------------------------


def test_markdown_regression():
    texte = bench.comparaison_en_markdown(bench.comparer(_resultat(_essai(total=13.0)), _resultat(_essai())))
    assert texte.startswith("## Non-régression : RÉGRESSION")
    assert "| p3-n100000-g1 | 1 | total_s | 10.000 | 13.000 | +30.0 | 20 | régression |" in texte


def test_markdown_environnement_et_manquants():
    env = bench.comparaison_en_markdown(bench.comparer(_resultat(env=ENV | {"coeurs_utilisables": 2}), _resultat()))
    assert "autre environnement" in env
    assert "- `coeurs_utilisables` : référence 4, actuel 2" in env
    manquant = bench.comparaison_en_markdown(bench.comparer(_resultat(), _resultat(_essai(), _essai(parallele=8))))
    assert "- essai absent : p3-n100000-g1 avec --parallel 8" in manquant
    assert "| Jeu |" in manquant


# -- ligne de commande --------------------------------------------------------


def _ecrire(chemin: Path, donnees) -> str:
    chemin.write_text(json.dumps(donnees), encoding="utf-8")
    return str(chemin)


def test_main_resultat_sans_regression(tmp_path, capsys):
    ref = _ecrire(tmp_path / "ref.json", _resultat())
    res = _ecrire(tmp_path / "res.json", _resultat(_essai(total=9.0)))
    resume = tmp_path / "resume.md"
    resume.write_text("début\n", encoding="utf-8")
    assert bench.main(["--resultat", res, "--reference", ref, "--resume", str(resume)]) == 0
    sortie = capsys.readouterr().out
    assert "aucune régression" in sortie
    assert resume.read_text(encoding="utf-8") == "début\n" + sortie


def test_main_regression_code_3(tmp_path, capsys):
    ref = _ecrire(tmp_path / "ref.json", _resultat())
    res = _ecrire(tmp_path / "res.json", _resultat(_essai(total=20.0)))
    assert bench.main(["--resultat", res, "--reference", ref]) == bench.CODE_REGRESSION
    assert bench.main(["--resultat", res, "--reference", ref, "--seuil-duree", "150"]) == 0
    assert "RÉGRESSION" in capsys.readouterr().out


def test_main_incomparable_code_2(tmp_path):
    ref = _ecrire(tmp_path / "ref.json", _resultat(_essai(), _essai(parallele=2)))
    res = _ecrire(tmp_path / "res.json", _resultat())
    assert bench.main(["--resultat", res, "--reference", ref]) == 2


def test_main_environnement_different_code_0(tmp_path, capsys):
    ref = _ecrire(tmp_path / "ref.json", _resultat())
    res = _ecrire(tmp_path / "res.json", _resultat(_essai(total=50.0), env=ENV | {"cpu": "autre"}))
    assert bench.main(["--resultat", res, "--reference", ref]) == 0
    assert "autre environnement" in capsys.readouterr().out


def test_main_mesure_puis_compare(tmp_path):
    from tests.test_bench import Executeur

    dossier = tmp_path / "p2-n200-g1"
    bench_synth = pytest.importorskip("netcross_core.testing.synth")
    bench_synth.generer(bench_synth.Configuration(points=2, paquets=200, graine=1), dossier)
    sortie = tmp_path / "banc.json"
    assert bench.main(["--jeux", str(dossier), "--json", str(sortie)], executeur=Executeur(durees=(1.0,))) == 0
    reference = json.loads(sortie.read_text(encoding="utf-8"))
    ref = _ecrire(tmp_path / "ref.json", reference)
    lent = Executeur(durees=(2.0,))
    assert bench.main(["--jeux", str(dossier), "--reference", ref], executeur=lent) == bench.CODE_REGRESSION


def test_main_fichiers_invalides(tmp_path, capsys):
    ref = _ecrire(tmp_path / "ref.json", _resultat())
    assert bench.main(["--resultat", str(tmp_path / "absent.json"), "--reference", ref]) == 2
    assert bench.main(["--resultat", _ecrire(tmp_path / "liste.json", []), "--reference", ref]) == 2
    assert bench.main(["--resultat", _ecrire(tmp_path / "vide.json", {}), "--reference", ref]) == 2
    (tmp_path / "casse.json").write_text("{", encoding="utf-8")
    assert bench.main(["--resultat", str(tmp_path / "casse.json"), "--reference", ref]) == 2
    err = capsys.readouterr().err
    assert "illisible" in err
    assert "non conforme" in err


def test_main_resultat_exige_reference(tmp_path, capsys):
    with pytest.raises(SystemExit):
        bench.main(["--resultat", _ecrire(tmp_path / "res.json", _resultat())])
    assert "--resultat exige --reference" in capsys.readouterr().err


def test_pourcentage():
    assert bench._pourcentage("12.5") == 12.5
    assert bench._pourcentage("0") == 0.0
    for faux in ("-1", "beaucoup"):
        with pytest.raises(argparse.ArgumentTypeError):
            bench._pourcentage(faux)


# -- référence versionnée et workflow ------------------------------------------


def test_reference_versionnee_conforme():
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
    assert bench.valider(reference) == []
    assert {(e["jeu"], e["parallele"]) for e in reference["essais"]} == {("p3-n100000-g1", 1), ("p3-n100000-g1", 2)}
    # la référence se compare à elle-même sans régression
    assert bench.comparer(copy.deepcopy(reference), reference)["statut"] == "ok"


def test_workflow_hebdomadaire_et_a_la_demande_pas_sur_les_pr():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    declencheurs = workflow.get("on", workflow.get(True))
    assert set(declencheurs) == {"schedule", "workflow_dispatch"}
    assert declencheurs["schedule"][0]["cron"]
    entrees = declencheurs["workflow_dispatch"]["inputs"]
    assert {"ref", "seuil_duree", "seuil_memoire"} <= set(entrees)
    texte = WORKFLOW.read_text(encoding="utf-8")
    assert "benchmarks/reference.json" in texte
    assert "GITHUB_STEP_SUMMARY" in texte
    assert "actions/upload-artifact" in texte
    assert "--points 3 --paquets 100000" in texte
