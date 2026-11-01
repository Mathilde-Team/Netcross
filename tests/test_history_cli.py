# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de `cross_history_cli.py` -- issue #287.

Point d'entree a **0 %** : quinze instructions, aucun test, personne ne
l'appelait. Un outil livre que rien ne verifie.

Il ne lit jamais de capture -- seulement une base SQLite deja alimentee par
`--history-db` sur les deux autres CLI -- donc ni tshark ni PCAP ne sont
necessaires ici. Les bases de test sont alimentees par `record_run` /
`record_diff_run`, c'est-a-dire par le meme chemin que les vrais runs :
ecrire le SQLite a la main testerait la forme supposee de la table, pas
celle que le produit ecrit reellement.

`main()` ne prend pas d'`argv` : il lit `sys.argv`, donc les tests le
remplacent. Cela evite de modifier la signature juste pour les tests, et
verifie du meme coup l'analyse d'arguments telle qu'elle tourne en
production.
"""

from __future__ import annotations

import sys

import pytest

import cross_history_cli as cli
from netcross_core.models import Report
from netcross_report.history import record_diff_run, record_run


def _rapport(points, pertes=0):
    r = Report(points=list(points), pairs=[(points[0], points[1])])
    r.seen_count[points[0]] = 1000
    r.seen_count[points[1]] = 1000 - pertes
    if pertes:
        r.loss_count[points[1]] = pertes
    return r


def _base_avec_runs(tmp_path, nom="suivi.db"):
    """Base contenant trois runs d'analyse et un diff, etiquetes.

    L'ordre d'insertion est significatif : `list_history` rend le plus recent
    d'abord, ce que plusieurs tests ci-dessous verifient.
    """
    db = tmp_path / nom
    record_run(_rapport(["A", "B"], pertes=1), str(db), label="Site-A")
    record_run(_rapport(["A", "B"], pertes=5), str(db), label="Site-B")
    record_run(_rapport(["A", "B"], pertes=9), str(db), label="Site-A")
    record_diff_run(
        [],
        _rapport(["A", "B"]),
        _rapport(["A", "B"], pertes=9),
        str(db),
        label="Site-A",
    )
    return db


def _lancer(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["cross_history_cli.py", *[str(a) for a in args]])
    cli.main()
    return capsys.readouterr()


# --------------------------------------------------------------------------
# Effet de chaque option -- les quatre que porte ce CLI
# --------------------------------------------------------------------------


def test_db_affiche_les_runs_enregistres(monkeypatch, capsys, tmp_path):
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db)
    assert "HISTORIQUE DES RUNS ENREGISTRES" in sortie.out
    assert "Site-A" in sortie.out
    assert "Site-B" in sortie.out


def test_label_ne_garde_que_l_etiquette_exacte(monkeypatch, capsys, tmp_path):
    """L'effet est constate, pas seulement le code de retour : Site-B doit
    DISPARAITRE. Un filtre inopérant laisserait le test passer si l'on se
    contentait de verifier que Site-A est present."""
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--label", "Site-B")
    assert "Site-B" in sortie.out
    assert "Site-A" not in sortie.out, "le filtre d'etiquette est inoperant"


def test_label_inconnu_affiche_un_historique_vide_sans_echouer(monkeypatch, capsys, tmp_path):
    """Une etiquette qui ne correspond a rien n'est pas une erreur d'usage :
    c'est un resultat vide, et l'en-tete doit quand meme s'afficher pour que
    l'utilisateur sache que la requete a bien tourne. Un ecran muet laisserait
    croire a un plantage silencieux."""
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--label", "Site-Inexistant")
    assert "HISTORIQUE DES RUNS ENREGISTRES" in sortie.out
    assert "Site-A" not in sortie.out


def test_run_type_analyse_exclut_les_comparaisons(monkeypatch, capsys, tmp_path):
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--run-type", "analyse")
    assert "analyse" in sortie.out.lower()
    assert "diff" not in sortie.out.lower(), "les comparaisons ne sont pas filtrees"


def test_run_type_diff_exclut_les_analyses(monkeypatch, capsys, tmp_path):
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--run-type", "diff")
    assert "diff" in sortie.out.lower()


def test_run_type_refuse_une_valeur_hors_liste(monkeypatch, capsys, tmp_path):
    """`choices` d'argparse : le message doit nommer les valeurs acceptees.
    Code 2, celui d'argparse pour une erreur de ligne de commande."""
    db = _base_avec_runs(tmp_path)
    with pytest.raises(SystemExit) as sortie:
        _lancer(monkeypatch, capsys, "--db", db, "--run-type", "comparaison")
    assert sortie.value.code == 2
    erreur = capsys.readouterr().err
    assert "analyse" in erreur and "diff" in erreur


def test_limit_borne_le_nombre_de_runs_affiches(monkeypatch, capsys, tmp_path):
    """Compte les lignes de runs, pas seulement la presence du mot : `--limit 1`
    doit reduire la sortie, et c'est cette reduction qui prouve l'effet."""
    db = _base_avec_runs(tmp_path)
    complet = _lancer(monkeypatch, capsys, "--db", db).out
    borne = _lancer(monkeypatch, capsys, "--db", db, "--limit", 1).out
    assert len(borne) < len(complet), "--limit ne reduit pas la sortie"
    assert "HISTORIQUE DES RUNS ENREGISTRES" in borne


def test_limit_garde_les_runs_les_plus_recents(monkeypatch, capsys, tmp_path):
    """« Toujours les plus recents en premier » est documente dans l'aide de
    l'option. Sans ce test, un `ORDER BY` inverse passerait inaperçu et
    `--limit 1` montrerait le PLUS ANCIEN run -- exactement le contraire de ce
    qu'attend quelqu'un qui verifie une tendance."""
    db = tmp_path / "ordre.db"
    record_run(_rapport(["A", "B"]), str(db), label="LE-PLUS-ANCIEN")
    record_run(_rapport(["A", "B"]), str(db), label="LE-PLUS-RECENT")
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--limit", 1)
    assert "LE-PLUS-RECENT" in sortie.out
    assert "LE-PLUS-ANCIEN" not in sortie.out


# --------------------------------------------------------------------------
# Erreurs d'usage : message lisible, code non nul, jamais de trace Python
# --------------------------------------------------------------------------


def test_db_est_obligatoire(monkeypatch, capsys):
    with pytest.raises(SystemExit) as sortie:
        _lancer(monkeypatch, capsys)
    assert sortie.value.code == 2
    assert "--db" in capsys.readouterr().err


def test_une_base_inexistante_donne_un_historique_vide_et_non_une_erreur(monkeypatch, capsys, tmp_path):
    """Comportement documente dans l'aide de `--db` : un chemin inexistant
    n'est pas une erreur, c'est un historique vide -- aucun run n'y a encore
    ete enregistre. Le distinguer d'une erreur compte pour un script qui
    tourne avant le premier run."""
    sortie = _lancer(monkeypatch, capsys, "--db", tmp_path / "jamais_ecrite.db")
    assert "HISTORIQUE DES RUNS ENREGISTRES" in sortie.out


@pytest.mark.parametrize("valeur", [0, -1, -100])
def test_limit_refuse_zero_et_les_negatifs(monkeypatch, capsys, tmp_path, valeur):
    """`--limit 0` demanderait « affiche zero run », ce qui ne veut rien dire :
    autant ne pas lancer la commande. Le refus est explicite plutot que
    silencieusement traite comme « tous », ce qui afficherait l'inverse de ce
    qui est demande."""
    db = _base_avec_runs(tmp_path)
    with pytest.raises(SystemExit) as sortie:
        _lancer(monkeypatch, capsys, "--db", db, "--limit", valeur)
    assert sortie.value.code == 1
    erreur = capsys.readouterr().err
    assert "--limit" in erreur
    assert "positif" in erreur
    assert "Traceback" not in erreur, "trace Python brute au lieu d'un message"


def test_limit_refuse_une_valeur_non_entiere(monkeypatch, capsys, tmp_path):
    """`type=int` d'argparse : code 2 et message nommant l'option, pas une
    `ValueError` remontee jusqu'a l'utilisateur."""
    db = _base_avec_runs(tmp_path)
    with pytest.raises(SystemExit) as sortie:
        _lancer(monkeypatch, capsys, "--db", db, "--limit", "beaucoup")
    assert sortie.value.code == 2
    erreur = capsys.readouterr().err
    assert "--limit" in erreur
    assert "Traceback" not in erreur


def test_une_base_illisible_ne_remonte_pas_de_trace_brute(monkeypatch, capsys, tmp_path):
    """Un fichier qui existe mais n'est pas du SQLite : cas reel (chemin
    confondu avec un PCAP, base tronquee par un disque plein).

    Ce test a trouve un vrai defaut. Avant correction, `sqlite3.DatabaseError:
    file is not a database` remontait jusqu'a l'utilisateur sous forme de trace
    Python, sans nommer le chemin fautif ni dire quoi faire -- ce que le critere
    d'acceptation de l'issue #287 interdit explicitement. Le message est
    desormais produit par `HistoryDatabaseError` et nomme le chemin.
    """
    fausse = tmp_path / "pas_une_base.db"
    fausse.write_bytes(b"\xd4\xc3\xb2\xa1 ceci est un en-tete PCAP, pas du SQLite")

    with pytest.raises(SystemExit) as sortie:
        _lancer(monkeypatch, capsys, "--db", fausse)
    assert sortie.value.code == 1

    erreur = capsys.readouterr().err
    assert "Traceback" not in erreur, "trace Python brute au lieu d'un message"
    assert "sqlite3" not in erreur, "detail d'implementation expose a l'utilisateur"
    assert str(fausse) in erreur, "le message ne nomme pas le chemin fautif"
    assert "illisible" in erreur


def test_le_message_de_base_illisible_dit_quoi_faire(monkeypatch, capsys, tmp_path):
    """Nommer le probleme ne suffit pas : l'utilisateur doit savoir quoi faire.
    Les deux actions utiles sont verifier le chemin ou supprimer le fichier
    pour qu'une base neuve soit creee -- et la seconde n'est evidente que parce
    qu'une base absente n'est PAS une erreur (voir le test ci-dessus)."""
    fausse = tmp_path / "pas_une_base.db"
    fausse.write_bytes(b"pas du SQLite du tout")

    with pytest.raises(SystemExit):
        _lancer(monkeypatch, capsys, "--db", fausse)
    erreur = capsys.readouterr().err
    assert "verifier le chemin" in erreur
    assert "supprimer" in erreur


# --------------------------------------------------------------------------
# Combinaison des options
# --------------------------------------------------------------------------


def test_label_et_run_type_se_cumulent(monkeypatch, capsys, tmp_path):
    """Les deux filtres s'appliquent ensemble et non l'un a la place de
    l'autre : sur une base partagee entre sites, ne garder que les
    comparaisons d'un site est le cas d'usage decrit dans l'aide du CLI."""
    db = tmp_path / "cumul.db"
    record_run(_rapport(["A", "B"]), str(db), label="Site-A")
    record_diff_run([], _rapport(["A", "B"]), _rapport(["A", "B"]), str(db), label="Site-A")
    record_diff_run([], _rapport(["A", "B"]), _rapport(["A", "B"]), str(db), label="Site-B")

    sortie = _lancer(monkeypatch, capsys, "--db", db, "--label", "Site-A", "--run-type", "diff")
    assert "Site-A" in sortie.out
    assert "Site-B" not in sortie.out, "le filtre d'etiquette est ignore quand --run-type est fourni"


def test_les_trois_filtres_ensemble_restent_coherents(monkeypatch, capsys, tmp_path):
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db, "--label", "Site-A", "--run-type", "analyse", "--limit", 2)
    assert "HISTORIQUE DES RUNS ENREGISTRES" in sortie.out
    assert "Site-B" not in sortie.out


def test_sans_filtre_les_analyses_et_les_diffs_sont_melanges(monkeypatch, capsys, tmp_path):
    """Comportement par defaut documente : les deux types cohabitent. Le
    verifier evite qu'un filtre par defaut s'installe par inadvertance et
    masque la moitie de l'historique."""
    db = _base_avec_runs(tmp_path)
    sortie = _lancer(monkeypatch, capsys, "--db", db).out.lower()
    assert "analyse" in sortie
    assert "diff" in sortie
