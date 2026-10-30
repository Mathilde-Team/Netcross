"""Inventaire des détecteurs (issue #1020) : aucun oubli, doc à jour."""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from netcross_core import detector_inventory as inv
from netcross_core.exploit_signatures import available_detectors
from netcross_core.models import Report

RACINE = Path(__file__).resolve().parents[1]
ANALYSIS = RACINE / "src" / "netcross_core" / "analysis.py"
FINDINGS = RACINE / "src" / "netcross_core" / "security" / "findings.py"
DOC = RACINE / "docs" / "detectors.md"


def _phases_analyse() -> set[str]:
    """Noms des ``with _phase("...")`` de analysis.py (détecteurs réellement exécutés par analyse())."""
    noms = set()
    for noeud in ast.walk(ast.parse(ANALYSIS.read_text(encoding="utf-8"))):
        if isinstance(noeud, ast.With):
            for item in noeud.items:
                appel = item.context_expr
                if isinstance(appel, ast.Call) and getattr(appel.func, "id", None) == "_phase":
                    noms.add(appel.args[0].value)
    return noms


def _detecteurs_securite() -> set[str]:
    """Fonctions appelées sur ``all_packets`` par apply_security_findings (hors builtins)."""
    arbre = ast.parse(FINDINGS.read_text(encoding="utf-8"))
    fonction = next(
        n for n in ast.walk(arbre) if isinstance(n, ast.FunctionDef) and n.name == "apply_security_findings"
    )
    noms = set()
    for noeud in ast.walk(fonction):
        if (
            isinstance(noeud, ast.Call)
            and noeud.args
            and isinstance(noeud.args[0], ast.Name)
            and noeud.args[0].id == "all_packets"
        ):
            nom = noeud.func.id if isinstance(noeud.func, ast.Name) else noeud.func.attr
            if nom not in {"len", "list", "sorted", "set", "tuple"}:
                noms.add(nom)
    return noms


def _noms(provenance: str) -> set[str]:
    return {d.nom for d in inv.DETECTEURS if d.provenance == provenance}


def test_toute_phase_d_analyse_est_classee():
    phases = _phases_analyse()
    assert len(phases) >= 25  # garde-fou : l'extraction AST trouve bien les phases
    manquantes = phases - _noms(inv.PHASE)
    assert not manquantes, f"phases de analyse() sans classe dans detector_inventory : {sorted(manquantes)}"


def test_aucune_phase_inventoriee_n_a_disparu():
    obsoletes = _noms(inv.PHASE) - _phases_analyse()
    assert not obsoletes, f"phases inventoriées absentes de analyse() : {sorted(obsoletes)}"


def test_toute_signature_enregistree_est_classee():
    assert set(available_detectors()) == _noms(inv.SIGNATURE)


def test_tout_detecteur_de_securite_est_classe():
    appeles = _detecteurs_securite()
    assert "detect_beaconing" in appeles  # garde-fou de l'extraction
    connus = {d.nom for d in inv.DETECTEURS}
    manquants = appeles - connus
    assert not manquants, f"détecteurs de apply_security_findings sans classe : {sorted(manquants)}"
    assert _noms(inv.SECURITE) <= appeles, "détecteur de sécurité inventorié mais plus appelé"


def test_entrees_completes_et_coherentes():
    noms = [d.nom for d in inv.DETECTEURS]
    assert len(noms) == len(set(noms)), "noms en double"
    champs_rapport = {f.name for f in dataclasses.fields(Report)}
    for d in inv.DETECTEURS:
        assert d.classe in inv.CLASSES, d.nom
        assert d.provenance in inv.PROVENANCES, d.nom
        assert d.etat.strip(), d.nom
        assert d.fenetre.strip(), d.nom
        assert "|" not in d.etat + d.fenetre + d.note, d.nom  # tableau Markdown
        assert set(d.champs) <= champs_rapport, (d.nom, set(d.champs) - champs_rapport)
        if d.classe == inv.INCREMENTAL:
            assert d.fenetre == "aucune", d.nom


def test_chaque_classe_est_representee():
    assert {d.classe for d in inv.DETECTEURS} == set(inv.CLASSES)


def test_classe_de():
    assert inv.classe_de("infer_topology") == inv.SECONDE_PASSE
    assert inv.classe_de("compute_throughput") == inv.INCREMENTAL
    assert inv.classe_de("pertes") == inv.FENETRE_BORNEE
    with pytest.raises(KeyError):
        inv.classe_de("inexistant")


def test_doc_publie_le_tableau_a_jour():
    doc = DOC.read_text(encoding="utf-8")
    assert inv.tableau_markdown() in doc, (
        "docs/detectors.md n'est pas à jour : recopier "
        "`python -c 'from netcross_core.detector_inventory import tableau_markdown; print(tableau_markdown())'`"
    )


def test_tableau_une_ligne_par_detecteur():
    tableau = inv.tableau_markdown()
    lignes = [ligne for ligne in tableau.splitlines() if ligne.startswith("| `")]
    assert len(lignes) == len(inv.DETECTEURS)
    assert tableau.startswith(inv.DEBUT_TABLEAU)
    assert tableau.endswith(inv.FIN_TABLEAU)
    assert f"Total : {len(inv.DETECTEURS)} détecteurs" in tableau
