# SPDX-License-Identifier: GPL-3.0-or-later
"""Banc de performance reproductible de Netcross (issue #1017, chantier #994).

Exécute la vraie ligne de commande (``cross_capture_analyzer_cli.py``) sur
des jeux pcapng multi-points (ceux de :mod:`netcross_core.testing.synth`,
#1015) et relève, pour chaque jeu et chaque degré de parallélisme demandé :

- la durée totale et la durée par étape (``lecture``, ``correlation``,
  ``detecteurs``, ``rapport``), lues dans le fichier ``--profile-steps`` de
  #1016 ;
- le pic RSS du processus d'analyse et celui de ses enfants (tshark, et les
  processus de lecture en mode ``--parallel``) ;
- le débit en paquets/s (paquets de tous les points / durée totale).

Le résultat est un JSON au schéma versionné (:data:`SCHEMA`,
:data:`VERSION_SCHEMA`, vérifié par :func:`valider`) qui note aussi
l'environnement : cœurs logiques et cœurs réellement utilisables, modèle
de CPU, RAM, versions de tshark, de Python et de Netcross. Le même
résultat se lit en tableau Markdown (:func:`en_markdown`).

Chaque analyse tourne dans un processus neuf : le pic RSS d'un essai ne
déborde pas sur le suivant. Avec ``--repetitions R``, l'essai retenu est
celui de durée totale médiane, les autres durées sont gardées dans
``durees_totales_s``.

``--mini`` génère un jeu de 2 points x 2 000 paquets (graine 1) dans un
dossier temporaire : quelques secondes, utilisable en CI.

Non-régression (issue #1019) : :func:`comparer` confronte un résultat à une
référence versionnée (``benchmarks/reference.json``) et signale toute mesure
qui dépasse la référence de plus d'un seuil configurable (durée totale, pics
RSS). ``--reference`` active la comparaison ; le code de sortie vaut alors 3
en cas de régression. Une référence prise sur un autre environnement (CPU ou
nombre de cœurs utilisables différents) n'est pas comparée.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_core.profiling import ETAPES_STANDARD

logger = get_logger(__name__)

SCHEMA = "netcross-bench"
VERSION_SCHEMA = 1
PARALLELE_DEFAUT = (1,)
MINI_POINTS, MINI_PAQUETS, MINI_GRAINE = 2, 2_000, 1
RACINE = Path(__file__).resolve().parents[3]
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"

# Clés obligatoires du résultat et de chaque essai (schéma version 1).
CLES_ENVIRONNEMENT = (
    "coeurs_logiques",
    "coeurs_utilisables",
    "cpu",
    "ram_mio",
    "systeme",
    "python",
    "tshark",
    "netcross",
)
CLES_ESSAI = (
    "jeu",
    "points",
    "paquets",
    "parallele",
    "repetitions",
    "total_s",
    "durees_totales_s",
    "mur_s",
    "etapes_s",
    "rss_max_mio",
    "rss_max_enfants_mio",
    "paquets_par_s",
)

# Non-régression (#1019) : seuils par défaut en pourcentage, mesures
# comparées et clés d'environnement qui doivent être identiques.
SEUIL_DUREE_DEFAUT_PCT = 20.0
SEUIL_MEMOIRE_DEFAUT_PCT = 20.0
MESURES_DUREE = ("total_s",)
MESURES_MEMOIRE = ("rss_max_mio", "rss_max_enfants_mio")
CLES_ENVIRONNEMENT_COMPARABLES = ("cpu", "coeurs_utilisables")
CODE_REGRESSION = 3

Executeur = Callable[[list[str]], int]


class BancError(RuntimeError):
    """Jeu introuvable, analyse en échec ou mesures absentes."""


# -- environnement -------------------------------------------------------------


def _lire(chemin: str) -> str:
    """Contenu d'un fichier système, chaîne vide s'il est illisible."""
    logger.debug("_lire: entrée ({})", chemin)
    try:
        texte = Path(chemin).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("_lire: {} illisible ({}) -> retour chaîne vide", chemin, exc)
        return ""
    logger.debug("_lire: retour")
    return texte


def modele_cpu(cpuinfo: str | None = None) -> str:
    """Modèle du processeur (``/proc/cpuinfo``), à défaut ``platform.processor()``."""
    logger.debug("modele_cpu: entrée")
    texte = _lire("/proc/cpuinfo") if cpuinfo is None else cpuinfo
    for ligne in texte.splitlines():
        cle, _, valeur = ligne.partition(":")
        if cle.strip() in ("model name", "Model", "Hardware") and valeur.strip():
            logger.debug("modele_cpu: retour (cpuinfo)")
            return valeur.strip()
    logger.debug("modele_cpu: retour (platform)")
    return platform.processor() or platform.machine() or "inconnu"


def ram_mio(meminfo: str | None = None) -> int | None:
    """RAM totale en Mio (``MemTotal`` de ``/proc/meminfo``), ``None`` si inconnue."""
    logger.debug("ram_mio: entrée")
    texte = _lire("/proc/meminfo") if meminfo is None else meminfo
    for ligne in texte.splitlines():
        if ligne.startswith("MemTotal:"):
            champs = ligne.split()
            if len(champs) >= 2 and champs[1].isdigit():
                logger.debug("ram_mio: retour (meminfo)")
                return int(champs[1]) // 1024
    logger.debug("ram_mio: retour None (MemTotal absent)")
    return None


_AFFINITE: Callable[[int], set[int]] | None = getattr(os, "sched_getaffinity", None)


def coeurs_utilisables(affinite: Callable[[int], set[int]] | None = _AFFINITE) -> int:
    """Cœurs réellement utilisables par ce processus (affinité, conteneurs).

    Sans ``os.sched_getaffinity`` (hors Linux), repli sur ``os.cpu_count()``.
    """
    logger.debug("coeurs_utilisables: entrée")
    if affinite is None:
        logger.debug("coeurs_utilisables: pas d'affinité -> retour cpu_count")
        return os.cpu_count() or 1
    logger.debug("coeurs_utilisables: retour (affinité)")
    return len(affinite(0))


def version_tshark(tshark: str | None = None) -> str | None:
    """Première ligne de ``tshark --version``, ``None`` si tshark est absent."""
    logger.debug("version_tshark: entrée")
    binaire = tshark or shutil.which("tshark")
    if binaire is None:
        logger.debug("version_tshark: tshark absent -> retour None")
        return None
    try:
        sortie = subprocess.run([binaire, "--version"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("tshark --version a échoué : {}", exc)
        logger.debug("version_tshark: échec -> retour None")
        return None
    premiere = (sortie.stdout or "").strip().splitlines()
    logger.debug("version_tshark: retour")
    return premiere[0] if premiere else None


def version_netcross() -> str:
    """Version installée de Netcross, ``inconnue`` hors installation."""
    logger.debug("version_netcross: entrée")
    from importlib import metadata

    try:
        version = metadata.version("netcross")
    except metadata.PackageNotFoundError:
        logger.debug("version_netcross: paquet non installé -> retour inconnue")
        return "inconnue"
    logger.debug("version_netcross: retour")
    return version


def environnement() -> dict:
    """Machine et versions sur lesquelles le banc a tourné."""
    logger.debug("environnement: entrée")
    env = {
        "coeurs_logiques": os.cpu_count() or 1,
        "coeurs_utilisables": coeurs_utilisables(),
        "cpu": modele_cpu(),
        "ram_mio": ram_mio(),
        "systeme": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": platform.python_version(),
        "tshark": version_tshark(),
        "netcross": version_netcross(),
    }
    logger.debug("environnement: retour")
    return env


# -- jeux ----------------------------------------------------------------------


def trouver_jeux(chemin: str | Path) -> list[Path]:
    """Dossiers de jeu sous ``chemin`` : lui-même s'il contient ``verite.json``,
    sinon ses sous-dossiers qui en contiennent un (sortie ``--matrice``), triés."""
    logger.debug("trouver_jeux: entrée ({})", chemin)
    racine = Path(chemin)
    if (racine / "verite.json").is_file():
        logger.debug("trouver_jeux: jeu unique -> retour")
        return [racine]
    jeux = sorted(d for d in racine.iterdir() if (d / "verite.json").is_file()) if racine.is_dir() else []
    if not jeux:
        logger.warning("aucun jeu (verite.json) sous {}", racine)
        raise BancError(f"aucun jeu synthétique (verite.json) sous {racine}")
    logger.debug("trouver_jeux: retour ({} jeux)", len(jeux))
    return jeux


def lire_verite(dossier: Path) -> dict:
    """Vérité terrain d'un jeu (points dans l'ordre du chemin, paquets par point)."""
    logger.debug("lire_verite: entrée ({})", dossier)
    verite = json.loads((dossier / "verite.json").read_text(encoding="utf-8"))
    manquants = [nom for nom in verite["points"] if not (dossier / f"{nom}.pcapng").is_file()]
    if manquants:
        logger.warning("jeu {} incomplet : {}", dossier, manquants)
        raise BancError(f"{dossier} : fichiers manquants pour {', '.join(manquants)}")
    logger.debug("lire_verite: retour")
    return verite


# -- exécution -----------------------------------------------------------------


def commande_analyse(dossier: Path, verite: dict, parallele: int, mesures: Path, python: str = sys.executable):
    """Ligne de commande de l'analyse d'un jeu, mesures dans ``mesures``."""
    logger.debug("commande_analyse: entrée (parallele={})", parallele)
    cmd = [python, str(CLI)]
    for nom in verite["points"]:
        cmd += ["--capture", f"{nom}={dossier / f'{nom}.pcapng'}"]
    cmd += ["--order", ",".join(verite["points"]), "--profile-steps", str(mesures)]
    if parallele > 1:
        cmd += ["--parallel", "--parallel-workers", str(parallele)]
    logger.debug("commande_analyse: retour")
    return cmd


def executer(cmd: list[str]) -> int:
    """Lance l'analyse, sorties jetées (seules les mesures comptent) ; code retour."""
    logger.debug("executer: entrée")
    code = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode
    logger.debug("executer: retour {}", code)
    return code


def _mio(ko: int) -> float:
    """Kio → Mio, arrondi au dixième."""
    logger.debug("_mio: retour")
    return round(ko / 1024, 1)


def mesurer(
    dossier: Path,
    parallele: int,
    repetitions: int = 1,
    executeur: Executeur = executer,
    horloge: Callable[[], float] = time.perf_counter,
) -> dict:
    """Essai d'un jeu à un degré de parallélisme ; renvoie l'essai médian."""
    logger.debug("mesurer: entrée ({}, parallele={}, repetitions={})", dossier, parallele, repetitions)
    verite = lire_verite(dossier)
    paquets = sum(verite["paquets_par_point"].values())
    essais = []
    with tempfile.TemporaryDirectory(prefix="netcross-bench-") as tmp:
        for numero in range(repetitions):
            fichier = Path(tmp) / f"mesures-{numero}.json"
            debut = horloge()
            code = executeur(commande_analyse(dossier, verite, parallele, fichier))
            mur = horloge() - debut
            if code != 0 or not fichier.is_file():
                logger.warning("analyse de {} en échec (code {}, mesures {})", dossier, code, fichier.is_file())
                raise BancError(f"analyse de {dossier} en échec (code {code}) avec --parallel {parallele}")
            essais.append((json.loads(fichier.read_text(encoding="utf-8")), mur))
    durees = [m["total_s"] for m, _ in essais]
    mediane = sorted(essais, key=lambda e: e[0]["total_s"])[(len(essais) - 1) // 2]
    mesures, mur = mediane
    total = mesures["total_s"]
    essai = {
        "jeu": dossier.name,
        "points": len(verite["points"]),
        "paquets": paquets,
        "parallele": parallele,
        "repetitions": repetitions,
        "total_s": total,
        "durees_totales_s": durees,
        "mur_s": round(mur, 6),
        "etapes_s": {nom: v["secondes"] for nom, v in mesures["etapes"].items()},
        "rss_max_mio": _mio(mesures["rss_max_ko"]),
        "rss_max_enfants_mio": _mio(mesures["rss_max_enfants_ko"]),
        "paquets_par_s": round(paquets / total) if total > 0 else None,
    }
    logger.info(
        "banc {} --parallel {} : {:.3f} s, {} paquets/s", dossier.name, parallele, total, essai["paquets_par_s"]
    )
    logger.debug("mesurer: retour")
    return essai


def lancer(
    jeux: list[Path],
    paralleles: list[int],
    repetitions: int = 1,
    executeur: Executeur = executer,
    env: dict | None = None,
) -> dict:
    """Banc complet : chaque jeu, pour chaque degré de parallélisme."""
    logger.debug("lancer: entrée ({} jeux, parallèles {})", len(jeux), paralleles)
    resultat = {
        "schema": SCHEMA,
        "version": VERSION_SCHEMA,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environnement": environnement() if env is None else dict(env),
        "essais": [mesurer(jeu, n, repetitions, executeur) for jeu in jeux for n in paralleles],
    }
    logger.debug("lancer: retour")
    return resultat


# -- schéma et rendu -----------------------------------------------------------


def valider(resultat: dict) -> list[str]:
    """Écarts au schéma ``netcross-bench`` version 1 (liste vide si conforme)."""
    logger.debug("valider: entrée")
    erreurs = []
    if resultat.get("schema") != SCHEMA:
        erreurs.append(f"schema différent de {SCHEMA}")
    if resultat.get("version") != VERSION_SCHEMA:
        erreurs.append(f"version différente de {VERSION_SCHEMA}")
    if not isinstance(resultat.get("date"), str):
        erreurs.append("date absente")
    env = resultat.get("environnement")
    if not isinstance(env, dict):
        erreurs.append("environnement absent")
    else:
        erreurs += [f"environnement.{cle} absent" for cle in CLES_ENVIRONNEMENT if cle not in env]
    essais = resultat.get("essais")
    if not isinstance(essais, list) or not essais:
        erreurs.append("aucun essai")
        essais = []
    for i, essai in enumerate(essais):
        erreurs += [f"essais[{i}].{cle} absent" for cle in CLES_ESSAI if cle not in essai]
        etapes = essai.get("etapes_s", {})
        erreurs += [f"essais[{i}].etapes_s.{nom} absent" for nom in ETAPES_STANDARD if nom not in etapes]
        if not isinstance(essai.get("total_s"), (int, float)) or essai.get("total_s", 0) <= 0:
            erreurs.append(f"essais[{i}].total_s non positif")
    logger.debug("valider: retour ({} écarts)", len(erreurs))
    return erreurs


def _cellule(valeur, format_nombre: str = "{:.3f}") -> str:
    """Valeur d'un tableau Markdown, « n/d » si absente."""
    logger.debug("_cellule: entrée")
    if valeur is None:
        logger.debug("_cellule: valeur absente -> retour n/d")
        return "n/d"
    logger.debug("_cellule: retour")
    return format_nombre.format(valeur) if isinstance(valeur, float) else str(valeur)


def en_markdown(resultat: dict) -> str:
    """Environnement puis une ligne par essai, en Markdown."""
    logger.debug("en_markdown: entrée")
    env = resultat["environnement"]
    lignes = [
        f"## Banc Netcross du {resultat['date']}",
        "",
        f"- CPU : {env['cpu']} ({env['coeurs_utilisables']} cœurs utilisables sur {env['coeurs_logiques']})",
        f"- RAM : {_cellule(env['ram_mio'])} Mio",
        f"- Système : {env['systeme']}",
        f"- Python {env['python']}, {env['tshark'] or 'tshark absent'}, Netcross {env['netcross']}",
        "",
        "| Jeu | Points | Paquets | Parallèle | Total (s) | "
        + " | ".join(f"{nom} (s)" for nom in ETAPES_STANDARD)
        + " | Pic RSS (Mio) | Pic RSS enfants (Mio) | Paquets/s |",
        "|---|---:|---:|---:|---:|" + "---:|" * len(ETAPES_STANDARD) + "---:|---:|---:|",
    ]
    for e in resultat["essais"]:
        etapes = " | ".join(_cellule(e["etapes_s"].get(nom)) for nom in ETAPES_STANDARD)
        lignes.append(
            f"| {e['jeu']} | {e['points']} | {e['paquets']} | {e['parallele']} | {_cellule(e['total_s'])} | {etapes} "
            f"| {_cellule(e['rss_max_mio'], '{:.1f}')} | {_cellule(e['rss_max_enfants_mio'], '{:.1f}')} "
            f"| {_cellule(e['paquets_par_s'])} |"
        )
    logger.debug("en_markdown: retour")
    return "\n".join(lignes) + "\n"


# -- non-régression (#1019) ---------------------------------------------------


def _ecart_pct(actuel: float, reference: float) -> float | None:
    """Écart relatif en pourcentage ; None si la référence est nulle."""
    logger.debug("_ecart_pct: entrée")
    if not reference:
        logger.debug("_ecart_pct: référence nulle -> retour None")
        return None
    logger.debug("_ecart_pct: retour")
    return round((actuel - reference) / reference * 100, 1)


def comparer(
    resultat: dict,
    reference: dict,
    seuil_duree_pct: float = SEUIL_DUREE_DEFAUT_PCT,
    seuil_memoire_pct: float = SEUIL_MEMOIRE_DEFAUT_PCT,
) -> dict:
    """Compare chaque essai de la référence à l'essai (jeu, parallèle) du résultat.

    Statut : ``ok``, ``regression`` (une mesure dépasse la référence de plus
    du seuil), ``environnement_different`` (CPU ou cœurs utilisables
    différents : rien n'est comparé) ou ``incomparable`` (essai de la
    référence absent du résultat). Une amélioration n'est jamais une
    régression.
    """
    logger.debug("comparer: entrée (seuils durée {} %, mémoire {} %)", seuil_duree_pct, seuil_memoire_pct)
    env_ref = reference.get("environnement", {})
    env_act = resultat.get("environnement", {})
    differences = [
        {"cle": cle, "reference": env_ref.get(cle), "actuel": env_act.get(cle)}
        for cle in CLES_ENVIRONNEMENT_COMPARABLES
        if env_ref.get(cle) != env_act.get(cle)
    ]
    comparaison: dict = {
        "seuil_duree_pct": seuil_duree_pct,
        "seuil_memoire_pct": seuil_memoire_pct,
        "environnement": differences,
        "manquants": [],
        "lignes": [],
    }
    if differences:
        comparaison["statut"] = "environnement_different"
        logger.debug("comparer: environnement différent -> retour sans comparaison")
        return comparaison
    actuels = {(e["jeu"], e["parallele"]): e for e in resultat.get("essais", [])}
    seuils = [(m, seuil_duree_pct) for m in MESURES_DUREE] + [(m, seuil_memoire_pct) for m in MESURES_MEMOIRE]
    for essai_ref in reference.get("essais", []):
        cle = (essai_ref["jeu"], essai_ref["parallele"])
        essai = actuels.get(cle)
        if essai is None:
            comparaison["manquants"].append({"jeu": cle[0], "parallele": cle[1]})
            continue
        for mesure, seuil in seuils:
            valeur_ref, valeur = essai_ref.get(mesure), essai.get(mesure)
            if valeur_ref is None or valeur is None:
                continue
            ecart = _ecart_pct(valeur, valeur_ref)
            comparaison["lignes"].append(
                {
                    "jeu": cle[0],
                    "parallele": cle[1],
                    "mesure": mesure,
                    "reference": valeur_ref,
                    "actuel": valeur,
                    "ecart_pct": ecart,
                    "seuil_pct": seuil,
                    "regression": ecart is not None and ecart > seuil,
                }
            )
    if comparaison["manquants"]:
        comparaison["statut"] = "incomparable"
    elif any(ligne["regression"] for ligne in comparaison["lignes"]):
        comparaison["statut"] = "regression"
    else:
        comparaison["statut"] = "ok"
    logger.debug("comparer: retour statut {}", comparaison["statut"])
    return comparaison


_LIBELLES_STATUT = {
    "ok": "aucune régression",
    "regression": "RÉGRESSION",
    "environnement_different": "référence prise sur un autre environnement, non comparée",
    "incomparable": "essais de la référence absents du résultat",
}


def comparaison_en_markdown(comparaison: dict) -> str:
    """Résumé Markdown de :func:`comparer` (pour ``$GITHUB_STEP_SUMMARY``)."""
    logger.debug("comparaison_en_markdown: entrée")
    lignes = [
        f"## Non-régression : {_LIBELLES_STATUT[comparaison['statut']]}",
        "",
        f"Seuils : durée +{comparaison['seuil_duree_pct']:g} %, mémoire +{comparaison['seuil_memoire_pct']:g} %.",
        "",
    ]
    lignes += [
        f"- `{d['cle']}` : référence {d['reference']!r}, actuel {d['actuel']!r}" for d in comparaison["environnement"]
    ]
    lignes += [f"- essai absent : {m['jeu']} avec --parallel {m['parallele']}" for m in comparaison["manquants"]]
    if comparaison["lignes"]:
        lignes += [
            "| Jeu | Parallèle | Mesure | Référence | Actuel | Écart (%) | Seuil (%) | Verdict |",
            "|---|---:|---|---:|---:|---:|---:|---|",
        ]
        for ligne in comparaison["lignes"]:
            verdict = "régression" if ligne["regression"] else "ok"
            lignes.append(
                f"| {ligne['jeu']} | {ligne['parallele']} | {ligne['mesure']} | {_cellule(ligne['reference'])} "
                f"| {_cellule(ligne['actuel'])} | {_cellule(ligne['ecart_pct'], '{:+.1f}')} "
                f"| {ligne['seuil_pct']:g} | {verdict} |"
            )
    logger.debug("comparaison_en_markdown: retour")
    return "\n".join(lignes) + "\n"


def _lire_json(chemin: str) -> dict:
    """Résultat ou référence JSON conforme au schéma ; BancError sinon."""
    logger.debug("_lire_json: entrée ({})", chemin)
    try:
        donnees = json.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("_lire_json: lecture impossible -> levée")
        raise BancError(f"{chemin} illisible : {exc}") from exc
    erreurs = valider(donnees) if isinstance(donnees, dict) else ["objet JSON attendu"]
    if erreurs:
        logger.debug("_lire_json: schéma non conforme -> levée")
        raise BancError(f"{chemin} non conforme : {', '.join(erreurs)}")
    logger.debug("_lire_json: retour")
    return donnees


def _pourcentage(texte: str) -> float:
    """Seuil en pourcentage, positif ou nul (argparse)."""
    logger.debug("_pourcentage: entrée")
    try:
        valeur = float(texte)
    except ValueError as exc:
        logger.debug("_pourcentage: valeur non numérique -> levée")
        raise argparse.ArgumentTypeError(f"pourcentage attendu : {texte}") from exc
    if valeur < 0:
        logger.debug("_pourcentage: valeur négative -> levée")
        raise argparse.ArgumentTypeError(f"pourcentage positif attendu : {texte}")
    logger.debug("_pourcentage: retour")
    return valeur


# -- ligne de commande --------------------------------------------------------


def _liste_paralleles(texte: str) -> list[int]:
    """``"1,2,4"`` → ``[1, 2, 4]`` ; refuse les valeurs < 1 (argparse)."""
    logger.debug("_liste_paralleles: entrée")
    try:
        valeurs = [int(x) for x in texte.split(",") if x.strip()]
    except ValueError as exc:
        logger.debug("_liste_paralleles: valeur non entière -> levée")
        raise argparse.ArgumentTypeError(f"liste d'entiers attendue : {texte}") from exc
    if not valeurs or min(valeurs) < 1:
        logger.debug("_liste_paralleles: valeur < 1 -> levée")
        raise argparse.ArgumentTypeError(f"entiers >= 1 attendus : {texte}")
    logger.debug("_liste_paralleles: retour")
    return valeurs


def construire_parseur() -> argparse.ArgumentParser:
    """Analyseur d'arguments de ``scripts/bench.py``."""
    logger.debug("construire_parseur: entrée")
    p = argparse.ArgumentParser(
        prog="bench.py",
        description="Banc de performance de Netcross sur des jeux synthétiques (issue #1017).",
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--jeux", help="jeu (dossier avec verite.json) ou dossier de jeux (sortie --matrice)")
    source.add_argument("--mini", action="store_true", help="mini-jeu 2 points x 2 000 paquets, généré à la volée")
    source.add_argument("--resultat", help="résultat JSON déjà mesuré, à comparer à --reference sans relancer le banc")
    p.add_argument(
        "--parallel",
        type=_liste_paralleles,
        default=list(PARALLELE_DEFAUT),
        help="degrés de parallélisme de la lecture, ex. 1,2,4,8 (1 = lecture séquentielle)",
    )
    p.add_argument("--repetitions", type=int, default=1, help="essais par mesure, médiane retenue (défaut 1)")
    p.add_argument("--json", dest="sortie_json", help="écrit le résultat JSON dans ce fichier")
    p.add_argument("--markdown", dest="sortie_markdown", help="écrit le tableau Markdown dans ce fichier")
    p.add_argument("--reference", help="référence JSON (ex. benchmarks/reference.json) : active la non-régression")
    p.add_argument(
        "--seuil-duree",
        type=_pourcentage,
        default=SEUIL_DUREE_DEFAUT_PCT,
        help=f"hausse de durée tolérée en %% (défaut {SEUIL_DUREE_DEFAUT_PCT:g})",
    )
    p.add_argument(
        "--seuil-memoire",
        type=_pourcentage,
        default=SEUIL_MEMOIRE_DEFAUT_PCT,
        help=f"hausse de pic RSS tolérée en %% (défaut {SEUIL_MEMOIRE_DEFAUT_PCT:g})",
    )
    p.add_argument(
        "--resume", help="ajoute le tableau et la comparaison en Markdown à ce fichier ($GITHUB_STEP_SUMMARY)"
    )
    logger.debug("construire_parseur: retour")
    return p


def main(argv: list[str] | None = None, executeur: Executeur = executer) -> int:
    """Point d'entrée ; 0 si le banc est complet (et sans régression), 2 sur
    jeu, analyse ou fichier en échec, 3 sur régression (avec --reference)."""
    logger.debug("main: entrée")
    parseur = construire_parseur()
    args = parseur.parse_args(argv)
    if args.repetitions < 1:
        logger.debug("main: --repetitions < 1 -> levée SystemExit")
        parseur.error("--repetitions doit valoir au moins 1")
    if args.resultat and not args.reference:
        logger.debug("main: --resultat sans --reference -> levée SystemExit")
        parseur.error("--resultat exige --reference")
    try:
        reference = _lire_json(args.reference) if args.reference else None
        resultat = _lire_json(args.resultat) if args.resultat else _mesurer_depuis_arguments(args, executeur)
    except BancError as exc:
        logger.warning("banc interrompu : {}", exc)
        print(f"erreur : {exc}", file=sys.stderr)
        logger.debug("main: retour 2 (banc interrompu)")
        return 2
    texte = en_markdown(resultat)
    if args.sortie_json:
        Path(args.sortie_json).write_text(json.dumps(resultat, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.sortie_markdown:
        Path(args.sortie_markdown).write_text(texte, encoding="utf-8")
    code = 0
    if reference is not None:
        comparaison = comparer(resultat, reference, args.seuil_duree, args.seuil_memoire)
        texte += "\n" + comparaison_en_markdown(comparaison)
        if comparaison["statut"] == "regression":
            code = CODE_REGRESSION
        elif comparaison["statut"] == "incomparable":
            code = 2
        elif comparaison["statut"] == "environnement_different":
            logger.warning("référence prise sur un autre environnement : comparaison ignorée")
    if args.resume:
        with Path(args.resume).open("a", encoding="utf-8") as resume:
            resume.write(texte)
    print(texte, end="")
    logger.debug("main: retour {}", code)
    return code


def _mesurer_depuis_arguments(args: argparse.Namespace, executeur: Executeur) -> dict:
    """Lance le banc sur ``--mini`` ou ``--jeux`` ; BancError en cas d'échec."""
    logger.debug("_mesurer_depuis_arguments: entrée")
    with tempfile.TemporaryDirectory(prefix="netcross-mini-") as tmp:
        if args.mini:
            from netcross_core.testing.synth import Configuration, generer

            generer(Configuration(points=MINI_POINTS, paquets=MINI_PAQUETS, graine=MINI_GRAINE), tmp)
            jeux = [Path(tmp)]
        else:
            jeux = trouver_jeux(args.jeux)
        resultat = lancer(jeux, args.parallel, args.repetitions, executeur)
        if args.mini:
            for essai in resultat["essais"]:
                essai["jeu"] = "mini"
    logger.debug("_mesurer_depuis_arguments: retour")
    return resultat
