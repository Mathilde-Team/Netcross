#!/usr/bin/env python3
"""Tests réels : analyse de la banque de pcap de la VM runner (issue #1008).

La banque (``/app/pcaps`` sur la VM ``ubuntu`` du runner ``docker``) contient
des captures **sensibles** : elles ne quittent jamais la VM. Ce harnais lance
Netcross sur chacune d'elles et ne publie qu'un verdict **anonyme** :

- chaque cas est désigné par un identifiant opaque (empreinte SHA-256 du
  chemin relatif), jamais par son nom de fichier, ses points, ses adresses
  ou le texte de ses constats ;
- la sortie de Netcross n'est jamais recopiée : en cas d'exception, seuls
  son type et l'emplacement dans le **code** de Netcross sont affichés ;
- les rapports sont écrits dans un répertoire temporaire 0700, supprimé à
  la fin de chaque cas.

Deux niveaux :

1. **fumée** : toute capture non citée par un manifeste est analysée seule
   (un point) ; l'analyse doit aboutir (code 0), produire un JSON valide,
   sans exception Python, dans le temps imparti ;
2. **scénarios** : les manifestes ``netcross-cas.yaml`` rangés dans la
   banque (donc jamais dans le dépôt public) décrivent des cas multi-points
   et les résultats attendus. Format : voir ``docs/quality/tests-reels.md``.

Usage : python3 scripts/pcap_reels.py --banque /app/pcaps [--resume FICHIER]
Code retour : 0 tout est conforme, 1 au moins un cas en échec, 2 banque ou
manifeste inutilisable.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

RACINE = Path(__file__).resolve().parent.parent
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"
NOM_MANIFESTE = "netcross-cas.yaml"
EXTENSIONS = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")
DUREE_MAX_DEFAUT = 1800.0
# Options permises dans un manifeste : liste BLANCHE des options d'analyse
# pure. Tout le reste est refusé : les options qui écrivent un fichier (hors
# du répertoire temporaire du cas, donc sur le disque partagé du runner),
# émettent sur le réseau (--notify-*, --ai-endpoint, --replay), capturent en
# direct (--live*) ou chargent du code (--plugin-path). Le harnais gère seul
# la sortie --json-report et l'ordre (--order).
OPTIONS_PERMISES = frozenset(
    {
        "--split-interfaces",
        "--time-offset",
        "--normalize-time",
        "--align-to",
        "--names",
        "--nat-tolerant",
        "--nat-window-ms",
        "--detect-duplicates",
        "--exclude-duplicates",
        "--duplicate-threshold-ms",
        "--max-packets",
        "--sample",
        "--bucket-ms",
        "--rtp-clock-rate",
        "--idle-timeout-seconds",
        "--triage",
        "--triage-top-n",
        "--tls",
        "--quic",
        "--security-report",
        "--cve-db",
        "--known-destinations",
        "--known-hosts",
        "--test-net-external",
        "--rule-engine",
        "--expert-section",
        "--client-group",
        "--client-reference",
        "--parallel",
        "--parallel-workers",
        "--redact",
        "--media-quality",
        "--flow-timeline",
        "--flow-timeline-window",
        "--tshark-stats",
        "--merge-dedup",
    }
)
CLES_CAS = {"nom", "captures", "ordre", "options", "attendu"}
CLES_ATTENDU = {"code_retour", "score_sante", "label_sante", "constats", "constats_absents", "duree_max_s"}
CLES_CONSTAT = {"rule_id", "severite", "categorie", "segment", "message_contient", "nombre_min"}
_FRAME_RE = re.compile(r'File "([^"]+)", line (\d+), in (\S+)')
_EXC_RE = re.compile(r"^([A-Za-z_][\w.]*)(?::|$)")


class BanqueError(Exception):
    """Banque ou manifeste inutilisable (code retour 2)."""


@dataclass
class Cas:
    """Un cas à exécuter : un ou plusieurs points, et ce qui est attendu."""

    ident: str
    nom_reel: str
    type: str
    captures: dict[str, list[Path]]
    ordre: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    attendu: dict = field(default_factory=dict)


@dataclass
class Resultat:
    """Verdict d'un cas. ``ecarts`` ne contient jamais de donnée de la banque."""

    ident: str
    nom_reel: str
    type: str
    duree_s: float
    ecarts: list[str]

    @property
    def ok(self) -> bool:
        logger.debug("Resultat.ok: retour")
        return not self.ecarts


def identifiant(prefixe: str, texte: str) -> str:
    """Identifiant opaque et stable d'un cas (rien du chemin n'est lisible)."""
    logger.debug("identifiant: entrée")
    empreinte = hashlib.sha256(texte.encode("utf-8")).hexdigest()[:10]
    logger.debug("identifiant: retour")
    return f"{prefixe}-{empreinte}"


def est_capture(chemin: Path) -> bool:
    """Vrai si le fichier porte une extension de capture lue par tshark."""
    logger.debug("est_capture: entrée")
    nom = chemin.name.lower()
    resultat = chemin.is_file() and not nom.startswith(".") and nom.endswith(EXTENSIONS)
    logger.debug("est_capture: retour")
    return resultat


def _dans_banque(banque: Path, chemin: Path) -> Path:
    """Résout ``chemin`` et refuse qu'il sorte de la banque."""
    logger.debug("_dans_banque: entrée")
    resolu = chemin.resolve()
    if resolu != banque and banque not in resolu.parents:
        logger.error("chemin de manifeste hors de la banque")
        raise BanqueError("un manifeste cite un fichier hors de la banque")
    logger.debug("_dans_banque: retour")
    return resolu


def _verifier_cles(bloc: dict, permises: set[str], quoi: str, repere: str) -> None:
    """Refuse toute clé inconnue (une faute de frappe ne doit pas passer pour un test)."""
    logger.debug("_verifier_cles: entrée")
    inconnues = sorted(set(bloc) - permises)
    if inconnues:
        logger.error("clé inconnue dans un manifeste")
        raise BanqueError(f"{repere} : clé(s) inconnue(s) dans {quoi} : {', '.join(inconnues)}")
    logger.debug("_verifier_cles: retour")


def verifier_options(options: list[str], repere: str) -> None:
    """Refuse toute option hors de la liste blanche ``OPTIONS_PERMISES``."""
    logger.debug("verifier_options: entrée")
    for opt in options:
        if not isinstance(opt, str):
            logger.error("option de manifeste non textuelle")
            raise BanqueError(f"{repere} : option non textuelle")
        nom = opt.split("=", 1)[0]
        if opt.startswith("-") and nom not in OPTIONS_PERMISES:
            logger.error("option non permise dans un manifeste")
            raise BanqueError(f"{repere} : option non permise dans un manifeste : {nom}")
    logger.debug("verifier_options: retour")


def _lire_yaml(chemin: Path) -> dict:
    """Lit un manifeste YAML (pyyaml, extra dev)."""
    logger.debug("_lire_yaml: entrée")
    try:
        import yaml
    except ImportError as exc:
        logger.error("pyyaml absent : {}", type(exc).__name__)
        raise BanqueError("pyyaml requis pour lire les manifestes (uv sync --extra dev)") from exc
    try:
        donnees = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.error("manifeste illisible : {}", type(exc).__name__)
        raise BanqueError(f"manifeste illisible ({type(exc).__name__})") from exc
    if not isinstance(donnees, dict):
        logger.error("manifeste : racine non dictionnaire")
        raise BanqueError("manifeste : la racine doit être un dictionnaire")
    logger.debug("_lire_yaml: retour")
    return donnees


def lire_manifeste(banque: Path, chemin: Path) -> tuple[list[Cas], set[Path], list[str]]:
    """Cas décrits par un manifeste, captures qu'il cite, motifs ``ignorer``."""
    logger.debug("lire_manifeste: entrée")
    rel = chemin.relative_to(banque).as_posix()
    repere = identifiant("m", rel)
    donnees = _lire_yaml(chemin)
    _verifier_cles(donnees, {"cas", "ignorer"}, "la racine", repere)
    dossier = chemin.parent
    ignorer = [(dossier.relative_to(banque) / motif).as_posix() for motif in donnees.get("ignorer") or []]
    cas_liste: list[Cas] = []
    citees: set[Path] = set()
    for i, bloc in enumerate(donnees.get("cas") or [], start=1):
        rep = f"{repere} cas n°{i}"
        if not isinstance(bloc, dict):
            logger.error("cas de manifeste non dictionnaire")
            raise BanqueError(f"{rep} : un cas doit être un dictionnaire")
        _verifier_cles(bloc, CLES_CAS, "le cas", rep)
        attendu = bloc.get("attendu") or {}
        _verifier_cles(attendu, CLES_ATTENDU, "attendu", rep)
        for cle in ("constats", "constats_absents"):
            for motif in attendu.get(cle) or []:
                _verifier_cles(motif, CLES_CONSTAT, cle, rep)
        captures: dict[str, list[Path]] = {}
        for point, fichiers in (bloc.get("captures") or {}).items():
            liste = [fichiers] if isinstance(fichiers, str) else list(fichiers)
            chemins = [_dans_banque(banque, dossier / f) for f in liste]
            manquants = [c for c in chemins if not c.is_file()]
            if manquants:
                logger.error("capture citée absente")
                raise BanqueError(f"{rep} : {len(manquants)} capture(s) citée(s) absente(s)")
            captures[str(point)] = chemins
            citees.update(chemins)
        if not captures:
            logger.error("cas sans capture")
            raise BanqueError(f"{rep} : aucune capture")
        options = [str(o) for o in bloc.get("options") or []]
        verifier_options(options, rep)
        nom = str(bloc.get("nom") or f"cas-{i}")
        cas_liste.append(
            Cas(
                ident=identifiant("s", f"{rel}#{nom}"),
                nom_reel=f"{rel}#{nom}",
                type="scénario",
                captures=captures,
                ordre=[str(p) for p in bloc.get("ordre") or []],
                options=options,
                attendu=attendu,
            )
        )
    logger.debug("lire_manifeste: retour")
    return cas_liste, citees, ignorer


def decouvrir(banque: Path, filtre: str | None = None) -> list[Cas]:
    """Tous les cas de la banque : scénarios des manifestes puis fumée."""
    logger.debug("decouvrir: entrée")
    if not banque.is_dir():
        logger.error("banque absente")
        raise BanqueError("banque absente (répertoire introuvable)")
    banque = banque.resolve()
    scenarios: list[Cas] = []
    citees: set[Path] = set()
    ignorer: list[str] = []
    for manifeste in sorted(banque.rglob(NOM_MANIFESTE)):
        cas_liste, cit, ign = lire_manifeste(banque, manifeste)
        scenarios.extend(cas_liste)
        citees |= cit
        ignorer.extend(ign)
    fumee: list[Cas] = []
    for chemin in sorted(banque.rglob("*")):
        if not est_capture(chemin) or chemin.resolve() in citees:
            continue
        rel = chemin.relative_to(banque).as_posix()
        if any(fnmatch.fnmatch(rel, motif) for motif in ignorer):
            continue
        fumee.append(Cas(ident=identifiant("f", rel), nom_reel=rel, type="fumée", captures={"P": [chemin]}))
    tous = scenarios + fumee
    if filtre:
        tous = [c for c in tous if fnmatch.fnmatch(c.nom_reel, filtre) or c.ident == filtre]
    if not tous:
        logger.error("banque vide")
        raise BanqueError("aucun cas à exécuter (banque vide ou filtre sans correspondance)")
    logger.debug("decouvrir: retour")
    return tous


def commande(cas: Cas, rapport: Path) -> list[str]:
    """Ligne de commande Netcross du cas (le JSON va dans le répertoire du cas)."""
    logger.debug("commande: entrée")
    cmd = [sys.executable, str(CLI)]
    for point, chemins in cas.captures.items():
        cmd += ["--capture", f"{point}=" + ",".join(str(c) for c in chemins)]
    if cas.ordre:
        cmd += ["--order", ",".join(cas.ordre)]
    cmd += [*cas.options, "--json-report", str(rapport)]
    logger.debug("commande: retour")
    return cmd


def resumer_exception(stderr: str) -> str | None:
    """Type d'exception et dernier emplacement dans le code Netcross, sans message.

    Le message d'une exception peut contenir une adresse ou un nom tiré de la
    capture : il n'est jamais repris. Seuls le type et ``fichier:ligne
    (fonction)`` du code source de Netcross sont publiés.
    """
    logger.debug("resumer_exception: entrée")
    if "Traceback (most recent call last)" not in stderr:
        logger.debug("resumer_exception: retour (aucune)")
        return None
    bloc = stderr[stderr.rfind("Traceback (most recent call last)") :]
    lieu = "emplacement inconnu"
    for chemin, ligne, fonction in _FRAME_RE.findall(bloc):
        marque = chemin.replace("\\", "/")
        for racine in ("/src/", "/scripts/"):
            if racine in marque:
                lieu = f"{marque.rsplit(racine, 1)[1]}:{ligne} ({fonction})"
    type_exc = "exception"
    for ligne in bloc.splitlines():
        m = _EXC_RE.match(ligne)
        if m and not ligne.startswith("Traceback"):
            # première ligne non indentée après les cadres : l'exception
            type_exc = m.group(1)
            break
    logger.debug("resumer_exception: retour")
    return f"{type_exc} dans {lieu}"


def _constat_correspond(constat: dict, motif: dict) -> bool:
    """Vrai si un constat du rapport satisfait un motif du manifeste."""
    logger.debug("_constat_correspond: entrée")
    paires = (
        ("rule_id", "rule_id"),
        ("severite", "severity"),
        ("categorie", "category"),
        ("segment", "segment"),
    )
    for cle_motif, cle_rapport in paires:
        if cle_motif in motif and str(constat.get(cle_rapport)) != str(motif[cle_motif]):
            logger.debug("_constat_correspond: retour (champ différent)")
            return False
    if "message_contient" in motif and str(motif["message_contient"]) not in str(constat.get("message", "")):
        logger.debug("_constat_correspond: retour (message différent)")
        return False
    logger.debug("_constat_correspond: retour (correspond)")
    return True


def _decrire_motif(numero: int, motif: dict) -> str:
    """Désignation publiable d'un motif : numéro et identifiant de règle (code)."""
    logger.debug("_decrire_motif: entrée")
    regle = f" (rule_id={motif['rule_id']})" if "rule_id" in motif else ""
    logger.debug("_decrire_motif: retour")
    return f"n°{numero}{regle}"


def verifier_rapport(rapport: dict, attendu: dict) -> list[str]:
    """Écarts entre le rapport JSON et les attentes (messages sans donnée de capture)."""
    logger.debug("verifier_rapport: entrée")
    ecarts = [
        f"rapport JSON incomplet (clé {cle} absente)"
        for cle in ("points", "findings", "health_score")
        if cle not in rapport
    ]
    constats = rapport.get("findings") or []
    score = rapport.get("health_score")
    plage = attendu.get("score_sante")
    if plage is not None:
        bas, haut = plage.get("min", 0), plage.get("max", 100)
        if not isinstance(score, (int, float)) or not bas <= score <= haut:
            ecarts.append(f"score de santé {score} hors de la plage [{bas}, {haut}]")
    labels = attendu.get("label_sante")
    if labels is not None:
        permis = [labels] if isinstance(labels, str) else list(labels)
        if rapport.get("health_label") not in permis:
            ecarts.append(f"label de santé {rapport.get('health_label')} non attendu")
    for i, motif in enumerate(attendu.get("constats") or [], start=1):
        trouves = sum(1 for c in constats if _constat_correspond(c, motif))
        minimum = int(motif.get("nombre_min", 1))
        if trouves < minimum:
            ecarts.append(f"constat attendu {_decrire_motif(i, motif)} : {trouves} trouvé(s), {minimum} attendu(s)")
    for i, motif in enumerate(attendu.get("constats_absents") or [], start=1):
        trouves = sum(1 for c in constats if _constat_correspond(c, motif))
        if trouves:
            ecarts.append(f"constat interdit {_decrire_motif(i, motif)} présent {trouves} fois")
    logger.debug("verifier_rapport: retour")
    return ecarts


def executer(cas: Cas, delai_defaut: float = DUREE_MAX_DEFAUT) -> Resultat:
    """Lance Netcross sur un cas dans un répertoire temporaire privé, puis vérifie."""
    logger.debug("executer: entrée")
    attendu = cas.attendu
    delai = float(attendu.get("duree_max_s", delai_defaut))
    code_attendu = int(attendu.get("code_retour", 0))
    env = dict(os.environ, PYTHONPATH=str(RACINE / "src"), NO_COLOR="1")
    ecarts: list[str] = []
    debut = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="netcross-reel-") as tmp:
        os.chmod(tmp, 0o700)
        rapport = Path(tmp) / "rapport.json"
        try:
            proc = subprocess.run(
                commande(cas, rapport),
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=delai,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("cas {} : délai dépassé", cas.ident)
            duree = time.monotonic() - debut
            logger.debug("executer: retour (délai dépassé)")
            return Resultat(cas.ident, cas.nom_reel, cas.type, duree, [f"délai de {delai:.0f} s dépassé"])
        duree = time.monotonic() - debut
        exception = resumer_exception(proc.stderr)
        if exception:
            ecarts.append(exception)
        if proc.returncode != code_attendu:
            ecarts.append(f"code retour {proc.returncode} (attendu {code_attendu})")
        if code_attendu == 0 and proc.returncode == 0:
            try:
                donnees = json.loads(rapport.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                logger.debug("rapport illisible : {}", type(exc).__name__)
                ecarts.append(f"rapport JSON absent ou invalide ({type(exc).__name__})")
            else:
                ecarts.extend(verifier_rapport(donnees, attendu))
    logger.debug("executer: retour")
    return Resultat(cas.ident, cas.nom_reel, cas.type, duree, ecarts)


def formater(resultats: list[Resultat], noms: bool) -> tuple[str, str]:
    """Texte console et résumé Markdown. Sans ``noms``, aucune donnée de la banque."""
    logger.debug("formater: entrée")
    lignes = []
    tableau = ["| Cas | Type | Statut | Durée (s) | Écarts |", "|---|---|---|---|---|"]
    for r in resultats:
        nom = r.nom_reel if noms else r.ident
        statut = "OK" if r.ok else "ÉCHEC"
        lignes.append(f"{statut:5} {r.type:9} {nom}  {r.duree_s:7.1f} s")
        lignes.extend(f"      - {e}" for e in r.ecarts)
        tableau.append(f"| `{nom}` | {r.type} | {statut} | {r.duree_s:.1f} | {'<br>'.join(r.ecarts) or '—'} |")
    echecs = sum(1 for r in resultats if not r.ok)
    total = f"{len(resultats)} cas, {len(resultats) - echecs} conformes, {echecs} en échec"
    lignes.append(total)
    resume = "\n".join(["## Tests réels (banque de pcap)", "", total, "", *tableau, ""])
    logger.debug("formater: retour")
    return "\n".join(lignes), resume


def _parser() -> argparse.ArgumentParser:
    """Options de la ligne de commande."""
    logger.debug("_parser: entrée")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--banque", type=Path, default=Path(os.environ.get("NETCROSS_PCAP_BANK", "/app/pcaps")))
    ap.add_argument("--filtre", help="motif fnmatch sur le chemin relatif, ou identifiant d'un cas")
    ap.add_argument("--jobs", type=int, default=1, help="cas exécutés en parallèle (défaut 1)")
    ap.add_argument("--delai", type=float, default=DUREE_MAX_DEFAUT, help="délai par cas en secondes")
    ap.add_argument("--resume", type=Path, help="fichier Markdown où ajouter le résumé (ex. $GITHUB_STEP_SUMMARY)")
    ap.add_argument(
        "--noms",
        action="store_true",
        help="affiche les chemins réels (usage local sur la VM uniquement, jamais en CI)",
    )
    ap.add_argument("--lister", action="store_true", help="liste les cas sans les exécuter")
    logger.debug("_parser: retour")
    return ap


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : découverte, exécution, verdict."""
    logger.debug("main: entrée")
    args = _parser().parse_args(argv)
    try:
        cas_liste = decouvrir(args.banque, args.filtre)
    except BanqueError as exc:
        logger.error("banque inutilisable")
        print(f"ERREUR : {exc}", file=sys.stderr)
        logger.debug("main: retour 2")
        return 2
    if args.lister:
        for cas in cas_liste:
            print(f"{cas.type:9} {cas.nom_reel if args.noms else cas.ident}")
        logger.debug("main: retour 0 (liste)")
        return 0
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        resultats = list(pool.map(lambda c: executer(c, args.delai), cas_liste))
    texte, resume = formater(resultats, args.noms)
    print(texte)
    if args.resume:
        with args.resume.open("a", encoding="utf-8") as f:
            f.write(resume)
    code = 0 if all(r.ok for r in resultats) else 1
    logger.debug("main: retour {}", code)
    return code


if __name__ == "__main__":
    # Seuls les messages d'erreur du harnais lui-même (jamais de donnée de
    # capture) sont affichés ; le niveau DEBUG reste disponible en local.
    logger.remove()
    logger.add(sys.stderr, level=os.environ.get("NETCROSS_REELS_LOG", "WARNING"))
    sys.exit(main())
