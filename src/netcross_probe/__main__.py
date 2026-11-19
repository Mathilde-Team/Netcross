# SPDX-License-Identifier: GPL-3.0-or-later
"""Point d'entrée de la sonde : ``python3 -m netcross_probe`` (issue #1099).

Le dépôt n'est pas distribué comme wheel (``package = false`` dans
pyproject.toml) : les surfaces historiques se lancent par leur module.
La sonde suit le même modèle -- ``PYTHONPATH=src python3 -m netcross_probe``
-- plutôt qu'un point d'entrée console-script qui exigerait un build.

Deux sous-commandes :

- ``capture`` : démarre la capture locale en tampon circulaire (Ctrl-C
  pour arrêter proprement) ;
- ``fenetre`` : extrait une fenêtre [t1, t2] du tampon existant, avec
  filtre BPF optionnel, et imprime la description JSON de la fenêtre
  (miroir de ``Window`` du contrat v1, sans la couche réseau #1105).
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from collections.abc import Sequence

from loguru import logger

from netcross_probe.agent import AgentProbe
from netcross_probe.bpf import FiltreBpfInvalideError
from netcross_probe.capture import ReglagesCapture
from netcross_probe.fenetres import FenetreInvalideError, FenetreTropGrandeError, FenetreVideError

__all__ = ["construire_parseur", "main"]


def construire_parseur() -> argparse.ArgumentParser:
    """Parseur de la sonde (séparé de ``main`` pour les tests et la parité)."""
    logger.debug("construire_parseur: entrée")
    parseur = argparse.ArgumentParser(
        prog="netcross-probe",
        description="Sonde de capture Netcross : tampon circulaire local et fenêtres à la demande (#1099).",
    )
    sous_commandes = parseur.add_subparsers(dest="commande", required=True)

    capture = sous_commandes.add_parser("capture", help="capturer en local dans un tampon circulaire")
    capture.add_argument("--interface", required=True, help="interface à capturer (ex. eth0)")
    capture.add_argument("--dossier", required=True, help="répertoire du tampon circulaire")
    capture.add_argument("--nb-fichiers", type=int, default=5, help="profondeur du tampon (nombre de fichiers)")
    capture.add_argument("--duree-par-fichier", type=float, default=60.0, help="durée (s) par fichier du tampon")
    capture.add_argument("--prefixe", default="probe", help="préfixe des fichiers du tampon")
    capture.add_argument("--filtre-bpf", default=None, help="filtre de capture pcap-filter (optionnel)")

    fenetre = sous_commandes.add_parser("fenetre", help="extraire une fenêtre [t1, t2] du tampon")
    fenetre.add_argument("--dossier", required=True, help="répertoire du tampon circulaire")
    fenetre.add_argument("--debut", type=float, required=True, help="borne de début (secondes Unix, incluse)")
    fenetre.add_argument("--fin", type=float, required=True, help="borne de fin (secondes Unix, incluse)")
    fenetre.add_argument("--prefixe", default="probe", help="préfixe des fichiers du tampon")
    fenetre.add_argument("--filtre-bpf", default=None, help="filtre pcap-filter appliqué à l'extraction (optionnel)")
    fenetre.add_argument(
        "--inclure-inconnus",
        action="store_true",
        help="inclure les fichiers du tampon d'intervalle inconnu (en cours d'écriture)",
    )
    fenetre.add_argument(
        "--max-octets", type=int, default=None, help="taille maximale du pcapng produit (refus au-delà)"
    )
    fenetre.add_argument("--sortie", required=True, help="répertoire où écrire le pcapng de la fenêtre")
    logger.debug("construire_parseur: retour parseur")
    return parseur


def _patienter_par_defaut(duree: float) -> bool:
    """Attente de production : dort puis renvoie True (continuer)."""
    logger.debug("_patienter_par_defaut: entrée ({})", duree)
    time.sleep(duree)
    logger.debug("_patienter_par_defaut: retour True")
    return True


def _boucle_attente(agent: AgentProbe, patienter=None) -> bool:
    """Attend l'ordre d'arrêt ; renvoie True si l'enregistreur tourne toujours.

    ``patienter`` : fonction d'attente injectable (défaut : dormir),
    qui reçoit la durée d'un cycle et renvoie False pour demander l'arrêt
    (les tests s'en servent pour sortir immédiatement de la boucle). En
    production, l'arrêt vient de SIGINT/SIGTERM, interceptés ici.
    """
    logger.debug("_boucle_attente: entrée")
    if patienter is None:
        patienter = _patienter_par_defaut
    arret = {"demande": False}

    def _demander_arret(numero: int, _cadre: object) -> None:
        logger.debug("_demander_arret: signal {}", numero)
        arret["demande"] = True
        logger.debug("_demander_arret: fin")

    signal.signal(signal.SIGINT, _demander_arret)
    signal.signal(signal.SIGTERM, _demander_arret)
    while not arret["demande"]:
        if not agent.capture.en_cours:
            logger.debug("_boucle_attente: retour False (enregistreur arrêté seul)")
            return False
        if not patienter(0.05):
            break
    logger.debug("_boucle_attente: retour True")
    return True


def _commande_capture(args: argparse.Namespace, patienter=None) -> int:
    """Sous-commande capture : boucle jusqu'à SIGINT/SIGTERM.

    ``patienter`` : injecté dans :func:`_boucle_attente` (les tests s'en
    servent pour sortir immédiatement de la boucle d'attente).
    """
    logger.debug("_commande_capture: entrée")
    agent = AgentProbe(
        ReglagesCapture(
            interface=args.interface,
            dossier=args.dossier,
            nb_fichiers=args.nb_fichiers,
            duree_par_fichier=args.duree_par_fichier,
            prefixe=args.prefixe,
            filtre_bpf=args.filtre_bpf,
        ),
        dossier_fenetres=args.dossier,
    )
    agent.capture.demarrer()
    print(f"capture en cours sur {args.interface} (tampon : {args.dossier}), Ctrl-C pour arrêter", flush=True)
    if _boucle_attente(agent, patienter):
        agent.capture.arreter()
        print("capture arrêtée, tampon conservé", flush=True)
        logger.debug("_commande_capture: retour 0")
        return 0
    agent.capture.arreter()
    print("l'enregistreur s'est arrêté", file=sys.stderr, flush=True)
    logger.debug("_commande_capture: retour 1")
    return 1


def _commande_fenetre(args: argparse.Namespace) -> int:
    """Sous-commande fenetre : extraction + description JSON sur la sortie standard."""
    logger.debug("_commande_fenetre: entrée")
    try:
        resultat = extraire_fenetre_depuis_args(args)
    except FenetreVideError as erreur:
        print(f"rien dans le tampon pour cette fenêtre : {erreur}", file=sys.stderr)
        logger.debug("_commande_fenetre: retour 2 (fenêtre vide)")
        return 2
    except (FiltreBpfInvalideError, FenetreInvalideError) as erreur:
        print(f"fenêtre refusée : {erreur}", file=sys.stderr)
        logger.debug("_commande_fenetre: retour 3 (fenêtre invalide)")
        return 3
    except FenetreTropGrandeError as erreur:
        print(f"fenêtre trop grande : {erreur}", file=sys.stderr)
        logger.debug("_commande_fenetre: retour 4 (trop grande)")
        return 4
    print(
        json.dumps(
            {
                "window_id": resultat.identifiant,
                "requested": {"start": resultat.demande[0], "end": resultat.demande[1]},
                "covered": (
                    {"start": resultat.couvert[0], "end": resultat.couvert[1]} if resultat.couvert is not None else None
                ),
                "packet_count": resultat.nb_paquets,
                "bytes": resultat.octets,
                "sha256": resultat.sha256,
                "chemin": resultat.chemin,
                # Issue #1103 : pertes déclarées et état d'horloge (contrat v1).
                "capture_loss": resultat.pertes.vers_dict() if resultat.pertes is not None else None,
                "clock": resultat.horloge.vers_dict() if resultat.horloge is not None else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    logger.debug("_commande_fenetre: retour 0")
    return 0


def extraire_fenetre_depuis_args(args: argparse.Namespace):
    """Extraction factice des arguments de ``fenetre`` (séparée pour les tests)."""
    logger.debug("extraire_fenetre_depuis_args: entrée")
    from netcross_probe.fenetres import extraire_fenetre as _extraire

    resultat = _extraire(
        args.dossier,
        args.debut,
        args.fin,
        prefixe=args.prefixe,
        filtre_bpf=args.filtre_bpf,
        inclure_inconnus=args.inclure_inconnus,
        dossier_sortie=args.sortie,
        max_octets=args.max_octets,
    )
    logger.debug("extraire_fenetre_depuis_args: retour fenêtre {}", resultat.identifiant)
    return resultat


def main(argv: Sequence[str] | None = None) -> int:
    """Entrée de la sonde ; renvoie un code de sortie (0 nominal)."""
    logger.debug("main: entrée")
    args = construire_parseur().parse_args(argv)
    if args.commande == "capture":  # noqa: SIM108 -- deux sous-commandes distinctes, pas une alternative
        code = _commande_capture(args)
    else:
        code = _commande_fenetre(args)
    logger.debug("main: retour {}", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
