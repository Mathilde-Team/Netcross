# SPDX-License-Identifier: GPL-3.0-or-later
"""Extraction d'une fenêtre [t1, t2] filtrée du tampon circulaire de la sonde.

Issue #1099 : le collecteur demande une fenêtre bornée (secondes Unix,
bornes incluses) avec un filtre BPF optionnel ; la sonde sélectionne les
fichiers du tampon qui la couvrent, découpe l'intervalle, applique le
filtre BPF (libpcap, voir ``netcross_probe.bpf``) et produit un pcapng
décrit par :class:`FenetreResultat` (intervalle demandé, intervalle
réellement couvert, nombre de paquets, taille, SHA-256).

La sécurité (mTLS, #1101), les métadonnées pertes/horloge (#1103) et le
service HTTP lui-même (#1105) sont des sous-issues séparées : ce module
est la mécanique pure, testable en local.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import subprocess
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from loguru import logger

from netcross_probe.bpf import filtrer_capture
from netcross_probe.etat import EtatHorloge, PertesCapture, lire_etat_horloge, lire_pertes_capture
from pcap_parser.capinfos_source import read_capture_info
from pcap_parser.capture import RingFile, cut_capture_window, ring_inventory, select_ring_files

__all__ = [
    "FenetreInvalideError",
    "FenetreResultat",
    "FenetreTropGrandeError",
    "FenetreVideError",
    "extraire_fenetre",
]


class FenetreInvalideError(ValueError):
    """Fenêtre refusée : bornes inversées ou filtre BPF invalide (contrat v1 : 400)."""


class FenetreVideError(RuntimeError):
    """Aucun fichier du tampon ne couvre la fenêtre demandée (contrat v1 : 404)."""


class FenetreTropGrandeError(RuntimeError):
    """La fenêtre produite dépasse ``max_octets`` (contrat v1 : 413)."""


@dataclass(frozen=True)
class FenetreResultat:
    """Description d'une fenêtre extraite (miroir de ``Window`` du contrat v1).

    ``couvert`` : intervalle réellement couvert par les paquets retenus
    (premier/dernier paquet du pcapng final) ; ``None`` si la fenêtre est
    vide -- le tampon a peut-être déjà tourné, ce n'est pas une absence de
    trafic.
    """

    identifiant: str
    demande: tuple[float, float]
    couvert: tuple[float, float] | None
    nb_paquets: int
    octets: int
    sha256: str
    chemin: str
    # Issue #1103 : pertes déclarées par les ISB des fichiers du tampon
    # couvrant la fenêtre (None = aucune statistique lue), et état
    # d'horloge de la sonde au moment de l'extraction.
    pertes: PertesCapture | None = None
    horloge: EtatHorloge | None = None


def _outil_wireshark(nom: str) -> str:
    """Chemin d'un outil Wireshark (mergecap, editcap) ; même erreur que capture.py."""
    logger.debug("_outil_wireshark: entrée ({})", nom)
    chemin = shutil.which(nom)
    if chemin is None:
        logger.warning("_outil_wireshark: {} introuvable dans le PATH", nom)
        raise RuntimeError(
            f"{nom} introuvable dans le PATH -- installer le paquet 'tshark' "
            "(apt install tshark / dnf install wireshark-cli)."
        )
    logger.debug("_outil_wireshark: retour {}", chemin)
    return chemin


def _fusionner(morceaux: Sequence[str], sortie: str) -> None:
    """Fusionne les morceaux découpés en un seul fichier (mergecap, ou copie si un seul)."""
    logger.debug("_fusionner: entrée ({} morceau(x) -> {})", len(morceaux), sortie)
    dossier = os.path.dirname(sortie)
    if dossier:
        os.makedirs(dossier, exist_ok=True)
    if len(morceaux) == 1:
        os.replace(morceaux[0], sortie)
        logger.debug("_fusionner: fin (morceau unique déplacé)")
        return
    mergecap = _outil_wireshark("mergecap")
    resultat = subprocess.run(
        [mergecap, "-F", "pcapng", *morceaux, "-w", sortie],
        capture_output=True,
        text=True,
        check=False,
    )
    if resultat.returncode != 0:
        logger.warning("_fusionner: mergecap a échoué : {}", resultat.stderr.strip())
        raise RuntimeError(f"mergecap a échoué (code {resultat.returncode}) : {resultat.stderr.strip()}")
    logger.debug("_fusionner: fin")


def _convertir_pcapng(chemin_pcap: str, chemin_pcapng: str) -> None:
    """Convertit le pcap filtré en pcapng (editcap, sans perte d'horodatage)."""
    logger.debug("_convertir_pcapng: entrée ({} -> {})", chemin_pcap, chemin_pcapng)
    editcap = _outil_wireshark("editcap")
    resultat = subprocess.run(
        [editcap, "-F", "pcapng", chemin_pcap, chemin_pcapng],
        capture_output=True,
        text=True,
        check=False,
    )
    if resultat.returncode != 0:
        logger.warning("_convertir_pcapng: editcap a échoué : {}", resultat.stderr.strip())
        raise RuntimeError(f"editcap a échoué (code {resultat.returncode}) : {resultat.stderr.strip()}")
    logger.debug("_convertir_pcapng: fin")


def _sha256_fichier(chemin: str) -> str:
    """SHA-256 hexadécimal du fichier (contrat v1 : en-tête Digest du téléchargement)."""
    logger.debug("_sha256_fichier: entrée ({})", chemin)
    somme = hashlib.sha256()
    with open(chemin, "rb") as fichier:
        for bloc in iter(lambda: fichier.read(1 << 20), b""):
            somme.update(bloc)
    logger.debug("_sha256_fichier: retour")
    return somme.hexdigest()


def _selectionner_tampon(
    dossier: str, prefixe: str, debut: float, fin: float, inclure_inconnus: bool
) -> list[RingFile]:
    """Inventorie le tampon et sélectionne les fichiers couvrant [debut, fin]."""
    logger.debug("_selectionner_tampon: entrée ({}, [{}, {}])", dossier, debut, fin)
    inventaire = ring_inventory(dossier, prefix=prefixe)
    selection = select_ring_files(inventaire, debut, fin, include_unknown=inclure_inconnus)
    logger.debug("_selectionner_tampon: retour {} fichier(s) sur {}", len(selection), len(inventaire))
    return selection


def extraire_fenetre(
    dossier_tampon: str,
    debut: float,
    fin: float,
    *,
    prefixe: str = "probe",
    filtre_bpf: str | None = None,
    inclure_inconnus: bool = False,
    dossier_sortie: str,
    max_octets: int | None = None,
    lire_horloge=lire_etat_horloge,
) -> FenetreResultat:
    """Extrait la fenêtre [debut, fin] (epoch, bornes incluses) du tampon circulaire.

    Étapes (contrat v1, ``request_window``) :

    1. sélection des fichiers du tampon qui chevauchent la fenêtre
       (``select_ring_files``, #1086) -- ``FenetreVideError`` si aucun ;
    2. découpe de l'intervalle dans chaque fichier (``cut_capture_window``,
       editcap -A/-B) puis fusion (mergecap) ;
    3. application du filtre BPF (libpcap en relecture, ``netcross_probe.bpf``)
       et conversion du résultat en pcapng (editcap) ;
    4. calcul du SHA-256, de la taille et de l'intervalle réellement couvert
       (premier/dernier paquet via capinfos).

    Issue #1103 : les métadonnées de la fenêtre sont lues en même temps --
    pertes déclarées (somme des ISB des fichiers sélectionnés) et état
    d'horloge de la sonde (``lire_horloge``, injectable pour les tests).
    ``max_octets`` : si le pcapng final dépasse cette taille, il est
    supprimé et :class:`FenetreTropGrandeError` est levée (contrat v1 : 413).
    """
    logger.debug("extraire_fenetre: entrée (tampon {}, [{}, {}], filtre {!r})", dossier_tampon, debut, fin, filtre_bpf)
    if fin < debut:
        logger.debug("extraire_fenetre: si fin < debut -> levée FenetreInvalideError")
        raise FenetreInvalideError(f"fenêtre inversée : fin ({fin}) antérieure au début ({debut})")
    selection = _selectionner_tampon(dossier_tampon, prefixe, debut, fin, inclure_inconnus)
    if not selection:
        logger.debug("extraire_fenetre: tampon vide pour cette fenêtre -> levée FenetreVideError")
        raise FenetreVideError(f"aucun fichier du tampon {dossier_tampon!r} ne couvre [{debut}, {fin}]")
    # Issue #1103 : pertes déclarées par les fichiers du tampon retenus.
    pertes = lire_pertes_capture([fichier.path for fichier in selection])
    horloge = lire_horloge()

    os.makedirs(dossier_sortie, exist_ok=True)
    identifiant = uuid.uuid4().hex[:16]
    atelier = os.path.join(dossier_sortie, f".atelier-{identifiant}")
    os.makedirs(atelier, exist_ok=True)
    try:
        morceaux: list[str] = []
        for i, fichier in enumerate(selection, start=1):
            morceau = os.path.join(atelier, f"morceau-{i:03d}.pcapng")
            # editcap -B garde les paquets STRICTEMENT AVANT la borne : pour
            # une fenêtre à bornes incluses (contrat v1), on coupe jusqu'à
            # fin + 1 µs (les horodatages pcap/pcapng ont une résolution
            # d'au mieux la microseconde, fin lui-même est donc retenu).
            cut_capture_window(fichier.path, morceau, debut, fin + 1e-6)
            morceaux.append(morceau)
        brute = os.path.join(atelier, "fenetre-brute.pcapng")
        _fusionner(morceaux, brute)
        if filtre_bpf:
            pcap_filtre = os.path.join(atelier, "fenetre-filtre.pcap")
            filtrer_capture(brute, pcap_filtre, filtre_bpf)
            chemin_final_brut = os.path.join(atelier, "fenetre-filtre.pcapng")
            _convertir_pcapng(pcap_filtre, chemin_final_brut)
        else:
            chemin_final_brut = brute
        chemin_final = os.path.join(dossier_sortie, f"fenetre-{identifiant}.pcapng")
        os.replace(chemin_final_brut, chemin_final)
    finally:
        for racine, _dirs, fichiers in os.walk(atelier, topdown=False):
            for nom in fichiers:
                _supprimer(os.path.join(racine, nom))
            _supprimer(racine)

    octets = os.path.getsize(chemin_final)
    if max_octets is not None and octets > max_octets:
        logger.warning("extraire_fenetre: fenêtre de {} o > max {} o -> suppression et refus", octets, max_octets)
        _supprimer(chemin_final)
        logger.debug("extraire_fenetre: si octets > max_octets -> levée FenetreTropGrandeError")
        raise FenetreTropGrandeError(f"fenêtre de {octets} octets au-delà du maximum {max_octets}")
    infos = read_capture_info(chemin_final)
    nb_paquets = int(infos.packet_count or 0) if infos else 0
    couvert: tuple[float, float] | None = None
    if infos is not None and infos.start_time is not None and infos.end_time is not None:
        couvert = (float(infos.start_time), float(infos.end_time))
    resultat = FenetreResultat(
        identifiant=identifiant,
        demande=(float(debut), float(fin)),
        couvert=couvert,
        nb_paquets=nb_paquets,
        octets=octets,
        sha256=_sha256_fichier(chemin_final),
        chemin=chemin_final,
        pertes=pertes,
        horloge=horloge,
    )
    logger.debug(
        "extraire_fenetre: retour fenêtre {} ({} paquet(s), {} o, couvert {})",
        identifiant,
        nb_paquets,
        octets,
        couvert,
    )
    return resultat


def _supprimer(chemin: str) -> None:
    """Suppression tolérante : fichier ou répertoire, jamais bloquant."""
    logger.debug("_supprimer: entrée ({})", chemin)
    with contextlib.suppress(OSError):
        if os.path.isfile(chemin):
            os.remove(chemin)
        else:
            os.rmdir(chemin)
    logger.debug("_supprimer: fin")
