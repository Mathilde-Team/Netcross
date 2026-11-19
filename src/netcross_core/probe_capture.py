# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_core.probe_capture -- point de capture servi par une sonde
(issue #1105, sous-issue 5/6 du chantier #1002).

Une source ``probe://`` remplace le flux tiré à travers le réseau
(``rpcap://``, ``sshdump://``) : la sonde écrit localement dans son
tampon circulaire et la fenêtre utile est **tirée à la fin de la
session** puis décortiquée par le même pipeline que n'importe quel
fichier de capture (``parse_capture`` -- tshark, aucune dissection
nouvelle). Une coupure du lien d'administration ne fait perdre aucun
paquet au point de mesure.

Ce module est le point de branchement commun des trois surfaces (CLI
``--live``, API ``POST /live-captures``, GUI « capture en direct ») :
toutes trois finissent par :func:`collecter_fenetre_sonde`, qui demande
la fenêtre à la sonde (mTLS, ``netcross_probe.client``) et la lit.

Aucun secret dans les messages d'erreur ; les identités mTLS viennent
de l'environnement (``NETCROSS_PROBE_CERT_PEM`` etc., voir
``netcross_probe.client.client_depuis_env``).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_core.parsing import Pkt, parse_capture
from netcross_probe.client import ClientSonde, client_depuis_env
from pcap_parser.remote import CaptureSourceError, parse_source

logger = get_logger(__name__)

__all__ = ["collecter_fenetre_sonde", "est_source_sonde", "telecharger_fenetre_sonde", "url_sonde"]


def est_source_sonde(interface: str) -> bool:
    """Vrai si ``interface`` est une URL de sonde ``probe://`` (toute
    autre valeur -- interface locale, rpcap, pipe -- donne faux ; une
    URL invalide donne faux, l'erreur est portée par ``parse_source``
    à l'endroit qui valide les points)."""
    logger.debug("est_source_sonde: entrée ({})", interface)
    try:
        source = parse_source(interface)
    except CaptureSourceError:
        logger.debug("est_source_sonde: source invalide -> retour False")
        return False
    valeur = source.kind == "probe"
    logger.debug("est_source_sonde: retour {}", valeur)
    return valeur


def url_sonde(interface: str) -> str:
    """URL de base (``https://hote:port``) de la sonde décrite par
    ``interface`` -- le nom de sonde du chemin, informatif, est ignoré."""
    logger.debug("url_sonde: entrée ({})", interface)
    source = parse_source(interface)
    if source.kind != "probe":
        logger.debug("url_sonde: pas une sonde -> levée ValueError")
        raise ValueError(f"pas une source probe:// : {interface!r}")
    cible = source.interface  # probe://hote:port[/nom]
    netloc = cible.partition("://")[2]
    hote_port = netloc.split("/", 1)[0]
    url = f"https://{hote_port}"
    logger.debug("url_sonde: retour {}", url)
    return url


def telecharger_fenetre_sonde(
    interface: str,
    debut: float,
    fin: float,
    bpf: str | None = None,
    env: Mapping[str, str] | None = None,
    client: ClientSonde | None = None,
) -> bytes:
    """Le pcapng brut de la fenêtre [debut, fin] d'une sonde.

    ``debut``/``fin`` : secondes Unix, bornes incluses (le tampon de la
    sonde peut couvrir plus court -- ce n'est pas une absence de trafic).
    Sans ``client``, il est construit depuis l'environnement (identités
    mTLS ``NETCROSS_PROBE_*``) ; les fichiers en cours d'écriture du
    tampon sont inclus : c'est la fin de session, les paquets récents
    sont déjà sur disque.

    Une sonde injoignable ou un refus remonte tel quel (erreur explicite,
    jamais un corps vide silencieux) : l'appelant décide s'il s'agit d'un
    point en échec parmi d'autres.
    """
    logger.debug(
        "telecharger_fenetre_sonde: entrée ([{}, {}], bpf={!r})",
        debut,
        fin,
        bpf,
    )
    variables = os.environ if env is None else env
    if client is None:
        client = client_depuis_env(url_sonde(interface), env=variables)
    donnees = client.extraire_pcapng(debut, fin, bpf=bpf, inclure_inconnus=True)
    logger.debug("telecharger_fenetre_sonde: retour {} octet(s)", len(donnees))
    return donnees


def collecter_fenetre_sonde(
    label: str,
    interface: str,
    debut: float,
    fin: float,
    bpf: str | None = None,
    env: Mapping[str, str] | None = None,
    client: ClientSonde | None = None,
) -> list[Pkt]:
    """Tire la fenêtre [debut, fin] d'une sonde et la lit comme un
    fichier de capture étiqueté ``label`` (même pipeline que ``--capture``).

    Voir :func:`telecharger_fenetre_sonde` pour la fenêtre elle-même ;
    ici, le pcapng passe par un fichier temporaire puis le lecteur
    habituel (tshark), et le fichier est supprimé après lecture.
    """
    logger.debug("collecter_fenetre_sonde: entrée (point {})", label)
    donnees = telecharger_fenetre_sonde(interface, debut, fin, bpf=bpf, env=env, client=client)
    with tempfile.NamedTemporaryFile(prefix=f"netcross-sonde-{label}-", suffix=".pcapng", delete=False) as fichier:
        fichier.write(donnees)
        chemin = fichier.name
    try:
        pkts = parse_capture(label, chemin)
    finally:
        try:
            Path(chemin).unlink()
        except OSError:
            logger.debug("collecter_fenetre_sonde: pcapng temporaire {} déjà supprimé", chemin)
    logger.debug("collecter_fenetre_sonde: retour {} paquet(s)", len(pkts))
    return pkts
