# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.decrypted -- contenu TLS déchiffré par tshark, trame par trame
(issue #1045, chantier #997).

La sortie EK de tshark ne porte que les champs DISSÉQUÉS du contenu
déchiffré (``http.request.uri``...), jamais les octets en clair eux-mêmes :
``tls.app_data`` reste le texte chiffré. Les signatures d'exploits, qui
travaillent sur la charge utile brute, ont besoin de ces octets. tshark les
expose comme source de données « Decrypted TLS » dans son vidage hexadécimal
(``-x``) ; ce module lance donc une seconde lecture, limitée aux trames
portant des données applicatives TLS, et reconstitue
``{numéro de trame: octets déchiffrés}``.

Format lu (``-P -x`` avec une seule colonne, le numéro de trame) ::

       10
    <ligne vide>
    Packet (154 bytes):
    0000  02 00 ...   ..............
    Decrypted TLS (78 bytes):
    0000  47 45 54 20 ...   GET /netcross-se

Seuls les blocs « Decrypted TLS » sont gardés ; plusieurs blocs d'une même
trame (plusieurs enregistrements) sont concaténés dans l'ordre. QUIC n'est
pas couvert : ses blocs déchiffrés portent des trames QUIC, pas un flux
applicatif directement exploitable par les signatures.

Les secrets ne transitent jamais par ce module : seul le CHEMIN du fichier
de clés est passé à tshark (préférence ``tls.keylog_file``).
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Iterable

from loguru import logger as _loguru_logger

from pcap_parser.ek_source import TsharkError, TsharkNotFoundError, _tshark_path, tls_keylog_prefs

# pcap_parser reste independant de netcross_core (contrat import-linter).
logger = _loguru_logger.bind(name=__name__)

_BLOC = re.compile(r"^(?P<nom>[^\s].*) \(\d+ bytes\):$")
_LIGNE_HEX = re.compile(r"^[0-9a-f]{4,}  ")
_NUMERO = re.compile(r"^\s+(\d+)\s*$")
# colonnes du vidage : decalage (4+ chiffres), 2 espaces, 16 octets « hh »
# separes par un espace (47 caracteres), puis l'ASCII apres 3 espaces
_DEBUT_HEX = 6
_FIN_HEX = _DEBUT_HEX + 16 * 3 - 1
BLOC_TLS = "Decrypted TLS"


def parse_hex_dump(lignes: Iterable[str]) -> dict[int, bytes]:
    """``{trame: octets}`` des blocs « Decrypted TLS » d'une sortie ``-P -x``."""
    logger.debug("parse_hex_dump: entrée")
    resultat: dict[int, bytearray] = {}
    trame: int | None = None
    dans_bloc = False
    for ligne in lignes:
        ligne = ligne.rstrip("\n")
        numero = _NUMERO.match(ligne)
        if numero:
            trame, dans_bloc = int(numero.group(1)), False
            continue
        bloc = _BLOC.match(ligne)
        if bloc:
            dans_bloc = bloc.group("nom") == BLOC_TLS and trame is not None
            continue
        if not dans_bloc or not _LIGNE_HEX.match(ligne):
            continue
        offset = ligne.index("  ")
        zone = ligne[offset + 2 : offset + 2 + _FIN_HEX - _DEBUT_HEX]
        octets = bytes(int(tok, 16) for tok in zone.split() if len(tok) == 2)
        resultat.setdefault(trame, bytearray()).extend(octets)  # type: ignore[arg-type]
    logger.debug("parse_hex_dump: retour ({} trame(s))", len(resultat))
    return {n: bytes(v) for n, v in resultat.items()}


def _arguments(tls_keylog: str) -> list[str]:
    """Ligne de commande tshark de la lecture du contenu déchiffré. La capture
    arrive sur l'entrée standard (``-r -``), comme le repli de pcap_parser
    pour les tshark confinés (snap, AppArmor) qui ne peuvent pas l'ouvrir."""
    logger.debug("_arguments: entrée")
    args = [_tshark_path(), "-n", "-r", "-"]
    for pref in tls_keylog_prefs(tls_keylog):
        args += ["-o", pref]
    args += ["-o", 'gui.column.format:"No.","%m"', "-Y", "tls.app_data", "-P", "-x"]
    logger.debug("_arguments: retour")
    return args


def read_decrypted_tls(path: str, tls_keylog: str) -> dict[int, bytes]:
    """Octets TLS déchiffrés par trame (``{}`` si rien n'a pu être déchiffré).

    Lève ``TsharkNotFoundError`` sans tshark et ``TsharkError`` si tshark
    échoue ; l'appelant décide (le scanner d'exploits journalise et
    continue sur le seul contenu chiffré).
    """
    logger.debug("read_decrypted_tls: entrée ({})", path)
    # La capture est ouverte AVANT de chercher tshark : une capture absente
    # est signalée comme telle, que tshark soit installé ou non.
    try:
        capture = open(path, "rb")  # noqa: SIM115 -- fermé par le with ci-dessous
    except OSError as exc:
        logger.debug("read_decrypted_tls: capture illisible -> levée TsharkError")
        raise TsharkError(f"capture illisible : {path} ({exc.strerror})") from exc
    try:
        args = _arguments(tls_keylog)
    except TsharkNotFoundError:
        capture.close()
        logger.debug("read_decrypted_tls: tshark introuvable -> capture fermée, levée propagée")
        raise
    # stderr dans un fichier temporaire : un tube non lu pendant la lecture
    # de stdout pourrait se remplir et bloquer tshark.
    with capture, tempfile.TemporaryFile(mode="w+", errors="replace") as journal:
        with subprocess.Popen(
            args, stdin=capture, stdout=subprocess.PIPE, stderr=journal, text=True, errors="replace"
        ) as proc:
            assert proc.stdout is not None
            resultat = parse_hex_dump(proc.stdout)
            code = proc.wait()
        journal.seek(0)
        erreurs = journal.read()
    if code != 0:
        logger.debug("read_decrypted_tls: tshark code {} -> levée TsharkError", code)
        raise TsharkError(f"tshark a échoué (code {code}) sur {path} : {erreurs.strip()[:300]}")
    logger.debug("read_decrypted_tls: retour ({} trame(s) déchiffrée(s))", len(resultat))
    return resultat
