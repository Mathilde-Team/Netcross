# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.dechiffrement -- ce que le déchiffrement TLS/QUIC a réellement
couvert, point par point (issue #1043, chantier #997).

Un fichier de clés (``--tls-keylog``) ou des blocs DSB pcapng ne couvrent
souvent qu'une partie des sessions d'une capture : navigateur lancé avant
``SSLKEYLOGFILE``, autre poste, sessions reprises. Le rapport dit donc, pour
chaque point concerné, « 42/50 sessions TLS déchiffrées au point CLIENT ».

Définitions (voir ``pcap_parser.protocols.extract_dechiffrement``) :

- une session TLS est un ``tls.stream`` de la capture du point ; elle est
  déchiffrée si au moins un de ses enregistrements l'a été ;
- une session QUIC est un ``quic.connection.number`` ; elle est déchiffrée
  si au moins un paquet 1-RTT (en-tête court) a été déchiffré. Les paquets
  Initial, toujours déchiffrables, ne comptent pas.

Un paquet sans identifiant de session (paquet synthétique, ancien tshark)
est rattaché à sa conversation (adresses et ports, sans le sens).

Un point apparaît dans le rapport s'il a reçu un fichier de clés
(``Report.points_keylog``), si sa capture embarque des secrets (blocs DSB)
ou si au moins une de ses sessions a été déchiffrée. Les autres points ne
sont pas listés : « 0/50 » sur un point sans aucune clé n'apprendrait rien.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

PROTOCOLES = ("tls", "quic")
LIBELLES = {"tls": "TLS", "quic": "QUIC"}


def _conversation(pk: Pkt) -> tuple:
    """Clé de conversation sans le sens (repli sans identifiant de session)."""
    logger.debug("_conversation: entrée")
    extremites = sorted([(pk.src, pk.sport or 0), (pk.dst, pk.dport or 0)])
    logger.debug("_conversation: retour")
    return ("conv", pk.proto, *extremites[0], *extremites[1])


def _session(pk: Pkt, protocole: str) -> tuple | None:
    """Identifiant de session TLS ou QUIC du paquet, None s'il n'en porte pas."""
    logger.debug("_session: entrée ({})", protocole)
    if protocole == "tls":
        porte = pk.tls_stream is not None or pk.tls_dechiffre or pk.tls_client_hello or pk.tls_server_hello
        identifiant = pk.tls_stream
    else:
        porte = pk.quic_connexion is not None or pk.quic_dechiffre
        identifiant = pk.quic_connexion
    if not porte:
        logger.debug("_session: aucune session -> retour None")
        return None
    logger.debug("_session: retour")
    return ("id", identifiant) if identifiant is not None else _conversation(pk)


def compter_sessions(all_packets: Iterable[Pkt]) -> dict[str, dict[str, dict[str, int]]]:
    """``{point: {"tls": {"sessions": n, "dechiffrees": k}, "quic": {...}}}``.

    Seuls les protocoles présents sur un point figurent dans son entrée.
    """
    logger.debug("compter_sessions: entrée")
    sessions: dict[tuple[str, str], dict[tuple, bool]] = defaultdict(dict)
    for pk in all_packets:
        for protocole in PROTOCOLES:
            cle = _session(pk, protocole)
            if cle is None:
                continue
            dechiffre = pk.tls_dechiffre if protocole == "tls" else pk.quic_dechiffre
            vues = sessions[(pk.point, protocole)]
            vues[cle] = vues.get(cle, False) or dechiffre
    resultat: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for (point, protocole), vues in sorted(sessions.items()):
        resultat[point][protocole] = {"sessions": len(vues), "dechiffrees": sum(vues.values())}
    logger.debug("compter_sessions: retour ({} point(s))", len(resultat))
    return dict(resultat)


def _points_avec_dsb(capture_infos: Iterable[dict]) -> set[str]:
    """Points dont la capture embarque des secrets de déchiffrement (DSB)."""
    logger.debug("_points_avec_dsb: entrée")
    points = {info.get("label") for info in capture_infos if info.get("decryption_secrets_blocks")}
    logger.debug("_points_avec_dsb: retour ({} point(s))", len(points))
    return {p for p in points if p}


def points_a_signaler(report) -> list[str]:
    """Points du rapport dont la couverture du déchiffrement est à afficher."""
    logger.debug("points_a_signaler: entrée")
    compteurs = getattr(report, "dechiffrement", {}) or {}
    cles = set(getattr(report, "points_keylog", []) or []) | _points_avec_dsb(getattr(report, "capture_infos", []))
    retenus = [
        point
        for point, par_proto in compteurs.items()
        if point in cles or any(c["dechiffrees"] for c in par_proto.values())
    ]
    # un point avec fichier de clés mais sans aucune session TLS/QUIC est
    # signalé aussi : le lecteur doit savoir que la clé n'a rien trouvé.
    retenus += [point for point in cles if point not in compteurs]
    ordre = {p: i for i, p in enumerate(getattr(report, "points", []))}
    resultat = sorted(set(retenus), key=lambda p: (ordre.get(p, len(ordre)), p))
    logger.debug("points_a_signaler: retour ({} point(s))", len(resultat))
    return resultat


def phrase(point: str, protocole: str, compte: dict[str, int]) -> str:
    """« 42/50 sessions TLS déchiffrées au point CLIENT »."""
    logger.debug("phrase: entrée")
    texte = f"{compte['dechiffrees']}/{compte['sessions']} sessions {LIBELLES[protocole]} déchiffrées au point {point}"
    logger.debug("phrase: retour")
    return texte


def lignes(report) -> list[str]:
    """Phrases de couverture, une par point et par protocole présent."""
    logger.debug("lignes: entrée")
    compteurs = getattr(report, "dechiffrement", {}) or {}
    resultat = []
    for point in points_a_signaler(report):
        par_proto = compteurs.get(point, {})
        if not par_proto:
            resultat.append(f"aucune session TLS ou QUIC au point {point}")
            continue
        resultat += [phrase(point, proto, par_proto[proto]) for proto in PROTOCOLES if proto in par_proto]
    logger.debug("lignes: retour ({} ligne(s))", len(resultat))
    return resultat


def document_json(report) -> list[dict]:
    """Entrées ``decryption`` du rapport JSON (liste vide si rien à signaler)."""
    logger.debug("document_json: entrée")
    compteurs = getattr(report, "dechiffrement", {}) or {}
    cles = set(getattr(report, "points_keylog", []) or [])
    resultat = []
    for point in points_a_signaler(report):
        par_proto = compteurs.get(point, {})
        entree: dict = {"point": point, "keylog": point in cles}
        for proto in PROTOCOLES:
            compte = par_proto.get(proto, {"sessions": 0, "dechiffrees": 0})
            entree[f"{proto}_sessions"] = compte["sessions"]
            entree[f"{proto}_decrypted"] = compte["dechiffrees"]
        entree["summary"] = [phrase(point, proto, par_proto[proto]) for proto in PROTOCOLES if proto in par_proto]
        resultat.append(entree)
    logger.debug("document_json: retour ({} point(s))", len(resultat))
    return resultat
