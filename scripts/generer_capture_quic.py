# SPDX-License-Identifier: GPL-3.0-or-later
"""Génère ``tests/data/quic-1rtt.pcap`` et ``tests/data/quic-1rtt-keys.txt`` (issue #1045).

Joue en mémoire une vraie connexion QUIC v1 (aioquic) entre un client et un
serveur : poignée de main, données 1-RTT sur un flux bidirectionnel
(``GET /netcross-quic``), puis fermeture applicative (CONNECTION_CLOSE de
type 0x1d, code 0x42, raison « netcross »). Les datagrammes sont encapsulés
dans des trames Ethernet/IPv4/UDP et écrits dans un pcap classique ; les
secrets TLS du client sont écrits au format SSLKEYLOGFILE.

aioquic n'est PAS une dépendance du projet : ce script sert une seule fois,
le résultat est versionné. Usage ::

    uv run --with aioquic python scripts/generer_capture_quic.py
"""

from __future__ import annotations

import datetime
import struct
import sys
from pathlib import Path

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from loguru import logger

CLIENT = ("10.0.0.1", 50443, b"\x02\x00\x00\x00\x00\x01")
SERVEUR = ("10.0.0.2", 443, b"\x02\x00\x00\x00\x00\x02")
REQUETE = b"GET /netcross-quic\r\n"
CODE_FERMETURE = 0x42
RAISON = "netcross"


def _certificat(dossier: Path) -> tuple[Path, Path]:
    logger.debug("_certificat: entrée")
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic.test")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(days=1))
        .not_valid_after(maintenant + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("quic.test")]), critical=False)
        .sign(cle, hashes.SHA256())
    )
    chemin_cert, chemin_cle = dossier / "quic-cert.pem", dossier / "quic-key.pem"
    chemin_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    chemin_cle.write_bytes(
        cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    logger.debug("_certificat: retour")
    return chemin_cert, chemin_cle


def _somme(donnees: bytes) -> int:
    logger.debug("_somme: entrée")
    if len(donnees) % 2:
        donnees += b"\x00"
    total = sum(struct.unpack(f"!{len(donnees) // 2}H", donnees))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    logger.debug("_somme: retour")
    return ~total & 0xFFFF


def _trame(src, dst, charge: bytes, ident: int) -> bytes:
    logger.debug("_trame: entrée")
    ip_src = bytes(int(o) for o in src[0].split("."))
    ip_dst = bytes(int(o) for o in dst[0].split("."))
    udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(charge), 0) + charge
    pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", _somme(pseudo + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0x4000, 64, 17, 0, ip_src, ip_dst)
    ip = ip[:10] + struct.pack("!H", _somme(ip)) + ip[12:]
    logger.debug("_trame: retour")
    return dst[2] + src[2] + b"\x08\x00" + ip + udp


def generer(dossier: Path) -> tuple[Path, Path]:
    logger.debug("generer: entrée ({})", dossier)
    dossier.mkdir(parents=True, exist_ok=True)
    temporaire = dossier / "tmp-quic"
    temporaire.mkdir(exist_ok=True)
    chemin_cert, chemin_cle = _certificat(temporaire)
    keylog = dossier / "quic-1rtt-keys.txt"
    horloge = [1_700_000_000.0]

    conf_c = QuicConfiguration(is_client=True, alpn_protocols=["netcross"], server_name="quic.test")
    conf_c.verify_mode = 0  # ssl.CERT_NONE
    with keylog.open("w") as fichier_cles:
        conf_c.secrets_log_file = fichier_cles
        conf_s = QuicConfiguration(is_client=False, alpn_protocols=["netcross"])
        conf_s.load_cert_chain(chemin_cert, chemin_cle)
        client = QuicConnection(configuration=conf_c)
        # le serveur est cree avec le DCID initial choisi par le client
        serveur = QuicConnection(configuration=conf_s, original_destination_connection_id=client._peer_cid.cid)
        adr_c, adr_s = (CLIENT[0], CLIENT[1]), (SERVEUR[0], SERVEUR[1])
        datagrammes: list[tuple[bool, bytes]] = []

        def pomper() -> None:
            logger.debug("pomper: entrée")
            for _ in range(50):
                envoye = False
                for donnees, _adr in client.datagrams_to_send(now=horloge[0]):
                    datagrammes.append((True, donnees))
                    serveur.receive_datagram(donnees, adr_c, now=horloge[0])
                    envoye = True
                for donnees, _adr in serveur.datagrams_to_send(now=horloge[0]):
                    datagrammes.append((False, donnees))
                    client.receive_datagram(donnees, adr_s, now=horloge[0])
                    envoye = True
                horloge[0] += 0.001
                if not envoye:
                    logger.debug("pomper: plus rien à envoyer -> retour")
                    return
            logger.debug("pomper: fin")

        client.connect(adr_s, now=horloge[0])
        pomper()
        flux = client.get_next_available_stream_id()
        client.send_stream_data(flux, REQUETE, end_stream=True)
        pomper()
        recu = b""
        while (evenement := serveur.next_event()) is not None:
            if isinstance(evenement, StreamDataReceived):
                recu += evenement.data
                serveur.send_stream_data(evenement.stream_id, b"ok", end_stream=True)
        assert recu == REQUETE, recu
        pomper()
        client.close(error_code=CODE_FERMETURE, reason_phrase=RAISON)
        pomper()

    trames = [
        _trame(*((CLIENT, SERVEUR) if du_c else (SERVEUR, CLIENT)), d, i + 1) for i, (du_c, d) in enumerate(datagrammes)
    ]
    capture = dossier / "quic-1rtt.pcap"
    with capture.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, trame in enumerate(trames):
            f.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(trame), len(trame)))
            f.write(trame)
    for chemin in temporaire.iterdir():
        chemin.unlink()
    temporaire.rmdir()
    logger.debug("generer: retour")
    return capture, keylog


if __name__ == "__main__":
    cible = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "tests" / "data"
    print(*generer(cible))
