"""Capture TLS 1.3 + fichier de clés (SSLKEYLOGFILE) générés pour les tests (issue #1040).

Une vraie session TLS 1.3 (module ``ssl``, certificat autosigné éphémère) est
jouée en mémoire entre un client et un serveur (``ssl.MemoryBIO``), le client
écrivant ses secrets dans un fichier keylog. Les octets échangés sont ensuite
encapsulés dans des trames Ethernet/IPv4/TCP (sommes de contrôle valides) et
écrits dans un pcap classique. Aucun accès réseau ni privilège de capture.

La requête HTTP ``GET /netcross-secret`` n'est visible qu'en déchiffrant la
session : sans keylog, tshark ne voit que des enregistrements TLS.
"""

from __future__ import annotations

import datetime
import ssl
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REQUETE = b"GET /netcross-secret HTTP/1.1\r\nHost: tls13.test\r\nUser-Agent: netcross-test\r\n\r\n"
REPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
URI = "/netcross-secret"

CLIENT = ("10.0.0.1", 50000, b"\x02\x00\x00\x00\x00\x01")
SERVEUR = ("10.0.0.2", 443, b"\x02\x00\x00\x00\x00\x02")


def _certificat(dossier: Path) -> tuple[Path, Path]:
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls13.test")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(days=1))
        .not_valid_after(maintenant + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls13.test")]), critical=False)
        .sign(cle, hashes.SHA256())
    )
    chemin_cert, chemin_cle = dossier / "cert.pem", dossier / "cle.pem"
    chemin_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    chemin_cle.write_bytes(
        cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return chemin_cert, chemin_cle


def _session_tls13(dossier: Path, keylog: Path) -> list[tuple[bool, bytes]]:
    """Joue la session ; renvoie les octets échangés ``(du_client, données)`` dans l'ordre."""
    chemin_cert, chemin_cle = _certificat(dossier)
    ctx_serveur = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_serveur.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx_serveur.load_cert_chain(chemin_cert, chemin_cle)
    ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_client.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx_client.check_hostname = False
    ctx_client.verify_mode = ssl.CERT_NONE
    ctx_client.keylog_filename = str(keylog)

    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = ctx_client.wrap_bio(c_in, c_out, server_hostname="tls13.test")
    serveur = ctx_serveur.wrap_bio(s_in, s_out, server_side=True)
    echanges: list[tuple[bool, bytes]] = []

    def pomper() -> None:
        while True:
            donnees_c, donnees_s = c_out.read(), s_out.read()
            if not (donnees_c or donnees_s):
                return
            if donnees_c:
                echanges.append((True, donnees_c))
                s_in.write(donnees_c)
            if donnees_s:
                echanges.append((False, donnees_s))
                c_in.write(donnees_s)

    def etape(objet: ssl.SSLObject, action) -> bool:
        try:
            action(objet)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return False
        return True

    fini_c = fini_s = False
    for _ in range(20):
        fini_c = fini_c or etape(client, ssl.SSLObject.do_handshake)
        pomper()
        fini_s = fini_s or etape(serveur, ssl.SSLObject.do_handshake)
        pomper()
        if fini_c and fini_s:
            break
    assert fini_c and fini_s, "poignée de main TLS 1.3 inachevée"
    assert client.version() == "TLSv1.3"

    client.write(REQUETE)
    pomper()
    assert serveur.read(4096) == REQUETE
    serveur.write(REPONSE)
    pomper()
    assert client.read(4096) == REPONSE
    return echanges


def _somme(donnees: bytes) -> int:
    if len(donnees) % 2:
        donnees += b"\x00"
    total = sum(struct.unpack(f"!{len(donnees) // 2}H", donnees))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _trame(src, dst, seq: int, ack: int, drapeaux: int, charge: bytes, ident: int) -> bytes:
    ip_src = bytes(int(o) for o in src[0].split("."))
    ip_dst = bytes(int(o) for o in dst[0].split("."))
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, drapeaux, 65535, 0, 0) + charge
    pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _somme(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident, 0x4000, 64, 6, 0, ip_src, ip_dst)
    ip = ip[:10] + struct.pack("!H", _somme(ip)) + ip[12:]
    return dst[2] + src[2] + b"\x08\x00" + ip + tcp


def ecrire_capture(dossier: Path) -> tuple[Path, Path]:
    """Écrit ``tls13.pcap`` et ``keys.txt`` dans ``dossier`` ; renvoie leurs chemins."""
    dossier.mkdir(parents=True, exist_ok=True)
    keylog = dossier / "keys.txt"
    echanges = _session_tls13(dossier, keylog)

    seq = {True: 1000, False: 5000}
    trames: list[bytes] = []
    ident = 1

    def ajouter(du_client: bool, drapeaux: int, charge: bytes = b"") -> None:
        nonlocal ident
        src, dst = (CLIENT, SERVEUR) if du_client else (SERVEUR, CLIENT)
        ack = seq[not du_client] if drapeaux & 0x10 else 0
        trames.append(_trame(src, dst, seq[du_client], ack, drapeaux, charge, ident))
        ident += 1
        seq[du_client] += len(charge) + (1 if drapeaux & 0x03 else 0)

    ajouter(True, 0x02)  # SYN
    ajouter(False, 0x12)  # SYN-ACK
    ajouter(True, 0x10)  # ACK
    for du_client, donnees in echanges:
        for debut in range(0, len(donnees), 1400):
            ajouter(du_client, 0x18, donnees[debut : debut + 1400])

    capture = dossier / "tls13.pcap"
    with capture.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, trame in enumerate(trames):
            f.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(trame), len(trame)))
            f.write(trame)
    return capture, keylog
