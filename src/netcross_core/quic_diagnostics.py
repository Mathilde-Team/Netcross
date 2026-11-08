"""
netcross_core.quic_diagnostics -- extraction du SNI des paquets QUIC
Initial v1 et v2 (RFC 9000/9001/9369), pour voir le trafic HTTP/3 moderne (Chrome, Teams,
Meet, WhatsApp...) que le reste de l'outil ne voit aujourd'hui qu'en UDP
brut.

Ce que ce module fait, precisement :
  - detecte les paquets QUIC Initial (en-tete long) des versions 1
    (RFC 9000/9001) et 2 (RFC 9369, version 0x6b3343cf, issue #1061) ;
    chaque evenement porte sa version, signalee dans les constats
  - derive les cles de "protection initiale" -- PAS un vrai chiffrement
    secret, une obfuscation dont la cle est publique (derivee du
    Destination Connection ID + un sel fixe defini par la RFC), justement
    concue pour etre reversible par n'importe qui, cote comme cote
    serveur. Chaque etape de derivation (HKDF-Extract, HKDF-Expand-Label,
    cles/IV/HP) est validee ligne a ligne contre les vecteurs de test
    officiels de la RFC 9001 Annexe A.2 -- pas uniquement contre nos
    propres paquets construits a la main, qui seraient une preuve
    circulaire.
  - leve la protection d'en-tete (AES-ECB) et dechiffre la charge utile
    (AEAD AES-128-GCM) pour retrouver le ClientHello TLS 1.3 transporte
    dans la trame CRYPTO, puis en extrait le SNI avec le meme parseur que
    tls_diagnostics.py (reutilise, pas duplique).

Ce que ce module NE fait PAS (limites volontaires, pas des oublis) :
  - Versions autres que v1 et v2 (brouillons, versions privees, Version
    Negotiation) : ignorees. Pour v2 (RFC 9369), seuls changent le sel
    initial, les libelles HKDF ("quicv2 key/iv/hp") et les codes de type
    d'en-tete long (Initial = 0b01 au lieu de 0b00) ; le reste du
    pipeline est commun aux deux versions.
  - 0-RTT et 1-RTT (donnees applicatives apres le handshake) : chiffres
    avec des cles qui ne sont PAS publiques (derivees du secret partage
    TLS) -- structurellement indechiffrables sans capturer aussi les
    cles de session (keylog), hors de portee d'une analyse passive.
  - Retransmissions/reassemblage de CRYPTO frames fragmentees sur
    plusieurs paquets Initial (rare pour un simple SNI mais possible avec
    un ClientHello tres charge en extensions) : chaque paquet est traite
    isolement.
  - Le dechiffrement echoue proprement (exception interceptee, paquet
    ignore) plutot que de risquer de presenter une donnee corrompue --
    meme discipline que le decodeur CAPWAP.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pcap_parser
from netcross_core.logging_config import get_logger, summarize
from netcross_core.tls_diagnostics import parse_client_hello

logger = get_logger(__name__)
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    # leve plutot que de planter a l'import : un appelant (la CLI, la
    # GUI...) doit pouvoir importer netcross_core sans cryptography
    # installe tant qu'il n'a pas explicitement demande --quic, et
    # afficher son propre message plutot que de voir tout le process
    # mourir a l'import.
    logger.exception(f"échec dans opération: {e}")
    raise ImportError(
        "netcross_core.quic_diagnostics necessite cryptography : pip install cryptography --break-system-packages"
    ) from e


# sel public QUIC v1 (RFC 9001 section 5.2) -- pas un secret, juste une
# constante de derivation partagee par toutes les implementations QUIC v1
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V1 = 0x00000001

# QUIC v2 (RFC 9369 section 3.3.1) : sel initial public propre a v2,
# libelles HKDF prefixes "quicv2" (3.3.2) et type Initial = 0b01 (3.2)
QUIC_V2_INITIAL_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
QUIC_V2 = 0x6B3343CF


@dataclass(frozen=True)
class QuicVersion:
    """Parametres de la protection initiale d'une version QUIC geree."""

    number: int
    name: str  # "v1", "v2"
    rfc: str
    initial_salt: bytes
    label_prefix: str  # "quic" (v1) ou "quicv2" (v2)
    initial_type: int  # bits 0x30 de l'octet 0 : 0b00 (v1), 0b01 (v2)


QUIC_VERSIONS: dict[int, QuicVersion] = {
    QUIC_V1: QuicVersion(QUIC_V1, "v1", "RFC 9001", QUIC_V1_INITIAL_SALT, "quic", 0b00),
    QUIC_V2: QuicVersion(QUIC_V2, "v2", "RFC 9369", QUIC_V2_INITIAL_SALT, "quicv2", 0b01),
}

# frames QUIC sans corps a sauter en cherchant une frame CRYPTO (RFC 9000 19)
_FRAME_NO_BODY = {0x00, 0x01}  # PADDING, PING


@dataclass
class QuicEvent:
    point: str
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    dcid: bytes
    decryptable: bool
    sni: str | None = None
    tls_version: str | None = None
    # Issue #1061 : version QUIC du paquet Initial ("v1" ou "v2")
    quic_version: str = "v1"


# ------------------------- primitives HKDF (RFC 5869 / RFC 8446 7.1) -------
# Validees contre les vecteurs de test officiels RFC 9001 Annexe A.2 :
# hkdf_extract(salt, dcid=8394c8f03e515708) doit donner
# 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44, et la
# chaine complete jusqu'aux cles client (key/iv/hp) correspond exactement
# aux valeurs publiees dans la RFC -- verifie manuellement avant d'ecrire
# ce module, pas suppose.


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    logger.debug("_hkdf_extract: retour h.finalize(…)")
    return h.finalize()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = 32
    n = -(-length // hash_len)
    okm, t = b"", b""
    for i in range(1, n + 1):
        h = hmac.HMAC(prk, hashes.SHA256())
        h.update(t + info + bytes([i]))
        t = h.finalize()
        okm += t
    logger.debug("_hkdf_expand: retour okm[:length]")
    return okm[:length]


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label.encode("ascii")
    hkdf_label = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    logger.debug("_hkdf_expand_label: retour _hkdf_expand(…)")
    return _hkdf_expand(secret, hkdf_label, length)


def _version(version: int) -> QuicVersion:
    """Parametres d'une version geree (KeyError sinon : appel interne)."""
    logger.debug("_version: retour QuicVersion")
    return QUIC_VERSIONS[version]


def derive_initial_secrets(dcid: bytes, version: int = QUIC_V1) -> tuple[bytes, bytes]:
    """Renvoie (client_initial_secret, server_initial_secret) pour QUIC v1
    (defaut) ou v2 (``version=QUIC_V2``, sel de la RFC 9369)."""
    logger.debug("derive_initial_secrets: entrée (version 0x{:08x})", version)
    initial_secret = _hkdf_extract(_version(version).initial_salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", b"", 32)
    server_secret = _hkdf_expand_label(initial_secret, "server in", b"", 32)
    logger.debug("derive_initial_secrets: retour tuple de 2")
    return client_secret, server_secret


def derive_packet_protection_keys(secret: bytes, version: int = QUIC_V1) -> tuple[bytes, bytes, bytes]:
    """Renvoie (key, iv, hp) derives d'un secret initial (client ou serveur) ;
    libelles "quic ..." (v1) ou "quicv2 ..." (v2, RFC 9369 3.3.2)."""
    logger.debug("derive_packet_protection_keys: entrée (version 0x{:08x})", version)
    prefixe = _version(version).label_prefix
    key = _hkdf_expand_label(secret, f"{prefixe} key", b"", 16)
    iv = _hkdf_expand_label(secret, f"{prefixe} iv", b"", 12)
    hp = _hkdf_expand_label(secret, f"{prefixe} hp", b"", 16)
    logger.debug("derive_packet_protection_keys: retour tuple de 3")
    return key, iv, hp


# ------------------------- parsing du paquet QUIC Initial -------------------


def _read_varint(b: bytes, i: int) -> tuple[int, int] | None:
    """Varint QUIC (RFC 9000 16) : 2 bits de tete indiquent la longueur (1/2/4/8)."""
    if i >= len(b):
        logger.debug("_read_varint: si i >= len(b) -> retour None")
        return None
    first = b[i]
    length = 1 << (first >> 6)
    if i + length > len(b):
        logger.debug("_read_varint: si i + length > len(b) -> retour None")
        return None
    value = first & 0x3F
    for j in range(1, length):
        value = (value << 8) | b[i + j]
    logger.debug("_read_varint: retour tuple de 2")
    return value, i + length


def _parse_long_header(payload: bytes) -> dict | None:
    """Extrait les champs en clair d'un en-tete long Initial (avant toute
    levee de protection) : version, DCID, SCID, token, longueur, et
    l'offset ou commence le champ Packet Number (protege)."""
    if len(payload) < 7 or (payload[0] & 0xC0) != 0xC0:
        logger.debug("_parse_long_header: si len(payload) < 7 or payload[0] & 192 != 192 -> retour None")
        return None  # pas un en-tete long QUIC (form=1, fixed=1)

    version = int.from_bytes(payload[1:5], "big")
    parametres = QUIC_VERSIONS.get(version)
    if parametres is None:
        logger.trace("_parse_long_header: version QUIC 0x{:08x} non geree, paquet ignore", version)
        logger.debug("_parse_long_header: si version non geree -> retour None")
        return None  # seules v1 (RFC 9001) et v2 (RFC 9369) sont gerees -- voir limites en tete de fichier
    if (payload[0] & 0x30) >> 4 != parametres.initial_type:
        logger.debug("_parse_long_header: si type != Initial de la version -> retour None")
        return None  # pas un paquet Initial (type 0b00 en v1, 0b01 en v2)

    i = 5
    dcid_len = payload[i]
    i += 1
    if dcid_len > 20 or i + dcid_len > len(payload):
        logger.debug("_parse_long_header: si dcid_len > 20 or i + dcid_len > len(payload) -> retour None")
        return None
    dcid = payload[i : i + dcid_len]
    i += dcid_len

    if i >= len(payload):
        logger.debug("_parse_long_header: si i >= len(payload) -> retour None")
        return None
    scid_len = payload[i]
    i += 1
    if scid_len > 20 or i + scid_len > len(payload):
        logger.debug("_parse_long_header: si scid_len > 20 or i + scid_len > len(payload) -> retour None")
        return None
    i += scid_len  # SCID non utilise pour la derivation, juste saute

    token_len_r = _read_varint(payload, i)
    if token_len_r is None:
        logger.debug("_parse_long_header: si token_len_r is None -> retour None")
        return None
    token_len, i = token_len_r
    if i + token_len > len(payload):
        logger.debug("_parse_long_header: si i + token_len > len(payload) -> retour None")
        return None
    i += token_len

    length_r = _read_varint(payload, i)
    if length_r is None:
        logger.debug("_parse_long_header: si length_r is None -> retour None")
        return None
    remaining_len, i = length_r
    pn_offset = i

    if pn_offset + remaining_len > len(payload) or remaining_len < 4:
        logger.trace("_parse_long_header: longueur annoncee {} incoherente ({} octets)", remaining_len, len(payload))
        logger.debug(
            "_parse_long_header: si pn_offset + remaining_len > len(payload) or remaining_len <… -> retour None"
        )
        return None  # incoherent : pas assez de place pour PN(<=4)+charge utile+tag(16)

    logger.debug("_parse_long_header: retour dictionnaire")
    return {
        "version": version,
        "dcid": dcid,
        "pn_offset": pn_offset,
        "remaining_len": remaining_len,
    }


def _remove_header_protection(payload: bytearray, pn_offset: int, hp_key: bytes) -> int | None:
    """Leve la protection d'en-tete en place (RFC 9001 5.4). Renvoie
    pn_length (1-4) si l'operation est structurellement coherente, sinon
    None. Ne garantit pas a elle seule que le dechiffrement AEAD reussira
    -- c'est ce dernier qui fait foi (voir _decrypt_initial)."""
    sample_start = pn_offset + 4
    if sample_start + 16 > len(payload):
        logger.trace("_remove_header_protection: echantillon hors du paquet ({} octets)", len(payload))
        logger.debug("_remove_header_protection: si sample_start + 16 > len(payload) -> retour None")
        return None
    sample = bytes(payload[sample_start : sample_start + 16])
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    payload[0] ^= mask[0] & 0x0F
    pn_length = (payload[0] & 0x03) + 1
    if pn_offset + pn_length > len(payload):
        logger.debug("_remove_header_protection: si pn_offset + pn_length > len(payload) -> retour None")
        return None
    for i in range(pn_length):
        payload[pn_offset + i] ^= mask[1 + i]
    logger.debug("_remove_header_protection: retour pn_length={}", summarize(pn_length, "pn_length"))
    return pn_length


def _decrypt_initial(payload: bytes, client_secret: bytes, header_info: dict) -> bytes | None:
    """Pipeline complet : leve la protection d'en-tete puis dechiffre l'AEAD.
    Renvoie le texte clair (trames QUIC, dont la CRYPTO contenant le
    ClientHello) ou None si le dechiffrement echoue -- volontairement pas
    d'exception qui remonterait jusqu'a l'appelant : un echec de
    dechiffrement est un resultat normal (mauvais paquet, version, ou
    simplement pas assez de contexte), pas une erreur de programme."""
    key, iv, hp = derive_packet_protection_keys(client_secret, header_info.get("version", QUIC_V1))
    buf = bytearray(payload)
    pn_offset = header_info["pn_offset"]

    pn_length = _remove_header_protection(buf, pn_offset, hp)
    if pn_length is None:
        logger.debug("_decrypt_initial: si pn_length is None -> retour None")
        return None

    pn_bytes = bytes(buf[pn_offset : pn_offset + pn_length])
    packet_number = int.from_bytes(pn_bytes, "big")

    header = bytes(buf[: pn_offset + pn_length])
    end = pn_offset + header_info["remaining_len"]
    ciphertext = bytes(buf[pn_offset + pn_length : end])
    if len(ciphertext) < 16:
        logger.debug("_decrypt_initial: si len(ciphertext) < 16 -> retour None")
        return None

    nonce = bytearray(iv)
    pn_padded = packet_number.to_bytes(len(nonce), "big")
    for i in range(len(nonce)):
        nonce[i] ^= pn_padded[i]

    try:
        logger.debug("_decrypt_initial: retour AESGCM(key).decrypt(…)")
        return AESGCM(key).decrypt(bytes(nonce), ciphertext, header)
    except InvalidTag:
        # resultat normal (voir docstring), a chaque paquet : TRACE, sans traceback
        logger.trace("_decrypt_initial: tag AEAD invalide, paquet {} non dechiffrable", packet_number)
        logger.debug("_decrypt_initial: except InvalidTag -> retour None")
        return None


def _extract_client_hello_from_crypto(plaintext: bytes) -> bytes | None:
    """Parcourt les trames QUIC du texte clair a la recherche d'une trame
    CRYPTO (type 0x06, RFC 9000 19.6) et en isole le message TLS."""
    i = 0
    while i < len(plaintext):
        type_r = _read_varint(plaintext, i)
        if type_r is None:
            logger.debug("_extract_client_hello_from_crypto: si type_r is None -> retour None")
            return None
        frame_type, i = type_r
        if frame_type in _FRAME_NO_BODY:
            continue
        if frame_type == 0x06:  # CRYPTO
            offset_r = _read_varint(plaintext, i)
            if offset_r is None:
                logger.debug("_extract_client_hello_from_crypto: si offset_r is None -> retour None")
                return None
            offset, i = offset_r
            length_r = _read_varint(plaintext, i)
            if length_r is None:
                logger.debug("_extract_client_hello_from_crypto: si length_r is None -> retour None")
                return None
            length, i = length_r
            if i + length > len(plaintext):
                logger.debug("_extract_client_hello_from_crypto: si i + length > len(plaintext) -> retour None")
                return None
            if offset != 0:
                logger.trace("_extract_client_hello_from_crypto: CRYPTO a l'offset {}, ClientHello fragmente", offset)
                logger.debug("_extract_client_hello_from_crypto: si offset != 0 -> retour None")
                return None  # ClientHello fragmente sur plusieurs paquets : hors perimetre
            logger.debug("_extract_client_hello_from_crypto: si frame_type == 6 -> retour plaintext[i:i + length]")
            return plaintext[i : i + length]
        # autre type de frame (ACK, etc.) : pas de parseur generique pour
        # sauter son corps proprement, on s'arrete la plutot que deviner
        logger.trace("_extract_client_hello_from_crypto: trame 0x{:02x} avant CRYPTO, arret", frame_type)
        logger.debug("_extract_client_hello_from_crypto: boucle tant que i < len(plaintext) -> retour None")
        return None
    logger.debug("_extract_client_hello_from_crypto: retour None")
    return None


def _parse_tls_handshake_from_crypto(crypto_data: bytes) -> dict | None:
    if len(crypto_data) < 4 or crypto_data[0] != 0x01:  # 1 = client_hello
        logger.debug("_parse_tls_handshake_from_crypto: si len(crypto_data) < 4 or crypto_data[0] != 1 -> retour None")
        return None
    body_len = int.from_bytes(crypto_data[1:4], "big")
    body = crypto_data[4 : 4 + body_len]
    if len(body) < body_len:
        logger.trace("_parse_tls_handshake_from_crypto: ClientHello incomplet ({}/{} octets)", len(body), body_len)
        logger.debug("_parse_tls_handshake_from_crypto: si len(body) < body_len -> retour None")
        return None  # ClientHello incomplet dans ce paquet (fragmente) : hors perimetre
    logger.debug("_parse_tls_handshake_from_crypto: retour parse_client_hello(…)")
    return parse_client_hello(body)


def parse_quic_capture(label: str, path: str) -> list[QuicEvent]:
    """Lit une capture via pcap_parser (tshark -T ek) et renvoie un
    QuicEvent pour chaque paquet QUIC Initial v1 ou v2 detecte -- decrypte
    avec succes ou non (decryptable=False et sni=None dans ce dernier
    cas, jamais de donnee inventee)."""
    events: list[QuicEvent] = []
    raw_packets = pcap_parser.parse_capture(path, raise_on_error=False)
    logger.debug("parse_quic_capture: point {}, {} paquet(s) lus depuis {}", label, len(raw_packets), path)

    for raw in raw_packets:
        if raw.proto != "UDP" or not raw.payload:
            continue
        payload = raw.payload

        header_info = _parse_long_header(payload)
        if header_info is None:
            continue

        version = header_info["version"]
        client_secret, _server_secret = derive_initial_secrets(header_info["dcid"], version)
        plaintext = _decrypt_initial(payload, client_secret, header_info)

        ts = raw.ts
        if plaintext is None:
            events.append(
                QuicEvent(
                    point=label,
                    ts=ts,
                    src=raw.src,
                    dst=raw.dst,
                    sport=raw.sport or 0,
                    dport=raw.dport or 0,
                    dcid=header_info["dcid"],
                    decryptable=False,
                    quic_version=QUIC_VERSIONS[version].name,
                )
            )
            continue

        crypto_data = _extract_client_hello_from_crypto(plaintext)
        info = _parse_tls_handshake_from_crypto(crypto_data) if crypto_data else None
        events.append(
            QuicEvent(
                point=label,
                ts=ts,
                src=raw.src,
                dst=raw.dst,
                sport=raw.sport or 0,
                dport=raw.dport or 0,
                dcid=header_info["dcid"],
                decryptable=True,
                sni=info.get("sni") if info else None,
                tls_version=info.get("tls_version") if info else None,
                quic_version=QUIC_VERSIONS[version].name,
            )
        )

    logger.debug(
        "parse_quic_capture: point {}, {} Initial QUIC (v1/v2) dont {} non dechiffrable(s), {} avec SNI",
        label,
        len(events),
        sum(1 for ev in events if not ev.decryptable),
        sum(1 for ev in events if ev.sni),
    )
    return events


def _libelle(event: QuicEvent) -> str:
    """« QUIC » (v1, libelle historique) ou « QUIC v2 » (issue #1061)."""
    logger.debug("_libelle: retour str")
    return "QUIC" if event.quic_version == "v1" else f"QUIC {event.quic_version}"


def _constats_v2(events: list[QuicEvent]) -> list:
    """Un constat « info » par point ou des Initial QUIC v2 sont vus."""
    logger.debug("_constats_v2: entrée")
    from netcross_core.tls_diagnostics import TlsFinding

    par_point: dict[str, int] = {}
    for e in events:
        if e.quic_version == "v2":
            par_point[e.point] = par_point.get(e.point, 0) + 1
    constats = [
        TlsFinding(
            "info",
            "QUIC",
            p,
            f"{n} paquet(s) Initial QUIC v2 (RFC 9369, version 0x{QUIC_V2:08x}) reconnu(s)",
        )
        for p, n in par_point.items()
    ]
    logger.debug("_constats_v2: retour, {} constat(s)", len(constats))
    return constats


def diagnose_quic(events: list[QuicEvent], points_order: list[str] | None = None):
    """Compare les ClientHello QUIC vus a chaque point (par DCID -- identifie
    la connexion QUIC de facon stable meme a travers un NAT qui changerait
    IP/port). Format de sortie compatible netcross_report.triage (severity/
    category/segment/message), comme tls_diagnostics.TlsFinding."""
    from netcross_core.tls_diagnostics import TlsFinding  # reutilise le meme type de resultat

    by_dcid: dict[bytes, dict[str, QuicEvent]] = {}
    for e in events:
        by_dcid.setdefault(e.dcid, {})[e.point] = e

    findings: list[TlsFinding] = []
    decrypt_failures: dict[str, int] = {}
    for e in events:
        if not e.decryptable:
            decrypt_failures[e.point] = decrypt_failures.get(e.point, 0) + 1

    logger.debug(
        "diagnose_quic: {} evenement(s), {} connexion(s) (DCID), echecs de dechiffrement {}",
        len(events),
        len(by_dcid),
        decrypt_failures,
    )
    if not points_order:
        logger.debug("diagnose_quic: sans ordre des points, seuls les echecs de dechiffrement sont rapportes")
        for p, n in decrypt_failures.items():
            findings.append(
                TlsFinding(
                    "info",
                    "QUIC",
                    p,
                    f"{n} paquet(s) QUIC Initial detecte(s) mais non dechiffrable(s) "
                    f"(version non geree, ou paquet hors sequence)",
                )
            )
        findings.extend(_constats_v2(events))
        logger.debug("diagnose_quic: si not points_order -> retour findings={}", summarize(findings, "findings"))
        return findings

    for per_point in by_dcid.values():
        present = [p for p in points_order if p in per_point]
        if not present:
            continue
        with_sni = [p for p in present if per_point[p].sni]
        if not with_sni:
            continue
        sni = per_point[with_sni[0]].sni
        libelle = _libelle(per_point[with_sni[0]])
        missing = [p for p in points_order if p not in present]
        if missing and present:
            last_seen = present[-1]
            findings.append(
                TlsFinding(
                    "a_surveiller",
                    "QUIC",
                    last_seen,
                    f"ClientHello {libelle} (SNI {sni}) vu jusqu'a {last_seen}, absent ensuite "
                    f"-- QUIC/UDP-443 potentiellement bloque ou filtre au-dela (bascule "
                    f"TCP probable cote client si le blocage persiste)",
                )
            )
        else:
            findings.append(
                TlsFinding(
                    "info",
                    "QUIC",
                    present[-1],
                    f"ClientHello {libelle} (SNI {sni}) vu a tous les points captures ({', '.join(present)})",
                )
            )

    for p, n in decrypt_failures.items():
        findings.append(
            TlsFinding(
                "info",
                "QUIC",
                p,
                f"{n} paquet(s) QUIC Initial detecte(s) mais non dechiffrable(s)",
            )
        )

    findings.extend(_constats_v2(events))
    logger.debug("diagnose_quic: {} constat(s)", len(findings))
    return findings


def print_quic_diagnostics(findings) -> None:
    logger.debug("print_quic_diagnostics: {} constat(s)", len(findings))
    print("=" * 70)
    print("DIAGNOSTIC QUIC/HTTP3 -- ClientHello vus par point (SNI, QUIC v1 et v2)")
    print("=" * 70)
    if not findings:
        print("  aucun trafic QUIC Initial (v1 ou v2) detecte")
        logger.debug("print_quic_diagnostics: si not findings -> retour")
        return
    sev_label = {
        "anomalie": "anomalie   ",
        "a_surveiller": "a surveiller",
        "info": "info        ",
    }
    for f in findings:
        print(f"  [{sev_label.get(f.severity, f.severity):12s}] {f.segment:20s} : {f.message}")
    logger.debug("print_quic_diagnostics: fin")
