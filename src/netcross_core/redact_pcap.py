# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.redact_pcap -- réécriture pcapng anonymisée multi-points.

Issue #1157 (sous-issue 4/5 du chantier #1007) : partager les captures
ELLES-MÊMES, anonymisées de façon cohérente sur tous les points. La
mutation en place des objets Pkt/RawPacket (netcross_core.redact) ne
suffit pas : elle anonymise l'analyse, pas les fichiers. Ce module relit
chaque capture avec libpcap (mêmes mécanismes ctypes que la sonde
netcross_probe, aucune dépendance ajoutée : libpcap accompagne tshark
partout où le dépôt tourne), réécrit les trames au niveau des octets et
écrit un pcapng par point.

Ce qui est rédigé (mêmes tables que le run, via l'AddressRedactor passé
en argument -- une même adresse garde le même pseudonyme du paquet, du
constat ET du pcap produit) :

- adresses MAC Ethernet (émetteur/destinataire), IP source/destination
  (v4 et v6), y compris dans les en-têtes ARP ;
- charges utiles applicatives : REMPLACÉES PAR DES ZÉROS par défaut (les
  longueurs sont conservées, donc les constats de taille/fragmentation
  tiennent toujours) ; ``garder_payload=True`` les conserve telles
  quelles (déconseillé si la capture contient des données sensibles --
  c'est le sens de l'option, choisie explicitement par l'opérateur) ;
  les en-têtes de transport (options TCP comprises) sont conservés pour
  que l'analyse du pcap anonymisé retrouve les mêmes constats réseau --
  pertes, latences, retransmissions, MSS -- pseudonymes mis à part.

Sommes de contrôle recalculées après réécriture (RFC 1071) : en-tête
IPv4, TCP, UDP (si non nul), ICMP/ICMPv6 -- l'analyse du pcap anonymisé
ne génère AUCUN « bad checksum » qui n'existait pas dans l'original
(critère d'acceptation de #1157).

Horodatages conservés à la microseconde près ; ``decalage`` applique un
décalage UNIFORME (même valeur pour tous les paquets de tous les points,
donc les différences inter-points restent exactes).

Limites assumées (documentées ici plutôt que masquées) :

- types de liaison réécrits : Ethernet (1), IPv4/IPv6 brut (101/12),
  Linux SLL (113) et SLL2 (276). Tout autre type de liaison est recopié
  tel quel -- les adresses qu'il porte ne sont PAS anonymisées ;
- tunnels (VXLAN/GRE) : la charge utile est zéroée par défaut, l'adresse
  interne n'apparaît donc pas ; avec ``garder_payload=True`` elle
  resterait lisible (l'opérateur est réputé savoir ce qu'il partage) ;
- un pcapng PAR POINT : les fichiers --capture multiples d'un même point
  produisent un seul pcapng (concaténation dans l'ordre fourni).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
from pathlib import Path

from netcross_core.logging_config import get_logger
from netcross_core.redact import AddressRedactor

__all__ = [
    "LibpcapIndisponibleError",
    "ecrire_pcapng_anonymise",
]

logger = get_logger(__name__)

# Types de liaison compris par la réécriture (voir la docstring du
# module). Le décalage L3 (octets avant l'en-tête IP) suit.
_L3_OFFSETS = {1: 14, 101: 0, 12: 0, 113: 16, 276: 20}
# Position de l'etherType dans l'en-tête de niveau 2, par type de
# liaison ; None = pas d'etherType (IP brut, la réécriture MAC n'a pas de
# sens et seul le niveau IP est réécrit).
_ETHERTYPE_OFFSETS = {1: 12, 113: 14, 276: 0}


class LibpcapIndisponibleError(RuntimeError):
    """libpcap est introuvable : la réécriture pcapng ne peut pas relire
    les captures."""


class _EnTetePaquet(ctypes.Structure):
    """``struct pcap_pkthdr`` : timeval natif (deux long, 24 octets en
    64 bits -- vérifié empiriquement dans netcross_probe.bpf) puis
    caplen/len."""

    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint),
        ("len", ctypes.c_uint),
    ]


def _charger_libpcap() -> ctypes.CDLL:
    """Charge libpcap par son nom canonique ; lève si elle est absente."""
    logger.debug("_charger_libpcap: entrée")
    nom = ctypes.util.find_library("pcap")
    if nom is None:
        logger.debug("_charger_libpcap: levée LibpcapIndisponibleError")
        raise LibpcapIndisponibleError(
            "libpcap introuvable -- installer le paquet 'libpcap' (apt install libpcap0.8 / "
            "dnf install libpcap), requis pour relire les captures à anonymiser."
        )
    lib = ctypes.CDLL(nom)
    lib.pcap_open_offline.restype = ctypes.c_void_p
    lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.pcap_next_ex.restype = ctypes.c_int
    lib.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_EnTetePaquet)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    lib.pcap_datalink.restype = ctypes.c_int
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    logger.debug("_charger_libpcap: retour {}", nom)
    return lib


def _iterer_trames(chemin: str):
    """Itère (ts, caplen, len, trame) d'un fichier pcap/pcapng via
    libpcap ; lève LibpcapIndisponibleError si la bibliothèque manque."""
    logger.debug("_iterer_trames: entrée chemin={}", chemin)
    lib = _charger_libpcap()
    handle = lib.pcap_open_offline(chemin.encode(), b"libpcap")
    if not handle:
        logger.debug("_iterer_trames: levée LibpcapIndisponibleError (ouverture)")
        raise LibpcapIndisponibleError(f"impossible d'ouvrir la capture : {chemin}")
    try:
        linktype = lib.pcap_datalink(handle)
        entete = ctypes.POINTER(_EnTetePaquet)()
        donnees = ctypes.POINTER(ctypes.c_ubyte)()
        while True:
            code = lib.pcap_next_ex(handle, ctypes.byref(entete), ctypes.byref(donnees))
            if code != 1:
                logger.debug("_iterer_trames: fin d'itération (code {})", code)
                break
            h = entete.contents
            trame = bytes(ctypes.cast(donnees, ctypes.POINTER(ctypes.c_ubyte * h.caplen)).contents)
            ts = float(h.ts_sec) + float(h.ts_usec) / 1_000_000.0
            logger.debug("_iterer_trames: trame ts={} caplen={}", ts, h.caplen)
            yield ts, int(h.len), linktype, trame
    finally:
        lib.pcap_close(handle)
    logger.debug("_iterer_trames: fin")


# --------------------------------------------------------------------------
# Réécriture d'une trame
# --------------------------------------------------------------------------


def _somme_controle(donnees: bytes) -> int:
    """Somme de contrôle RFC 1071 (complément à un sur 16 bits)."""
    logger.debug("_somme_controle: entrée ({} octet(s))", len(donnees))
    if len(donnees) % 2:
        donnees = donnees + b"\x00"
    total = 0
    for i in range(0, len(donnees), 2):
        total += (donnees[i] << 8) | donnees[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    logger.debug("_somme_controle: retour")
    return (~total) & 0xFFFF


def _pseudonyme_mac(redactor: AddressRedactor, mac: bytes) -> bytes:
    """Pseudonyme (6 octets) d'une adresse MAC brute ; l'adresse d'origine
    est rendue telle quelle si la table n'en veut pas."""
    logger.debug("_pseudonyme_mac: entrée")
    texte = ":".join(f"{b:02x}" for b in mac)
    pseudo = redactor.pseudonymize_address(texte)
    logger.debug("_pseudonyme_mac: retour")
    return bytes(int(part, 16) for part in pseudo.split(":"))


def _pseudonyme_ip(redactor: AddressRedactor, adresse: bytes, famille: int) -> bytes:
    """Pseudonyme (4 ou 16 octets) d'une adresse IP brute."""
    logger.debug("_pseudonyme_ip: entrée")
    texte = socket.inet_ntop(famille, adresse)
    pseudo = redactor.pseudonymize_address(texte)
    logger.debug("_pseudonyme_ip: retour")
    return socket.inet_pton(famille, pseudo)


def _zero_charge_utile(l4: bytes, en_tete: int) -> bytes:
    """Remplace la charge utile au-delà de l'en-tête par des zéros (même
    longueur -- les constats de taille restent exacts)."""
    logger.debug("_zero_charge_utile: entrée")
    logger.debug("_zero_charge_utile: retour")
    return l4[:en_tete] + b"\x00" * (len(l4) - en_tete)


def _recrire_l4(l4: bytes, proto: int, src: bytes, dst: bytes, garder_payload: bool) -> bytes:
    """Réécrit le segment/gramme de transport : adresses du pseudo-en-tête
    mises à jour, charge utile zéroée par défaut, sommes de contrôle
    recalculées (TCP, UDP si non nul, ICMP/ICMPv6)."""
    logger.debug("_recrire_l4: entrée proto={}", proto)
    if proto == 6:  # TCP
        if len(l4) < 20:
            logger.debug("_recrire_l4: TCP trop court -> retour inchangé")
            return l4
        en_tete = (l4[12] >> 4) * 4
        corps = l4[en_tete:] if garder_payload else b"\x00" * (len(l4) - en_tete)
        segment = bytearray(l4[:en_tete] + corps)
        segment[16:18] = b"\x00\x00"
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
        somme = _somme_controle(pseudo + bytes(segment)) or 0xFFFF
        segment[16:18] = struct.pack("!H", somme)
        logger.debug("_recrire_l4: retour TCP")
        return bytes(segment)
    if proto == 17:  # UDP
        if len(l4) < 8:
            logger.debug("_recrire_l4: UDP trop court -> retour inchangé")
            return l4
        originaire_zero = l4[6:8] == b"\x00\x00"
        corps = l4[8:] if garder_payload else b"\x00" * (len(l4) - 8)
        segment = bytearray(l4[:8] + corps)
        segment[6:8] = b"\x00\x00"
        if originaire_zero:
            # Pas de somme de contrôle UDP à l'origine (permis en IPv4) :
            # on n'en invente pas.
            logger.debug("_recrire_l4: retour UDP sans somme")
            return bytes(segment)
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
        somme = _somme_controle(pseudo + bytes(segment)) or 0xFFFF
        segment[6:8] = struct.pack("!H", somme)
        logger.debug("_recrire_l4: retour UDP")
        return bytes(segment)
    if proto in (1, 58):  # ICMP / ICMPv6
        if len(l4) < 8:
            logger.debug("_recrire_l4: ICMP trop court -> retour inchangé")
            return l4
        corps = l4[8:] if garder_payload else b"\x00" * (len(l4) - 8)
        message = bytearray(l4[:8] + corps)
        message[2:4] = b"\x00\x00"
        somme = _somme_controle(bytes(message))
        message[2:4] = struct.pack("!H", somme)
        logger.debug("_recrire_l4: retour ICMP")
        return bytes(message)
    # Autre protocole (GRE, ESP...) : charge utile entièrement zéroée par
    # défaut -- un tunnel encapsule des adresses réelles.
    if garder_payload:
        logger.debug("_recrire_l4: retour protocole {} inchangé", proto)
        return l4
    logger.debug("_recrire_l4: retour protocole {} zéroé", proto)
    return b"\x00" * len(l4)


def _recrire_ipv4(seg: bytes, redactor: AddressRedactor, garder_payload: bool) -> bytes:
    """Réécrit un datagramme IPv4 : adresses, transport, sommes de
    contrôle (en-tête + transport)."""
    logger.debug("_recrire_ipv4: entrée")
    if len(seg) < 20:
        logger.debug("_recrire_ipv4: trop court -> retour inchangé")
        return seg
    ihl = (seg[0] & 0x0F) * 4
    fragment = struct.unpack("!H", seg[6:8])[0]
    decalage_frag = (fragment & 0x1FFF) * 8
    entete = bytearray(seg[:ihl])
    entete[12:16] = _pseudonyme_ip(redactor, bytes(seg[12:16]), socket.AF_INET)
    entete[16:20] = _pseudonyme_ip(redactor, bytes(seg[16:20]), socket.AF_INET)
    entete[10:12] = b"\x00\x00"
    entete[10:12] = struct.pack("!H", _somme_controle(bytes(entete)))
    if decalage_frag > 0:
        # Suite de fragmentation : pas d'en-tête de transport, la charge
        # utile est zéroée (les adresses internes ne fuient pas) et la
        # longueur est conservée.
        reste = seg[ihl:] if garder_payload else b"\x00" * (len(seg) - ihl)
        logger.debug("_recrire_ipv4: retour fragment")
        return bytes(entete) + reste
    proto = seg[9]
    l4 = _recrire_l4(seg[ihl:], proto, bytes(entete[12:16]), bytes(entete[16:20]), garder_payload)
    logger.debug("_recrire_ipv4: retour complet")
    return bytes(entete) + l4


def _recrire_ipv6(seg: bytes, redactor: AddressRedactor, garder_payload: bool) -> bytes:
    """Réécrit un datagramme IPv6 : adresses (pas de somme d'en-tête en
    v6), transport avec pseudo-en-tête recalculé."""
    logger.debug("_recrire_ipv6: entrée")
    if len(seg) < 40:
        logger.debug("_recrire_ipv6: trop court -> retour inchangé")
        return seg
    entete = bytearray(seg[:40])
    entete[8:24] = _pseudonyme_ip(redactor, bytes(seg[8:24]), socket.AF_INET6)
    entete[24:40] = _pseudonyme_ip(redactor, bytes(seg[24:40]), socket.AF_INET6)
    proto = seg[6]
    l4 = _recrire_l4(seg[40:], proto, bytes(entete[8:24]), bytes(entete[24:40]), garder_payload)
    logger.debug("_recrire_ipv6: retour")
    return bytes(entete) + l4


def _recrire_arp(trame: bytes, l3: int, redactor: AddressRedactor) -> bytes:
    """Réécrit les adresses MAC/IP portées par un paquet ARP."""
    logger.debug("_recrire_arp: entrée")
    if len(trame) < l3 + 28:
        logger.debug("_recrire_arp: trop court -> retour inchangé")
        return trame
    paquet = bytearray(trame)
    base = l3
    paquet[base + 8 : base + 14] = _pseudonyme_mac(redactor, bytes(trame[base + 8 : base + 14]))
    paquet[base + 14 : base + 18] = _pseudonyme_ip(redactor, bytes(trame[base + 14 : base + 18]), socket.AF_INET)
    paquet[base + 18 : base + 24] = _pseudonyme_mac(redactor, bytes(trame[base + 18 : base + 24]))
    paquet[base + 24 : base + 28] = _pseudonyme_ip(redactor, bytes(trame[base + 24 : base + 28]), socket.AF_INET)
    logger.debug("_recrire_arp: retour")
    return bytes(paquet)


def _recrire_trame(trame: bytes, linktype: int, redactor: AddressRedactor, garder_payload: bool) -> bytes:
    """Réécrit une trame complète selon son type de liaison ; les types
    non listés dans _L3_OFFSETS sont rendus tels quels (limite assumée,
    voir la docstring du module)."""
    logger.debug("_recrire_trame: entrée linktype={}", linktype)
    l3 = _L3_OFFSETS.get(linktype)
    if l3 is None or len(trame) < l3:
        logger.debug("_recrire_trame: type non réécrit -> retour inchangé")
        return trame
    # Ethernet : MAC émetteur/destinataire (SLL aussi, champ sll_addr).
    if linktype == 1:
        trame_b = bytearray(trame)
        trame_b[0:6] = _pseudonyme_mac(redactor, bytes(trame[0:6]))
        trame_b[6:12] = _pseudonyme_mac(redactor, bytes(trame[6:12]))
        trame = bytes(trame_b)
    # EtherType (VLAN compris : on saute l'entête 802.1Q).
    ethertype_offset = _ETHERTYPE_OFFSETS.get(linktype)
    if ethertype_offset is None:
        ethertype = 0x0800 if linktype == 101 else 0x86DD
    else:
        if len(trame) < ethertype_offset + 2:
            logger.debug("_recrire_trame: trame trop courte -> retour inchangé")
            return trame
        ethertype = struct.unpack("!H", trame[ethertype_offset : ethertype_offset + 2])[0]
        while ethertype in (0x8100, 0x88A8) and len(trame) >= ethertype_offset + 6:
            l3 += 4
            ethertype_offset += 4
            ethertype = struct.unpack("!H", trame[ethertype_offset : ethertype_offset + 2])[0]
    if ethertype == 0x0806:
        logger.debug("_recrire_trame: retour ARP réécrit")
        return _recrire_arp(trame, l3, redactor)
    if ethertype == 0x0800:
        logger.debug("_recrire_trame: retour IPv4 réécrit")
        return trame[:l3] + _recrire_ipv4(trame[l3:], redactor, garder_payload)
    if ethertype == 0x86DD:
        logger.debug("_recrire_trame: retour IPv6 réécrit")
        return trame[:l3] + _recrire_ipv6(trame[l3:], redactor, garder_payload)
    logger.debug("_recrire_trame: etherType {} non IP -> retour inchangé", ethertype)
    return trame


# --------------------------------------------------------------------------
# Écriture pcapng
# --------------------------------------------------------------------------


def _bloc(type_bloc: int, corps: bytes) -> bytes:
    """Bloc pcapng générique : la longueur totale (en-tête 8 + corps +
    champ final 4) est répétée au début et à la fin du bloc."""
    logger.debug("_bloc: entrée type={} corps={}", type_bloc, len(corps))
    total = 8 + len(corps) + 4
    bloc = struct.pack("<II", type_bloc, total) + corps + struct.pack("<I", total)
    logger.debug("_bloc: retour")
    return bloc


def _bloc_shb() -> bytes:
    """Section Header Block (boutisme little-endien, résolution µs)."""
    logger.debug("_bloc_shb: entrée")
    corps = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    bloc = _bloc(0x0A0D0D0A, corps)
    logger.debug("_bloc_shb: retour")
    return bloc


def _bloc_idb(linktype: int, interface_id: int) -> bytes:
    """Interface Description Block pour un type de liaison."""
    logger.debug("_bloc_idb: entrée linktype={}", linktype)
    corps = struct.pack("<HHI", linktype, 0, 0xFFFF)
    # if_tsresol = 10^-6 (µs) : option 9, valeur 1 octet, longueur 1.
    corps += struct.pack("<HH", 9, 1) + b"\x06" + b"\x00" * 3
    bloc = _bloc(1, corps)
    logger.debug("_bloc_idb: retour (interface {})", interface_id)
    return bloc


def _bloc_epb(interface_id: int, ts_us: int, trame: bytes, longueur_originale: int) -> bytes:
    """Enhanced Packet Block (horodatage µs depuis l'époque)."""
    logger.debug("_bloc_epb: entrée")
    remplit = (-len(trame)) % 4
    corps = (
        struct.pack("<IIIII", interface_id, ts_us >> 32, ts_us & 0xFFFFFFFF, len(trame), longueur_originale)
        + trame
        + b"\x00" * remplit
    )
    bloc = _bloc(6, corps)
    logger.debug("_bloc_epb: retour")
    return bloc


# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------


def ecrire_pcapng_anonymise(
    label: str,
    chemins: list[str],
    redactor: AddressRedactor,
    sortie: str | Path,
    *,
    garder_payload: bool = False,
    decalage: float = 0.0,
) -> Path:
    """Écrit ``sortie`` (pcapng) : concaténation anonymisée des captures
    ``chemins`` d'un même point, avec la table du run. Renvoie le chemin
    écrit.

    Les horodatages sont conservés (µs) ; ``decalage`` les décale
    uniformément. ``garder_payload`` conserve les charges utiles
    applicatives (par défaut : zéroées, longueurs conservées).
    """
    logger.debug(
        "ecrire_pcapng_anonymise: entrée label={} chemins={} sortie={}",
        label,
        len(chemins),
        sortie,
    )
    sortie = Path(sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    interfaces: dict[int, int] = {}
    blocs: list[bytes] = []
    for chemin in chemins:
        for ts, longueur_originale, linktype, trame in _iterer_trames(chemin):
            if linktype not in interfaces:
                interfaces[linktype] = len(interfaces)
                blocs.append(_bloc_idb(linktype, interfaces[linktype]))
            reecrite = _recrire_trame(trame, linktype, redactor, garder_payload)
            ts_us = round((ts + decalage) * 1_000_000)
            if ts_us < 0:
                logger.debug("ecrire_pcapng_anonymise: horodatage négatif borné à 0")
                ts_us = 0
            blocs.append(_bloc_epb(interfaces[linktype], ts_us, reecrite, longueur_originale))
    if not interfaces:
        logger.debug("ecrire_pcapng_anonymise: aucune trame -> SHB seul")
    with open(sortie, "wb") as fh:
        fh.write(_bloc_shb())
        for bloc in blocs:
            fh.write(bloc)
    logger.debug("ecrire_pcapng_anonymise: retour {}", sortie)
    return sortie
