# SPDX-License-Identifier: GPL-3.0-or-later
"""Generateur de la capture WPA2-PSK de reference versionnee (issue #1143).

Capture entierement synthetique, calculee pour ce projet a partir d'un
reseau fictif (SSID et phrase de passe ci-dessous, sans valeur hors de ces
tests ; aucune capture reelle, aucune donnee personnelle) : elle est donc
distribuee sous la licence du depot. Regenerer avec :

    uv run python tests/wpa2_reference.py

tests/test_wifi_dechiffrement.py verifie que le fichier versionne est
identique a la sortie de ce generateur.

Contenu (radiotap, linktype 127), point d'acces 02:00:00:00:00:01, station
02:00:00:00:00:02 :

1. EAPOL-Key message 1/4 (ANonce) ;
2. EAPOL-Key message 2/4 (SNonce, MIC calcule avec la KCK) ;
3. deux trames de donnees ToDS chiffrees CCMP (AES-CCM, cle TK du PTK),
   LLC/SNAP + IPv4/UDP 10.0.0.2:5000 -> 10.0.0.1:6000.

Derivation (IEEE 802.11-2020, 12.7.1) : PMK = PBKDF2-HMAC-SHA1(phrase,
SSID, 4096, 32) ; PTK = PRF-384(PMK, "Pairwise key expansion",
min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce)).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

DATA = Path(__file__).parent / "data"
WPA2_PCAP = DATA / "wpa2-psk-reference.pcap"

SSID = "NetcrossLab"
PHRASE = "exemple:netcross-wpa2"  # contient « : » : verifie l'encodage de la cle
AP = bytes.fromhex("020000000001")
STA = bytes.fromhex("020000000002")
ANONCE = bytes(range(0x10, 0x30))
SNONCE = bytes(range(0x40, 0x60))
RSN_IE = bytes.fromhex("30140100000fac040100000fac040100000fac020000")


def pmk() -> bytes:
    return hashlib.pbkdf2_hmac("sha1", PHRASE.encode(), SSID.encode(), 4096, 32)


def ptk() -> bytes:
    donnees = min(AP, STA) + max(AP, STA) + min(ANONCE, SNONCE) + max(ANONCE, SNONCE)
    sortie = b""
    i = 0
    while len(sortie) < 48:
        sortie += hmac.new(pmk(), b"Pairwise key expansion\x00" + donnees + bytes([i]), hashlib.sha1).digest()
        i += 1
    return sortie[:48]


def _radiotap() -> bytes:
    present = (1 << 3) | (1 << 5)  # canal, signal
    return struct.pack("<BBHI", 0, 0, 13, present) + struct.pack("<HHb", 2437, 0x00A0, -48)


def _eapol_key(key_info: int, replay: int, nonce: bytes, key_data: bytes, kck: bytes | None) -> bytes:
    corps = (
        struct.pack("!BHH", 2, key_info, 16)
        + struct.pack("!Q", replay)
        + nonce
        + bytes(16)  # IV
        + bytes(8)  # RSC
        + bytes(8)  # ID
        + bytes(16)  # MIC (calcule ensuite)
        + struct.pack("!H", len(key_data))
        + key_data
    )
    trame = struct.pack("!BBH", 2, 3, len(corps)) + corps
    if kck is not None:
        mic = hmac.new(kck, trame, hashlib.sha1).digest()[:16]
        debut = 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8
        trame = trame[:debut] + mic + trame[debut + 16 :]
    return trame


def _llc(ethertype: int) -> bytes:
    return bytes.fromhex("aaaa03000000") + struct.pack("!H", ethertype)


def _entete(fc1: int, seq: int, depuis_ap: bool) -> bytes:
    # FromDS : addr1 = DA, addr2 = BSSID, addr3 = SA ; ToDS : addr1 = BSSID, addr2 = SA, addr3 = DA
    adresses = STA + AP + AP if depuis_ap else AP + STA + AP
    return bytes([0x08, fc1]) + struct.pack("<H", 0) + adresses + struct.pack("<H", seq << 4)


def _ip_udp(payload: bytes) -> bytes:
    src, dst = bytes([10, 0, 0, 2]), bytes([10, 0, 0, 1])
    udp = struct.pack("!HHHH", 5000, 6000, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0, src, dst)
    total = sum(struct.unpack("!10H", ip))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ip[:10] + struct.pack("!H", ~total & 0xFFFF) + ip[12:] + udp


def _ccmp(seq: int, pn: int, clair: bytes) -> bytes:
    tk = ptk()[32:48]
    entete = _entete(0x41, seq, depuis_ap=False)  # ToDS + Protected
    fc0, fc1 = entete[0], entete[1]
    aad = bytes([fc0 & 0x8F, (fc1 & ~0x38 & 0xFF) | 0x40]) + entete[4:22] + struct.pack("<H", 0)
    pn_octets = pn.to_bytes(6, "big")
    nonce = b"\x00" + STA + pn_octets
    chiffre = AESCCM(tk, tag_length=8).encrypt(nonce, clair, aad)
    ccmp = bytes([pn_octets[5], pn_octets[4], 0, 0x20, pn_octets[3], pn_octets[2], pn_octets[1], pn_octets[0]])
    return entete + ccmp + chiffre


def frames() -> list[tuple[int, bytes]]:
    kck = ptk()[:16]
    t0 = 1_700_000_100_000_000
    m1 = _entete(0x02, 1, depuis_ap=True) + _llc(0x888E) + _eapol_key(0x008A, 1, ANONCE, b"", None)
    m2 = _entete(0x01, 1, depuis_ap=False) + _llc(0x888E) + _eapol_key(0x010A, 1, SNONCE, RSN_IE, kck)
    d1 = _ccmp(2, 1, _llc(0x0800) + _ip_udp(b"netcross-wifi-1"))
    d2 = _ccmp(3, 2, _llc(0x0800) + _ip_udp(b"netcross-wifi-2"))
    return [(t0 + i * 10_000, _radiotap() + trame) for i, trame in enumerate((m1, m2, d1, d2))]


def wpa2_bytes() -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for ts, data in frames():
        out += struct.pack("<IIII", ts // 10**6, ts % 10**6, len(data), len(data)) + data
    return out


if __name__ == "__main__":
    WPA2_PCAP.write_bytes(wpa2_bytes())
