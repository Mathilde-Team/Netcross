# SPDX-License-Identifier: GPL-3.0-or-later
"""
Fabriques et lecteurs pcap / pcapng SYNTHETIQUES pour les tests de
decoupage (test_capfile.py, test_split_capture.py) : aucun outil externe
(tshark, editcap) n'est necessaire pour construire ou relire un fichier
-- meme principe que conftest.make_pkt pour les Pkt.

Les lecteurs sont volontairement independants de pcap_parser.capfile
(un test ne doit pas verifier le code avec lui-meme). Chaque paquet
synthetique porte son propre numero d'ordre dans ses 4 premiers octets
(voir frame/frame_index), ce qui permet de verifier qu'un decoupage
conserve tous les paquets, sans doublon et dans l'ordre.
"""

from __future__ import annotations

import struct
from pathlib import Path

PCAP_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16


def frame(index: int, size: int = 100) -> bytes:
    """Trame factice de `size` octets, numero d'ordre en tete."""
    return struct.pack(">I", index) + bytes(size - 4)


def frame_index(data: bytes) -> int:
    return struct.unpack(">I", data[:4])[0]


# -- pcap classique ---------------------------------------------------------


def pcap_bytes(packets, *, endian: str = "<", nsec: bool = False) -> bytes:
    """packets : iterable de (ts_en_microsecondes, donnees) -- en
    NANOsecondes si nsec=True. Timestamps entiers : pas de derive
    flottante, les frontieres d'intervalle des tests sont exactes."""
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
    per_second = 1_000_000_000 if nsec else 1_000_000
    for ts, data in packets:
        out += struct.pack(endian + "IIII", ts // per_second, ts % per_second, len(data), len(data))
        out += data
    return bytes(out)


def write_pcap(path, packets, **kwargs) -> None:
    with open(path, "wb") as f:
        f.write(pcap_bytes(packets, **kwargs))


def read_pcap(path):
    """-> (en-tete global de 24 octets, [(ts_sec, ts_frac, donnees), ...]).
    L'endianness est deduite du magic."""
    raw = Path(path).read_bytes()
    endian = "<" if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    pos = PCAP_HEADER_LEN
    records = []
    while pos + PCAP_RECORD_HEADER_LEN <= len(raw):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", raw, pos)
        pos += PCAP_RECORD_HEADER_LEN
        records.append((sec, frac, raw[pos : pos + incl]))
        pos += incl
    return raw[:PCAP_HEADER_LEN], records


def synthetic_packets(count: int, step_us: int = 100_000, start_us: int = 1_700_000_000_000_000, size: int = 100):
    """count paquets espaces de step_us (100 ms par defaut), le premier a
    start_us."""
    return [(start_us + i * step_us, frame(i, size)) for i in range(count)]


# -- pcapng -------------------------------------------------------------------

SHB, IDB, EPB, DSB = 0x0A0D0D0A, 0x1, 0x6, 0xA


def _pad4(data: bytes) -> bytes:
    return data + bytes(-len(data) % 4)


def block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    body = _pad4(body)
    total = 12 + len(body)
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def shb(endian: str = "<") -> bytes:
    return block(SHB, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def idb(linktype: int = 1, endian: str = "<") -> bytes:
    return block(IDB, struct.pack(endian + "HHI", linktype, 0, 65535), endian)


def epb(data: bytes, ts_us: int = 0, interface: int = 0, endian: str = "<") -> bytes:
    head = struct.pack(endian + "IIIII", interface, ts_us >> 32, ts_us & 0xFFFFFFFF, len(data), len(data))
    return block(EPB, head + data, endian)


def dsb(secrets: bytes = b"CLIENT_RANDOM secret", endian: str = "<") -> bytes:
    return block(DSB, struct.pack(endian + "II", 0x544C534B, len(secrets)) + secrets, endian)


def write_bytes(path, *chunks: bytes) -> None:
    with open(path, "wb") as f:
        for chunk in chunks:
            f.write(chunk)


def read_pcapng(path):
    """-> liste de (type_de_bloc, corps_sans_padding_retire, interface|None,
    donnees|None) dans l'ordre du fichier. Relit l'endianness a chaque SHB.
    `donnees`/`interface` ne sont renseignes que pour les EPB."""
    raw = Path(path).read_bytes()
    endian = "<"
    pos = 0
    blocks = []
    while pos + 12 <= len(raw):
        if raw[pos : pos + 4] == b"\x0a\x0d\x0d\x0a":
            endian = "<" if raw[pos + 8 : pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        block_type, total = struct.unpack_from(endian + "II", raw, pos)
        body = raw[pos + 8 : pos + total - 4]
        interface = data = None
        if block_type == EPB:
            interface, _hi, _lo, caplen, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            data = body[20 : 20 + caplen]
        blocks.append((block_type, body, interface, data))
        pos += total
    return blocks


def pcapng_packets(path):
    """[(interface, donnees), ...] des seuls Enhanced Packet Blocks."""
    return [(b[2], b[3]) for b in read_pcapng(path) if b[0] == EPB]
