"""Generateur des captures 802.11 de reference versionnees (issue #1142).

Trames entierement synthetiques, ecrites a la main octet par octet pour
ce projet (aucune capture reelle, aucune donnee personnelle) : elles sont
donc distribuees sous la licence du depot. Regenerer avec :

    uv run python tests/radiotap_reference.py

tests/test_radio.py verifie que les fichiers versionnes sont identiques a
la sortie de ce generateur.

Contenu (4 trames de donnees 802.11 ToDS, LLC/SNAP, IPv4/UDP) :
1. legacy 54 Mbit/s, canal 6 (2437 MHz), -42 dBm ;
2. HT MCS 7, canal 36 (5180 MHz), -60 dBm, retry ;
3. HT MCS 15, canal 36, -61 dBm ;
4. VHT MCS 9 NSS 2 80 MHz, canal 36, -55 dBm.
"""

from __future__ import annotations

import struct
from pathlib import Path

DATA = Path(__file__).parent / "data"
RADIOTAP_PCAP = DATA / "radiotap-80211-reference.pcap"
NO_RADIOTAP_PCAP = DATA / "ieee80211-sans-radiotap.pcap"


def _ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    total = sum(struct.unpack("!10H", ip))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ip[:10] + struct.pack("!H", ~total & 0xFFFF) + ip[12:] + udp


def _wlan_data(retry, payload, seq):
    fc = bytes([0x08, 0x01 | (0x08 if retry else 0)])  # donnees, ToDS (+ retry)
    addrs = bytes.fromhex("020000000001020000000002020000000003")
    llc = bytes.fromhex("aaaa030000000800")
    return fc + struct.pack("<H", 0) + addrs + struct.pack("<H", seq << 4) + llc + payload


def _rt_legacy(rate_500k, freq, chflags, signal):
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    return struct.pack("<BBHI", 0, 0, 15, present) + struct.pack("<BBHHb", 0, rate_500k, freq, chflags, signal)


def _rt_ht(mcs, freq, chflags, signal):
    present = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 19)
    return struct.pack("<BBHI", 0, 0, 18, present) + struct.pack("<BxHHbBBB", 0, freq, chflags, signal, 0x07, 0x00, mcs)


def _rt_vht(mcs, nss, freq, chflags, signal):
    present = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 21)
    head = struct.pack("<BBHI", 0, 0, 28, present) + struct.pack("<BxHHbx", 0, freq, chflags, signal)
    return head + struct.pack("<HBB4BBBH", 0x0044, 0, 4, (mcs << 4) | nss, 0, 0, 0, 0, 0, 0)


def frames():
    payload = b"x" * 20
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    t0 = 1_700_000_000_000_000
    return [
        (t0, _rt_legacy(108, 2437, 0x00C0, -42) + _wlan_data(False, _ip_udp(a, b, 5000, 6000, payload), 1)),
        (t0 + 10_000, _rt_ht(7, 5180, 0x0140, -60) + _wlan_data(True, _ip_udp(a, b, 5000, 6000, payload), 1)),
        (t0 + 20_000, _rt_ht(15, 5180, 0x0140, -61) + _wlan_data(False, _ip_udp(b, a, 6000, 5000, payload), 2)),
        (t0 + 30_000, _rt_vht(9, 2, 5180, 0x0140, -55) + _wlan_data(False, _ip_udp(b, a, 6000, 5000, payload), 3)),
    ]


def _pcap(linktype, records):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, data in records:
        out += struct.pack("<IIII", ts // 10**6, ts % 10**6, len(data), len(data)) + data
    return out


def radiotap_bytes():
    return _pcap(127, frames())


def no_radiotap_bytes():
    stripped = [(ts, data[struct.unpack_from("<H", data, 2)[0] :]) for ts, data in frames()]
    return _pcap(105, stripped)


if __name__ == "__main__":
    RADIOTAP_PCAP.write_bytes(radiotap_bytes())
    NO_RADIOTAP_PCAP.write_bytes(no_radiotap_bytes())
