# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1145 : appariement d'un paquet vu dans l'air avec le meme paquet vu
sur un point filaire, retransmissions 802.11 non comptees comme doublons.

Point AIR : capture en mode moniteur synthetique, chiffree WPA2-PSK (meme
reseau fictif que tests/wpa2_reference.py), trois segments TCP dont le
premier est reemis par la station avec le bit retry. Point LAN : capture
Ethernet synthetisee des memes paquets IP, 2 ms plus tard (cote filaire du
point d'acces).
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import sys
from pathlib import Path

import pytest
from conftest import make_pkt
from pcap_builders import write_pcap

import netcross_core.parsing as parsing
import pcap_parser
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.retransmissions_radio import (
    FENETRE_RETRANSMISSION_S,
    FiltreRetransmissionsRadio,
    retirer_retransmissions_radio,
)
from pcap_parser.radio import RadioInfo, extract_mpdu_id
from pcap_parser.wifi_keys import ENV_WIFI_KEYS

sys.path.insert(0, str(Path(__file__).parent))
import wpa2_reference as w  # noqa: E402

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
STA = "02:00:00:00:00:02"
T0_US = 1_700_000_100_000_000


# -- fabriques ---------------------------------------------------------------


def _ip_tcp(seq: int, data: bytes) -> bytes:
    """IPv4/TCP 10.0.0.2:40000 -> 10.0.0.1:80, PSH-ACK, checksums IP valides."""
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + data
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        seq & 0xFFFF,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton("10.0.0.2"),
        socket.inet_aton("10.0.0.1"),
    )
    total = sum(struct.unpack("!10H", ip))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ip[:10] + struct.pack("!H", ~total & 0xFFFF) + ip[12:] + tcp


SEGMENTS = [_ip_tcp(1000 + 10 * i, f"segment-{i}!".encode()) for i in range(3)]


def _capture_air(chemin: Path, retry_de: frozenset[int] = frozenset({0})) -> Path:
    """Handshake EAPOL puis un segment chiffre CCMP toutes les 10 ms ; les
    segments de ``retry_de`` sont reemis 1 ms plus tard (meme sequence
    802.11, meme PN, bit retry)."""
    handshake = w.frames()[:2]
    trames = list(handshake)
    for i, ip in enumerate(SEGMENTS):
        trame = w._ccmp(2 + i, 1 + i, w._llc(0x0800) + ip)
        ts = T0_US + 100_000 + i * 10_000
        trames.append((ts, w._radiotap() + trame))
        if i in retry_de:
            retry = bytes([trame[0], trame[1] | 0x08]) + trame[2:]
            trames.append((ts + 1_000, w._radiotap() + retry))
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for ts, data in trames:
        out += struct.pack("<IIII", ts // 10**6, ts % 10**6, len(data), len(data)) + data
    chemin.write_bytes(out)
    return chemin


def _capture_lan(chemin: Path) -> Path:
    """Les memes paquets IP sur Ethernet, 2 ms apres leur passage dans l'air."""
    eth = bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + b"\x08\x00"
    write_pcap(chemin, [(T0_US + 102_000 + i * 10_000, eth + ip) for i, ip in enumerate(SEGMENTS)])
    return chemin


@pytest.fixture
def cles(tmp_path, monkeypatch):
    chemin = tmp_path / "cles.txt"
    chemin.write_text(f"wpa-pwd:{w.PHRASE}:{w.SSID}\n", encoding="utf-8")
    monkeypatch.setenv(ENV_WIFI_KEYS, str(chemin))
    return chemin


def _radio(retry: bool | None) -> RadioInfo:
    return RadioInfo(retry=retry)


# -- identite 802.11 ---------------------------------------------------------


def test_extract_mpdu_id():
    wlan = {"wlan_wlan_ta": STA, "wlan_wlan_seq": "42", "wlan_wlan_frag": "1"}
    assert extract_mpdu_id({"wlan": wlan}) == (STA, 42, 1)
    assert extract_mpdu_id({"wlan": [{}, {"wlan_wlan_sa": STA, "wlan_wlan_seq": "7"}]}) == (STA, 7, 0)
    assert extract_mpdu_id({"eth": {}}) is None
    assert extract_mpdu_id({"wlan": {"wlan_wlan_seq": "7"}}) is None
    assert extract_mpdu_id({"wlan": {"wlan_wlan_ta": STA}}) is None


# -- filtre ------------------------------------------------------------------


def _air(ts, seq, retry, point="AIR", ta=STA):
    return make_pkt(point=point, ts=ts, wlan_mpdu=(ta, seq, 0), radio=_radio(retry))


def test_filtre_fusionne_la_retransmission_dans_l_original(journal_info):
    original = _air(0.0, 1, False)
    paquets = [original, _air(0.001, 1, True), _air(0.002, 1, True), _air(0.003, 2, False)]
    gardes = retirer_retransmissions_radio(paquets)
    assert gardes == [paquets[0], paquets[3]]
    assert original.radio_retries == 2
    assert paquets[3].radio_retries == 0
    assert "[AIR] 2 retransmission(s) 802.11 (bit retry) fusionnée(s)" in journal_info.getvalue()


@pytest.mark.parametrize(
    "second",
    [
        _air(0.001, 1, False),  # meme identite sans retry : nouvelle trame (sequence revenue)
        _air(0.001, 1, None),  # retry inconnu
        _air(FENETRE_RETRANSMISSION_S + 0.5, 1, True),  # hors fenetre : sequence ayant fait le tour
        _air(0.001, 1, True, point="AIR2"),  # autre sonde
        _air(0.001, 1, True, ta="02:00:00:00:00:09"),  # autre emetteur
        _air(0.001, 2, True),  # autre sequence : original non capte, seule copie vue
    ],
)
def test_filtre_garde_ce_qui_n_est_pas_une_retransmission(second):
    premier = _air(0.0, 1, False)
    assert retirer_retransmissions_radio([premier, second]) == [premier, second]
    assert premier.radio_retries == 0


def test_retry_sans_original_garde_puis_sert_d_original():
    premier = _air(0.0, 5, True)  # l'original a echappe a la sonde
    assert retirer_retransmissions_radio([premier, _air(0.001, 5, True)]) == [premier]
    assert premier.radio_retries == 1


def test_sans_trame_80211_liste_inchangee():
    paquets = [make_pkt(), make_pkt(ts=1.0)]
    assert retirer_retransmissions_radio(paquets) is paquets
    filtre = FiltreRetransmissionsRadio()
    assert list(filtre.filtrer(paquets)) == paquets
    assert filtre.retirees == {}


def test_live_mono_et_multi(monkeypatch):
    # RawPacket simule par (ts, sequence, retry) ; _to_pkt le convertit.
    monkeypatch.setattr(parsing, "_to_pkt", lambda label, raw: _air(*raw, point=label))
    bruts = [(0.0, 1, False), (0.001, 1, True), (0.01, 2, False)]
    monkeypatch.setattr(pcap_parser, "iter_live", lambda *a, **k: iter(bruts))
    live = list(parsing.parse_live("AIR", "wlan0mon"))
    assert [p.wlan_mpdu[1] for p in live] == [1, 2]
    assert live[0].radio_retries == 1

    multi = [("AIR", r) for r in bruts] + [("AIR2", (0.002, 1, True))]
    monkeypatch.setattr(pcap_parser, "iter_live_multi", lambda *a, **k: iter(multi))
    live = list(parsing.parse_live_multi([("AIR", "a"), ("AIR2", "b")]))
    assert [(p.point, p.wlan_mpdu[1]) for p in live] == [("AIR", 1), ("AIR", 2), ("AIR2", 1)]


@pytest.fixture
def journal_info():
    import io

    from loguru import logger

    tampon = io.StringIO()
    sink = logger.add(tampon, level="INFO", format="{message}")
    yield tampon
    logger.remove(sink)


# -- bout en bout avec tshark -----------------------------------------------


@avec_tshark
def test_appariement_air_filaire_sans_faux_doublon(tmp_path, cles):
    air = parsing.parse_capture("AIR", str(_capture_air(tmp_path / "air.pcap")))
    lan = parsing.parse_capture("LAN", str(_capture_lan(tmp_path / "lan.pcap")))
    assert len(air) == len(lan) == 3
    assert [p.radio_retries for p in air] == [1, 0, 0]
    assert all(p.encap_tags == ("802.11(déchiffré)",) for p in air)

    flows = correlate(air + lan)
    assert len(flows) == 3
    for par_point in flows.values():
        assert {pt: len(pk) for pt, pk in par_point.items()} == {"AIR": 1, "LAN": 1}

    r = analyse(flows, ["AIR", "LAN"], air + lan)
    assert r.retrans["AIR"] == r.retrans["LAN"] == 0
    assert r.seen_count == {"AIR": 3, "LAN": 3}


@avec_tshark
def test_sans_filtre_la_retransmission_radio_serait_un_faux_doublon(tmp_path, cles):
    """Temoin : sans la fusion, la copie radio double le segment au point AIR
    et analyse() la compte comme retransmission TCP."""
    bruts = pcap_parser.parse_capture(str(_capture_air(tmp_path / "air.pcap")))
    air = [parsing._to_pkt("AIR", raw) for raw in bruts]
    lan = parsing.parse_capture("LAN", str(_capture_lan(tmp_path / "lan.pcap")))
    assert len(air) == 4
    r = analyse(correlate(air + lan), ["AIR", "LAN"], air + lan)
    assert r.retrans["AIR"] == 1


@avec_tshark
def test_capture_sans_retry_inchangee(tmp_path, cles):
    air = parsing.parse_capture("AIR", str(_capture_air(tmp_path / "air.pcap", retry_de=frozenset())))
    assert [p.radio_retries for p in air] == [0, 0, 0]
    assert os.environ[ENV_WIFI_KEYS] == str(cles)
