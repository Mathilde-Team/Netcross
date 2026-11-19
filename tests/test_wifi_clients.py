# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1146 : métriques et constats radio par client 802.11.

Jeu dédié « perte dans l'air » : capture en mode moniteur synthétique
(radiotap avec débit, canal et signal), station 02:00:00:00:00:02 associée
au point d'accès 02:00:00:00:00:01. Le premier segment TCP montant est
réémis deux fois par la radio (bit retry), puis retransmis par TCP 200 ms
plus tard : la perte s'est produite dans l'air.
"""

from __future__ import annotations

import shutil
import socket
import struct
from pathlib import Path

import pytest
from conftest import make_pkt

import netcross_core.parsing as parsing
from netcross_core import wifi
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.redact import redact_packets
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from pcap_parser.radio import RadioInfo, extract_station

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
AP = "02:00:00:00:00:01"
AP2 = "02:00:00:00:00:03"
STA = "02:00:00:00:00:02"
T0_US = 1_700_000_200_000_000


# -- fabriques ---------------------------------------------------------------


def _mac(texte: str) -> bytes:
    return bytes.fromhex(texte.replace(":", ""))


def _radiotap(debit_mbps: float, signal_dbm: int) -> bytes:
    """Radiotap : débit (unités de 500 kbit/s), canal 6, signal."""
    present = (1 << 2) | (1 << 3) | (1 << 5)
    corps = struct.pack("<BB", round(debit_mbps * 2), 0) + struct.pack("<HHb", 2437, 0x00A0, signal_dbm)
    return struct.pack("<BBHI", 0, 0, 8 + len(corps), present) + corps


def _ip_tcp(seq: int, data: bytes, montant: bool = True) -> bytes:
    """IPv4/TCP 10.0.0.2:40000 <-> 10.0.0.1:80, PSH-ACK."""
    sport, dport = (40000, 80) if montant else (80, 40000)
    src, dst = ("10.0.0.2", "10.0.0.1") if montant else ("10.0.0.1", "10.0.0.2")
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + data
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
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return ip + tcp


def _trame(seq80211: int, ip: bytes, *, montant: bool = True, retry: bool = False, bssid: str = AP) -> bytes:
    """Trame de données 802.11 non protégée, LLC/SNAP IPv4."""
    fc1 = (0x01 if montant else 0x02) | (0x08 if retry else 0)
    adresses = _mac(bssid) + _mac(STA) + _mac(bssid) if montant else _mac(STA) + _mac(bssid) + _mac(bssid)
    entete = bytes([0x08, fc1]) + struct.pack("<H", 0) + adresses + struct.pack("<H", seq80211 << 4)
    return entete + bytes.fromhex("aaaa03000000") + struct.pack("!H", 0x0800) + ip


def _ecrire(chemin: Path, trames: list[tuple[int, bytes]]) -> Path:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for ts, data in trames:
        out += struct.pack("<IIII", ts // 10**6, ts % 10**6, len(data), len(data)) + data
    chemin.write_bytes(out)
    return chemin


def _capture_perte_air(chemin: Path) -> Path:
    """Segment 1000 : deux copies retry puis retransmission TCP (seq 802.11 neuve)."""
    rt = _radiotap(54, -60)
    seg = _ip_tcp(1000, b"segment-0!")
    trames = [
        (T0_US, rt + _trame(10, seg)),
        (T0_US + 1_000, rt + _trame(10, seg, retry=True)),
        (T0_US + 2_000, rt + _trame(10, seg, retry=True)),
        (T0_US + 200_000, rt + _trame(11, seg)),
        (T0_US + 210_000, _radiotap(54, -40) + _trame(20, _ip_tcp(1, b"ack"), montant=False)),
    ]
    return _ecrire(chemin, trames)


def _st(emise: bool = True, bssid: str = AP, station: str = STA) -> tuple[str, str, bool]:
    return (station, bssid, emise)


def _pkt(ts: float, **kw):
    kw.setdefault("wlan_station", _st())
    kw.setdefault("tcp_len", 10)
    kw.setdefault("point", "AIR")
    return make_pkt(ts=ts, **kw)


# -- extraction de la station ------------------------------------------------


def test_extract_station_selon_les_bits_ds():
    montant = {"wlan_wlan_fc_ds": "0x01", "wlan_wlan_ta": STA, "wlan_wlan_bssid": AP}
    assert extract_station({"wlan": montant}) == (STA, AP, True)
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "1", "wlan_wlan_sa": STA, "wlan_wlan_bssid": AP}}) == (
        STA,
        AP,
        True,
    )
    descendant = {"wlan_wlan_fc_ds": "2", "wlan_wlan_ra": STA, "wlan_wlan_bssid": AP}
    assert extract_station({"wlan": [{}, descendant]}) == (STA, AP, False)
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "2", "wlan_wlan_da": STA, "wlan_wlan_bssid": AP}}) == (
        STA,
        AP,
        False,
    )


def test_extract_station_sans_station():
    assert extract_station({"eth": {}}) is None
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "3", "wlan_wlan_ta": STA, "wlan_wlan_bssid": AP}}) is None
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "0", "wlan_wlan_ta": STA}}) is None
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "1", "wlan_wlan_ta": STA}}) is None
    assert extract_station({"wlan": {"wlan_wlan_fc_ds": "1", "wlan_wlan_bssid": AP}}) is None


# -- fiches ------------------------------------------------------------------


def test_fiche_metriques_de_base():
    radio_sta = RadioInfo(rssi_dbm=-61, mcs=7, data_rate_mbps=65.0)
    radio_ap = RadioInfo(rssi_dbm=-30, mcs=5, data_rate_mbps=52.0)
    pkts = [
        _pkt(0.0, seq=1, radio=radio_sta, radio_retries=1, length=1000),
        _pkt(0.1, seq=2, radio=RadioInfo(rssi_dbm=-65, mcs=7, data_rate_mbps=65.0)),
        _pkt(0.2, seq=3, radio=radio_ap, wlan_station=_st(emise=False)),
        _pkt(0.3, seq=4, radio=RadioInfo(retry=False)),
        _pkt(0.4, seq=5, radio=None),
        make_pkt(point="LAN", ts=0.0),
    ]
    resultat = wifi.metriques_clients(pkts)
    assert list(resultat) == ["AIR"]
    (fiche,) = resultat["AIR"]
    assert fiche["station"] == STA
    assert fiche["trames"] == 5
    assert fiche["trames_emises"] == 4
    assert fiche["rssi_median_dbm"] == -63  # trames émises seulement
    assert fiche["mcs"] == {5: 1, 7: 2}
    assert fiche["debits_phy_mbps"] == {52.0: 1, 65.0: 2}
    assert fiche["debit_phy_median_mbps"] == 65.0
    assert fiche["retransmissions_radio"] == 1
    assert fiche["taux_retransmission_radio"] == pytest.approx(1 / 6)
    assert fiche["bssids"] == [AP]
    assert fiche["itinerances"] == []
    attendu = 1000 * 8 * 2 / 65e6 + 100 * 8 / 65e6 + 100 * 8 / 52e6
    assert fiche["temps_antenne_s"] == pytest.approx(attendu)
    assert fiche["pertes_tcp"] == {"air": 0, "apres_point_acces": 0, "indeterminee": 0}
    assert fiche["constats"] == []


def test_fiche_sans_radio():
    (fiche,) = wifi.metriques_clients([_pkt(0.0)])["AIR"]
    assert fiche["rssi_median_dbm"] is None
    assert fiche["debit_phy_median_mbps"] is None
    assert fiche["temps_antenne_s"] == 0
    assert fiche["taux_retransmission_radio"] == 0


def test_stations_et_points_separes_et_tries():
    pkts = [
        _pkt(0.0, point="B", wlan_station=_st(station="02:00:00:00:00:09")),
        _pkt(0.0, point="A", wlan_station=_st(station="02:00:00:00:00:09")),
        _pkt(0.1, point="A"),
        make_pkt(point="A", ts=0.2),
    ]
    resultat = wifi.metriques_clients(pkts)
    assert list(resultat) == ["A", "B"]
    assert [f["station"] for f in resultat["A"]] == [STA, "02:00:00:00:00:09"]


def test_constat_perte_dans_l_air():
    pkts = [_pkt(0.0, radio_retries=2), _pkt(0.2)]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["pertes_tcp"]["air"] == 1
    assert fiche["constats"] == [wifi.PERTE_AIR]


def test_constat_perte_apres_le_point_d_acces():
    # origine montante vue sans retry : acquittée en 802.11, perdue plus loin
    pkts = [_pkt(0.0), _pkt(0.2)]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["pertes_tcp"] == {"air": 0, "apres_point_acces": 1, "indeterminee": 0}
    assert fiche["constats"] == [wifi.PERTE_APRES_AP]


def test_origine_jamais_vue():
    assert wifi._origine_perte(None, emise=False) == "apres_point_acces"
    assert wifi._origine_perte(None, emise=True) == "indeterminee"


def test_segments_ignores_par_le_classement_des_pertes():
    pkts = [
        _pkt(0.0, proto="UDP"),
        _pkt(0.1, proto="UDP"),
        _pkt(0.2, tcp_len=0),
        _pkt(0.3, tcp_len=0),
        _pkt(0.4, seq=None),
        _pkt(0.5, seq=None),
    ]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["pertes_tcp"] == {"air": 0, "apres_point_acces": 0, "indeterminee": 0}


def test_constat_debit_phy_bas():
    pkts = [_pkt(0.0, radio=RadioInfo(data_rate_mbps=6.0)), _pkt(0.1, seq=2, radio=RadioInfo(data_rate_mbps=12.0))]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["debit_phy_median_mbps"] == 9.0
    assert fiche["constats"] == [wifi.DEBIT_PHY_BAS]


def test_itinerance_pendant_le_flux():
    pkts = [
        _pkt(0.0, seq=1),
        _pkt(0.1, seq=2, wlan_station=_st(bssid=AP2)),
        _pkt(0.2, seq=3, wlan_station=_st(bssid=AP2)),
    ]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["bssids"] == [AP, AP2]
    assert fiche["itinerances"] == [{"ts": 0.1, "de": AP, "vers": AP2, "flux_traverses": 1}]
    assert fiche["constats"] == [wifi.ITINERANCE_FLUX]


def test_itinerance_hors_flux():
    # changement de BSSID entre deux flux distincts : pas de constat
    pkts = [_pkt(0.0, seq=1, sport=1), _pkt(0.1, seq=2, sport=2, wlan_station=_st(bssid=AP2))]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    assert fiche["itinerances"][0]["flux_traverses"] == 0
    assert fiche["constats"] == []


def test_format_fiche():
    pkts = [_pkt(0.0, radio=RadioInfo(rssi_dbm=-70, data_rate_mbps=6.0), radio_retries=1), _pkt(0.2)]
    (fiche,) = wifi.metriques_clients(pkts)["AIR"]
    ligne = wifi.format_fiche("AIR", fiche)
    assert ligne.startswith(f"AIR : station {STA} -- 2 trame(s), RSSI médian -70 dBm, débit PHY médian 6 Mbit/s")
    assert "retransmissions radio 33.3%" in ligne
    assert ligne.endswith(f"constats : {wifi.PERTE_AIR}, {wifi.DEBIT_PHY_BAS}")
    sans = wifi.format_fiche("AIR", wifi.metriques_clients([_pkt(0.0)])["AIR"][0])
    assert "RSSI médian n/d" in sans and "débit PHY médian n/d" in sans and "constats" not in sans


# -- anonymisation -----------------------------------------------------------


def test_adresses_802_11_anonymisees():
    pkts = [_pkt(0.0, wlan_mpdu=(STA, 1, 0)), _pkt(0.1, wlan_station=("pas-une-mac", "ni-ceci", True))]
    redacteur = redact_packets(pkts)
    pseudo_sta = redacteur.mapping[STA]
    assert pseudo_sta != STA
    assert pkts[0].wlan_mpdu == (pseudo_sta, 1, 0)
    assert pkts[0].wlan_station == (pseudo_sta, redacteur.mapping[AP], True)
    assert pkts[1].wlan_station == ("pas-une-mac", "ni-ceci", True)
    (fiche, _autre) = sorted(wifi.metriques_clients(pkts)["AIR"], key=lambda f: f["station"] != pseudo_sta)
    assert fiche["station"] == pseudo_sta


def test_mpdu_sans_mac_inchange():
    pkts = [_pkt(0.0, wlan_mpdu=("inconnu", 1, 0), wlan_station=None)]
    redact_packets(pkts)
    assert pkts[0].wlan_mpdu == ("inconnu", 1, 0)


# -- jeu dédié, de bout en bout ----------------------------------------------


@avec_tshark
def test_jeu_dedie_perte_dans_l_air(tmp_path, capsys):
    chemin = _capture_perte_air(tmp_path / "perte-air.pcap")
    pkts = parsing.parse_capture("AIR", str(chemin))
    assert [p.radio_retries for p in pkts] == [2, 0, 0]
    assert pkts[0].wlan_station == (STA, AP, True)
    assert pkts[2].wlan_station == (STA, AP, False)
    rapport = analyse(correlate(pkts), ["AIR"], pkts)
    (fiche,) = rapport.wifi_clients["AIR"]
    assert fiche["rssi_median_dbm"] == -60
    assert fiche["debit_phy_median_mbps"] == 54.0
    assert fiche["retransmissions_radio"] == 2
    assert fiche["taux_retransmission_radio"] == pytest.approx(2 / 5)
    assert fiche["pertes_tcp"]["air"] == 1
    assert fiche["constats"] == [wifi.PERTE_AIR]
    assert build_json_report_document(rapport)["wifi_clients"]["AIR"][0]["constats"] == [wifi.PERTE_AIR]
    print_report(rapport)
    sortie = capsys.readouterr().out
    assert "-- Wi-Fi : métriques radio par client --" in sortie
    assert f"constats : {wifi.PERTE_AIR}" in sortie


def test_rapport_sans_wifi(capsys):
    pkts = [make_pkt(point="A", ts=0.0)]
    rapport = analyse(correlate(pkts), ["A"], pkts)
    assert rapport.wifi_clients == {}
    print_report(rapport)
    assert "Wi-Fi : métriques radio" not in capsys.readouterr().out
