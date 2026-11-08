"""Issue #1142 : capture 802.11 radiotap comme point de capture, lecture
par trame du RSSI, du MCS, du debit, du retry et du canal."""

from __future__ import annotations

import shutil

import pytest
from radiotap_reference import NO_RADIOTAP_PCAP, RADIOTAP_PCAP, no_radiotap_bytes, radiotap_bytes

import netcross_core.parsing as parsing
from pcap_parser.packet import RawPacket
from pcap_parser.radio import RadioInfo, extract_radio, missing_radiotap_note


def test_captures_de_reference_identiques_au_generateur():
    assert RADIOTAP_PCAP.read_bytes() == radiotap_bytes()
    assert NO_RADIOTAP_PCAP.read_bytes() == no_radiotap_bytes()


# -- extract_radio (enregistrements EK) ---------------------------------------


def test_extract_radio_hors_80211():
    assert extract_radio({"eth": {}, "ip": {}}) is None


def test_extract_radio_trame_ht_complete():
    layers = {
        "wlan_radio": {
            "wlan_radio_wlan_radio_signal_dbm": "-60",
            "wlan_radio_wlan_radio_11n_mcs_index": "7",
            "wlan_radio_wlan_radio_data_rate": "65",
            "wlan_radio_wlan_radio_channel": "36",
            "wlan_radio_wlan_radio_frequency": "5180",
        },
        "wlan": {"wlan_wlan_fc_retry": True},
    }
    assert extract_radio(layers) == RadioInfo(-60, 7, 65.0, True, 36, 5180)


def test_extract_radio_mcs_vht_multi_utilisateur_et_he():
    vht = {"wlan_radio": {"wlan_radio_wlan_radio_11ac_mcs": ["9", "4"]}, "wlan": [{}, {"wlan_wlan_fc_retry": "0"}]}
    assert extract_radio(vht) == RadioInfo(mcs=9, retry=False)
    he = {"wlan_radio": [{"wlan_radio_wlan_radio_11ax_mcs": "11"}], "wlan": {}}
    assert extract_radio(he) == RadioInfo(mcs=11)
    vide = {"wlan_radio": {"wlan_radio_wlan_radio_11ac_mcs": []}}
    assert extract_radio(vide) == RadioInfo()


def test_extract_radio_80211_sans_en_tete_radio():
    assert extract_radio({"wlan": {"wlan_wlan_fc_retry": True}}) == RadioInfo(retry=True)


def test_raw_packet_radio_none_par_defaut():
    assert RawPacket.__dataclass_fields__["radio"].default is None


# -- message explicite sans radiotap -----------------------------------------


def test_missing_radiotap_note(tmp_path):
    note = missing_radiotap_note(str(NO_RADIOTAP_PCAP))
    assert note is not None
    assert "sans en-tête radiotap (linktype 105)" in note
    assert "mode moniteur" in note
    assert missing_radiotap_note(str(RADIOTAP_PCAP)) is None
    assert missing_radiotap_note(str(tmp_path / "absent.pcap")) is None
    other = tmp_path / "x.bin"
    other.write_bytes(b"pas une capture")
    assert missing_radiotap_note(str(other)) is None


def test_missing_radiotap_note_pcapng_mixte_et_tronque(tmp_path, monkeypatch):
    from pcap_builders import epb, frame, idb, shb, write_bytes

    import pcap_parser.radio as radio

    mixte, seul = tmp_path / "m.pcapng", tmp_path / "s.pcapng"
    write_bytes(mixte, shb(), idb(105), idb(127), epb(frame(0)))
    write_bytes(seul, shb(), idb(1), idb(105), epb(frame(0)))
    assert missing_radiotap_note(str(mixte)) is None
    assert missing_radiotap_note(str(seul)) is not None

    def tronque(_path):
        raise ValueError("tronque")

    monkeypatch.setattr(radio, "read_structure", tronque)
    assert missing_radiotap_note(str(seul)) is None


def test_parse_capture_avertit_sans_radiotap(monkeypatch):
    from pcap_parser.packet import build_packet

    messages = []
    layers = {
        "frame": {"frame_frame_len": "60", "frame_frame_number": "1", "frame_frame_protocols": "wlan:llc:ip:udp"},
        "wlan": {"wlan_wlan_fc_retry": True},
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},
        "udp": {"udp_udp_srcport": "5000", "udp_udp_dstport": "6000"},
    }
    monkeypatch.setattr(
        parsing.pcap_parser, "parse_capture", lambda path, raise_on_error=False: [build_packet(1.0, layers)]
    )
    monkeypatch.setattr(parsing.logger, "warning", lambda fmt, *args: messages.append(fmt.format(*args)))
    pkts = parsing.parse_capture("WIFI", str(NO_RADIOTAP_PCAP))
    assert pkts[0].radio == RadioInfo(retry=True)
    assert len(messages) == 1
    assert messages[0].startswith("[WIFI] capture 802.11 sans en-tête radiotap")
    messages.clear()
    parsing.parse_capture("WIFI", str(RADIOTAP_PCAP))
    assert messages == []


# -- bout en bout avec tshark --------------------------------------------------


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_capture_radiotap_de_reference_bout_en_bout():
    pkts = parsing.parse_capture("WIFI", str(RADIOTAP_PCAP))
    assert [(p.src, p.dst, p.proto, p.sport, p.dport) for p in pkts[:2]] == [
        ("10.0.0.1", "10.0.0.2", "UDP", 5000, 6000),
        ("10.0.0.1", "10.0.0.2", "UDP", 5000, 6000),
    ]
    assert [p.radio for p in pkts] == [
        RadioInfo(rssi_dbm=-42, mcs=None, data_rate_mbps=54.0, retry=False, channel=6, frequency_mhz=2437),
        RadioInfo(rssi_dbm=-60, mcs=7, data_rate_mbps=65.0, retry=True, channel=36, frequency_mhz=5180),
        RadioInfo(rssi_dbm=-61, mcs=15, data_rate_mbps=130.0, retry=False, channel=36, frequency_mhz=5180),
        RadioInfo(rssi_dbm=-55, mcs=9, data_rate_mbps=780.0, retry=False, channel=36, frequency_mhz=5180),
    ]


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_capture_80211_sans_radiotap_bout_en_bout():
    pkts = parsing.parse_capture("WIFI", str(NO_RADIOTAP_PCAP))
    assert len(pkts) == 4
    assert [p.radio for p in pkts] == [
        RadioInfo(retry=False),
        RadioInfo(retry=True),
        RadioInfo(retry=False),
        RadioInfo(retry=False),
    ]
