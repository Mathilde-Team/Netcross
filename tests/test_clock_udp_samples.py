# SPDX-License-Identifier: GPL-3.0-or-later
"""Identités UDP non ambiguës et estimation sans aucun handshake TCP."""

from dataclasses import replace
from hashlib import sha256

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.clock_samples import collect_udp_samples
from netcross_core.clock_sync import EchantillonHorloge, estimer_decalage
from netcross_core.correlate import correlate
from netcross_core.parsing import _to_pkt
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from pcap_parser.packet import build_packet

PAIRS = [("A", "B")]


def dns_exchange(txn=1, name="example.org", start=0.0, client="10.0.0.1", port=5000):
    common = {"proto": "UDP", "dns_txn_id": txn, "dns_qry_name": name}
    request = dict(src=client, dst="10.0.0.2", sport=port, dport=53, **common)
    reply = dict(src="10.0.0.2", dst=client, sport=53, dport=port, dns_is_response=True, **common)
    return [
        make_pkt(point="A", ts=start, **request),
        make_pkt(point="B", ts=start + 0.022, **request),
        make_pkt(point="B", ts=start + 0.032, **reply),
        make_pkt(point="A", ts=start + 0.014, **reply),
    ]


def media_exchange(kind="RTP", start=0.0, offset=0.02, drift=0.0, number=1):
    common = {"proto": "UDP", "length": 100}
    if kind == "RTP":
        common.update(is_rtp=True, rtp_ssrc=7, rtp_seq=number, rtp_ts=number * 160)
    else:
        common["rtcp_hash"] = f"rtcp-{number}"
    forward = dict(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=5002, **common)
    backward = dict(src="10.0.0.2", dst="10.0.0.1", sport=5002, dport=5000, **common)
    if kind == "RTP":
        backward["rtp_ssrc"] = 8
    else:
        backward["rtcp_hash"] = f"rtcp-reverse-{number}"
    return [
        make_pkt(point="A", ts=start, **forward),
        make_pkt(point="B", ts=(start + 0.002) * (1 + drift) + offset, **forward),
        make_pkt(point="B", ts=(start + 0.010) * (1 + drift) + offset, **backward),
        make_pkt(point="A", ts=start + 0.012, **backward),
    ]


def test_dns_sans_tcp_avec_nom_normalise_et_nom_absent_sur_un_paquet():
    packets = dns_exchange(txn=0)
    packets[1] = replace(packets[1], dns_qry_name="EXAMPLE.ORG.")
    packets[2] = replace(packets[2], dns_qry_name=None)
    samples = collect_udp_samples(packets, PAIRS)[("A", "B")]
    assert len(samples) == 1
    estimate = estimer_decalage(samples)
    assert estimate.decalage_ms == pytest.approx(20)
    assert estimate.sources == ("DNS",)
    assert "DNS" in estimate.methode


@pytest.mark.parametrize(
    "other",
    [
        {"client": "10.0.0.3"},
        {"port": 6000},
        {"name": "other.org"},
    ],
)
def test_dns_identifiant_partage_ne_melange_pas_clients_ports_ou_noms(other):
    samples = collect_udp_samples(dns_exchange() + dns_exchange(start=10, **other), PAIRS)[("A", "B")]
    assert len(samples) == 2
    assert [sample.decalage_ms for sample in samples] == pytest.approx([20, 20])


def test_dns_identifiant_reutilise_sans_identite_unique_refuse():
    assert not collect_udp_samples(dns_exchange() + dns_exchange(start=10), PAIRS)


@pytest.mark.parametrize("indices", [[0, 1, 2], [0, 1], [0, 3], [2, 3]])
def test_dns_echange_incomplet_refuse(indices):
    packets = dns_exchange()
    assert not collect_udp_samples([packets[index] for index in indices], PAIRS)


def test_dns_reponse_anterieure_et_nom_manquant_ambigu_refuses():
    packets = dns_exchange()
    packets[3] = replace(packets[3], ts=-1)
    assert not collect_udp_samples(packets, PAIRS)
    ambiguous = dns_exchange(name="one.org") + dns_exchange(name="two.org")
    ambiguous.append(replace(ambiguous[0], dns_qry_name=None))
    assert len(collect_udp_samples(ambiguous, PAIRS)[("A", "B")]) == 2


def test_dns_nat_exige_empreintes_et_refuse_collisions():
    packets = dns_exchange()
    packets = [replace(packet, payload_hash="reply" if packet.dns_is_response else "request") for packet in packets]
    for index in (1, 2):
        packet = packets[index]
        packets[index] = replace(
            packet,
            src="192.0.2.1" if not packet.dns_is_response else packet.src,
            dst="192.0.2.1" if packet.dns_is_response else packet.dst,
            sport=6000 if not packet.dns_is_response else packet.sport,
            dport=6000 if packet.dns_is_response else packet.dport,
        )
    assert not collect_udp_samples(packets, PAIRS)
    assert len(collect_udp_samples(packets, PAIRS, nat_tolerant=True)[("A", "B")]) == 1
    assert not collect_udp_samples([replace(packet, payload_hash=None) for packet in packets], PAIRS, True)
    other = [
        replace(
            packet,
            src="10.0.0.3" if not packet.dns_is_response else packet.src,
            dst="10.0.0.3" if packet.dns_is_response else packet.dst,
        )
        for packet in packets
        if packet.point == "A"
    ]
    assert not collect_udp_samples(packets + other, PAIRS, True)


@pytest.mark.parametrize("kind", ["RTP", "RTCP"])
def test_media_bidir_estime_decalage_et_derive_sans_tcp(kind):
    packets = [
        packet for index in range(12) for packet in media_exchange(kind, start=index * 10, drift=10e-6, number=index)
    ]
    samples = collect_udp_samples(packets, PAIRS)[("A", "B")]
    estimate = estimer_decalage(samples)
    assert len(samples) == 12
    assert estimate.decalage_a(0) == pytest.approx(20)
    assert estimate.derive_ppm == pytest.approx(10)
    assert estimate.sources == (kind,)
    reverse = estimer_decalage(collect_udp_samples(packets, [("B", "A")])[("B", "A")])
    assert reverse.decalage_a(0) == pytest.approx(-20 / (1 + 10e-6))


@pytest.mark.parametrize("kind", ["RTP", "RTCP"])
def test_media_unidirectionnel_ou_duplique_refuse(kind):
    packets = media_exchange(kind)
    assert not collect_udp_samples(packets[:2], PAIRS)
    assert not collect_udp_samples([*packets, packets[0]], PAIRS)


def test_media_trop_lointain_ou_connexions_incoherentes_refuse():
    packets = media_exchange()
    assert not collect_udp_samples(packets[:2] + [replace(packet, ts=packet.ts + 2) for packet in packets[2:]], PAIRS)
    assert not collect_udp_samples(
        [replace(packet, sport=9000) if index == 2 else packet for index, packet in enumerate(packets)], PAIRS
    )


def test_media_reprend_apres_paquets_isoles_et_refuse_saut_horloge():
    first, later = media_exchange(number=1), media_exchange(start=10, number=2)
    assert len(collect_udp_samples(first[:2] + later, PAIRS)[("A", "B")]) == 1
    assert len(collect_udp_samples(first[2:] + later, PAIRS)[("A", "B")]) == 1
    assert not collect_udp_samples(
        [replace(packet, ts=100) if index == 2 else packet for index, packet in enumerate(first)], PAIRS
    )
    reversed_at_b = [
        replace(packet, src=packet.dst, dst=packet.src, sport=packet.dport, dport=packet.sport)
        if index == 2
        else packet
        for index, packet in enumerate(first)
    ]
    assert not collect_udp_samples(reversed_at_b, PAIRS)


def test_paquets_invalides_sans_identite_ou_ports_ignores_et_dns_non_double():
    packets = [
        make_pkt(proto="TCP"),
        make_pkt(proto="UDP", ts=float("nan")),
        make_pkt(proto="UDP"),
        make_pkt(proto="UDP", is_rtp=True),
        make_pkt(proto="UDP", sport=None),
        make_pkt(proto="UDP", dport=None),
    ]
    assert not collect_udp_samples(packets, PAIRS)
    dns = [replace(packet, is_rtp=True, rtp_ssrc=1, rtp_seq=1, rtp_ts=160) for packet in dns_exchange()]
    assert len(collect_udp_samples(dns, PAIRS)[("A", "B")]) == 1


def test_sources_mixtes_et_echantillon_tcp_compatible():
    packets = dns_exchange() + media_exchange() + media_exchange("RTCP")
    estimate = estimer_decalage(collect_udp_samples(packets, PAIRS)[("A", "B")])
    assert estimate.sources == ("DNS", "RTCP", "RTP")
    assert all(source in estimate.methode for source in estimate.sources)
    assert estimer_decalage([EchantillonHorloge(0, 20, 4)]).sources == ("TCP",)


@pytest.mark.parametrize("kind", ["DNS", "RTP", "RTCP"])
def test_analyse_sans_tcp_expose_sources_dans_texte_et_json(kind, capsys):
    packets = dns_exchange() if kind == "DNS" else media_exchange(kind)
    report = analyse(correlate(packets), points_order=["A", "B"], all_packets=packets)
    estimate = report.clock_offset_estimate[("A", "B")]
    assert estimate.decalage_ms == pytest.approx(20)
    assert estimate.sources == (kind,)
    doc = build_json_report_document(report)
    assert doc["clock_offsets"][0]["sources"] == [kind]
    assert kind in doc["clock_offsets"][0]["method"]
    print_report(report)
    assert f"sources : {kind}" in capsys.readouterr().out
    imposed = analyse(
        correlate(packets), points_order=["A", "B"], all_packets=packets, clock_offsets={("A", "B"): 12.5}
    )
    assert imposed.clock_offset_estimate[("A", "B")].sources == ()
    assert build_json_report_document(imposed)["clock_offsets"][0]["sources"] == []


@pytest.mark.parametrize("payload", ["80:c8:00:01:00:00:00:07", None])
def test_parseur_rtcp_natif_empreinte_et_adaptateur(payload):
    udp = {"udp_udp_srcport": "5001", "udp_udp_dstport": "5003"}
    if payload:
        udp["udp_udp_payload"] = payload
    raw = build_packet(
        0.0,
        {
            "frame": {"frame_frame_len": "60"},
            "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},
            "udp": udp,
            "rtcp": {},
        },
    )
    expected = sha256(bytes.fromhex(payload.replace(":", ""))).hexdigest() if payload else None
    assert raw.rtcp_hash == expected
    assert not raw.is_rtp
    assert _to_pkt("A", raw).rtcp_hash == expected
