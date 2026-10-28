# SPDX-License-Identifier: GPL-3.0-or-later
"""
Commentaires pcapng (Job 39, issue #159) -- paquets ET section.

Cote pcap_parser : build_packet extrait le commentaire de PAQUET de la
pseudo-couche EK "pkt_comment" (emplacement contre-intuitif verifie
empiriquement sur tshark 4.2.2, voir la docstring de RawPacket.comment) ;
un paquet sans cette pseudo-couche (pcap classique, ou pcapng non commente
sur CE paquet) donne comment=None sans erreur. Cote netcross_core :
_to_pkt propage le champ a Pkt, analyse() pre-formate
Report.packet_comments ("point — trame N : texte") et print_report affiche
la section dediee. La lecture du commentaire de SECTION par capinfos est
couverte par tests/test_capinfos_source.py ; ici, read_capture_comments
n'est teste que sur le cablage du label (monkeypatch du module appele,
jamais un vrai binaire capinfos).
"""

from conftest import make_pkt

import netcross_core.parsing as parsing_mod
from netcross_core import analyse, correlate, read_capture_comments
from netcross_core.report_text import print_report
from pcap_parser.packet import build_packet


def _ip_layers(**extra):
    layers = {
        "frame": {"frame_frame_len": "60", "frame_frame_number": "7"},
        "ip": {
            "ip_ip_src": "10.0.0.1",
            "ip_ip_dst": "10.0.0.2",
            "ip_ip_ttl": "64",
            "ip_ip_dsfield_dscp": "0",
            "ip_ip_dsfield_ecn": "0",
            "ip_ip_id": "0x1234",
        },
        "tcp": {
            "tcp_tcp_srcport": "51234",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "1000",
            "tcp_tcp_ack_raw": "0",
            "tcp_tcp_window_size_value": "65535",
            "tcp_tcp_flags_str": "········S·",
        },
    }
    layers.update(extra)
    return layers


# -- build_packet : extraction du commentaire de paquet -------------------


def test_build_packet_extrait_le_commentaire_de_pkt_comment():
    # "pkt_comment" : pseudo-couche TOP-LEVEL dediee (PAS sous "frame"),
    # champ unique "frame_frame_comment" -- voir RawPacket.comment.
    layers = _ip_layers(pkt_comment={"frame_frame_comment": "paquet suspect"})
    pkt = build_packet(1.0, layers)
    assert pkt is not None
    assert pkt.comment == "paquet suspect"


def test_build_packet_sans_pkt_comment_donne_comment_none():
    # pcap classique ou pcapng non commente sur ce paquet : la pseudo-couche
    # est entierement ABSENTE des layers (pas presente avec valeur vide).
    pkt = build_packet(1.0, _ip_layers())
    assert pkt is not None
    assert pkt.comment is None


def test_to_pkt_propage_le_commentaire_vers_pkt():
    raw = build_packet(1.0, _ip_layers(pkt_comment={"frame_frame_comment": "retransmission"}))
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert pkt.comment == "retransmission"


def test_parse_captures_parallel_n_echoue_pas_sur_paquet_sans_commentaire():
    # garde anti-regression : la nouvelle extraction ne doit rien casser au
    # parcours normal (paquet sans pseudo-couche pkt_comment).
    pkt = parsing_mod._to_pkt("LAN", build_packet(1.0, _ip_layers()))
    assert pkt.comment is None


# -- read_capture_comments : cablage du label ----------------------------


def test_read_capture_comments_attache_le_label(monkeypatch):
    monkeypatch.setattr(parsing_mod, "read_capture_comment", lambda path: f"commentaire de {path}")
    assert read_capture_comments([("LAN", "a.pcapng"), ("WAN", "b.pcapng")]) == [
        "LAN : commentaire de a.pcapng",
        "WAN : commentaire de b.pcapng",
    ]


def test_read_capture_comments_ignore_les_fichiers_sans_commentaire(monkeypatch):
    monkeypatch.setattr(parsing_mod, "read_capture_comment", lambda path: None)
    assert read_capture_comments([("LAN", "a.pcap")]) == []


# -- analyse() : Report.packet_comments -----------------------------------


def _analyse(pkts, **kwargs):
    flows = correlate(pkts)
    return analyse(flows, points_order=["A", "B"], all_packets=pkts, **kwargs)


def test_analyse_pre_formate_les_commentaires_de_paquets():
    pkts = [
        make_pkt(point="A", sport=1, frame_number=7, comment="debut de session"),
        make_pkt(point="B", sport=2, frame_number=8, comment=None),
        make_pkt(point="A", sport=3, frame_number=9, comment="retransmission vue"),
    ]
    r = _analyse(pkts)
    assert r.packet_comments == [
        "A — trame 7 : debut de session",
        "A — trame 9 : retransmission vue",
    ]


def test_analyse_sans_commentaire_donne_une_liste_vide():
    r = _analyse([make_pkt(point="A", sport=1), make_pkt(point="B", sport=2)])
    assert r.packet_comments == []


def test_analyse_exclut_les_commentaires_des_doublons_exclus():
    # meme coherence que le reste du rapport : un paquet retire de tous les
    # compteurs par exclude_duplicates n'apparait pas dans les commentaires.
    dup = make_pkt(point="A", sport=4, frame_number=11, comment="vu au miroir")
    dup.is_duplicate = True
    pkts = [make_pkt(point="A", sport=1, frame_number=7, comment="ok"), dup, make_pkt(point="B", sport=2)]
    r = _analyse(pkts, exclude_duplicates=True, duplicate_counts={("A", "B"): 1})
    assert r.packet_comments == ["A — trame 7 : ok"]


# -- print_report : section dediee ----------------------------------------


def test_print_report_affiche_la_section_commentaires(capsys):
    pkts = [make_pkt(point="A", sport=1, frame_number=7, comment="anomalie ici")]
    r = _analyse(pkts)
    r.capture_comments = ["LAN : capture de test"]
    print_report(r)
    out = capsys.readouterr().out
    assert "-- Commentaires pcapng --" in out
    assert "[section] LAN : capture de test" in out
    assert "[paquet] A — trame 7 : anomalie ici" in out


def test_print_report_sans_commentaire_ne_modifie_pas_la_sortie(capsys):
    r = _analyse([make_pkt(point="A", sport=1), make_pkt(point="B", sport=2)])
    print_report(r)
    out = capsys.readouterr().out
    assert "Commentaires pcapng" not in out
