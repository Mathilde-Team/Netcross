"""
pcap_parser.packet.build_packet -- assemble un RawPacket a partir des
couches EK d'un paquet. On construit ici des dicts "layers" synthetiques
qui imitent la sortie de `tshark -T ek`, exactement comme la validation
manuelle decrite dans claude.md (Session 3 : "construction de RawPacket
synthetiques a la main... monkeypatch de pcap_parser.parse_capture")
faite faute de tshark disponible dans l'environnement de developpement.
"""

import pytest

from pcap_parser.packet import RawPacket, _intern, build_packet


def _frame(length=100, number=None):
    layer = {"frame_frame_len": str(length)}
    if number is not None:
        layer["frame_frame_number"] = str(number)
    return {"frame": layer}


def test_build_packet_tcp_simple():
    layers = {
        **_frame(60),
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
            "tcp_tcp_flags_str": "\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7S\u00b7",
        },
    }
    pkt = build_packet(1000.5, layers)
    assert pkt is not None
    assert pkt.proto == "TCP"
    assert pkt.src == "10.0.0.1" and pkt.dst == "10.0.0.2"
    assert pkt.sport == 51234 and pkt.dport == 443
    assert pkt.length == 60
    assert pkt.ttl == 64
    assert pkt.seq == 1000
    assert pkt.key_id == 1000  # cle = seq pour TCP
    assert pkt.ip_id == 0x1234
    assert pkt.payload_hash is None  # pas de payload -> pas de hash
    assert pkt.ts == 1000.5


def test_build_packet_expose_le_numero_de_trame():
    # frame.number (Session 35) -- premiere donnee source de PacketEvidence
    # (netcross_core.expert_model) : entier 1-indexe attribue par tshark,
    # extrait comme le reste des champs numeriques de la couche frame.
    layers = {
        **_frame(60, number=17),
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},
        "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.frame_number == 17


def test_build_packet_numero_de_trame_absent_reste_none():
    # Tolerance documentee (jamais observe en pratique avec un vrai
    # tshark) -- meme discipline que les autres champs optionnels de ce
    # module : absence du champ EK -> None, pas d'exception.
    layers = {
        **_frame(60),
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},
        "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.frame_number is None


def test_build_packet_tcp_seq_raw_prefere_a_seq_relatif():
    # tcp.seq (relatif au process tshark) ne doit JAMAIS etre lu -- seule
    # tcp.seq_raw (valeur sur le fil) est comparable entre points de
    # capture issus de processus tshark independants (claude.md Session 1,
    # bug trouve en croisant avec analysis.py._analyse_handshake).
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "tcp": {
            "tcp_tcp_srcport": "1",
            "tcp_tcp_dstport": "2",
            "tcp_tcp_seq": "0",  # relatif -- ne doit pas etre utilise
            "tcp_tcp_seq_raw": "999999",
            "tcp_tcp_ack_raw": "0",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.seq == 999999


def test_build_packet_udp_avec_payload_et_hash():
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "udp": {
            "udp_udp_srcport": "5000",
            "udp_udp_dstport": "5060",
            "udp_udp_payload": "de:ad:be:ef",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "UDP"
    assert pkt.payload == b"\xde\xad\xbe\xef"
    assert pkt.payload_hash is not None
    assert pkt.key_id == pkt.ip_id  # cle = ip_id pour non-TCP


def test_build_packet_icmp():
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "icmp": {
            "icmp_icmp_type": "3",
            "icmp_icmp_code": "4",
            "icmp_icmp_ident": "1",
            "icmp_icmp_seq": "2",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ICMP"
    assert pkt.icmp_type == 3
    assert pkt.icmp_code == 4


def test_build_packet_icmpv6_echo():
    # Champs verifies empiriquement contre un vrai tshark 4.2.2 (pcap
    # scapy synthetique ICMPv6EchoRequest, voir claude.md Session 22).
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "2001:db8::1", "ipv6_ipv6_dst": "2001:db8::2"},
        "icmpv6": {
            "icmpv6_icmpv6_type": "128",
            "icmpv6_icmpv6_code": "0",
            "icmpv6_icmpv6_echo_identifier": "0x1234",
            "icmpv6_icmpv6_echo_sequence_number": "1",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ICMPv6"
    assert pkt.icmpv6_type == 128
    assert pkt.icmpv6_code == 0
    # Identifiant/sequence portes par sport/dport, meme convention que
    # icmp.ident/icmp.seq cote ICMPv4 (voir test_build_packet_icmp).
    assert pkt.sport == 0x1234
    assert pkt.dport == 1
    # Champs ICMPv4 restent bien a None -- ne pas confondre les deux
    # espaces de valeurs (voir RawPacket.icmpv6_type/code).
    assert pkt.icmp_type is None
    assert pkt.icmp_code is None


def test_build_packet_icmpv6_packet_too_big_pas_de_ident_seq():
    # Type 2 (Packet Too Big, RFC 4443 S3.2) -- l'analogue IPv6 de
    # "ICMP Fragmentation Needed", moteur de la detection PMTUD IPv6
    # (voir netcross_core.analysis._analyse_pmtud). Pas de champ
    # echo.identifier/sequence_number sur ce type de message -- verifie
    # empiriquement (tshark 4.2.2) qu'ils sont absents du layer, pas
    # juste vides ; g() doit renvoyer None sans lever.
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "2001:db8::fe", "ipv6_ipv6_dst": "2001:db8::1"},
        "icmpv6": {
            "icmpv6_icmpv6_type": "2",
            "icmpv6_icmpv6_code": "0",
            "icmpv6_icmpv6_mtu": "1280",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ICMPv6"
    assert pkt.icmpv6_type == 2
    assert pkt.icmpv6_code == 0
    assert pkt.sport is None
    assert pkt.dport is None


def test_build_packet_icmpv6_neighbor_solicitation():
    # Type 135 (Neighbor Solicitation) -- juste pour verifier que
    # n'importe quel message ICMPv6 (pas seulement Echo/Packet Too Big)
    # est correctement decode en type/code, meme sans ident/seq/mtu.
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "2001:db8::1", "ipv6_ipv6_dst": "ff02::1:ff00:2"},
        "icmpv6": {
            "icmpv6_icmpv6_type": "135",
            "icmpv6_icmpv6_code": "0",
            "icmpv6_icmpv6_nd_ns_target_address": "2001:db8::2",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ICMPv6"
    assert pkt.icmpv6_type == 135
    assert pkt.icmpv6_code == 0


def test_build_packet_icmpv6_ignore_couches_imbriquees_du_message_erreur():
    # Un message d'erreur ICMPv6 (Packet Too Big, Dest Unreach, Time
    # Exceeded...) embarque le datagramme original en cause -- tshark
    # imbrique ALORS les couches "ipv6"/"udp" de ce datagramme embarque
    # SOUS la cle "icmpv6" elle-meme (verifie empiriquement, tshark
    # 4.2.2, voir claude.md Session 22), pas au meme niveau que la vraie
    # couche IPv6 externe. Ce test verifie explicitement que l'adresse
    # source/destination retenue est bien celle de l'ENVELOPPE externe
    # (le routeur qui emet l'erreur), pas celle du datagramme embarque
    # (le vrai client) -- layer()/innermost() ne recursent pas, donc pas
    # de risque de confusion, mais ce comportement merite un test dedie
    # plutot que d'etre suppose.
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "2001:db8::fe", "ipv6_ipv6_dst": "2001:db8::1"},
        "icmpv6": {
            "icmpv6_icmpv6_type": "2",
            "icmpv6_icmpv6_code": "0",
            "icmpv6_icmpv6_mtu": "1280",
            # Couches du datagramme EMBARQUE (celui qui a declenche
            # l'erreur) -- imbriquees ICI par tshark, pas au niveau
            # racine de `layers`.
            "ipv6": {
                "ipv6_ipv6_src": "2001:db8::1",
                "ipv6_ipv6_dst": "2001:db8::9",
            },
            "udp": {"udp_udp_srcport": "1234", "udp_udp_dstport": "5678"},
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ICMPv6"
    # Adresse de l'enveloppe externe (le routeur), pas du datagramme
    # embarque.
    assert pkt.src == "2001:db8::fe"
    assert pkt.dst == "2001:db8::1"


def test_build_packet_arp_requete():
    # Champs verifies empiriquement contre un vrai tshark 4.2.2 (pcap
    # scapy synthetique ARP who-has, voir claude.md Session 24).
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_src_proto_ipv4": "10.0.0.1",
            "arp_arp_dst_hw_mac": "00:00:00:00:00:00",
            "arp_arp_dst_proto_ipv4": "10.0.0.9",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ARP"
    assert pkt.src == "10.0.0.1"
    assert pkt.dst == "10.0.0.9"
    assert pkt.arp_opcode == 1
    assert pkt.arp_sender_mac == "aa:aa:aa:aa:aa:01"
    assert pkt.arp_is_gratuitous is False
    # ttl/dscp/ecn/ip_id/is_fragment/df n'ont pas de sens pour une trame
    # ARP (pas d'en-tete IP) -- doivent rester a leurs valeurs neutres.
    assert pkt.ttl is None
    assert pkt.dscp is None
    assert pkt.ecn is None
    assert pkt.ip_id is None
    assert pkt.is_fragment is False
    assert pkt.df is False
    # sport/dport ne sont PAS reutilises pour ARP (contrairement a
    # ICMP(v6) ou ils portent ident/seq) -- champs dedies arp_opcode/
    # arp_sender_mac a la place, voir RawPacket.
    assert pkt.sport is None
    assert pkt.dport is None


def test_build_packet_arp_reponse():
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "2",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:09",
            "arp_arp_src_proto_ipv4": "10.0.0.9",
            "arp_arp_dst_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_dst_proto_ipv4": "10.0.0.1",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "ARP"
    assert pkt.arp_opcode == 2
    assert pkt.src == "10.0.0.9"
    assert pkt.dst == "10.0.0.1"
    assert pkt.arp_sender_mac == "aa:aa:aa:aa:aa:09"


def test_build_packet_arp_gratuit():
    # arp.isgratuitous : classification NATIVE tshark (sender IP ==
    # target IP), lue telle quelle -- pas de comparaison src==dst
    # reimplementee ici (voir _analyse_arp_ip_conflict/build_packet).
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:02",
            "arp_arp_src_proto_ipv4": "10.0.0.2",
            "arp_arp_dst_hw_mac": "00:00:00:00:00:00",
            "arp_arp_dst_proto_ipv4": "10.0.0.2",
            "arp_arp_isgratuitous": True,
            "arp_arp_isannouncement": True,
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.arp_is_gratuitous is True


def test_build_packet_arp_isgratuitous_absent_vaut_false():
    # Verifie empiriquement (tshark 4.2.2) : arp.isgratuitous est
    # ABSENT du layer sur un ARP ordinaire (pas juste "false") -- meme
    # discipline que as_bool(None) -> False pour tout champ booleen
    # optionnel de ce module.
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_src_proto_ipv4": "10.0.0.1",
            "arp_arp_dst_proto_ipv4": "10.0.0.9",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.arp_is_gratuitous is False


def test_build_packet_stp_configuration_bpdu():
    # Champs verifies empiriquement contre un vrai tshark 4.2.2 (pcap
    # scapy synthetique construit via scapy.layers.l2.STP, disponible
    # nativement dans cette version -- voir claude.md Session 25).
    layers = {
        **_frame(),
        "eth": {"eth_eth_src": "aa:aa:aa:aa:aa:01", "eth_eth_dst": "01:80:c2:00:00:00"},
        "llc": {},
        "stp": {
            "stp_stp_type": "0x00",
            "stp_stp_flags_tc": False,
            "stp_stp_root_prio": "32768",
            "stp_stp_root_hw": "aa:aa:aa:aa:aa:01",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "STP"
    assert pkt.src == "aa:aa:aa:aa:aa:01"
    assert pkt.dst == "01:80:c2:00:00:00"
    assert pkt.stp_bpdu_type == 0
    assert pkt.stp_flags_tc is False
    assert pkt.stp_root_id == "32768/aa:aa:aa:aa:aa:01"
    # ttl/dscp/ecn n'ont pas de sens pour une trame STP (pas d'en-tete IP).
    assert pkt.ttl is None
    assert pkt.dscp is None
    assert pkt.ecn is None


def test_build_packet_stp_configuration_bpdu_avec_tc():
    layers = {
        **_frame(),
        "eth": {"eth_eth_src": "aa:aa:aa:aa:aa:01", "eth_eth_dst": "01:80:c2:00:00:00"},
        "stp": {
            "stp_stp_type": "0x00",
            "stp_stp_flags_tc": True,
            "stp_stp_root_prio": "32768",
            "stp_stp_root_hw": "aa:aa:aa:aa:aa:01",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.stp_flags_tc is True


def test_build_packet_stp_tcn():
    # Une TCN (Topology Change Notification, type 0x80) est une BPDU
    # minimale de 4 octets utiles : PAS de champs root/bridge, PAS de
    # champ flags -- verifie empiriquement absents du layer EK (pas
    # juste vides), voir docstring de build_packet/RawPacket.
    layers = {
        **_frame(),
        "eth": {"eth_eth_src": "aa:aa:aa:aa:aa:02", "eth_eth_dst": "01:80:c2:00:00:00"},
        "stp": {"stp_stp_type": "0x80"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "STP"
    assert pkt.stp_bpdu_type == 0x80
    # arp.flags.tc absent -> False (meme discipline que le reste du
    # module pour un champ booleen optionnel).
    assert pkt.stp_flags_tc is False
    # aucun champ root sur une TCN -> stp_root_id reste None.
    assert pkt.stp_root_id is None


def test_build_packet_ipv6():
    layers = {
        **_frame(),
        "ipv6": {
            "ipv6_ipv6_src": "::1",
            "ipv6_ipv6_dst": "::2",
            "ipv6_ipv6_hlim": "64",
            "ipv6_ipv6_tclass_dscp": "0",
            "ipv6_ipv6_tclass_ecn": "0",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.src == "::1" and pkt.dst == "::2"
    assert pkt.is_fragment is False
    assert pkt.ip_id is None  # pas de notion d'IP ID cote IPv6 ici


def test_build_packet_fragment_ipv6_premier_fragment():
    # Format reel observe (tshark 4.2.2, pcap scapy fragmente via
    # fragment6(), voir claude.md/FEATURES.md "Fragmentation IPv6") :
    # le PREMIER fragment porte deja l'en-tete Fragment (offset=0,
    # more=True), contrairement a l'intuition qu'on pourrait avoir que
    # seuls les fragments suivants le porteraient.
    layers = {
        **_frame(1280),
        "ipv6": {
            "ipv6_ipv6_src": "2001:db8::1",
            "ipv6_ipv6_dst": "2001:db8::2",
            "ipv6_ipv6_hlim": "64",
            "ipv6_fraghdr": {
                "ipv6_fraghdr_ipv6_fraghdr_ident": "0x711aec75",
                "ipv6_fraghdr_ipv6_fraghdr_offset": "0",
                "ipv6_fraghdr_ipv6_fraghdr_more": True,
            },
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is True
    assert pkt.ip_id == 0x711AEC75


def test_build_packet_fragment_ipv6_dernier_fragment():
    # Dernier fragment (more=False) : porte aussi l'en-tete Fragment
    # avec le MEME identifiant -- c'est ce qui permet de reconnaitre
    # que tous les fragments appartiennent au meme datagramme original
    # via (src, dst, ip_id), voir netcross_core.analysis.
    layers = {
        **_frame(592),
        "ipv6": {
            "ipv6_ipv6_src": "2001:db8::1",
            "ipv6_ipv6_dst": "2001:db8::2",
            "ipv6_ipv6_hlim": "64",
            "ipv6_fraghdr": {
                "ipv6_fraghdr_ipv6_fraghdr_ident": "0x711aec75",
                "ipv6_fraghdr_ipv6_fraghdr_offset": "308",
                "ipv6_fraghdr_ipv6_fraghdr_more": False,
            },
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is True
    assert pkt.ip_id == 0x711AEC75


def test_build_packet_ipv6_non_fragmente_pas_dip_id():
    # Un datagramme IPv6 jamais fragmente n'a par construction AUCUN
    # en-tete Fragment -- ip_id doit rester None (pas de notion d'IP ID
    # "ordinaire" cote IPv6, contrairement a IPv4), meme quand d'autres
    # champs de l'en-tete IPv6 sont presents. Cas deja couvert par
    # test_build_packet_ipv6 ci-dessus (minimal) ; ce test verifie en
    # plus que la simple absence de la cle "ipv6_fraghdr" (plutot qu'une
    # valeur vide) est bien geree sans lever d'exception.
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "::1", "ipv6_ipv6_dst": "::2"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is False
    assert pkt.ip_id is None


def test_build_packet_ipv6_fraghdr_normalise_liste():
    # Normalisation defensive liste/dict (par symetrie avec
    # layer()/innermost() ci-dessus) -- jamais observee en liste sur les
    # captures de test (RFC 8200 n'autorise qu'un seul en-tete Fragment
    # par datagramme), mais tolerance a cout nul.
    layers = {
        **_frame(),
        "ipv6": {
            "ipv6_ipv6_src": "2001:db8::1",
            "ipv6_ipv6_dst": "2001:db8::2",
            "ipv6_fraghdr": [
                {
                    "ipv6_fraghdr_ipv6_fraghdr_ident": "0x1",
                    "ipv6_fraghdr_ipv6_fraghdr_offset": "0",
                    "ipv6_fraghdr_ipv6_fraghdr_more": True,
                }
            ],
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is True
    assert pkt.ip_id == 1


def test_build_packet_sans_ip_ni_arp_ni_stp_renvoie_none():
    # LLDP/CDP/etc -- toujours hors perimetre (aucun en-tete IP, pas ARP,
    # pas STP non plus). ARP (Session 24) et STP (Session 25), eux, sont
    # desormais decodes -- voir test_build_packet_arp_*/test_build_
    # packet_stp_* plus loin, non confondus avec ce cas.
    assert build_packet(0.0, {**_frame(), "lldp": {}}) is None


def test_build_packet_fragment_ipv4():
    layers = {
        **_frame(),
        "ip": {
            "ip_ip_src": "1.1.1.1",
            "ip_ip_dst": "2.2.2.2",
            "ip_ip_id": "5",
            "ip_ip_flags_mf": "1",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is True


def test_build_packet_df_actif_ipv4():
    # format reel observe (tshark 4.2.2, voir claude.md Session 9) :
    # ip.flags.df est rendu en booleen JSON natif, pas en chaine "0"/"1"
    layers = {
        **_frame(),
        "ip": {
            "ip_ip_src": "1.1.1.1",
            "ip_ip_dst": "2.2.2.2",
            "ip_ip_id": "5",
            "ip_ip_flags_df": True,
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.df is True


def test_build_packet_df_inactif_mais_present_ipv4():
    # cas qui avait revele le bug bool("0")==True lors de l'ecriture de ce
    # test (Session 9) : le champ est present (comme c'est le cas pour tout
    # sous-champ d'un octet de flags fixe) meme quand la valeur est fausse.
    layers = {
        **_frame(),
        "ip": {
            "ip_ip_src": "1.1.1.1",
            "ip_ip_dst": "2.2.2.2",
            "ip_ip_id": "5",
            "ip_ip_flags_df": False,
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.df is False


def test_build_packet_df_tolere_une_representation_en_chaine():
    # tolerance defensive (autre version de tshark/generateur EK) --
    # voir ek_fields.as_bool
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2", "ip_ip_flags_df": "0"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.df is False


def test_build_packet_df_absent_du_layer_vaut_faux():
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.df is False


def test_build_packet_mf_inactif_mais_present_ipv4():
    # meme correction que df (as_bool plutot que bool nu) appliquee a
    # is_fragment/ip.flags.mf, deja en production -- meme bug potentiel,
    # jamais couvert par un test avant Session 9 (l'ancien
    # test_build_packet_fragment_ipv4 ne testait que le cas actif)
    layers = {
        **_frame(),
        "ip": {
            "ip_ip_src": "1.1.1.1",
            "ip_ip_dst": "2.2.2.2",
            "ip_ip_id": "5",
            "ip_ip_flags_mf": False,
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_fragment is False


def _tcp_layers(analysis_expert_key=None):
    layers = {
        **_frame(1040),
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2", "ip_ip_id": "1"},
        "tcp": {
            "tcp_tcp_srcport": "5555",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "2000",
            "tcp_tcp_ack_raw": "1",
            "tcp_tcp_window_size_value": "8192",
            "tcp_tcp_flags_str": "\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
        },
    }
    if analysis_expert_key:
        layers["tcp"]["_ws_expert"] = {analysis_expert_key: None}
    return layers


def test_build_packet_retransmission_classique_rto():
    pkt = build_packet(0.0, _tcp_layers("tcp_tcp_analysis_retransmission"))
    assert pkt.is_retransmission is True
    assert pkt.is_fast_retransmission is False
    assert pkt.is_spurious_retransmission is False


def test_build_packet_fast_retransmission():
    pkt = build_packet(0.0, _tcp_layers("tcp_tcp_analysis_fast_retransmission"))
    assert pkt.is_fast_retransmission is True
    assert pkt.is_retransmission is False


def test_build_packet_spurious_retransmission():
    pkt = build_packet(0.0, _tcp_layers("tcp_tcp_analysis_spurious_retransmission"))
    assert pkt.is_spurious_retransmission is True
    assert pkt.is_retransmission is False
    assert pkt.is_fast_retransmission is False


def test_build_packet_sans_retransmission():
    pkt = build_packet(0.0, _tcp_layers(None))
    assert pkt.is_retransmission is False
    assert pkt.is_fast_retransmission is False
    assert pkt.is_spurious_retransmission is False


def test_build_packet_expert_flags_reflete_le_flag_present():
    # Session 1 : vue brute generique, complementaire aux trois booleens
    # ci-dessus -- meme paquet, meme flag, mais expose sous sa forme
    # "liste de tous les noms" plutot qu'un seul booleen dedie.
    pkt = build_packet(0.0, _tcp_layers("tcp_tcp_analysis_retransmission"))
    assert pkt.expert_flags == ("tcp_tcp_analysis_retransmission",)


def test_build_packet_expert_flags_vide_si_aucune_expertise():
    pkt = build_packet(0.0, _tcp_layers(None))
    assert pkt.expert_flags == ()


def test_build_packet_expert_flags_plusieurs_flags_simultanes():
    # _tcp_layers() ne pose qu'un seul flag a la fois (voir sa signature
    # ci-dessus) -- ce test construit directement une couche tcp avec
    # deux conditions d'expertise simultanees, cas reel possible (ex:
    # ACK duplique ET fenetre pleine sur le meme segment).
    layers = _tcp_layers(None)
    layers["tcp"]["_ws_expert"] = {
        "tcp_tcp_analysis_duplicate_ack": None,
        "tcp_tcp_analysis_window_full": None,
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_flags == ("tcp_tcp_analysis_duplicate_ack", "tcp_tcp_analysis_window_full")


def test_build_packet_expert_flags_vide_sur_paquet_non_tcp_sans_signal():
    # Un paquet ARP (ou tout non-TCP) SANS aucun signal d'expertise sur
    # aucune de ses couches a bien expert_flags vide -- ne pas confondre
    # avec l'ancienne limite "TCP uniquement" (levee dans cette session,
    # voir test ci-dessous : un _ws_expert sur la couche ARP EST
    # desormais capte).
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_src_proto_ipv4": "10.0.0.1",
            "arp_arp_dst_hw_mac": "00:00:00:00:00:00",
            "arp_arp_dst_proto_ipv4": "10.0.0.9",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_flags == ()


def test_build_packet_expert_flags_capture_aussi_les_couches_non_tcp():
    # Limite LEVEE dans cette session (l'ancienne version de ce test,
    # avant cette session, affirmait l'inverse -- voir claude.md
    # Session 39) : expert_flags/expert_details sont desormais une union
    # sur TOUTES les couches du paquet, pas seulement TCP. Fixture
    # inspiree d'un signal reellement observe avec un vrai tshark 4.2.2
    # (checksum ARP -- ici -- ou IP invalide, meme convention de nommage
    # "<couche>_<couche>_..._expert").
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_src_proto_ipv4": "10.0.0.1",
            "arp_arp_dst_hw_mac": "00:00:00:00:00:00",
            "arp_arp_dst_proto_ipv4": "10.0.0.9",
            "_ws_expert": {"arp_arp_duplicate_address_detected": None},
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_flags == ("arp_arp_duplicate_address_detected",)


def test_build_packet_expert_flags_union_l3_et_l4_simultanement():
    # Un paquet peut porter un signal d'expertise SIMULTANEMENT sur sa
    # couche L3 (ip) et sa couche L4 (tcp) -- les deux doivent apparaitre,
    # tries ensemble (pas seulement le dernier verifie).
    layers = _tcp_layers("tcp_tcp_analysis_retransmission")
    layers["ip"] = {
        "ip_ip_src": "10.0.0.1",
        "ip_ip_dst": "10.0.0.2",
        "ip_ip_ttl": "64",
        "ip_ip_dsfield_dscp": "0",
        "ip_ip_dsfield_ecn": "0",
        "ip_ip_id": "0x1",
        "_ws_expert": {"ip_ip_checksum_bad_expert": None},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_flags == ("ip_ip_checksum_bad_expert", "tcp_tcp_analysis_retransmission")


def test_build_packet_expert_details_vide_si_aucune_expertise():
    pkt = build_packet(0.0, _tcp_layers(None))
    assert pkt.expert_details == ()


def test_build_packet_expert_details_severite_groupe_message_natifs():
    # Fixture EXACTE observee avec un vrai tshark 4.2.2 (voir claude.md
    # Session 39) -- meme paquet que test_build_packet_retransmission_
    # classique_rto, mais avec severite/groupe/message natifs en plus du
    # seul nom de condition.
    layers = _tcp_layers(None)
    layers["tcp"]["_ws_expert"] = {
        "tcp_tcp_analysis_retransmission": None,
        "_ws_expert__ws_expert_severity": "4194304",
        "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
        "_ws_expert__ws_expert_group": "33554432",
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_details == (
        (
            "tcp_tcp_analysis_retransmission",
            "Note",
            "Sequence",
            "This frame is a (suspected) retransmission",
        ),
    )


def test_build_packet_expert_details_code_severite_inconnu_repli_brut():
    layers = _tcp_layers(None)
    layers["tcp"]["_ws_expert"] = {
        "tcp_tcp_analysis_retransmission": None,
        "_ws_expert__ws_expert_severity": "123456",
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_details == (("tcp_tcp_analysis_retransmission", "123456", None, None),)


def test_build_packet_expert_details_plusieurs_occurrences_independantes():
    # Fixture EXACTE observee avec un vrai tshark 4.2.2 (checksum TCP
    # invalide ET retransmission simultanes, voir claude.md Session 39).
    layers = _tcp_layers(None)
    layers["tcp"]["_ws_expert"] = [
        {
            "tcp_tcp_checksum_bad_expert": None,
            "_ws_expert__ws_expert_severity": "8388608",
            "_ws_expert__ws_expert_message": "Bad checksum [should be 0x8cfa]",
            "_ws_expert__ws_expert_group": "16777216",
        },
        {
            "tcp_tcp_analysis_retransmission": None,
            "_ws_expert__ws_expert_severity": "4194304",
            "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
            "_ws_expert__ws_expert_group": "33554432",
        },
    ]
    pkt = build_packet(0.0, layers)
    assert pkt.expert_details == (
        ("tcp_tcp_analysis_retransmission", "Note", "Sequence", "This frame is a (suspected) retransmission"),
        ("tcp_tcp_checksum_bad_expert", "Error", "Checksum", "Bad checksum [should be 0x8cfa]"),
    )


def test_build_packet_expert_details_capture_aussi_les_couches_non_tcp():
    # Codes severite/groupe reels (memes tables verifiees "tshark -G
    # values" que les autres tests de ce fichier), mais scenario ARP lui-
    # meme illustratif -- seul le mecanisme (capture sur une couche non-
    # TCP) est verifie ici, pas la classification specifique de ce flag
    # precis par tshark (non declenchee empiriquement dans cette session,
    # contrairement aux fixtures "EXACTE observee" ci-dessus).
    layers = {
        **_frame(),
        "arp": {
            "arp_arp_opcode": "1",
            "arp_arp_src_hw_mac": "aa:aa:aa:aa:aa:01",
            "arp_arp_src_proto_ipv4": "10.0.0.1",
            "arp_arp_dst_hw_mac": "00:00:00:00:00:00",
            "arp_arp_dst_proto_ipv4": "10.0.0.9",
            "_ws_expert": {
                "arp_arp_duplicate_address_detected": None,
                "_ws_expert__ws_expert_severity": "6291456",
                "_ws_expert__ws_expert_message": "Duplicate IP address configured",
                "_ws_expert__ws_expert_group": "50331648",
            },
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.expert_details == (
        ("arp_arp_duplicate_address_detected", "Warning", "Response", "Duplicate IP address configured"),
    )


def _syn_layers(mss=None, wscale=None, sack_perm=False, flags_str="\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7S\u00b7"):
    tcp = {
        "tcp_tcp_srcport": "5555",
        "tcp_tcp_dstport": "443",
        "tcp_tcp_seq_raw": "1000",
        "tcp_tcp_flags_str": flags_str,
    }
    if mss is not None:
        tcp["tcp_tcp_options_mss_val"] = str(mss)
    if wscale is not None:
        tcp["tcp_tcp_options_wscale_shift"] = str(wscale)
    if sack_perm:
        tcp["tcp_options_sack_perm"] = "04:02"
    layers = {
        **_frame(60),
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2", "ip_ip_id": "1"},
        "tcp": tcp,
    }
    return layers


def test_build_packet_options_syn_completes():
    pkt = build_packet(0.0, _syn_layers(mss=1460, wscale=7, sack_perm=True))
    assert pkt.mss_val == 1460
    assert pkt.wscale_shift == 7
    assert pkt.sack_permitted is True


def test_build_packet_options_syn_sans_wscale_ni_sack():
    pkt = build_packet(0.0, _syn_layers(mss=1460))
    assert pkt.mss_val == 1460
    assert pkt.wscale_shift is None
    assert pkt.sack_permitted is False


def test_build_packet_options_absentes_hors_handshake():
    layers = {
        **_frame(60),
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2", "ip_ip_id": "1"},
        "tcp": {
            "tcp_tcp_srcport": "5555",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "1000",
            "tcp_tcp_flags_str": "\u00b7\u00b7\u00b7A\u00b7\u00b7\u00b7\u00b7",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.mss_val is None
    assert pkt.wscale_shift is None
    assert pkt.sack_permitted is False


def test_build_packet_ipv6_df_toujours_faux():
    # pas de bit DF cote IPv6 -- voir commentaire dans build_packet()
    layers = {
        **_frame(),
        "ipv6": {"ipv6_ipv6_src": "::1", "ipv6_ipv6_dst": "::2"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.df is False


def test_build_packet_vlan_tag_externe():
    layers = {
        **_frame(),
        "vlan": [{"vlan_vlan_id": "100", "vlan_vlan_priority": "3"}, {"vlan_vlan_id": "200"}],
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
    }
    pkt = build_packet(0.0, layers)
    # le tag EXTERNE (premiere occurrence), pas le plus interne -- c'est
    # ce que verrait un equipement intermediaire qui ne depile pas le tag.
    assert pkt.vlan_id == 100
    assert pkt.vlan_prio == 3


def test_build_packet_tunnel_gre_prend_l_ip_la_plus_interne():
    layers = {
        **_frame(),
        "gre": {},
        "ip": [
            {"ip_ip_src": "192.0.2.1", "ip_ip_dst": "192.0.2.2"},  # tunnel
            {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},  # vrai client
        ],
        "tcp": [
            {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2", "tcp_tcp_seq_raw": "0"},
            {"tcp_tcp_srcport": "51234", "tcp_tcp_dstport": "443", "tcp_tcp_seq_raw": "42"},
        ],
    }
    pkt = build_packet(0.0, layers)
    assert pkt.src == "10.0.0.1" and pkt.dst == "10.0.0.2"
    assert pkt.sport == 51234
    assert pkt.encap_tags == ("GRE",)


def test_build_packet_udp_rtp_heuristique_bout_en_bout():
    import struct

    rtp_bytes = struct.pack("!BBHII", 0x80, 0, 100, 90000, 0xAABBCCDD) + b"\x00" * 20
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "udp": {
            "udp_udp_srcport": "10000",
            "udp_udp_dstport": "10002",
            "udp_udp_payload": rtp_bytes.hex(":"),
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.is_rtp is True
    assert pkt.rtp_seq == 100
    assert pkt.rtp_ssrc == 0xAABBCCDD


def test_build_packet_udp_dhcp():
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "0.0.0.0", "ip_ip_dst": "255.255.255.255"},
        "udp": {"udp_udp_srcport": "68", "udp_udp_dstport": "67"},
        "dhcp": {"dhcp_dhcp_type": "1", "dhcp_dhcp_id": "0x1"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.dhcp_msg_type == "discover"
    assert pkt.dhcp_xid == 1


def _ip_layer(src="10.0.0.5", dst="8.8.8.8"):
    return {"ip_ip_src": src, "ip_ip_dst": dst, "ip_ip_ttl": "64", "ip_ip_dsfield_dscp": "0", "ip_ip_dsfield_ecn": "0"}


def test_build_packet_udp_dns_requete():
    layers = {
        **_frame(),
        "ip": _ip_layer(),
        "udp": {"udp_udp_srcport": "54321", "udp_udp_dstport": "53"},
        "dns": {
            "dns_dns_id": "0xabcd",
            "dns_dns_flags_response": False,
            "dns_dns_qry_name": "example.com",
            "dns_dns_flags_rcode": "0",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "UDP"
    assert pkt.dns_txn_id == 0xABCD
    assert pkt.dns_is_response is False
    assert pkt.dns_qry_name == "example.com"
    assert pkt.dns_rcode == 0


def test_build_packet_tcp_dns_reponse():
    # DNS peut aussi circuler sur TCP (transfert de zone, reponse
    # tronquee) -- extract_dns n'est pas limite au bloc UDP.
    layers = {
        **_frame(),
        "ip": _ip_layer(),
        "tcp": {
            "tcp_tcp_srcport": "53",
            "tcp_tcp_dstport": "54322",
            "tcp_tcp_seq_raw": "1",
            "tcp_tcp_ack_raw": "1",
            "tcp_tcp_window_size_value": "1000",
            "tcp_tcp_flags_str": ".......",
        },
        "dns": {
            "dns_dns_id": "0x1",
            "dns_dns_flags_response": True,
            "dns_dns_qry_name": "zone.example.",
            "dns_dns_flags_rcode": "2",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "TCP"
    assert pkt.dns_txn_id == 1
    assert pkt.dns_is_response is True
    assert pkt.dns_rcode == 2


def test_build_packet_sans_dns_champs_a_none():
    layers = {
        **_frame(),
        "ip": _ip_layer(dst="10.0.0.2"),
        "tcp": {
            "tcp_tcp_srcport": "1",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "1",
            "tcp_tcp_ack_raw": "0",
            "tcp_tcp_window_size_value": "1000",
            "tcp_tcp_flags_str": ".......S.",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.dns_txn_id is None
    assert pkt.dns_is_response is False
    assert pkt.dns_qry_name is None
    assert pkt.dns_rcode is None
    assert pkt.http_is_request is False
    assert pkt.http_is_response is False
    assert pkt.http_method is None
    assert pkt.http_uri is None
    assert pkt.http_status_code is None
    assert pkt.http_response_time_ms is None


def _tcp_http_layer(sport, dport):
    return {
        "tcp_tcp_srcport": str(sport),
        "tcp_tcp_dstport": str(dport),
        "tcp_tcp_seq_raw": "1",
        "tcp_tcp_ack_raw": "1",
        "tcp_tcp_window_size_value": "65535",
        "tcp_tcp_flags_str": ".......",
    }


def test_build_packet_tcp_http_requete():
    layers = {
        **_frame(),
        "ip": _ip_layer(dst="127.0.0.1"),
        "tcp": _tcp_http_layer(54321, 8080),
        "http": {
            "http_http_request": True,
            "http_http_request_method": "GET",
            "http_http_request_uri": "/",
            "http_http_request_full_uri": "http://127.0.0.1:8080/",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "TCP"
    assert pkt.http_is_request is True
    assert pkt.http_is_response is False
    assert pkt.http_method == "GET"
    assert pkt.http_uri == "http://127.0.0.1:8080/"
    assert pkt.http_status_code is None
    assert pkt.http_response_time_ms is None


def test_build_packet_tcp_http_reponse():
    layers = {
        **_frame(),
        "ip": _ip_layer(src="127.0.0.1", dst="10.0.0.5"),
        "tcp": _tcp_http_layer(8080, 54321),
        "http": {
            "http_http_response": True,
            "http_http_response_code": "500",
            "http_http_response_for_uri": "http://127.0.0.1:8080/error",
            "http_http_time": "0.000182044",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.http_is_request is False
    assert pkt.http_is_response is True
    assert pkt.http_method is None
    assert pkt.http_uri == "http://127.0.0.1:8080/error"
    assert pkt.http_status_code == 500
    assert pkt.http_response_time_ms == pytest.approx(0.182044)


def test_build_packet_http_ignore_sur_udp():
    # HTTP/1.x est TCP uniquement (voir extract_http/build_packet) : HTTP/3
    # est QUIC sur UDP, deja couvert separement par quic_diagnostics -- une
    # couche "http" presente aux cotes d'UDP ne doit jamais etre lue ici,
    # meme si elle existait dans le paquet (ne devrait pas arriver en
    # pratique avec un vrai tshark, teste par prudence contre une
    # regression du gating "if proto == 'TCP'").
    layers = {
        **_frame(),
        "ip": _ip_layer(),
        "udp": {"udp_udp_srcport": "12345", "udp_udp_dstport": "80"},
        "http": {"http_http_request": True, "http_http_request_method": "GET"},
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "UDP"
    assert pkt.http_is_request is False
    assert pkt.http_method is None


def test_build_packet_tls_certificate():
    # Champs verifies empiriquement contre un vrai tshark 4.2.2 (capture
    # TLS 1.2 reelle sur loopback -- serveur+client locaux openssl, voir
    # claude.md Session 26).
    layers = {
        **_frame(),
        "ip": _ip_layer(src="127.0.0.1", dst="127.0.0.1"),
        "tcp": _tcp_http_layer(44332, 54321),
        "tls": {
            "x509af_x509af_utcTime": ["2026-08-31 18:46:38 (UTC)", "2027-08-31 18:46:38 (UTC)"],
            "x509ce_x509ce_dNSName": ["test.transcende.fr", "alt.transcende.fr"],
            "x509af_x509af_serialNumber": "38:f5:42:4e:fc:8e:44:c1:50:f9:3c:d4:21:ed:90:60:b9:df:5c:f6",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "TCP"
    assert pkt.tls_cert_not_before == "2026-08-31 18:46:38 (UTC)"
    assert pkt.tls_cert_not_after == "2027-08-31 18:46:38 (UTC)"
    assert pkt.tls_cert_san == ("test.transcende.fr", "alt.transcende.fr")
    assert pkt.tls_cert_serial == "38:f5:42:4e:fc:8e:44:c1:50:f9:3c:d4:21:ed:90:60:b9:df:5c:f6"


def test_build_packet_tls_sans_certificat_champs_neutres():
    # Paquet TCP ordinaire (ClientHello, Application Data...) : aucun
    # certificat present -- les 4 champs restent a None, comme n'importe
    # quel paquet TCP sans lien avec TLS.
    layers = {
        **_frame(),
        "ip": _ip_layer(src="127.0.0.1", dst="127.0.0.1"),
        "tcp": _tcp_http_layer(44332, 54321),
    }
    pkt = build_packet(0.0, layers)
    assert pkt.tls_cert_not_before is None
    assert pkt.tls_cert_not_after is None
    assert pkt.tls_cert_san is None
    assert pkt.tls_cert_serial is None


def test_build_packet_tls_ignore_sur_udp():
    # Comme HTTP ci-dessus : TLS est TCP uniquement (QUIC/TLS-sur-UDP
    # deja couvert separement par quic_diagnostics) -- gating "if proto
    # == 'TCP'" teste par prudence.
    layers = {
        **_frame(),
        "ip": _ip_layer(),
        "udp": {"udp_udp_srcport": "12345", "udp_udp_dstport": "443"},
        "tls": {
            "x509af_x509af_utcTime": ["2026-01-01 00:00:00 (UTC)", "2027-01-01 00:00:00 (UTC)"],
            "x509af_x509af_serialNumber": "01:02:03",
        },
    }
    pkt = build_packet(0.0, layers)
    assert pkt.proto == "UDP"
    assert pkt.tls_cert_serial is None


def test_raw_packet_utilise_des_slots():
    # Piste "gestion memoire des grosses captures" (voir FEATURES.md/
    # claude.md) : RawPacket ne doit plus avoir de __dict__ par instance
    # (mesure empiriquement comme le principal poste de cout memoire par
    # paquet sur ce projet, cf. claude.md). Un attribut hors __slots__
    # doit lever AttributeError, pas etre silencieusement accepte.
    layers = {
        "frame": {"frame_frame_len": "60"},
        "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2", "ip_ip_ttl": "64"},
        "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2"},
    }
    pkt = build_packet(0.0, layers)
    assert not hasattr(pkt, "__dict__")
    with pytest.raises(AttributeError):
        pkt.champ_inexistant = 1


def test_intern_reutilise_le_meme_objet_str():
    import json

    # json.loads (comme la vraie lecture NDJSON de tshark) produit un
    # nouvel objet str a chaque appel, meme pour une valeur textuelle
    # identique -- contrairement a une concaneation de litteraux, que
    # CPython replierait a la compilation en un seul objet partage (piege
    # constate en ecrivant ce test, voir claude.md).
    a = json.loads('{"v": "10.0.0.1"}')["v"]
    b = json.loads('{"v": "10.0.0.1"}')["v"]
    assert a is not b  # verifie que le test isole bien deux objets distincts
    assert _intern(a) is _intern(b)


def test_intern_tolere_none():
    assert _intern(None) is None


def test_build_packet_interne_src_dst():
    # Deux paquets avec la meme IP source/destination doivent partager le
    # meme objet str en memoire une fois passes par build_packet -- c'est
    # ce qui evite la duplication observee empiriquement avec un vrai
    # tshark (chaque ligne NDJSON decodee independamment produit sinon un
    # nouvel objet str pour la meme valeur textuelle, voir claude.md).
    def make():
        return {
            "frame": {"frame_frame_len": "60"},
            "ip": {"ip_ip_src": "10.0.0.1"[:], "ip_ip_dst": "10.0.0.2"[:], "ip_ip_ttl": "64"},
            "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2"},
        }

    p1 = build_packet(0.0, make())
    p2 = build_packet(1.0, make())
    assert p1.src is p2.src
    assert p1.dst is p2.dst


def test_raw_packet_champs_attendus_dans_slots():
    # Garde-fou : si un champ est ajoute a la dataclass sans etre ajoute a
    # __slots__, l'instanciation plante immediatement (dataclass genere un
    # __init__ qui assigne tous les champs) -- ce test documente juste
    # l'attendu (mêmes noms des deux cotes) pour qu'une revue de code
    # future n'ait pas a le reverifier a la main.
    field_names = set(RawPacket.__dataclass_fields__)
    assert field_names == set(RawPacket.__slots__)


def test_build_packet_sip_porte_les_points_media_sdp():
    """Issue #1120 : le SDP d'un message SIP est reporte dans sip_sdp_media,
    puis recopie sur Pkt par parsing._to_pkt."""
    from netcross_core.parsing import _to_pkt

    sip = (
        b"INVITE sip:bob@example.org SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 40000 RTP/AVP 0\r\n"
    )
    layers = {
        **_frame(),
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "udp": {
            "udp_udp_srcport": "5060",
            "udp_udp_dstport": "5060",
            "udp_udp_payload": sip.hex(":"),
        },
    }
    raw = build_packet(0.0, layers)
    assert raw.sip_call_id == "abc"
    assert raw.sip_sdp_media == (("1.1.1.1", 40000),)
    assert _to_pkt("A", raw).sip_sdp_media == (("1.1.1.1", 40000),)
