# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.redact -- anonymisation des adresses IP/MAC (--redact).

Couvre les generateurs de pseudonymes purs (bornes de debordement
IPv4 comprises), la classification adresse (IP v4/v6, MAC), le
comportement d'AddressRedactor (mapping deterministe/partage, cas STP
ou src/dst portent une MAC et non une IP, champs MAC secondaires
arp_sender_mac/stp_root_id, robustesse aux champs absents/malformes),
et l'export CSV du mapping (--redact-map).
"""

import csv

from conftest import make_pkt

from netcross_core.redact import (
    AddressRedactor,
    _ip_kind,
    _ipv4_pseudonym,
    _ipv6_pseudonym,
    _is_mac,
    _mac_pseudonym,
    redact_packets,
    write_redaction_map_csv,
)

# ---------------------------------------------------------------------
# Generateurs de pseudonymes -- fonctions pures
# ---------------------------------------------------------------------


def test_ipv4_pseudonym_premier_bloc_rfc5737():
    assert _ipv4_pseudonym(0) == "192.0.2.1"
    assert _ipv4_pseudonym(253) == "192.0.2.254"


def test_ipv4_pseudonym_bascule_sur_le_bloc_suivant():
    assert _ipv4_pseudonym(254) == "198.51.100.1"
    assert _ipv4_pseudonym(507) == "198.51.100.254"
    assert _ipv4_pseudonym(508) == "203.0.113.1"
    assert _ipv4_pseudonym(761) == "203.0.113.254"


def test_ipv4_pseudonym_deborde_sur_240_0_0_0_4_au_dela_de_762():
    assert _ipv4_pseudonym(762) == "240.0.0.0"
    assert _ipv4_pseudonym(763) == "240.0.0.1"


def test_ipv4_pseudonym_jamais_de_octet_0_ou_255_dans_un_bloc_doc():
    for i in range(0, 762):
        octet = int(_ipv4_pseudonym(i).rsplit(".", 1)[1])
        assert 1 <= octet <= 254


def test_ipv6_pseudonym_prefixe_documentation():
    assert _ipv6_pseudonym(0) == "2001:db8::1"
    assert _ipv6_pseudonym(255) == "2001:db8::100"


def test_mac_pseudonym_prefixe_localement_administre():
    assert _mac_pseudonym(0) == "02:00:00:00:00:00"
    assert _mac_pseudonym(1) == "02:00:00:00:00:01"
    assert _mac_pseudonym(256) == "02:00:00:00:01:00"


# ---------------------------------------------------------------------
# Classification -- _ip_kind / _is_mac
# ---------------------------------------------------------------------


def test_ip_kind_ipv4():
    assert _ip_kind("10.0.0.5") == "ipv4"


def test_ip_kind_ipv6():
    assert _ip_kind("fe80::1") == "ipv6"


def test_ip_kind_invalide_renvoie_none():
    assert _ip_kind("pas-une-ip") is None
    assert _ip_kind("00:11:22:33:44:55") is None  # une MAC n'est pas une IP


def test_is_mac_valide():
    assert _is_mac("00:11:22:33:44:55") is True
    assert _is_mac("AA:BB:CC:DD:EE:FF") is True


def test_is_mac_invalide():
    assert _is_mac("10.0.0.5") is False
    assert _is_mac("pas-une-mac") is False
    assert _is_mac("00:11:22:33:44") is False  # trop court


# ---------------------------------------------------------------------
# AddressRedactor -- cas courant IP (src/dst)
# ---------------------------------------------------------------------


def test_redact_ipv4_src_dst():
    pk = make_pkt(src="10.0.0.5", dst="10.0.0.10")
    redactor = redact_packets([pk])
    assert pk.src == "192.0.2.1"
    assert pk.dst == "192.0.2.2"
    assert redactor.mapping == {"10.0.0.5": "192.0.2.1", "10.0.0.10": "192.0.2.2"}


def test_redact_meme_adresse_toujours_le_meme_pseudonyme():
    pk1 = make_pkt(point="LAN", src="10.0.0.5", dst="10.0.0.10")
    pk2 = make_pkt(point="WAN", src="10.0.0.10", dst="10.0.0.5")
    redactor = redact_packets([pk1, pk2])
    assert pk1.src == pk2.dst
    assert pk1.dst == pk2.src
    assert len(redactor) == 2  # 2 adresses distinctes, pas 4


def test_redact_ipv6_et_ipv4_ont_des_compteurs_independants():
    pk = make_pkt(src="10.0.0.5", dst="2001:db8::abcd")
    redact_packets([pk])
    assert pk.src == "192.0.2.1"  # index 0 du pool IPv4
    assert pk.dst == "2001:db8::1"  # index 0 du pool IPv6, pas "partage" avec IPv4


def test_redact_ne_touche_pas_aux_champs_non_adresses():
    pk = make_pkt(src="10.0.0.5", dst="10.0.0.10", sport=1234, dport=443, flags=".......")
    redact_packets([pk])
    assert pk.sport == 1234
    assert pk.dport == 443
    assert pk.flags == "......."


def test_redact_tolere_src_dst_none():
    # ARP/STP peuvent laisser certains champs a None selon le cas -- ne
    # doit jamais lever, meme si src/dst ne le sont normalement jamais
    # en pratique (voir pcap_parser.packet).
    pk = make_pkt(src=None, dst=None)
    redact_packets([pk])  # ne doit pas lever
    assert pk.src is None
    assert pk.dst is None


# ---------------------------------------------------------------------
# AddressRedactor -- cas STP (src/dst = MAC, pas IP)
# ---------------------------------------------------------------------


def test_redact_stp_src_dst_traites_comme_des_mac():
    pk = make_pkt(proto="STP", src="00:11:22:33:44:55", dst="01:80:c2:00:00:00")
    redact_packets([pk])
    assert pk.src == "02:00:00:00:00:00"
    assert pk.dst == "02:00:00:00:00:01"


def test_redact_stp_mac_coherente_avec_arp_sender_mac_ailleurs():
    # La meme adresse MAC physique vue une fois comme src/dst STP et une
    # fois comme emetteur ARP doit obtenir le MEME pseudonyme -- mapping
    # partage independant du champ d'origine.
    pk_stp = make_pkt(proto="STP", src="00:11:22:33:44:55", dst="01:80:c2:00:00:00")
    pk_arp = make_pkt(proto="ARP", src="10.0.0.5", dst="10.0.0.6", arp_sender_mac="00:11:22:33:44:55")
    redact_packets([pk_stp, pk_arp])
    assert pk_stp.src == pk_arp.arp_sender_mac


# ---------------------------------------------------------------------
# AddressRedactor -- champs secondaires (arp_sender_mac, dhcp_server_id,
# stp_root_id)
# ---------------------------------------------------------------------


def test_redact_arp_sender_mac():
    pk = make_pkt(proto="ARP", src="10.0.0.5", dst="10.0.0.6", arp_sender_mac="aa:bb:cc:dd:ee:ff")
    redact_packets([pk])
    assert pk.arp_sender_mac == "02:00:00:00:00:00"


def test_redact_dhcp_server_id():
    pk = make_pkt(proto="UDP", src="10.0.0.50", dst="255.255.255.255", dhcp_server_id="10.0.0.1")
    redactor = redact_packets([pk])
    assert pk.dhcp_server_id in redactor.mapping.values()
    assert pk.dhcp_server_id != "10.0.0.1"


def test_redact_stp_root_id_priorite_preservee_mac_redigee():
    pk = make_pkt(proto="STP", src="00:11:22:33:44:55", dst="01:80:c2:00:00:00", stp_root_id="32768/aa:bb:cc:dd:ee:ff")
    redact_packets([pk])
    prio, _, mac = pk.stp_root_id.partition("/")
    assert prio == "32768"
    assert _is_mac(mac)
    assert mac != "aa:bb:cc:dd:ee:ff"


def test_redact_stp_root_id_none_ne_leve_pas():
    pk = make_pkt(proto="STP", src="00:11:22:33:44:55", dst="01:80:c2:00:00:00", stp_root_id=None)
    redact_packets([pk])  # TCN : pas de root_id -- ne doit pas lever
    assert pk.stp_root_id is None


# ---------------------------------------------------------------------
# AddressRedactor -- reutilisation du meme redacteur sur plusieurs
# appels a .redact() (cas cross_capture_diff_cli.py : baseline puis
# courant doivent partager le meme mapping)
# ---------------------------------------------------------------------


def test_redactor_reutilise_partage_le_mapping_entre_deux_appels():
    redactor = AddressRedactor()
    baseline = [make_pkt(src="10.0.0.5", dst="10.0.0.10")]
    current = [make_pkt(src="10.0.0.10", dst="10.0.0.5")]
    redactor.redact(baseline)
    redactor.redact(current)
    assert baseline[0].src == current[0].dst
    assert baseline[0].dst == current[0].src
    assert len(redactor) == 2


def test_redactor_nouvelle_adresse_au_2e_appel_prolonge_le_meme_compteur():
    redactor = AddressRedactor()
    redactor.redact([make_pkt(src="10.0.0.5", dst="10.0.0.10")])
    redactor.redact([make_pkt(src="10.0.0.99", dst="10.0.0.5")])
    # 10.0.0.5 (deja vue) reutilise son pseudonyme, 10.0.0.99 en obtient un nouveau
    assert len(redactor) == 3
    assert redactor.mapping["10.0.0.5"] == "192.0.2.1"
    assert redactor.mapping["10.0.0.99"] == "192.0.2.3"


# ---------------------------------------------------------------------
# entries() / mapping -- format d'export
# ---------------------------------------------------------------------


def test_entries_triees_par_type_puis_pseudonyme():
    redactor = AddressRedactor()
    redactor.redact(
        [
            make_pkt(proto="ARP", src="10.0.0.5", dst="10.0.0.6", arp_sender_mac="aa:bb:cc:dd:ee:ff"),
            make_pkt(src="2001:db8:1234::1", dst="10.0.0.99"),
        ]
    )
    entries = redactor.entries()
    kinds = [k for _addr, _pseudo, k in entries]
    assert kinds == sorted(kinds)


# ---------------------------------------------------------------------
# write_redaction_map_csv
# ---------------------------------------------------------------------


def test_write_redaction_map_csv(tmp_path):
    redactor = AddressRedactor()
    redactor.redact([make_pkt(src="10.0.0.5", dst="10.0.0.10")])
    out = tmp_path / "redact_map.csv"
    write_redaction_map_csv(redactor, str(out))
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["adresse_reelle", "pseudonyme", "type"]
    assert len(rows) == 3  # entete + 2 adresses
    real_addresses = {row[0] for row in rows[1:]}
    assert real_addresses == {"10.0.0.5", "10.0.0.10"}
    for row in rows[1:]:
        assert row[2] == "ipv4"


# ---------------------------------------------------------------------
# Compatibilite RawPacket (duck typing, pas d'isinstance -- voir
# docstring de module)
# ---------------------------------------------------------------------


def test_redact_fonctionne_sur_un_raw_packet_pas_seulement_pkt():
    from pcap_parser.packet import RawPacket

    raw = RawPacket(
        ts=0.0,
        frame_number=None,
        proto="TCP",
        src="10.0.0.5",
        dst="10.0.0.10",
        sport=1234,
        dport=443,
        length=100,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=1000,
        ack=0,
        window=65535,
        flags=".......",
        key_id=1000,
        payload_hash=None,
        payload=b"",
        ip_id=1,
        is_fragment=False,
        df=False,
        is_retransmission=False,
        is_fast_retransmission=False,
        is_spurious_retransmission=False,
        mss_val=None,
        wscale_shift=None,
        sack_permitted=False,
        icmp_type=None,
        icmp_code=None,
        icmpv6_type=None,
        icmpv6_code=None,
        arp_opcode=None,
        arp_sender_mac=None,
        arp_is_gratuitous=False,
        stp_bpdu_type=None,
        stp_flags_tc=False,
        stp_root_id=None,
        tls_cert_not_before=None,
        tls_cert_not_after=None,
        tls_cert_san=None,
        tls_cert_serial=None,
        tls_cert_issuer=None,
        tls_cert_subject=None,
        tls_cert_sig_hash=None,
        tls_cert_key_type=None,
        tls_cert_key_bits=None,
        tls_cert_san_ip=None,
        tls_cert_chain_len=None,
        tls_client_hello=False,
        tls_server_hello=False,
        tls_application_data=False,
        vlan_id=None,
        vlan_prio=None,
        is_rtp=False,
        rtp_seq=None,
        rtp_ts=None,
        rtp_ssrc=None,
        encap_tags=(),
        dhcp_xid=None,
        dhcp_msg_type=None,
        dhcp_server_id=None,
        dhcp_vendor_class=None,
        sip_call_id=None,
        sip_msg_type=None,
        sip_cseq=None,
        sip_user_agent=None,
        sip_server=None,
        dns_txn_id=None,
        dns_is_response=False,
        dns_qry_name=None,
        dns_rcode=None,
        http_is_request=False,
        http_is_response=False,
        http_method=None,
        http_uri=None,
        http_status_code=None,
        http_response_time_ms=None,
        expert_flags=(),
        expert_details=(),
    )
    redact_packets([raw])
    assert raw.src == "192.0.2.1"
    assert raw.dst == "192.0.2.2"
