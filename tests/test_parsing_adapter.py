# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.parsing -- adaptateur fin entre pcap_parser et le modele
Pkt de netcross_core. Ne refait aucun decodage lui-meme : on verifie
donc surtout (1) que _to_pkt/parse_capture cablent bien label + tous
les champs de RawPacket vers Pkt sans en perdre un, et (2) que la
gestion d'erreur tshark (absent/en echec) respecte le contrat de
l'ancienne API (avaler l'erreur sauf raise_on_error=True) -- voir
claude.md Session 1 : "conserve exactement les memes signatures que
l'ancienne version scapy".
"""

import pytest

import netcross_core.parsing as parsing_mod
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.packet import RawPacket


def _raw(**overrides) -> RawPacket:
    defaults = {
        "ts": 1.0,
        "frame_number": None,
        "proto": "TCP",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 1,
        "dport": 2,
        "length": 60,
        "ttl": 64,
        "dscp": 0,
        "ecn": 0,
        "seq": 42,
        "ack": 0,
        "window": 1000,
        "flags": "S",
        "key_id": 42,
        "payload_hash": None,
        "payload": b"",
        "ip_id": 1,
        "is_fragment": False,
        "df": False,
        "is_retransmission": False,
        "is_fast_retransmission": False,
        "is_spurious_retransmission": False,
        "expert_flags": (),
        "expert_details": (),
        "mss_val": None,
        "wscale_shift": None,
        "sack_permitted": False,
        "icmp_type": None,
        "icmp_code": None,
        "icmpv6_type": None,
        "icmpv6_code": None,
        "arp_opcode": None,
        "arp_sender_mac": None,
        "arp_is_gratuitous": False,
        "stp_bpdu_type": None,
        "stp_flags_tc": False,
        "stp_root_id": None,
        "tls_cert_not_before": None,
        "tls_cert_not_after": None,
        "tls_cert_san": None,
        "tls_cert_serial": None,
        "tls_cert_issuer": None,
        "tls_cert_subject": None,
        "tls_cert_sig_hash": None,
        "tls_cert_key_type": None,
        "tls_cert_key_bits": None,
        "tls_cert_san_ip": None,
        "tls_cert_chain_len": None,
        "tls_client_hello": False,
        "tls_server_hello": False,
        "tls_application_data": False,
        "vlan_id": None,
        "vlan_prio": None,
        "is_rtp": False,
        "rtp_seq": None,
        "rtp_ts": None,
        "rtp_ssrc": None,
        "encap_tags": (),
        "dhcp_xid": None,
        "dhcp_msg_type": None,
        "dhcp_server_id": None,
        "dhcp_vendor_class": None,
        "sip_call_id": None,
        "sip_msg_type": None,
        "sip_cseq": None,
        "sip_user_agent": None,
        "sip_server": None,
        "dns_txn_id": None,
        "dns_is_response": False,
        "dns_qry_name": None,
        "dns_rcode": None,
        "http_is_request": False,
        "http_is_response": False,
        "http_method": None,
        "http_uri": None,
        "http_status_code": None,
        "http_response_time_ms": None,
    }
    defaults.update(overrides)
    return RawPacket(**defaults)


def test_to_pkt_attache_le_label_et_conserve_les_champs():
    raw = _raw(src="1.2.3.4", seq=999)
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert pkt.point == "LAN"
    assert pkt.src == "1.2.3.4"
    assert pkt.seq == 999
    # tous les champs de RawPacket (hors 'payload', absent de Pkt par
    # design -- voir claude.md Session 3) doivent avoir ete reportes
    for f in raw.__dataclass_fields__:
        if f == "payload":
            continue
        assert getattr(pkt, f) == getattr(raw, f)


def test_to_pkt_conserve_le_flag_df():
    raw = _raw(df=True)
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert pkt.df is True


def test_to_pkt_conserve_la_classification_de_retransmission():
    raw = _raw(is_fast_retransmission=True)
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert pkt.is_fast_retransmission is True
    assert pkt.is_retransmission is False
    assert pkt.is_spurious_retransmission is False


def test_parse_capture_avale_l_erreur_par_defaut(monkeypatch, capsys):
    def boom(path, raise_on_error=True):
        raise TsharkNotFoundError("tshark introuvable")

    monkeypatch.setattr(parsing_mod.pcap_parser, "parse_capture", boom)
    result = parsing_mod.parse_capture("LAN", "capture.pcapng")
    assert result == []
    assert "LAN" in capsys.readouterr().err


def test_parse_capture_relaie_l_erreur_si_demande(monkeypatch):
    def boom(path, raise_on_error=True):
        raise TsharkError("erreur tshark")

    monkeypatch.setattr(parsing_mod.pcap_parser, "parse_capture", boom)
    with pytest.raises(TsharkError):
        parsing_mod.parse_capture("LAN", "capture.pcapng", raise_on_error=True)


def test_parse_capture_convertit_les_raw_packets(monkeypatch):
    raws = [_raw(src="1.1.1.1"), _raw(src="2.2.2.2")]
    monkeypatch.setattr(parsing_mod.pcap_parser, "parse_capture", lambda path, raise_on_error=True: raws)
    pkts = parsing_mod.parse_capture("WAN", "capture.pcapng")
    assert [p.src for p in pkts] == ["1.1.1.1", "2.2.2.2"]
    assert all(p.point == "WAN" for p in pkts)


def test_pkt_utilise_des_slots():
    # Meme piste memoire que RawPacket (voir tests/test_packet.py) --
    # Pkt est l'objet garde le plus longtemps en RAM (toute l'analyse
    # tourne dessus), le plus important des deux a optimiser.
    raw = _raw()
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert not hasattr(pkt, "__dict__")
    with pytest.raises(AttributeError):
        pkt.champ_inexistant = 1


def test_pkt_champs_attendus_dans_slots():
    from netcross_core.models import Pkt

    field_names = set(Pkt.__dataclass_fields__)
    assert field_names == set(Pkt.__slots__)


def test_parse_capture_libere_les_raw_packets_au_fur_et_a_mesure(monkeypatch):
    # Piste "gestion memoire des grosses captures" : parse_capture ne doit
    # plus garder raw_packets et le Pkt correspondant tous les deux vivants
    # jusqu'a la fin de la fonction -- chaque RawPacket converti est
    # remplace par None dans la liste source des sa conversion (voir
    # claude.md pour la mesure du pic memoire transitoire evite).
    raws = [_raw(src="1.1.1.1"), _raw(src="2.2.2.2"), _raw(src="3.3.3.3")]
    monkeypatch.setattr(parsing_mod.pcap_parser, "parse_capture", lambda path, raise_on_error=True: raws)
    pkts = parsing_mod.parse_capture("WAN", "capture.pcapng")
    assert [p.src for p in pkts] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert raws == [None, None, None]


def test_parse_rtp_reexport_heuristique():
    import struct

    payload = struct.pack("!BBHII", 0x80, 0, 1, 1, 1) + b"\x00" * 20
    result = parsing_mod.parse_rtp(payload)
    assert result is not None and result["seq"] == 1


def test_parse_sip_reexport_heuristique():
    payload = b"BYE sip:bob@example.com SIP/2.0\r\nCall-ID: x\r\n\r\n"
    result = parsing_mod.parse_sip(payload)
    assert result["msg_type"] == "BYE"


def test_detect_encapsulation_reexport():
    assert parsing_mod.detect_encapsulation({"gre": {}}) == ("GRE",)


def test_api_publique_inchangee():
    # contrat explicite documente dans le module : ces noms doivent
    # rester exposes tels quels.
    for name in (
        "compute_mos",
        "detect_encapsulation",
        "parse_capture",
        "parse_captures_parallel",
        "parse_live",
        "parse_live_multi",
        "parse_rtp",
        "parse_sip",
    ):
        assert hasattr(parsing_mod, name), f"{name} manquant de l'API publique"


# -- parse_live_multi : capture simultanee sur plusieurs interfaces (Job 48) --


def test_parse_live_multi_etiquette_chaque_pkt_du_label_de_son_interface(monkeypatch):
    def fake_iter_live_multi(interfaces, stop_event=None, *, bpf_filter=None):
        yield "WAN", _raw(ts=2.0, src="10.0.1.1")
        yield "LAN", _raw(ts=3.0, src="10.0.0.1")

    monkeypatch.setattr(parsing_mod.pcap_parser, "iter_live_multi", fake_iter_live_multi)

    pkts = list(parsing_mod.parse_live_multi([("LAN", "eth0"), ("WAN", "eth1")]))

    # le label venu de pcap_parser devient le point du Pkt, champs de RawPacket conserves
    assert [(p.point, p.ts, p.src) for p in pkts] == [("WAN", 2.0, "10.0.1.1"), ("LAN", 3.0, "10.0.0.1")]


def test_parse_live_multi_transmet_interfaces_stop_event_et_filtre(monkeypatch):
    captured = {}

    def fake_iter_live_multi(interfaces, stop_event=None, *, bpf_filter=None):
        captured.update(interfaces=list(interfaces), stop_event=stop_event, bpf_filter=bpf_filter)
        return iter([])

    monkeypatch.setattr(parsing_mod.pcap_parser, "iter_live_multi", fake_iter_live_multi)
    stop_event = object()

    assert list(parsing_mod.parse_live_multi([("LAN", "eth0")], stop_event=stop_event, bpf_filter="udp")) == []
    assert captured == {"interfaces": [("LAN", "eth0")], "stop_event": stop_event, "bpf_filter": "udp"}


def test_parse_live_multi_valide_ses_arguments_des_l_appel():
    # pas de monkeypatch : c'est bien la validation de pcap_parser qui parle, et
    # elle doit remonter a l'appel meme (parse_live_multi n'est pas un generateur)
    with pytest.raises(ValueError, match="au moins une interface"):
        parsing_mod.parse_live_multi([])
    with pytest.raises(ValueError, match="en double"):
        parsing_mod.parse_live_multi([("LAN", "eth0"), ("LAN", "eth1")])


# -- couverture des branches manquantes (issue #246) -------------------------


def test_parse_capture_timed_renvoie_pkts_et_duree(monkeypatch):
    """Lines 188-192 : _parse_capture_timed renvoie (pkts, duree)."""
    raws = [_raw(src="1.1.1.1"), _raw(src="2.2.2.2")]
    monkeypatch.setattr(parsing_mod.pcap_parser, "parse_capture", lambda path, raise_on_error=True: raws)
    pkts, seconds = parsing_mod._parse_capture_timed("WAN", "capture.pcap")
    assert [p.src for p in pkts] == ["1.1.1.1", "2.2.2.2"]
    assert isinstance(seconds, float) and seconds >= 0.0


def test_parse_captures_parallel_succes_et_tri(monkeypatch):
    """Lines 199-239 : parse_captures_parallel avec deux captures reussies."""
    import concurrent.futures

    # ThreadPoolExecutor pour que le monkeypatch de parse_capture soit visible
    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor)

    raws_a = [_raw(src="1.1.1.1")]
    raws_b = [_raw(src="2.2.2.2")]

    def fake_parse(label, path, raise_on_error=False):
        if "a" in path:
            return raws_a
        return raws_b

    monkeypatch.setattr(parsing_mod, "parse_capture", fake_parse)
    pkts, stats = parsing_mod.parse_captures_parallel([("A", "/fake/a.pcap"), ("B", "/fake/b.pcap")])
    assert len(pkts) == 2
    assert [s["label"] for s in stats] == ["A", "B"]
    assert stats[0]["count"] == 1
    assert stats[0]["error"] is None


def test_parse_captures_parallel_capture_en_echec_ne_stoppe_pas(monkeypatch):
    """Lines 222-234 : un fichier en echec ne stoppe pas les autres."""
    import concurrent.futures

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor)

    def boom(label, path, raise_on_error=False):
        raise RuntimeError("tshark absent")

    monkeypatch.setattr(parsing_mod, "parse_capture", boom)
    pkts, stats = parsing_mod.parse_captures_parallel([("A", "/fake/a.pcap")])
    assert pkts == []
    assert stats[0]["count"] == 0
    assert stats[0]["seconds"] is None
    assert "RuntimeError" in stats[0]["error"]


def test_parse_live_yield_un_pkt_par_raw(monkeypatch):
    """Line 344 : parse_live yield un Pkt etiquete pour chaque raw."""

    def fake_iter_live(interface, bpf_filter=None, stop_event=None):
        yield _raw(ts=1.0, src="10.0.0.1")
        yield _raw(ts=2.0, src="10.0.0.2")

    monkeypatch.setattr(parsing_mod.pcap_parser, "iter_live", fake_iter_live)
    pkts = list(parsing_mod.parse_live("LAN", "eth0"))
    assert [p.src for p in pkts] == ["10.0.0.1", "10.0.0.2"]
    assert all(p.point == "LAN" for p in pkts)


def test_to_pkt_conserve_entropie_et_longueur_du_payload():
    """#351 : payload_len = taille du payload brut (Pkt ne garde pas les
    octets) -- sert a ponderer l'entropie par flux dans flow_stats."""
    raw = _raw(payload=b"x" * 300, payload_entropy=0.0)
    pkt = parsing_mod._to_pkt("LAN", raw)
    assert pkt.payload_len == 300
    assert pkt.payload_entropy == 0.0
    assert parsing_mod._to_pkt("LAN", _raw(payload=b"")).payload_len == 0
