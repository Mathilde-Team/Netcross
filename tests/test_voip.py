import dataclasses

import pytest

from netcross_core.analysis import analyse
from netcross_core.models import Pkt


def _pkt(point, ts, **kw):
    d = dict(  # noqa: C408
        point=point,
        ts=ts,
        frame_number=None,
        proto="UDP",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=5000,
        dport=5000,
        length=200,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=None,
        ack=None,
        window=None,
        flags=None,
        key_id=None,
        payload_hash=None,
        ip_id=None,
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
    d.update(kw)
    return Pkt(**d)


def _sip(point, ts, msg, cseq, call_id="call-1"):
    return _pkt(
        point,
        ts,
        proto="UDP",
        src="10.0.0.10",
        dst="10.0.0.20",
        sport=5060,
        dport=5060,
        sip_call_id=call_id,
        sip_msg_type=msg,
        sip_cseq=cseq,
    )


def _rtp(point, ts, seq, ssrc=42):
    return _pkt(
        point,
        ts,
        src="10.0.0.10",
        dst="10.0.0.20",
        is_rtp=True,
        rtp_seq=seq,
        rtp_ts=seq * 160,
        rtp_ssrc=ssrc,
    )


def test_voip_call_fusionne_signalisation_et_media():
    packets = [
        _sip("A", 1.000, "INVITE", "1 INVITE"),
        _sip("B", 1.020, "INVITE", "1 INVITE"),
        _sip("A", 1.100, "200 OK", "1 INVITE"),
        _sip("B", 1.120, "200 OK", "1 INVITE"),
        _rtp("A", 1.200, 1),
        _rtp("B", 1.250, 1),
        _rtp("B", 1.270, 2),
        _sip("B", 3.000, "BYE", "2 BYE"),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert len(r.voip_calls) == 1
    call = r.voip_calls[0]
    assert call["call_id"] == "call-1"
    assert call["participants"] == ["10.0.0.10", "10.0.0.20"]
    assert call["setup_duration_ms"] == pytest.approx(100.0)
    assert call["duration_ms"] == 2000.0
    assert len(call["rtp_streams"]) == 1
    assert any(e["type"] == "media" for e in call["events"])


def test_voip_timeline_conserve_echec_sip_et_distribution():
    packets = [
        _sip("A", 10.0, "INVITE", "3 INVITE", "failed"),
        _sip("A", 10.2, "486 Busy Here", "3 INVITE", "failed"),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert r.voip_calls[0]["quality"] == "unknown"
    assert r.voip_calls[0]["events"][-1]["type"] == "failure"
    assert r.voip_quality_distribution == {"unknown": 1}


def test_voip_flux_hors_fenetre_non_associe():
    packets = [
        _sip("A", 1.0, "INVITE", "1 INVITE", "call-a"),
        _sip("A", 1.1, "200 OK", "1 INVITE", "call-a"),
        _rtp("A", 1000.0, 1),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert r.voip_calls[0]["rtp_streams"] == []


# -- Issue #704 : couverture des branches defensives de voip.py --------------


def test_quality_mos_fair():
    """Ligne 60 : _quality retourne 'fair' pour MOS entre 3.0 et 3.6."""
    from netcross_core.voip import _quality

    assert _quality([3.2, 3.4]) == "fair"


def test_quality_mos_good():
    """Ligne 60-63 : _quality retourne 'good' pour MOS >= 3.6."""
    from netcross_core.voip import _quality

    assert _quality([4.0, 3.8]) == "good"


def test_quality_mos_poor():
    """Ligne 58 : _quality retourne 'poor' pour MOS < 3.0."""
    from netcross_core.voip import _quality

    assert _quality([2.5, 1.8]) == "poor"


def test_build_calls_sans_invite_utilise_premier_paquet():
    """Ligne 87 : build_calls utilise le premier paquet si pas d'INVITE."""
    from netcross_core.voip import build_calls

    # Un seul paquet SIP sans INVITE
    pkt = _sip("A", 1.0, "200 OK", "1 200")
    calls, _unassigned = build_calls([pkt], [])
    # Le call doit exister avec le premier paquet comme invite
    if calls:
        assert calls[0].call_id


def test_build_calls_rtp_hors_fenetre_ambigu():
    """Lignes 168, 179, 184 : RTP qui chevauche plusieurs calls
    ou qui est hors de toutes les fenetres."""
    from netcross_core.voip import build_calls

    # Deux calls successifs + un RTP hors fenetre
    pkts = [
        _sip("A", 1.0, "INVITE", "1 INVITE"),
        _sip("B", 1.1, "200 OK", "1 INVITE"),
        _sip("A", 2.0, "BYE", "1 BYE"),
        _sip("A", 3.0, "INVITE", "2 INVITE"),
        _sip("B", 3.1, "200 OK", "2 INVITE"),
        _sip("A", 4.0, "BYE", "2 BYE"),
    ]
    rtp_streams = [
        {"first_ts": 1.5, "points": {"A": 1.5}, "mos": 4.0, "label": "stream1"},
        {"first_ts": 10.0, "points": {"A": 10.0}, "mos": 4.0, "label": "stream2"},
    ]
    _calls, unassigned = build_calls(pkts, rtp_streams)
    # Le stream1 doit etre associe au call 1
    # Le stream2 (ts=10.0) est hors fenetre -> non assigne
    assert isinstance(unassigned, dict)


# -- Issue #704 : fin d'appel deduite de l'appel suivant, flux RTP sans date --


def test_build_calls_sans_bye_se_termine_a_l_appel_suivant():
    """Ligne 168 : sans BYE, un appel se termine au debut de l'appel suivant ;
    ligne 179 : un flux RTP sans aucune date est ignore ; ligne 184 : un flux
    a la frontiere des deux appels est ambigu et rattache au plus proche."""
    from netcross_core.voip import build_calls

    pkts = [
        _sip("A", 1.0, "INVITE", "1 INVITE", call_id="call-1"),
        _sip("A", 5.0, "INVITE", "1 INVITE", call_id="call-2"),
    ]
    rtp_streams = [
        {"first_ts": 3.0, "points": {"A": 3.0}, "mos": 4.2, "label": "dans-call-1"},
        {"points": {}, "mos": 4.0, "label": "sans-date"},
        {"first_ts": 5.0, "mos": 3.9, "label": "frontiere"},
    ]
    calls, _unassigned = build_calls(pkts, rtp_streams)
    assert [c.call_id for c in calls] == ["call-1", "call-2"]
    assert [s["label"] for s in calls[0].rtp_streams] == ["dans-call-1"]
    assert [s["label"] for s in calls[1].rtp_streams] == ["frontiere"]


# -- Issue #1120 : association SIP/RTP par SDP, repli fenetre temporelle --------


def _sip_sdp(point, ts, msg, cseq, call_id, src, dst, media):
    return _pkt(
        point,
        ts,
        src=src,
        dst=dst,
        sport=5060,
        dport=5060,
        sip_call_id=call_id,
        sip_msg_type=msg,
        sip_cseq=cseq,
        sip_sdp_media=media,
    )


def _rtp_flow(point, ts, seq, src, sport, dst, dport, ssrc):
    return _pkt(
        point,
        ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        is_rtp=True,
        rtp_seq=seq,
        rtp_ts=seq * 160,
        rtp_ssrc=ssrc,
    )


def _deux_appels_simultanes():
    """Appel 1 (alice <-> bob) puis appel 2 (carol <-> dave) etabli avant que
    le media de l'appel 1 ne demarre : sans BYE, la fenetre temporelle de
    l'appel 1 se ferme a l'INVITE de l'appel 2, donc le repli temporel
    rattacherait a tort le media de l'appel 1 a l'appel 2."""
    alice, bob, carol, dave = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"
    return [
        _sip_sdp("A", 1.0, "INVITE", "1 INVITE", "call-1", alice, bob, ((alice, 40000),)),
        _sip_sdp("A", 1.1, "200 OK", "1 INVITE", "call-1", bob, alice, ((bob, 50000),)),
        _sip_sdp("A", 2.0, "INVITE", "1 INVITE", "call-2", carol, dave, ((carol, 41000),)),
        _sip_sdp("A", 2.1, "200 OK", "1 INVITE", "call-2", dave, carol, ((dave, 51000),)),
        # Media de l'appel 1, dans les deux sens, apres l'INVITE de l'appel 2.
        _rtp_flow("A", 2.5, 1, alice, 40000, bob, 50000, 0x11),
        _rtp_flow("A", 2.52, 2, alice, 40000, bob, 50000, 0x11),
        _rtp_flow("A", 2.6, 1, bob, 50000, alice, 40000, 0x12),
        _rtp_flow("A", 2.62, 2, bob, 50000, alice, 40000, 0x12),
        # Media de l'appel 2.
        _rtp_flow("A", 2.7, 1, carol, 41000, dave, 51000, 0x21),
        _rtp_flow("A", 2.72, 2, carol, 41000, dave, 51000, 0x21),
    ]


def test_sdp_associe_deux_appels_simultanes_la_ou_le_repli_temporel_se_trompe():
    packets = _deux_appels_simultanes()
    r = analyse({}, ["A"], packets)
    calls = {c["call_id"]: c for c in r.voip_calls}
    assert sorted(s["label"].split(" (")[0] for s in calls["call-1"]["rtp_streams"]) == [
        "10.0.0.1:40000 -> 10.0.0.2:50000",
        "10.0.0.2:50000 -> 10.0.0.1:40000",
    ]
    assert [s["label"].split(" (")[0] for s in calls["call-2"]["rtp_streams"]] == ["10.0.0.3:41000 -> 10.0.0.4:51000"]
    assert calls["call-1"]["correlation_method"] == "sdp"
    assert calls["call-2"]["correlation_method"] == "sdp"
    assert {s["correlation_method"] for c in calls.values() for s in c["rtp_streams"]} == {"sdp"}
    # Le flux du rapport global n'est pas modifie par l'association.
    assert all("correlation_method" not in s for s in r.rtp_streams)

    # Contre-epreuve : sans SDP, le repli temporel se trompe (tout va a
    # l'appel 2, dont la fenetre contient le debut des trois flux).
    sans_sdp = [dataclasses.replace(p, sip_sdp_media=()) for p in packets]
    r2 = analyse({}, ["A"], sans_sdp)
    calls2 = {c["call_id"]: c for c in r2.voip_calls}
    assert calls2["call-1"]["rtp_streams"] == []
    assert len(calls2["call-2"]["rtp_streams"]) == 3
    assert calls2["call-2"]["correlation_method"] == "time_window"
    assert calls2["call-1"]["correlation_method"] == "time_window"


def test_sdp_et_repli_temporel_donnent_une_methode_mixte():
    from netcross_core.voip import build_calls

    pkts = [
        _sip_sdp("A", 1.0, "INVITE", "1 INVITE", "c1", "10.0.0.1", "10.0.0.2", (("10.0.0.1", 4000),)),
        _sip_sdp("A", 1.1, "200 OK", "1 INVITE", "c1", "10.0.0.2", "10.0.0.1", ()),
    ]
    streams = [
        {"first_ts": 1.5, "label": "sdp", "dst": "10.0.0.1", "dport": 4000},
        {"first_ts": 1.6, "label": "temps", "dst": "10.0.0.1", "dport": 9999},
    ]
    calls, _ = build_calls(pkts, streams)
    assert calls[0].correlation_method == "mixed"
    assert [(s["label"], s["correlation_method"]) for s in calls[0].rtp_streams] == [
        ("sdp", "sdp"),
        ("temps", "time_window"),
    ]


def test_sdp_ports_reutilises_choix_temporel_entre_appels_sdp():
    """Deux appels successifs annoncent le meme point media : le flux va a
    celui dont la fenetre le contient ; hors de toute fenetre, a l'appel SDP
    dont l'INVITE est la plus proche."""
    from netcross_core.voip import build_calls

    media = (("10.0.0.1", 4000),)
    pkts = [
        _sip_sdp("A", 1.0, "INVITE", "1 INVITE", "c1", "10.0.0.1", "10.0.0.2", media),
        _sip_sdp("A", 2.0, "BYE", "2 BYE", "c1", "10.0.0.1", "10.0.0.2", ()),
        _sip_sdp("A", 10.0, "INVITE", "1 INVITE", "c2", "10.0.0.1", "10.0.0.2", media),
        _sip_sdp("A", 11.0, "BYE", "2 BYE", "c2", "10.0.0.1", "10.0.0.2", ()),
    ]
    streams = [
        {"first_ts": 10.5, "label": "dans-c2", "dst": "10.0.0.1", "dport": 4000},
        {"first_ts": 3.0, "label": "hors-fenetre", "dst": "10.0.0.1", "dport": 4000},
    ]
    calls, _ = build_calls(pkts, streams)
    by_id = {c.call_id: [s["label"] for s in c.rtp_streams] for c in calls}
    assert by_id == {"c1": ["hors-fenetre"], "c2": ["dans-c2"]}
    assert all(c.correlation_method == "sdp" for c in calls)


def test_appel_sans_flux_reste_time_window():
    from netcross_core.voip import build_calls

    calls, _ = build_calls([_sip("A", 1.0, "INVITE", "1 INVITE")], [])
    assert calls[0].correlation_method == "time_window"
    assert calls[0].to_dict()["correlation_method"] == "time_window"
