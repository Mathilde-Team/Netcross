# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_stats.py — Exploration statistique interactive (Job 27, issue #22).

Tests du module netcross_core.stats : Top-N, tri, regroupement, filtres
temporels, export CSV/JSON.
"""

from netcross_core.correlate import build_flows
from netcross_core.models import Pkt, Report
from netcross_core.stats import (
    StatsQuery,
    compute_stats,
    export_csv,
    export_json,
)


def _pkt(**kw):
    base = dict(  # noqa: C408
        point="LAN",
        ts=1.0,
        frame_number=1,
        proto="TCP",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=50000,
        dport=80,
        length=100,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=1,
        ack=0,
        window=1000,
        flags=None,
        key_id=1,
        payload_hash=None,
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
    base.update(kw)
    return Pkt(**base)


def _make_flows():
    """Cree un jeu de flows de test : 3 flux entre 2 endpoints."""
    packets = [
        _pkt(
            point="LAN",
            ts=1.0,
            frame_number=1,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=100,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=2.0,
            frame_number=2,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=200,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=3.0,
            frame_number=3,
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=80,
            dport=50000,
            length=150,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=4.0,
            frame_number=4,
            src="10.0.0.1",
            dst="10.0.0.3",
            sport=50001,
            dport=443,
            length=500,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=5.0,
            frame_number=5,
            src="10.0.0.1",
            dst="10.0.0.3",
            sport=50001,
            dport=443,
            length=300,
            proto="TCP",
        ),
        _pkt(
            point="WAN",
            ts=1.5,
            frame_number=6,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=100,
            proto="TCP",
        ),
    ]
    from netcross_core.correlate import flow_key

    flows_dict: dict[tuple, dict[str, list[Pkt]]] = {}
    for pk in packets:
        fk = flow_key(pk)
        flows_dict.setdefault(fk, {}).setdefault(pk.point, []).append(pk)

    flows = build_flows(flows_dict)
    return flows, packets


def test_group_by_endpoint():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "endpoint" for r in rows)
    # Le groupe avec le plus d'octets doit etre en premier
    assert rows[0].bytes >= rows[-1].bytes


def test_group_by_protocol():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="protocol", sort_by="packets", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "protocol" for r in rows)


def test_group_by_segment():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="segment", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "segment" for r in rows)


def test_group_by_flow():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "flow" for r in rows)


def test_top_n_limit():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=2)
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) <= 2


def test_top_n_none_returns_all():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) >= 2


def test_sort_by_packets():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="packets", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].packets >= rows[i + 1].packets


def test_sort_by_bytes():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].bytes >= rows[i + 1].bytes


def test_sort_by_duration():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="duration_ms", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].duration_ms >= rows[i + 1].duration_ms


def test_sort_by_throughput():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="throughput_bps", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].throughput_bps >= rows[i + 1].throughput_bps


def test_time_filter():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    # Filtre : seulement les paquets entre t=1.0 et t=3.0
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        time_start=1.0,
        time_end=3.0,
    )
    rows = compute_stats(flows, report, packets, query)
    # Les flux avec des paquets apres t=3.0 doivent etre filtres
    for row in rows:
        assert row.duration_ms <= 2000.0  # max 2s = 2000ms


def test_segment_filter():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        segment="WAN",
    )
    rows = compute_stats(flows, report, packets, query)
    # Seuls les flux vus au point WAN doivent apparaitre
    for row in rows:
        assert len(row.flow_keys) >= 1


def test_invalid_group_by():
    import pytest

    with pytest.raises(ValueError, match="group_by"):
        StatsQuery(group_by="invalid", sort_by="bytes")


def test_invalid_sort_by():
    import pytest

    with pytest.raises(ValueError, match="sort_by"):
        StatsQuery(group_by="endpoint", sort_by="invalid")


def test_invalid_top_n():
    import pytest

    with pytest.raises(ValueError, match="top_n"):
        StatsQuery(group_by="endpoint", sort_by="bytes", top_n=0)


def test_export_csv():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=5)
    rows = compute_stats(flows, report, packets, query)

    csv_str = export_csv(rows)
    assert "label" in csv_str
    assert "packets" in csv_str
    assert "bytes" in csv_str
    assert len(csv_str) > 0


def test_export_json():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=5)
    rows = compute_stats(flows, report, packets, query)

    json_data = export_json(rows)
    assert isinstance(json_data, list)
    assert len(json_data) == len(rows)
    assert "label" in json_data[0]
    assert "bytes" in json_data[0]


def test_export_empty_rows():
    assert export_csv([]) == ""
    assert export_json([]) == []


def test_drill_down_flow_keys():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    for row in rows:
        assert isinstance(row.flow_keys, list)
        # Chaque flow_key doit etre un tuple
        for fk in row.flow_keys:
            assert isinstance(fk, tuple)


def test_events_count_with_index():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    events_by_segment = {"LAN": [{"event": 1}, {"event": 2}], "WAN": []}
    query = StatsQuery(group_by="segment", sort_by="events", top_n=10)
    rows = compute_stats(flows, report, packets, query, events_by_segment=events_by_segment)
    assert any(r.events > 0 for r in rows)


# -- Tests de couverture des branches partielles (issue #288) ------------------


def test_duration_s_property():
    """StatRow.duration_s convertit les ms en secondes (ligne 68)."""
    from netcross_core.stats import StatRow

    row = StatRow(label="test", group_by="endpoint", duration_ms=2000.0)
    assert row.duration_s == 2.0


def test_flow_label_short_key():
    """_flow_label avec une cle trop courte pour le format long (ligne 157)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_label

    f = Flow(key=("TCP",), points=["LAN"], endpoints=("10.0.0.1", "10.0.0.2"))
    label = _flow_label(f, "flow")
    assert label == str(("TCP",))


def test_flow_label_endpoint_unknown():
    """_flow_label avec endpoints vides (ligne 161)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_label

    f = Flow(key=("TCP", "10.0.0.1", 80, "10.0.0.2", 443), points=["LAN"], endpoints=())
    label = _flow_label(f, "endpoint")
    assert label == "endpoints inconnus"


def test_flow_label_segment_unknown():
    """_flow_label avec points vides (ligne 167)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_label

    f = Flow(key=("TCP", "10.0.0.1", 80, "10.0.0.2", 443), points=[], endpoints=("a", "b"))
    label = _flow_label(f, "segment")
    assert label == "segment inconnu"


def test_flow_duration_ms_zero_sans_timestamps():
    """_flow_duration_ms renvoie 0.0 sans timestamps (ligne 124-127)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_duration_ms

    f = Flow(key=("TCP", "a", 1, "b", 2), points=["LAN"])
    assert _flow_duration_ms(f) == 0.0


def test_flow_throughput_zero_with_zero_duration():
    """_flow_throughput_bps renvoie 0.0 avec duree nulle (lignes 140-143)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_throughput_bps

    f = Flow(key=("TCP", "a", 1, "b", 2), points=["LAN"])
    assert _flow_throughput_bps(f) == 0.0


def test_flow_throughput_nonzero_with_data():
    """_flow_throughput_bps calcule un debit non nul avec des donnees."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_throughput_bps

    f = Flow(
        key=("TCP", "10.0.0.1", 80, "10.0.0.2", 443),
        points=["LAN"],
        first_ts={"LAN": 1.0},
        last_ts={"LAN": 2.0},
        byte_count={"LAN": 1250},
    )
    bps = _flow_throughput_bps(f)
    # 1250 octets * 8 bits / 1.0 seconde = 10000 bps
    assert bps == 10000.0


def test_time_filter_empty_packets():
    """_time_filter avec liste vide renvoie vide (ligne 112-113)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _time_filter

    f = Flow(key=("TCP",), points=["LAN"])
    assert _time_filter([], f) == []


def test_time_filter_no_timestamps():
    """_time_filter sans timestamps renvoie les paquets intacts (ligne 115-116)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _time_filter

    f = Flow(key=("TCP",), points=["LAN"])
    pkts = [_pkt(ts=1.0), _pkt(ts=2.0)]
    result = _time_filter(pkts, f)
    assert len(result) == 2


def test_time_filter_with_timestamps():
    """_time_filter filtre par fenetre temporelle du flux (lignes 117-119)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _time_filter

    f = Flow(
        key=("TCP",),
        points=["LAN"],
        first_ts={"LAN": 1.5},
        last_ts={"LAN": 3.5},
    )
    pkts = [_pkt(ts=1.0), _pkt(ts=2.0), _pkt(ts=3.0), _pkt(ts=4.0)]
    result = _time_filter(pkts, f)
    # Seuls les paquets entre 1.5 et 3.5 doivent passer
    assert all(1.5 <= p.ts <= 3.5 for p in result)


def test_aggregate_group_latency():
    """_aggregate_group calcule la latence depuis report.latency (lignes 211-215)."""
    from netcross_core.expert_model import Flow
    from netcross_core.models import Report
    from netcross_core.stats import StatsQuery, _aggregate_group

    f = Flow(
        key=("TCP", "10.0.0.1", 80, "10.0.0.2", 443),
        points=["LAN"],
        endpoints=("10.0.0.1", "10.0.0.2"),
        first_ts={"LAN": 1.0},
        last_ts={"LAN": 2.0},
        packet_count={"LAN": 5},
        byte_count={"LAN": 1000},
    )
    report = Report(points=["LAN"])
    report.latency[("LAN", "WAN")] = [10.0, 20.0, 30.0]
    query = StatsQuery(group_by="endpoint", sort_by="bytes")
    row = _aggregate_group("test", "endpoint", [f], report, [], query)
    assert row.latency_ms is not None
    assert row.latency_ms == 20.0  # moyenne de [10, 20, 30]


def test_compute_stats_time_filter_excludes_flows_before_start():
    """compute_stats filtre les flux avant time_start (ligne 268)."""
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        time_start=10.0,  # apres tous les paquets
    )
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) == 0


def test_compute_stats_time_filter_excludes_flows_after_end():
    """compute_stats filtre les flux apres time_end (ligne 270)."""
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        time_end=0.5,  # avant tous les paquets
    )
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) == 0


def test_compute_stats_time_filter_with_only_start():
    """compute_stats avec time_start seul (branche 265->272)."""
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        time_start=2.5,  # garde les flux qui durent apres 2.5
    )
    rows = compute_stats(flows, report, packets, query)
    # Au moins un flux devrait passer (ceux avec paquets apres t=2.5)
    assert len(rows) >= 1


def test_flow_packets_filters_by_point():
    """_flow_packets filtre les paquets par point (ligne 103)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_packets

    f = Flow(key=("TCP",), points=["LAN"])
    pkts = [_pkt(point="LAN", ts=1.0), _pkt(point="WAN", ts=2.0)]
    result = _flow_packets(f, pkts)
    assert len(result) == 1
    assert result[0].point == "LAN"


def test_flow_label_nat_key_flow():
    """_flow_label gere les cles NAT dans le groupe flow (lignes 151-156)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_label

    f = Flow(
        key=("NAT", "TCP", 80, "10.0.0.2", 443),
        points=["LAN"],
        endpoints=("10.0.0.1", "10.0.0.2"),
    )
    label = _flow_label(f, "flow")
    assert "TCP" in label
    assert "NAT:80" in label


def test_flow_label_nat_key_protocol():
    """_flow_label gere les cles NAT dans le groupe protocol (ligne 164)."""
    from netcross_core.expert_model import Flow
    from netcross_core.stats import _flow_label

    f = Flow(
        key=("NAT", "TCP", 80, "10.0.0.2", 443),
        points=["LAN"],
        endpoints=("10.0.0.1", "10.0.0.2"),
    )
    label = _flow_label(f, "protocol")
    assert label == "TCP"
