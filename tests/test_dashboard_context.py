# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests pour netcross_gtk4.dashboard_context (issue #18, section 6.17).

Logique pure (sans Gtk) : construit un Report + flows + findings reels via
make_pkt -> correlate -> analyse, puis verifie le snapshot et les selections
liees.
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import build_flows, correlate
from netcross_gtk4.dashboard_context import (
    DashboardSelection,
    build_dashboard_snapshot,
    clear_selection,
    select_endpoint,
    select_event,
    select_flow,
    select_protocol,
)


def _scenario():
    """Deux points A/B, un flux TCP 10.0.0.1:1234 -> 10.0.0.2:80 vu aux deux
    points, plus un flux UDP. Retourne (report, flows_list)."""
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=0.0,
            length=100,
            payload_hash="h1",
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=0.05,
            length=100,
            payload_hash="h1",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=1.0,
            length=100,
            payload_hash="h2",
        ),
        make_pkt(
            point="B",
            proto="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=1234,
            dport=80,
            ts=1.05,
            length=100,
            payload_hash="h2",
        ),
        make_pkt(
            point="A",
            proto="UDP",
            src="10.0.0.3",
            dst="10.0.0.4",
            sport=5000,
            dport=5353,
            ts=0.2,
            length=80,
            payload_hash="h3",
        ),
    ]
    flows_dict = correlate(pkts)
    report = analyse(flows_dict, points_order=["A", "B"], all_packets=pkts)
    flows_list = build_flows(flows_dict)
    return report, flows_list


# -- snapshot vide ----------------------------------------------------------


def test_snapshot_vide_si_pas_de_donnees():
    snap = build_dashboard_snapshot(None, None)
    assert snap.timeline_rows == []
    assert snap.flow_rows == []
    assert snap.endpoint_rows == []
    assert snap.protocol_rows == []
    assert snap.event_rows == []
    assert snap.selection_summary == "aucune selection active"


# -- snapshot peuple toutes les vues ----------------------------------------


def test_snapshot_peuple_les_six_vues():
    report, flows = _scenario()
    snap = build_dashboard_snapshot(report, flows)
    # flows : TCP + UDP = 2
    assert len(snap.flow_rows) == 2
    assert {r["protocol"] for r in snap.flow_rows} == {"TCP", "UDP"}
    # endpoints : 10.0.0.1/2 (TCP) + 10.0.0.3/4 (UDP)
    eps = {r["endpoint"] for r in snap.endpoint_rows}
    assert "10.0.0.1" in eps and "10.0.0.3" in eps
    # protocoles : TCP et UDP
    protos = {r["protocol"] for r in snap.protocol_rows}
    assert protos == {"TCP", "UDP"}
    # segments : paire (A, B)
    assert any(r["pair"] == "A -> B" for r in snap.segment_rows)


def test_snapshot_timeline_peuple_depuis_loss_event_buckets():
    # Report construit a la main avec des buckets de perte connus : la
    # timeline doit les reprendre, tries par bucket, avec le bon libelle.
    from netcross_core.models import Report

    report = Report(points=["A", "B"], pairs=[("A", "B")], bucket_seconds=1.0)
    report.loss_event_buckets[("A", "B")] = [0, 0, 2]
    snap = build_dashboard_snapshot(report, flows=[])
    assert len(snap.timeline_rows) == 2  # buckets distincts : 0 et 2
    labels = {r["bucket"]: r for r in snap.timeline_rows}
    assert labels[0]["loss_events"] == 2  # deux paires d'evenements au bucket 0
    assert labels[2]["loss_events"] == 1
    assert labels[0]["label"].startswith("0.0-")


def test_snapshot_events_inclut_findings_et_signaux_tshark():
    report, flows = _scenario()

    class FakeTsharkEvent:
        category = "tcp.analysis"
        severity = "chat"
        segment = "A"
        message = "Out-Of-Order"
        source = "tshark"
        protocol = "TCP"

    snap = build_dashboard_snapshot(report, flows, wireshark_expert_events=[FakeTsharkEvent()])
    assert len(snap.event_rows) == 1
    ev = snap.event_rows[0]
    assert ev["source"] == "tshark"
    assert ev["protocol"] == "TCP"
    assert ev["id"] == 0  # indice dans la liste fusionnee


def test_snapshot_events_filtres_par_protocole():
    report, flows = _scenario()

    class Ev:
        def __init__(self, proto):
            self.category = "x"
            self.severity = "info"
            self.segment = "A"
            self.message = "m"
            self.source = "tshark"
            self.protocol = proto

    sel = select_protocol(DashboardSelection(), "TCP")
    snap = build_dashboard_snapshot(report, flows, wireshark_expert_events=[Ev("TCP"), Ev("UDP")], selection=sel)
    # seul l'evenement TCP survive au filtre protocole
    assert len(snap.event_rows) == 1
    assert snap.event_rows[0]["protocol"] == "TCP"


# -- selection endpoint filtre les flows ------------------------------------


def test_selection_endpoint_filtre_flows():
    report, flows = _scenario()
    sel = select_endpoint(DashboardSelection(), "10.0.0.1")
    snap = build_dashboard_snapshot(report, flows, selection=sel)
    # seul le flux TCP implique 10.0.0.1
    assert len(snap.flow_rows) == 1
    assert snap.flow_rows[0]["protocol"] == "TCP"
    assert snap.selection_summary == "endpoint=10.0.0.1"


# -- selection protocole filtre endpoints/flows -----------------------------


def test_selection_protocole_filtre_endpoints_et_flows():
    report, flows = _scenario()
    sel = select_protocol(DashboardSelection(), "UDP")
    snap = build_dashboard_snapshot(report, flows, selection=sel)
    assert {r["protocol"] for r in snap.flow_rows} == {"UDP"}
    eps = {r["endpoint"] for r in snap.endpoint_rows}
    assert eps == {"10.0.0.3", "10.0.0.4"}


# -- selection flow propage endpoint/protocol/pair --------------------------


def test_selection_flow_propage_endpoint_protocol_pair():
    report, flows = _scenario()
    tcp_flow = next(f for f in flows if _flow_proto(f) == "TCP")
    sel = select_flow(DashboardSelection(), tcp_flow)
    assert sel.flow_key == tcp_flow.key
    assert sel.protocol == "TCP"
    assert sel.endpoint == "10.0.0.1" or sel.endpoint == "10.0.0.2"
    # flow vu sur A et B -> paire derivee
    assert sel.pair == ("A", "B")
    # le snapshot ne montre que ce flow
    snap = build_dashboard_snapshot(report, flows, selection=sel)
    assert len(snap.flow_rows) == 1
    assert "flow=selectionne" in snap.selection_summary


# -- selection evenement propage point/protocol -----------------------------


def test_selection_evenement_propage_point_et_protocole():
    report, flows = _scenario()

    class FakeEvent:
        protocol = "TCP"
        segment = "A"
        category = "test"
        severity = "info"
        message = "evenement de test"
        source = "tshark"

    sel = select_event(DashboardSelection(), 0, [FakeEvent()])
    assert sel.event_id == 0
    assert sel.protocol == "TCP"
    assert sel.point == "A"
    snap = build_dashboard_snapshot(report, flows, selection=sel)
    assert snap.selection_summary.startswith("point=A")


def test_selection_evenement_hors_plage_ne_plante_pas():
    sel = select_event(DashboardSelection(), 99, [])
    assert sel.event_id == 99
    # pas de propagation sur indice invalide
    assert sel.protocol is None


# -- clear reinitialise -----------------------------------------------------


def test_clear_selection_reinitialise_tout():
    report, flows = _scenario()
    tcp_flow = next(f for f in flows if _flow_proto(f) == "TCP")
    sel = select_flow(select_protocol(DashboardSelection(), "TCP"), tcp_flow)
    assert sel.protocol is not None
    cleared = clear_selection(sel)
    assert cleared.protocol is None
    assert cleared.flow_key is None
    assert cleared.endpoint is None
    snap = build_dashboard_snapshot(report, flows, selection=cleared)
    assert len(snap.flow_rows) == 2  # tous les flows revenus


# -- selection point filtre segments/timeline -------------------------------


def test_selection_point_filtre_segments():
    report, flows = _scenario()
    from netcross_gtk4.dashboard_context import select_point

    sel = select_point(DashboardSelection(), "A")
    snap = build_dashboard_snapshot(report, flows, selection=sel)
    # la paire (A, B) contient A -> conservee
    assert any("A" in r["pair"] for r in snap.segment_rows)
    assert "point=A" in snap.selection_summary


def _flow_proto(flow):
    """Helper local : protocole d'un flow (cle strict ou NAT)."""
    key = flow.key
    if key and key[0] == "NAT" and len(key) >= 2:
        return key[1]
    return key[0] if key else None
