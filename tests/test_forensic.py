# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_forensic.py -- tests de l'index de correlation bidirectionnel
(netcross_core.forensic, Job 8/issue #5).

Verifie la navigation dans les deux sens :
- Evenement → flows → paquets
- Paquet → flow → evenement
"""

from conftest import make_pkt

from netcross_core.correlate import correlate
from netcross_core.expert_model import EvidenceLink, ExpertEvent, Flow, PacketEvidence
from netcross_core.forensic import (
    ForensicIndex,
    annotations_by_tag,
    annotations_sidecar_path,
    read_annotations,
    write_annotations,
)
from netcross_core.models import PacketAnnotation, Pkt


def _pkt(**overrides) -> Pkt:
    return make_pkt(**overrides)


def _build_index(packets=None, events=None):
    """Construit un ForensicIndex a partir de paquets synthetiques."""
    if packets is None:
        packets = [
            _pkt(point="A", frame_number=1, ts=1.0),
            _pkt(point="A", frame_number=2, ts=2.0),
            _pkt(point="B", frame_number=1, ts=1.5),
            _pkt(point="B", frame_number=2, ts=2.5),
        ]
    flows = correlate(packets)
    if events is None:
        events = []
    return ForensicIndex(all_packets=packets, flows=flows, events=events)


# -- Paquet → flow --------------------------------------------------------


def test_packet_to_flow_retourne_le_bon_flow():
    idx = _build_index()
    flow = idx.packet_to_flow("A", 1)
    assert flow is not None
    assert "A" in flow.points


def test_packet_to_flow_paquet_inexistant_retourne_none():
    idx = _build_index()
    assert idx.packet_to_flow("A", 999) is None


def test_packet_to_flow_paquet_dans_deux_points_distincts():
    """Deux paquets avec le meme frame_number mais sur des points
    differents doivent chacun retrouver leur flow."""
    idx = _build_index()
    flow_a = idx.packet_to_flow("A", 1)
    flow_b = idx.packet_to_flow("B", 1)
    assert flow_a is not None
    assert flow_b is not None
    assert "A" in flow_a.points
    assert "B" in flow_b.points


# -- Flow → paquets -------------------------------------------------------


def test_flow_to_packets_retourne_tous_les_paquets():
    packets = [
        _pkt(point="A", frame_number=1, ts=1.0),
        _pkt(point="A", frame_number=2, ts=2.0),
        _pkt(point="B", frame_number=1, ts=1.5),
    ]
    idx = _build_index(packets=packets)
    flows = correlate(packets)
    first_key = next(iter(flows))
    flow = idx._flow_by_key[first_key]
    pkts = idx.flow_to_packets(flow)
    assert len(pkts) == 3  # 2 sur A + 1 sur B


def test_flow_to_packets_flow_vide_retourne_liste_vide():
    idx = _build_index()
    empty_flow = Flow(key=("TCP", "x", 1, "y", 2, 3))
    assert idx.flow_to_packets(empty_flow) == []


# -- Evenement → flows (par segment) --------------------------------------


def test_event_to_flows_matching_par_point():
    """Un ExpertEvent avec segment="A" doit trouver les flows qui
    passent par le point A."""
    idx = _build_index()
    ev = ExpertEvent(
        category="Pertes",
        severity="anomalie",
        segment="A",
        message="paquets manquants",
    )
    flows = idx.event_to_flows(ev)
    assert len(flows) >= 1
    for f in flows:
        assert "A" in f.points


def test_event_to_flows_matching_par_paire():
    """Un ExpertEvent avec segment="A -> B" doit trouver les flows qui
    passent par A ou B."""
    idx = _build_index()
    ev = ExpertEvent(
        category="TCP",
        severity="a_surveiller",
        segment="A -> B",
        message="retransmission",
    )
    flows = idx.event_to_flows(ev)
    assert len(flows) >= 1


def test_event_to_flows_matching_par_flow_keys():
    """Un ExpertEvent avec flow_keys peuple (source tshark) doit
    matcher directement par cle de flux."""
    packets = [_pkt(point="A", frame_number=1, ts=1.0)]
    flows = correlate(packets)
    first_key = next(iter(flows))
    ev = ExpertEvent(
        category="TCP",
        severity="info",
        segment="A",
        message="flag tshark",
        flow_keys=[first_key],
    )
    idx = _build_index(packets=packets, events=[ev])
    result = idx.event_to_flows(ev)
    assert len(result) == 1
    assert result[0].key == first_key


def test_event_to_flows_matching_par_evidence_packet():
    """Un ExpertEvent dont l'evidence reference un PacketEvidence doit
    retrouver le flow du paquet."""
    packets = [
        _pkt(point="A", frame_number=42, ts=1.0),
        _pkt(point="A", frame_number=43, ts=2.0),
    ]
    ev = ExpertEvent(
        category="PMTUD",
        severity="anomalie",
        segment="A",
        message="PMTUD black hole",
        evidence=[EvidenceLink(point="A", text="seg 1200o", packet=PacketEvidence(point="A", frame_number=42))],
    )
    idx = _build_index(packets=packets, events=[ev])
    flows = idx.event_to_flows(ev)
    assert len(flows) == 1


def test_event_to_flows_segment_global_matche_tout():
    """Un ExpertEvent avec segment='global' ne matche aucun point nomme
    specifiquement, mais ne doit pas planter."""
    idx = _build_index()
    ev = ExpertEvent(
        category="DNS",
        severity="a_surveiller",
        segment="global",
        message="resolution lente",
    )
    flows = idx.event_to_flows(ev)
    # 'global' ne correspond a aucun point de capture -> liste vide
    assert flows == []


# -- Evenement → paquets ---------------------------------------------------


def test_event_to_packets_depuis_evidence():
    """Les paquets d'evidence (EvidenceLink.packet) doivent etre
    retournes en premier."""
    packets = [
        _pkt(point="A", frame_number=10, ts=1.0),
        _pkt(point="A", frame_number=11, ts=2.0),
    ]
    ev = ExpertEvent(
        category="TCP",
        severity="anomalie",
        segment="A",
        message="retransmission",
        evidence=[EvidenceLink(point="A", text="RST", packet=PacketEvidence(point="A", frame_number=10))],
    )
    idx = _build_index(packets=packets, events=[ev])
    pkts = idx.event_to_packets(ev)
    assert len(pkts) >= 1
    assert pkts[0].point == "A"
    assert pkts[0].frame_number == 10


def test_event_to_packets_depuis_packet_evidence():
    """Les packet_evidence (source tshark) doivent etre retournes."""
    ev = ExpertEvent(
        category="TCP",
        severity="info",
        segment="A",
        message="flag expert",
        packet_evidence=[PacketEvidence(point="A", frame_number=5)],
    )
    idx = _build_index(events=[ev])
    pkts = idx.event_to_packets(ev)
    assert len(pkts) >= 1
    assert any(p.frame_number == 5 for p in pkts)


def test_event_to_packets_complement_depuis_flows():
    """Les paquets des flows lies doivent completer la liste."""
    packets = [
        _pkt(point="A", frame_number=1, ts=1.0),
        _pkt(point="A", frame_number=2, ts=2.0),
    ]
    ev = ExpertEvent(
        category="Pertes",
        severity="anomalie",
        segment="A",
        message="paquets manquants",
    )
    idx = _build_index(packets=packets, events=[ev])
    pkts = idx.event_to_packets(ev)
    # Au moins les paquets du flow lie au segment "A"
    assert len(pkts) >= 2


def test_event_to_packets_sans_rien_retourne_vide():
    """Un evenement sans evidence ni flow lie retourne une liste vide."""
    idx = _build_index()
    ev = ExpertEvent(
        category="DNS",
        severity="a_surveiller",
        segment="global",
        message="resolution lente",
    )
    pkts = idx.event_to_packets(ev)
    assert pkts == []


# -- Flow → evenements -----------------------------------------------------


def test_flow_to_events_par_segment():
    """Les evenements dont le segment correspond a un point du flow
    doivent etre retournes."""
    packets = [_pkt(point="A", frame_number=1, ts=1.0)]
    ev = ExpertEvent(
        category="Pertes",
        severity="anomalie",
        segment="A",
        message="paquets manquants",
    )
    idx = _build_index(packets=packets, events=[ev])
    flows = correlate(packets)
    first_key = next(iter(flows))
    flow = idx._flow_by_key[first_key]
    events = idx.flow_to_events(flow)
    assert len(events) == 1
    assert events[0].message == "paquets manquants"


def test_flow_to_events_par_flow_keys():
    """Les evenements dont flow_keys contient la cle du flow doivent
    etre retournes (source tshark)."""
    packets = [_pkt(point="A", frame_number=1, ts=1.0)]
    flows = correlate(packets)
    first_key = next(iter(flows))
    ev = ExpertEvent(
        category="TCP",
        severity="info",
        segment="A",
        message="flag expert",
        flow_keys=[first_key],
    )
    idx = _build_index(packets=packets, events=[ev])
    flow = idx._flow_by_key[first_key]
    events = idx.flow_to_events(flow)
    assert len(events) == 1


def test_flow_to_events_aucun_event_retourne_vide():
    idx = _build_index()
    packets = [_pkt(point="A", frame_number=1, ts=1.0)]
    flows = correlate(packets)
    first_key = next(iter(flows))
    flow = idx._flow_by_key[first_key]
    events = idx.flow_to_events(flow)
    assert events == []


# -- Cas limites -----------------------------------------------------------


def test_index_vide_pas_erreur():
    idx = ForensicIndex(all_packets=[], flows={}, events=[])
    assert idx.packet_to_flow("A", 1) is None


def test_index_avec_nat_tolerant():
    """L'index doit fonctionner en mode NAT-tolerant."""
    pk1 = _pkt(point="A", frame_number=1, ts=1.0, payload_hash="abc")
    pk2 = _pkt(point="B", frame_number=1, ts=1.5, payload_hash="abc")
    packets = [pk1, pk2]
    flows = correlate(packets, nat_tolerant=True)
    idx = ForensicIndex(
        all_packets=packets,
        flows=flows,
        events=[],
        nat_tolerant=True,
    )
    flow = idx.packet_to_flow("A", 1)
    assert flow is not None


def test_event_to_flows_dedoublonne():
    """Si un flow est trouve par plusieurs strategies, il n'apparait
    qu'une fois."""
    packets = [_pkt(point="A", frame_number=1, ts=1.0)]
    flows = correlate(packets)
    first_key = next(iter(flows))
    ev = ExpertEvent(
        category="TCP",
        severity="info",
        segment="A",
        message="flag",
        flow_keys=[first_key],
        evidence=[EvidenceLink(point="A", text="test", packet=PacketEvidence(point="A", frame_number=1))],
    )
    idx = _build_index(packets=packets, events=[ev])
    result = idx.event_to_flows(ev)
    assert len(result) == 1


# -- Etiquetage et signets sur paquets (Job 40/issue #160) -------------------


def test_read_annotations_sans_sidecar_retourne_liste_vide(tmp_path):
    """Aucun sidecar sur disque : pas une erreur, juste "pas d'annotation"
    (critere d'acceptation explicite de l'issue #160)."""
    capture = str(tmp_path / "capture.pcapng")
    assert read_annotations(capture) == []


def test_write_puis_read_annotations_persiste(tmp_path):
    capture = str(tmp_path / "capture.pcapng")
    annotations = [
        PacketAnnotation(frame_number=12, tag="suspect", comment="retransmission etrange"),
        PacketAnnotation(frame_number=42, tag="a-verifier", color="#ff0000"),
    ]
    write_annotations(capture, annotations)
    reread = read_annotations(capture)
    assert reread == annotations


def test_write_annotations_ecrase_le_sidecar_precedent(tmp_path):
    """write_annotations remplace integralement -- pas de fusion."""
    capture = str(tmp_path / "capture.pcapng")
    write_annotations(capture, [PacketAnnotation(frame_number=1, tag="premier")])
    write_annotations(capture, [PacketAnnotation(frame_number=2, tag="second")])
    reread = read_annotations(capture)
    assert reread == [PacketAnnotation(frame_number=2, tag="second")]


def test_annotations_sidecar_path_deduit_du_chemin_de_capture(tmp_path):
    capture = str(tmp_path / "run1.pcapng")
    assert annotations_sidecar_path(capture) == f"{capture}.annotations.json"


def test_annotations_by_tag_regroupe():
    annotations = [
        PacketAnnotation(frame_number=1, tag="suspect"),
        PacketAnnotation(frame_number=2, tag="suspect"),
        PacketAnnotation(frame_number=3, tag="ok"),
    ]
    grouped = annotations_by_tag(annotations)
    assert set(grouped.keys()) == {"suspect", "ok"}
    assert len(grouped["suspect"]) == 2
    assert len(grouped["ok"]) == 1


def test_annotations_by_tag_liste_vide():
    assert annotations_by_tag([]) == {}
