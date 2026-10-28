# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_causality.py -- tests du moteur de correlation causale
(netcross_core.causality, Job 4/issue #4).

Verifie que :
- Les trois patterns (congestion, PMTUD, ralentissement serveur) declenchent
  correctement et renseignent cause/impact sur les bons ExpertEvent.
- Les ExpertEvent dont le rule_id ne participe pas au pattern gardent
  cause/impact a None.
- Les objets sont mutes en place (meme liste, ordre preserve, evidence inchange).
- Diagnosis.cause/impact sont derives des ExpertEvent enrichis.
- Aucune correlation quand les symptomes sont sur des segments differents.
"""

from netcross_core.causality import correlate_diagnosis_causes, correlate_event_causes
from netcross_core.expert_model import Diagnosis, EvidenceLink, ExpertEvent


def _ev(
    segment: str = "A",
    category: str = "TCP",
    rule_id: str | None = None,
    severity: str = "anomalie",
    message: str = "test",
) -> ExpertEvent:
    return ExpertEvent(
        category=category,
        severity=severity,
        segment=segment,
        message=message,
        rule_id=rule_id,
    )


# -- Pattern 1 : Congestion / saturation ----------------------------------


def test_congestion_declenche_cause_et_impact():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
    ]
    result = correlate_event_causes(events)
    assert result is events  # meme liste (mutation en place)
    for ev in result:
        assert ev.cause is not None
        assert "Congestion" in ev.cause
        assert ev.impact is not None
        assert "bout en bout" in ev.impact


def test_congestion_avec_saturation_au_lieu_de_bufferbloat():
    events = [
        _ev(segment="B", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="B", category="TCP", rule_id="tcp_retransmission_fast"),
        _ev(segment="B", category="Saturation", rule_id="saturation"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None
        assert "Congestion" in ev.cause


def test_congestion_evenement_non_concerne_garde_none():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
        _ev(segment="A", category="DNS", rule_id="dns_nxdomain"),
    ]
    correlate_event_causes(events)
    dns_ev = next(e for e in events if e.rule_id == "dns_nxdomain")
    assert dns_ev.cause is None
    assert dns_ev.impact is None


def test_congestion_manque_un_symptome_pas_de_correlation():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        # pas de bufferbloat ni saturation
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is None
        assert ev.impact is None


def test_congestion_symptomes_sur_segments_differents_pas_de_correlation():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="B", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is None


# -- Pattern 2 : PMTUD / MTU insuffisant -----------------------------------


def test_pmtud_declenche_avec_fragmentation():
    events = [
        _ev(segment="A -> B", category="PMTUD", rule_id="pmtud_blackhole"),
        _ev(segment="A -> B", category="Fragmentation", rule_id="fragmentation_new"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None
        assert "MTU" in ev.cause
        assert ev.impact is not None
        assert "stagnent" in ev.impact


def test_pmtud_declenche_avec_icmp_fragmentation_needed():
    events = [
        _ev(segment="A -> B", category="PMTUD", rule_id="pmtud_blackhole"),
        _ev(segment="A -> B", category="ICMP", rule_id="icmp_fragmentation_needed"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None
        assert "MTU" in ev.cause


def test_pmtud_manque_un_symptome_pas_de_correlation():
    events = [
        _ev(segment="A -> B", category="PMTUD", rule_id="pmtud_blackhole"),
    ]
    correlate_event_causes(events)
    assert events[0].cause is None


# -- Pattern 3 : Ralentissement applicatif --------------------------------


def test_server_processing_declenche_avec_http_slow():
    events = [
        _ev(segment="global", category="Reseau/Serveur", rule_id="server_processing_dominant"),
        _ev(segment="global", category="HTTP", rule_id="http_slow_response"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None
        assert "applicatif" in ev.cause
        assert ev.impact is not None
        assert "applicative" in ev.impact


def test_server_processing_declenche_avec_http_timeout():
    events = [
        _ev(segment="global", category="Reseau/Serveur", rule_id="server_processing_dominant"),
        _ev(segment="global", category="HTTP", rule_id="http_timeout"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None


def test_server_processing_manque_http_pas_de_correlation():
    events = [
        _ev(segment="global", category="Reseau/Serveur", rule_id="server_processing_dominant"),
        _ev(segment="global", category="DNS", rule_id="dns_slow_resolution"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is None


# -- Preservation des objets -----------------------------------------------


def test_mutation_en_place_ordre_preserve():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
    ]
    original_ids = [id(e) for e in events]
    result = correlate_event_causes(events)
    assert [id(e) for e in result] == original_ids


def test_evidence_inchange():
    ev1 = _ev(segment="A", category="Pertes", rule_id="loss_per_segment")
    ev1.evidence = [EvidenceLink(point="A", text="paquet perdu")]
    ev2 = _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto")
    ev3 = _ev(segment="A", category="Saturation", rule_id="bufferbloat")
    events = [ev1, ev2, ev3]
    correlate_event_causes(events)
    assert len(events[0].evidence) == 1
    assert events[0].evidence[0].text == "paquet perdu"


def test_evenement_sans_rule_id_garde_none():
    events = [
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
        _ev(segment="A", category="Custom", rule_id=None),
    ]
    correlate_event_causes(events)
    custom_ev = next(e for e in events if e.rule_id is None)
    assert custom_ev.cause is None
    assert custom_ev.impact is None


def test_liste_vide_pas_erreur():
    events: list[ExpertEvent] = []
    result = correlate_event_causes(events)
    assert result == []


# -- Diagnosis -------------------------------------------------------------


def test_diagnosis_cause_derivee_des_events_enrichis():
    ev1 = _ev(segment="A", category="Pertes", rule_id="loss_per_segment")
    ev2 = _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto")
    ev3 = _ev(segment="A", category="Saturation", rule_id="bufferbloat")
    events = [ev1, ev2, ev3]
    correlate_event_causes(events)
    diag = Diagnosis(segment="A", events=events)
    correlate_diagnosis_causes([diag])
    assert diag.cause is not None
    assert "Congestion" in diag.cause
    assert diag.impact is not None


def test_diagnosis_sans_event_enrichi_garde_none():
    ev1 = _ev(segment="A", category="DNS", rule_id="dns_nxdomain")
    diag = Diagnosis(segment="A", events=[ev1])
    correlate_diagnosis_causes([diag])
    assert diag.cause is None
    assert diag.impact is None


def test_diagnosis_vide_pas_erreur():
    diag = Diagnosis(segment="A", events=[])
    correlate_diagnosis_causes([diag])
    assert diag.cause is None
    assert diag.impact is None


# -- Cas mixtes -----------------------------------------------------------


def test_deux_patterns_sur_meme_segment():
    """Si deux patterns different declenchent sur le meme segment, chaque
    evenement ne recoit que le premier pattern qui le concerne (priorite
    ordre _PATTERNS)."""
    events = [
        # Pattern congestion
        _ev(segment="A", category="Pertes", rule_id="loss_per_segment"),
        _ev(segment="A", category="TCP", rule_id="tcp_retransmission_rto"),
        _ev(segment="A", category="Saturation", rule_id="bufferbloat"),
        # Pattern PMTUD
        _ev(segment="A", category="PMTUD", rule_id="pmtud_blackhole"),
        _ev(segment="A", category="Fragmentation", rule_id="fragmentation_new"),
    ]
    correlate_event_causes(events)
    loss_ev = next(e for e in events if e.rule_id == "loss_per_segment")
    pmtud_ev = next(e for e in events if e.rule_id == "pmtud_blackhole")
    assert "Congestion" in loss_ev.cause
    assert "MTU" in pmtud_ev.cause


def test_segment_global_avec_server_processing():
    """Le segment 'global' est valide pour le pattern ralentissement serveur."""
    events = [
        _ev(segment="global", category="Reseau/Serveur", rule_id="server_processing_dominant"),
        _ev(segment="global", category="HTTP", rule_id="http_timeout"),
    ]
    correlate_event_causes(events)
    for ev in events:
        assert ev.cause is not None
