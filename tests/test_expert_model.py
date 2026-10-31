# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.expert_model -- verifie uniquement la forme du contrat (les
neuf objets de la Session 0 exposent bien les champs decrits par leur
docstring, comparables par valeur comme tout dataclass). La logique de
peuplement reelle (quelles categories recoivent des preuves, comment un
Report devient des Flow/ExpertEvent/ComplianceResult...) est testee cote
consommateur (tests/test_synthesis.py, test_correlate.py,
test_expert_events.py, test_compliance.py) -- ce module reste un simple
conteneur de donnees, sans comportement propre a verifier ici.
"""

from netcross_core.expert_model import (
    ComplianceResult,
    Conversation,
    Diagnosis,
    EvidenceLink,
    ExpertEvent,
    Flow,
    PacketEvidence,
    ReferenceProfile,
)


def test_evidence_link_expose_point_et_text():
    e = EvidenceLink("A -> B", "exemple de preuve")
    assert e.point == "A -> B"
    assert e.text == "exemple de preuve"


def test_evidence_link_packet_absent_par_defaut():
    # Session 35 : packet est optionnel, None sans le passer -- aucune
    # regression pour les sept categories qui n'ont pas encore de
    # PacketEvidence cablee (voir synthesis.py).
    e = EvidenceLink("A -> B", "exemple de preuve")
    assert e.packet is None


def test_evidence_link_egalite_par_valeur():
    assert EvidenceLink("A", "x") == EvidenceLink("A", "x")
    assert EvidenceLink("A", "x") != EvidenceLink("A", "y")
    assert EvidenceLink("A", "x") != EvidenceLink("B", "x")
    assert EvidenceLink("A", "x") != EvidenceLink("A", "x", packet=PacketEvidence("A", 1))


def test_packet_evidence_expose_point_et_frame_number():
    p = PacketEvidence("A -> B", 42)
    assert p.point == "A -> B"
    assert p.frame_number == 42


def test_packet_evidence_egalite_par_valeur():
    assert PacketEvidence("A", 1) == PacketEvidence("A", 1)
    assert PacketEvidence("A", 1) != PacketEvidence("A", 2)
    assert PacketEvidence("A", 1) != PacketEvidence("B", 1)


def test_evidence_link_avec_packet():
    e = EvidenceLink("A -> B", "seq=42 retransmis 3x", packet=PacketEvidence("A -> B", 42))
    assert e.packet == PacketEvidence("A -> B", 42)


# -- confidence/first_seen/last_seen (Session 40, premier lot de la
# Session 2 de FEATURES.md section 13.3) ------------------------------


def test_expert_event_confidence_first_seen_last_seen_absents_par_defaut():
    # Retrocompatible avec tout ExpertEvent construit avant cette
    # session -- None sans les passer, meme convention que cause/impact.
    ev = ExpertEvent("Pertes", "anomalie", "A", "20% de pertes")
    assert ev.confidence is None
    assert ev.first_seen is None
    assert ev.last_seen is None


def test_expert_event_confidence_first_seen_last_seen_valorisables():
    ev = ExpertEvent("Wireshark/TShark", "info", "A", "m", confidence=1.0, first_seen=10.0, last_seen=12.5)
    assert ev.confidence == 1.0
    assert ev.first_seen == 10.0
    assert ev.last_seen == 12.5


# -- layer/protocol (Session 41, deuxieme lot de la Session 2 de
# FEATURES.md section 13.3) ---------------------------------------------


def test_expert_event_layer_protocol_absents_par_defaut():
    # Retrocompatible avec tout ExpertEvent construit avant cette
    # session -- None sans les passer, meme convention que confidence/
    # first_seen/last_seen.
    ev = ExpertEvent("Pertes", "anomalie", "A", "20% de pertes")
    assert ev.layer is None
    assert ev.protocol is None


def test_expert_event_layer_protocol_valorisables():
    ev = ExpertEvent("Wireshark/TShark", "info", "A", "m", layer="transport", protocol="TCP")
    assert ev.layer == "transport"
    assert ev.protocol == "TCP"


# -- flow_keys (Session 43, troisieme lot de la Session 2 de FEATURES.md
# section 13.3) ----------------------------------------------------------


def test_expert_event_flow_keys_liste_vide_par_defaut():
    # Retrocompatible avec tout ExpertEvent construit avant cette
    # session -- [] (pas None) sans le passer, meme convention que
    # evidence.
    ev = ExpertEvent("Pertes", "anomalie", "A", "20% de pertes")
    assert ev.flow_keys == []


def test_expert_event_flow_keys_valorisable():
    key = ("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000)
    ev = ExpertEvent("Wireshark/TShark", "info", "A", "m", flow_keys=[key])
    assert ev.flow_keys == [key]


# -- packet_evidence (Session 44, quatrieme lot de la Session 2 de
# FEATURES.md section 13.3) -------------------------------------------


def test_expert_event_packet_evidence_liste_vide_par_defaut():
    # Retrocompatible avec tout ExpertEvent construit avant cette
    # session -- [] (pas None) sans le passer, meme convention que
    # evidence/flow_keys.
    ev = ExpertEvent("Pertes", "anomalie", "A", "20% de pertes")
    assert ev.packet_evidence == []


def test_expert_event_packet_evidence_valorisable():
    pe = PacketEvidence(point="A", frame_number=42)
    ev = ExpertEvent("Wireshark/TShark", "info", "A", "m", packet_evidence=[pe])
    assert ev.packet_evidence == [pe]


# -- remediation (Session 45, cinquieme et dernier lot cote ExpertEvent de
# la Session 2 de FEATURES.md section 13.3) -------------------------------


def test_expert_event_remediation_absente_par_defaut():
    # Retrocompatible avec tout ExpertEvent construit avant cette
    # session -- None sans le passer, meme convention que confidence/
    # layer/protocol.
    ev = ExpertEvent("Pertes", "anomalie", "A", "20% de pertes")
    assert ev.remediation is None


def test_expert_event_remediation_valorisable():
    ev = ExpertEvent("Wireshark/TShark", "info", "A", "m", remediation="verifier le RTT")
    assert ev.remediation == "verifier le RTT"


# -- Flow / Conversation (Session 36) --


def test_flow_valeurs_par_defaut():
    f = Flow(key=("TCP", "10.0.0.1", 1, "10.0.0.2", 2, 3))
    assert f.points == []
    assert f.packet_count == {}
    assert f.byte_count == {}
    assert f.first_ts == {}
    assert f.last_ts == {}
    assert f.endpoints is None


def test_flow_egalite_par_valeur():
    assert Flow(key=("A",)) == Flow(key=("A",))
    assert Flow(key=("A",)) != Flow(key=("B",))


def test_conversation_valeurs_par_defaut():
    c = Conversation(endpoints=("10.0.0.1", "10.0.0.2"))
    assert c.flow_keys == []
    assert c.packet_count == 0
    assert c.byte_count == 0


# -- ExpertEvent / Diagnosis (Session 36) --


def test_expert_event_cause_impact_toujours_none_par_defaut():
    # Moteur de causalite absent (Session 3, FEATURES.md section 13.3) --
    # cause/impact ne doivent jamais etre devines ici.
    ev = ExpertEvent(category="PMTUD", severity="anomalie", segment="A -> B", message="noir PMTUD")
    assert ev.cause is None
    assert ev.impact is None
    assert ev.evidence == []


def test_expert_event_source_vaut_netcross_par_defaut():
    # Session 1 (ajoute apres la Session 36) : retrocompatible -- tout
    # appelant qui construit un ExpertEvent sans preciser `source` (ex:
    # build_expert_events, cablee avant l'ajout de ce champ) obtient
    # "netcross", jamais "tshark" par accident.
    ev = ExpertEvent(category="PMTUD", severity="anomalie", segment="A -> B", message="noir PMTUD")
    assert ev.source == "netcross"


def test_expert_event_source_tshark_explicite():
    # Ne pas confondre avec ReferenceProfile.source ci-dessous (reference
    # bibliographique type "RFC 1191") : ici, provenance de l'evenement
    # lui-meme -- voir netcross_core.wireshark_expert.
    ev = ExpertEvent(
        category="Wireshark/TShark",
        severity="info",
        segment="A -> B",
        message="tcp.analysis.retransmission : 3 occurrence(s)",
        source="tshark",
    )
    assert ev.source == "tshark"


def test_diagnosis_regroupe_des_expert_events():
    ev = ExpertEvent(category="PMTUD", severity="anomalie", segment="A -> B", message="noir PMTUD")
    d = Diagnosis(segment="A -> B", events=[ev])
    assert d.events == [ev]
    assert d.cause is None
    assert d.impact is None


# -- ReferenceProfile / ComplianceResult (Session 36) --


def test_reference_profile_expose_ses_champs():
    ref = ReferenceProfile(
        id="pmtud-no-blackhole",
        metric="pmtud_blackhole_total",
        operator="<=",
        threshold=0.0,
        unit="occurrence(s)",
        source="RFC 1191 / RFC 8201",
    )
    assert ref.id == "pmtud-no-blackhole"
    assert ref.operator == "<="
    assert ref.threshold == 0.0


def test_compliance_result_expose_reference_observed_status():
    ref = ReferenceProfile(id="x", metric="m", operator="<=", threshold=1.0, unit="%", source="s")
    result = ComplianceResult(reference=ref, observed=0.5, status="CONFORME")
    assert result.reference is ref
    assert result.observed == 0.5
    assert result.status == "CONFORME"
