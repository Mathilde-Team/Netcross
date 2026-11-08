# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.expert_events -- build_expert_events()/build_diagnoses()
(Session 36, objets de contrat de la Session 0 : ExpertEvent/Diagnosis).
Verifie que la conversion Finding/DiffFinding -> ExpertEvent ne fait que
recopier des champs deja calcules (rien de nouveau detecte), que
cause/impact restent toujours None (moteur de causalite absent), et que
le regroupement par segment de build_diagnoses() est correct.
"""

from netcross_core.baseline_diff import DiffFinding
from netcross_core.expert_model import EvidenceLink
from netcross_report.expert_events import build_diagnoses, build_expert_events
from netcross_report.synthesis import Finding


def test_build_expert_events_recopie_les_champs_du_finding():
    f = Finding("anomalie", "PMTUD", "A -> B", "noir PMTUD", evidence=[EvidenceLink("A -> B", "seq=123")])
    events = build_expert_events([f])
    assert len(events) == 1
    ev = events[0]
    assert ev.category == "PMTUD"
    assert ev.severity == "anomalie"
    assert ev.segment == "A -> B"
    assert ev.message == "noir PMTUD"
    assert ev.evidence == [EvidenceLink("A -> B", "seq=123")]


def test_build_expert_events_cause_impact_toujours_none():
    f = Finding("anomalie", "Pertes", "A", "20% de pertes")
    ev = build_expert_events([f])[0]
    assert ev.cause is None
    assert ev.impact is None


def test_build_expert_events_layer_protocol_toujours_none():
    # Session 41 : Finding.category est un regroupement metier ("Pertes"
    # ici), pas un protocole/une couche fiable a en deduire -- voir
    # docstring de module d'expert_model.py.
    f = Finding("anomalie", "Pertes", "A", "20% de pertes")
    ev = build_expert_events([f])[0]
    assert ev.layer is None
    assert ev.protocol is None


def test_build_expert_events_evidence_vide_par_defaut():
    f = Finding("info", "DNS", "A", "contexte")
    ev = build_expert_events([f])[0]
    assert ev.evidence == []


def test_build_expert_events_attache_l_event_au_finding():
    """ "Finding enrichi" (Session 0) : depuis un Finding deja construit, on
    peut naviguer vers l'ExpertEvent qui le represente."""
    f = Finding("anomalie", "PMTUD", "A -> B", "noir PMTUD")
    assert f.event is None
    events = build_expert_events([f])
    assert f.event is events[0]


def test_build_expert_events_fonctionne_avec_un_diff_finding():
    """DiffFinding est duck-type comme Finding (severity/category/segment/
    message/evidence), mais ne declare PAS de champ `event` -- ne doit pas
    lever d'exception, ni en ajouter un dynamiquement."""
    df = DiffFinding("regression", "PMTUD", "A -> B", "noir PMTUD nouveau")
    events = build_expert_events([df])
    assert len(events) == 1
    assert events[0].category == "PMTUD"
    assert not hasattr(df, "event")


def test_build_diagnoses_regroupe_par_segment():
    f1 = Finding("anomalie", "PMTUD", "A -> B", "m1")
    f2 = Finding("anomalie", "TCP", "A -> B", "m2")
    f3 = Finding("anomalie", "Pertes", "C -> D", "m3")
    events = build_expert_events([f1, f2, f3])
    diagnoses = build_diagnoses(events)
    assert len(diagnoses) == 2
    by_segment = {d.segment: d for d in diagnoses}
    assert len(by_segment["A -> B"].events) == 2
    assert len(by_segment["C -> D"].events) == 1


def test_build_diagnoses_cause_impact_toujours_none():
    f = Finding("anomalie", "PMTUD", "A -> B", "m")
    diag = build_diagnoses(build_expert_events([f]))[0]
    assert diag.cause is None
    assert diag.impact is None


def test_build_diagnoses_liste_vide():
    assert build_diagnoses([]) == []


def test_build_expert_events_confidence_first_seen_last_seen_toujours_none():
    # Session 40 : Finding ne porte aujourd'hui aucune notion de
    # confiance ni de timestamp -- voir docstring expert_model.
    # ExpertEvent, seule netcross_core.wireshark_expert les calcule.
    f = Finding("anomalie", "PMTUD", "A -> B", "noir PMTUD")
    ev = build_expert_events([f])[0]
    assert ev.confidence is None
    assert ev.first_seen is None
    assert ev.last_seen is None


def test_build_expert_events_recopie_le_rule_id_du_finding():
    # Session 48 : miroir exact de remediation, mais dans l'autre sens --
    # voir docstring de module d'expert_model.py.
    f = Finding("anomalie", "TCP", "A", "3 paquets avec fenetre TCP=0", rule_id="tcp_zero_window")
    ev = build_expert_events([f])[0]
    assert ev.rule_id == "tcp_zero_window"


def test_build_expert_events_rule_id_none_par_defaut():
    """Un Finding sans correspondance au catalogue (voir docstring de
    module de synthesis.py) garde rule_id=None cote ExpertEvent aussi --
    pas d'AttributeError pour un consommateur generique."""
    f = Finding("anomalie", "TLS", "A", "certificat hors validite")
    ev = build_expert_events([f])[0]
    assert ev.rule_id is None


def test_build_expert_events_rule_id_none_pour_un_diff_finding():
    """DiffFinding ne declare pas rule_id -- meme discipline duck-type
    que pour evidence (getattr defensif), ne doit pas lever d'exception."""
    df = DiffFinding("regression", "PMTUD", "A -> B", "noir PMTUD nouveau")
    ev = build_expert_events([df])[0]
    assert ev.rule_id is None
