"""Tests du planificateur de mesures actives (issue #1063) -- sans reseau."""

from __future__ import annotations

import socket
import subprocess

import pytest

from netcross_core.active import planner
from netcross_core.active.planner import (
    ELIGIBLE_RULES,
    PARIS_TRACEROUTE,
    TWAMP_LIGHT,
    TWAMP_PORT,
    FiveTuple,
    ProposedMeasurement,
    five_tuple_from_flow_key,
    ineligibility_reason,
    plan_from_diagnoses,
    plan_measurements,
)
from netcross_core.expert_model import Diagnosis, ExpertEvent

TCP_KEY = ("TCP", "10.0.0.1", 40000, "192.0.2.10", 443, None)
UDP_KEY = ("UDP", "10.0.0.1", 5004, "192.0.2.20", 5004, None)
ICMP_KEY = ("ICMP", "10.0.0.1", None, "192.0.2.30", None, None)


def _ev(rule_id="loss_per_segment", segment="ROUTEUR->SERVEUR", severity="anomalie", flow_keys=None):
    return ExpertEvent(
        category="perte",
        severity=severity,
        segment=segment,
        message="m",
        rule_id=rule_id,
        flow_keys=[TCP_KEY] if flow_keys is None else flow_keys,
    )


@pytest.fixture(autouse=True)
def _aucun_reseau(monkeypatch):
    """Toute tentative d'emission reseau ou de sous-processus fait echouer le test."""

    def interdit(*_a, **_k):
        raise AssertionError("emission reseau ou sous-processus interdit dans le planificateur")

    monkeypatch.setattr(socket, "socket", interdit)
    monkeypatch.setattr(socket, "create_connection", interdit)
    monkeypatch.setattr(socket, "getaddrinfo", interdit)
    monkeypatch.setattr(subprocess, "run", interdit)
    monkeypatch.setattr(subprocess, "Popen", interdit)


# -- five_tuple_from_flow_key ------------------------------------------------------


def test_five_tuple_tcp_udp_icmp():
    assert five_tuple_from_flow_key(TCP_KEY) == FiveTuple("TCP", "10.0.0.1", 40000, "192.0.2.10", 443)
    assert five_tuple_from_flow_key(UDP_KEY) == FiveTuple("UDP", "10.0.0.1", 5004, "192.0.2.20", 5004)
    assert five_tuple_from_flow_key(ICMP_KEY) == FiveTuple("ICMP", "10.0.0.1", None, "192.0.2.30", None)
    assert five_tuple_from_flow_key(("ICMPv6", "fe80::1", None, "2001:db8::1", None, None)).proto == "ICMPv6"
    assert five_tuple_from_flow_key(("tcp", "a", 1, "b", 2, None)).proto == "TCP"


@pytest.mark.parametrize(
    "key",
    [
        ("NAT", "TCP", "hash", 12),  # mode --nat-tolerant : pas de 5-uplet
        ("TCP", "a", 1),  # trop courte
        ("ARP", "a", None, "b", None, None),  # protocole non sondable
        ("TCP", "", 1, "b", 2, None),  # adresse absente
        ("UDP", "a", None, "b", 53, None),  # port absent
        (None, "a", 1, "b", 2, None),
    ],
)
def test_five_tuple_cles_inexploitables(key):
    assert five_tuple_from_flow_key(key) is None


def test_five_tuple_str():
    assert str(FiveTuple("TCP", "a", 1, "b", 2)) == "TCP a:1 -> b:2"
    assert str(FiveTuple("ICMP", "a", None, "b", None)) == "ICMP a -> b"


# -- eligibilite ----------------------------------------------------------------------


def test_eligible():
    assert ineligibility_reason(_ev()) is None


@pytest.mark.parametrize(
    ("kwargs", "attendu"),
    [
        ({"rule_id": "dns_timeout"}, "sans mesure active"),
        ({"rule_id": None}, "sans mesure active"),
        ({"segment": "global"}, "non localise"),
        ({"segment": " Global "}, "non localise"),
        ({"segment": ""}, "non localise"),
        ({"severity": "info"}, "informatif"),
        ({"flow_keys": []}, "aucun 5-uplet"),
        ({"flow_keys": [("NAT", "TCP", "h", 1)]}, "aucun 5-uplet"),
    ],
)
def test_ineligible(kwargs, attendu):
    raison = ineligibility_reason(_ev(**kwargs))
    assert raison is not None
    assert attendu in raison


@pytest.mark.parametrize("rule", ["http_slow_response", "tls_cert_mismatch", "arp_ip_conflict", "stp_instability"])
def test_constats_applicatifs_ou_l2_exclus(rule):
    assert rule not in ELIGIBLE_RULES
    assert plan_measurements([_ev(rule_id=rule)]) == []


# -- plan_measurements ------------------------------------------------------------------


def test_perte_tcp_propose_traceroute_et_twamp():
    mesures = plan_measurements([_ev()])
    assert [m.kind for m in mesures] == [PARIS_TRACEROUTE, TWAMP_LIGHT]
    tr, tw = mesures
    assert tr.five_tuple == FiveTuple("TCP", "10.0.0.1", 40000, "192.0.2.10", 443)
    assert tr.protocol == "tcp-syn"
    assert tr.target_port == 443
    assert "ROUTEUR->SERVEUR" in tr.reason
    assert tw.protocol == "udp"
    assert tw.target_port == TWAMP_PORT
    assert tr.rule_ids == ["loss_per_segment"]
    assert tr.segments == ["ROUTEUR->SERVEUR"]


def test_protocole_de_sonde_suit_le_flux():
    assert plan_measurements([_ev(rule_id="pmtud_blackhole", flow_keys=[UDP_KEY])])[0].protocol == "udp"
    icmp = plan_measurements([_ev(rule_id="ttl_variation", flow_keys=[ICMP_KEY])])
    assert icmp[0].protocol == "icmp-echo"
    assert icmp[0].target_port is None


def test_bufferbloat_twamp_seul():
    assert [m.kind for m in plan_measurements([_ev(rule_id="bufferbloat")])] == [TWAMP_LIGHT]


def test_a_surveiller_eligible():
    assert plan_measurements([_ev(severity="a_surveiller", rule_id="nat_fw_silent_drop")])[0].kind == PARIS_TRACEROUTE


def test_fusion_des_constats_sur_le_meme_flux():
    mesures = plan_measurements(
        [
            _ev(rule_id="loss_per_segment", segment="A->B"),
            _ev(rule_id="tcp_retransmission_rto", segment="B->C"),
            _ev(rule_id="loss_per_segment", segment="A->B"),
        ]
    )
    assert len(mesures) == 2
    assert mesures[0].rule_ids == ["loss_per_segment", "tcp_retransmission_rto"]
    assert mesures[0].segments == ["A->B", "B->C"]


def test_max_flows_par_constat_et_dedoublonnage():
    ev = _ev(rule_id="pmtud_blackhole", flow_keys=[("NAT", "x", "y", 1), TCP_KEY, TCP_KEY, UDP_KEY, ICMP_KEY])
    assert [m.five_tuple.proto for m in plan_measurements([ev])] == ["TCP"]
    assert [m.five_tuple.proto for m in plan_measurements([ev], max_flows_per_event=2)] == ["TCP", "UDP"]
    assert len(plan_measurements([ev], max_flows_per_event=10)) == 3


def test_max_flows_invalide():
    with pytest.raises(ValueError):
        plan_measurements([_ev()], max_flows_per_event=0)


def test_aucun_constat_et_generateur():
    assert plan_measurements([]) == []
    assert len(plan_measurements(e for e in [_ev()])) == 2


def test_sortie_deterministe():
    evs = [_ev(flow_keys=[UDP_KEY]), _ev(rule_id="ttl_variation", flow_keys=[ICMP_KEY]), _ev()]
    assert [m.to_dict() for m in plan_measurements(evs)] == [m.to_dict() for m in plan_measurements(evs)]


def test_to_dict():
    d = plan_measurements([_ev()])[0].to_dict()
    assert d == {
        "kind": "paris_traceroute",
        "five_tuple": {"proto": "TCP", "src": "10.0.0.1", "sport": 40000, "dst": "192.0.2.10", "dport": 443},
        "protocol": "tcp-syn",
        "target_port": 443,
        "reason": "localiser le saut fautif sur le segment ROUTEUR->SERVEUR (loss_per_segment)",
        "rule_ids": ["loss_per_segment"],
        "segments": ["ROUTEUR->SERVEUR"],
    }
    assert isinstance(plan_measurements([_ev()])[0], ProposedMeasurement)


def test_plan_from_diagnoses():
    diags = [
        Diagnosis(segment="A->B", events=[_ev(segment="A->B")]),
        Diagnosis(segment="global", events=[_ev(rule_id="dns_timeout", segment="global")]),
    ]
    assert [m.kind for m in plan_from_diagnoses(diags)] == [PARIS_TRACEROUTE, TWAMP_LIGHT]


def test_module_n_importe_aucune_bibliotheque_reseau():
    import inspect

    source = inspect.getsource(planner)
    for interdit in ("import socket", "import subprocess", "scapy", "urllib", "requests"):
        assert interdit not in source
