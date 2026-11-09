# SPDX-License-Identifier: GPL-3.0-or-later
"""Garde-fous et raccordement actif : aucun réseau dans cette sélection."""

import socket
import subprocess
from dataclasses import replace

import pytest
from conftest import make_pkt

from netcross_core.active import confirmation, paris_traceroute, twamp
from netcross_core.active.planner import FiveTuple
from netcross_core.correlate import correlate
from netcross_core.expert_model import ExpertEvent
from netcross_core.models import Report
from netcross_report import active_confirmation as surface
from netcross_report.json_report import build_json_report_document

KEY = ("UDP", "192.0.2.1", 49000, "198.51.100.2", 33435, 1)


def evenement(rule="loss_per_segment", key=KEY):
    return ExpertEvent(
        category="perte",
        severity="anomalie",
        segment="A -> B",
        message="Perte passive",
        rule_id=rule,
        flow_keys=[key],
    )


@pytest.fixture(autouse=True)
def sans_reseau(monkeypatch):
    def interdit(*_a, **_k):
        raise AssertionError("réseau ou processus interdit")

    monkeypatch.setattr(socket, "socket", interdit)
    monkeypatch.setattr(socket, "getaddrinfo", interdit)
    monkeypatch.setattr(subprocess, "run", interdit)
    monkeypatch.setattr(paris_traceroute, "mesurer_proposition", interdit)
    monkeypatch.setattr(twamp, "mesurer", interdit)


def test_desactive_ne_planifie_meme_pas(monkeypatch):
    monkeypatch.setattr(confirmation, "plan_measurements", lambda _: pytest.fail("planification par défaut"))
    assert confirmation.confirmer([evenement()]) == {
        "enabled": False,
        "dry_run": False,
        "omitted": 0,
        "measurements": [],
    }
    rapport = Report()
    assert surface.confirmer_rapport(rapport, {})["measurements"] == []
    assert rapport.active_confirmation is None
    assert surface.lignes_confirmation(None) == []


@pytest.mark.parametrize("enabled", [False, True])
def test_simulation_prioritaire_et_commandes_reproductibles(enabled):
    resultat = confirmation.confirmer([evenement()], enabled=enabled, dry_run=True)
    assert len(resultat["measurements"]) == 2
    paris, mesure = resultat["measurements"]
    assert paris["status"] == mesure["status"] == "simulation"
    assert paris["result"] is mesure["result"] is None
    assert "scamper" in paris["command"] and "-S 192.0.2.1" in paris["command"]
    assert "udp-paris" in paris["command"] and "198.51.100.2" in mesure["command"]
    assert "nombre=10" in mesure["command"]
    assert "Simulation sans émission." in surface.lignes_confirmation(resultat)


def test_budget_global_explicite():
    events = [evenement(key=(*KEY[:4], 10000 + i, i)) for i in range(10)]
    resultat = confirmation.confirmer(events, dry_run=True)
    assert len(resultat["measurements"]) == 8
    assert resultat["omitted"] == 12


@pytest.mark.parametrize("adresse", ["nom.example.invalid", "224.0.0.1", "0.0.0.0", "255.255.255.255", "fe80::1%eth0"])
def test_cibles_non_litterales_ou_non_unicast_refusees(adresse):
    resultat = confirmation.confirmer([evenement(key=(*KEY[:3], adresse, *KEY[4:]))], dry_run=True)
    assert all(m["status"] == "erreur" for m in resultat["measurements"])
    assert all(m["sent"] is None for m in resultat["measurements"])
    assert any("Erreur :" in texte for texte in surface.lignes_confirmation(resultat))


def test_execution_explicitement_demandee_et_divergence(monkeypatch):
    paris = paris_traceroute.ResultatParis(
        flux=FiveTuple(*KEY[:5]),
        debut="2026-11-09T00:00:00Z",
        statut="ok",
        message="COMPLETED",
        envoyees=3,
        donnees={
            "hops": [
                {"probe_ttl": 1, "addr": "192.0.2.254", "rtt": 1.2},
                {"probe_ttl": 3, "addr": "198.51.100.2", "rtt": 2.5},
            ]
        },
    )
    calls = []

    def trace(proposition):
        calls.append(proposition.kind)
        return paris

    class Twamp:
        def to_dict(self):
            return {
                "reflecteur_present": True,
                "message": "réflecteur présent",
                "statistiques": {"recues": 10, "pertes": 0, "aller_retour_moyen_ms": 4.2},
            }

    def mesure(*args, **kwargs):
        calls.append((args, kwargs))
        return Twamp()

    monkeypatch.setattr(paris_traceroute, "mesurer_proposition", trace)
    monkeypatch.setattr(twamp, "mesurer", mesure)
    resultat = confirmation.confirmer([evenement()], enabled=True)
    assert calls[0] == "paris_traceroute"
    assert calls[1] == (("198.51.100.2", 862), {"nombre": 10, "intervalle": 0.1, "timeout": 1.0})
    a, b = resultat["measurements"]
    assert a["status"] == b["status"] == "ok"
    assert a["result"]["sauts"][1]["non_reponse_pct"] == 100.0
    assert a["result"]["sauts"][0]["reponses"][0]["rtt_ms"] == 1.2
    assert "Divergence possible" in b["divergence"]
    texte = "\n".join(surface.lignes_confirmation(resultat))
    assert "TTL 2" in texte and "RTT et pertes TWAMP" in texte and "COMPLETED" in texte


def test_sans_reflecteur_et_echec_partiel_sans_faux_zero(monkeypatch):
    monkeypatch.setattr(
        paris_traceroute,
        "mesurer_proposition",
        lambda _: paris_traceroute.ResultatParis(FiveTuple(*KEY[:5]), "maintenant", "erreur", "sortie interrompue"),
    )
    monkeypatch.setattr(
        twamp,
        "mesurer",
        lambda *_a, **_k: twamp.ResultatTwamp("198.51.100.2", 862, "maintenant", False, "aucun réflecteur"),
    )
    a, b = confirmation.confirmer([evenement()], enabled=True)["measurements"]
    assert a["result"]["envoyees"] is None and a["result"]["sauts"] == []
    assert b["status"] == "sans_reflecteur"
    assert "Indéterminée" in b["divergence"]
    assert confirmation._sauts({"donnees": {"hops": [{"probe_ttl": 2}]}})[0]["non_reponse_pct"] is None


@pytest.mark.parametrize("exc", [ValueError("refus"), OSError("interruption")])
def test_exception_conserve_incertitude_emission(monkeypatch, exc):
    def echec(_):
        raise exc

    monkeypatch.setattr(paris_traceroute, "mesurer_proposition", echec)
    m = confirmation.confirmer([evenement("pmtud_blackhole")], enabled=True)["measurements"][0]
    assert m["status"] == "erreur" and m["sent"] is None


def rapport_pmtud():
    rapport = Report(points=["A", "B"], pairs=[("A", "B")])
    rapport.pmtud_blackhole[("A", "B")] = 1
    rapport.pmtud_blackhole_examples[("A", "B")] = ["segment de 1500 octets retransmis"]
    rapport.pmtud_blackhole_frames[("A", "B")] = [42]
    pkt = make_pkt(
        point="A",
        proto="TCP",
        src=KEY[1],
        sport=KEY[2],
        dst=KEY[3],
        dport=KEY[4],
        key_id=KEY[5],
        frame_number=42,
        flags="PA",
        payload_hash="donnees",
        df=True,
        length=1500,
        seq=KEY[5],
    )
    return rapport, pkt


def test_preuve_pmtud_vers_flux_exact_et_json():
    rapport, pkt = rapport_pmtud()
    document = surface.confirmer_rapport(rapport, correlate([pkt]), dry_run=True)
    assert len(document["measurements"]) == 1
    proposition = document["measurements"][0]["proposal"]
    assert proposition["five_tuple"]["dst"] == KEY[3]
    assert proposition["rule_ids"] == ["pmtud_blackhole"]
    assert proposition["segments"] == ["A -> B"]
    assert build_json_report_document(rapport)["active_confirmation"] == document


def test_preuves_dupliquees_sans_frame_et_applicatives():
    rapport, pkt = rapport_pmtud()
    rapport.pmtud_blackhole_examples[("A", "B")] = ["première preuve", "même paquet", "sans trame"]
    rapport.pmtud_blackhole_frames[("A", "B")] = [42, 42, None]
    dns = replace(pkt, proto="UDP", dport=53, frame_number=7)
    rapport.dns_timeout["A"] = ["requête sans réponse"]
    rapport.dns_timeout_frames["A"] = [7]
    resultat = surface.confirmer_rapport(rapport, correlate([pkt, dns]), dry_run=True)
    assert len(resultat["measurements"]) == 1
    assert resultat["measurements"][0]["proposal"]["rule_ids"] == ["pmtud_blackhole"]
    assert any(item["rule_id"] == "dns_timeout" for item in resultat["ineligible"])


@pytest.mark.parametrize("cas", ["absente", "ambigue", "segment_inconnu", "sans_frame", "nat", "cle_perimee"])
def test_pas_de_cible_devinee(cas):
    rapport, pkt = rapport_pmtud()
    packets = [pkt]
    if cas == "absente":
        packets = []
    elif cas == "ambigue":
        packets.append(replace(pkt, dport=443))
    elif cas == "segment_inconnu":
        rapport.pairs = []
    elif cas == "sans_frame":
        packets = [replace(pkt, frame_number=None)]
    elif cas == "cle_perimee":
        packets = []
        rapport.loss_count["B"] = 1
        rapport.active_flow_evidence[("loss_per_segment", "B")] = [KEY]
    flows = correlate(packets, nat_tolerant=cas == "nat")
    resultat = surface.confirmer_rapport(rapport, flows, dry_run=True)
    assert resultat["measurements"] == []
    assert resultat["ineligible"]


@pytest.mark.parametrize("enabled,dry_run", [(True, False), (False, True), (True, True)])
def test_redact_refuse_meme_en_simulation(enabled, dry_run):
    with pytest.raises(ValueError, match="anonymisées"):
        surface.confirmer_rapport(Report(), {}, enabled=enabled, dry_run=dry_run, redact=True)
