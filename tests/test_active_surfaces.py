# SPDX-License-Identifier: GPL-3.0-or-later
"""Parcours CLI/API réels sur paquets typés, backends réseau interdits."""

import importlib
import json
import sys

import pytest
from conftest import make_pkt
from fastapi.testclient import TestClient

import cross_capture_analyzer_cli as cli
from netcross_core.active import paris_traceroute, twamp
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.security import findings as security

api = importlib.import_module("netcross_api.app")


def paquets(point, _path, **_kwargs):
    base = {
        "point": point,
        "src": "192.0.2.1",
        "dst": "198.51.100.2",
        "sport": 49000,
        "dport": 443,
        "proto": "TCP",
        "flags": "PA",
        "df": True,
        "payload_hash": "donnees",
    }
    petits = [make_pkt(**base, key_id=10, seq=10, length=100, frame_number=1, ts=0.005 if point == "B" else 0.0)]
    grands = [
        make_pkt(**base, key_id=110, seq=110, length=1500, frame_number=42 + i, ts=1.0 + i * 0.2) for i in range(3)
    ]
    return petits + grands if point == "A" else petits


@pytest.fixture
def backends(monkeypatch):
    appels = []
    monkeypatch.setattr(api, "_ACTIVE_ALLOWED", False)

    def trace(proposition):
        appels.append(proposition)
        return paris_traceroute.ResultatParis(
            proposition.five_tuple,
            "2026-11-09T00:00:00Z",
            "indisponible",
            "backend absent dans cet essai sans réseau",
            envoyees=0,
        )

    def mesure(cible, port, **_kwargs):
        appels.append(("twamp", cible, port))
        return twamp.ResultatTwamp(cible, port, "maintenant", False, "aucune sonde dans ce backend simulé")

    monkeypatch.setattr(paris_traceroute, "mesurer_proposition", trace)
    monkeypatch.setattr(twamp, "mesurer", mesure)
    monkeypatch.setattr(cli, "parse_capture", paquets)
    monkeypatch.setattr(api, "parse_capture", paquets)
    monkeypatch.setattr(api, "scan_capture_exploits", lambda *_a, **_k: [])
    monkeypatch.setattr(security, "scan_capture_exploits", lambda *_a, **_k: [])
    return appels


@pytest.mark.parametrize(
    "options,emissions",
    [
        ([], 0),
        (["--active-dry-run"], 0),
        (["--confirm-active", "--active-dry-run"], 0),
        (["--confirm-active"], 2),
    ],
)
def test_cli_bout_en_bout(monkeypatch, tmp_path, capsys, backends, options, emissions):
    fichier = tmp_path / "rapport.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "netcross",
            "--capture",
            "A=a.pcap",
            "--capture",
            "B=b.pcap",
            "--order",
            "A,B",
            "--json-report",
            str(fichier),
            *options,
        ],
    )
    cli.main()
    assert len(backends) == emissions
    document = json.loads(fichier.read_text())
    confirmation = document["active_confirmation"]
    if options:
        assert len(confirmation["measurements"]) == 2
        mesure = confirmation["measurements"][0]
        assert mesure["proposal"]["rule_ids"] == ["pmtud_blackhole", "loss_per_segment"]
        assert mesure["proposal"]["five_tuple"]["proto"] == "TCP"
        assert "Confirmation active" in capsys.readouterr().out
    else:
        assert confirmation is None
        assert "Confirmation active" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "confirm,dry,emissions",
    [
        (False, False, 0),
        (False, True, 0),
        (True, True, 0),
        (True, False, 2),
    ],
)
def test_api_multi_bout_en_bout(backends, confirm, dry, emissions, monkeypatch):
    if emissions:
        monkeypatch.setattr(api, "_ACTIVE_ALLOWED", True)
    with TestClient(api.app) as client:
        reponse = client.post(
            "/captures/multi?wait=true",
            files=[
                ("files", ("a.pcap", b"capture-A", "application/octet-stream")),
                ("files", ("b.pcap", b"capture-B", "application/octet-stream")),
            ],
            data={
                "labels": "A,B",
                "points_order": "A,B",
                "confirm_active": str(confirm).lower(),
                "active_dry_run": str(dry).lower(),
            },
        )
        assert reponse.status_code == 201, reponse.text
        identifiant = reponse.json()["analysis_id"]
        document = client.get(f"/analyses/{identifiant}/report").json()
        assert len(backends) == emissions
        if confirm or dry:
            assert len(document["active_confirmation"]["measurements"]) == 2
        else:
            assert document["active_confirmation"] is None


@pytest.mark.parametrize("option", ["confirm_active", "active_dry_run"])
def test_api_refuse_anonymisation_avant_lecture(option, monkeypatch):
    monkeypatch.setattr(api, "parse_capture", lambda *_a, **_k: pytest.fail("lecture interdite"))
    with TestClient(api.app) as client:
        reponse = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", b"capture", "application/octet-stream")},
            data={"label": "A", "redact": "true", option: "true"},
        )
    assert reponse.status_code == 400
    assert "incompatibles" in reponse.text


def test_api_emission_fermee_par_defaut(backends):
    with TestClient(api.app) as client:
        reponse = client.post(
            "/captures?wait=true",
            files={"file": ("a.pcap", b"capture", "application/octet-stream")},
            data={"label": "A", "confirm_active": "true"},
        )
    assert reponse.status_code == 403
    assert "NETCROSS_API_ACTIVE=1" in reponse.text
    assert backends == []


@pytest.mark.parametrize("flag", ["--confirm-active", "--active-dry-run"])
def test_cli_refuse_anonymisation_avant_lecture(flag, monkeypatch):
    monkeypatch.setattr(cli, "parse_capture", lambda *_a, **_k: pytest.fail("lecture interdite"))
    monkeypatch.setattr(sys, "argv", ["netcross", "--capture", "A=a.pcap", "--redact", flag])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2


def test_preuves_de_perte_uniquement_sur_demande():
    pkts = paquets("A", "") + paquets("B", "")
    flows = correlate(pkts)
    passif = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    assert passif.loss_count["B"] == 1
    assert passif.active_flow_evidence == {}
    actif = analyse(flows, points_order=["A", "B"], all_packets=pkts, collect_active_evidence=True)
    cles = actif.active_flow_evidence[("loss_per_segment", "B")]
    assert len(cles) == 1
    assert set(flows[cles[0]]) == {"A"}
