# SPDX-License-Identifier: GPL-3.0-or-later
# ruff: noqa: F811 -- fixtures pytest importées de test_issue_902_api_live
"""Issue #1105 : points ``probe://`` de ``POST /live-captures``.

La fenêtre de sonde est tirée par dépendance injectée (aucun réseau) :
la capture en direct accepte un point sonde, écrit son pcapng comme
fichier du point et l'analyse habituelle suit ; une sonde muette fait
échouer la capture (erreur explicite), pas une analyse vide."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.test_issue_902_api_live import CLE, _attendre, _corps, _pkts, actif, api, client, recorder  # noqa: F401

pytest.importorskip("fastapi", reason="extra [api] non installé")

PROBE = "probe://sonde.lan:9443/ROUTEUR"


@pytest.fixture
def sonde_fenetre(monkeypatch):
    """Faux tirage de fenêtre de sonde : pcapng factice, appels mémorisés."""
    appels = {"fenetres": [], "raise": None}

    def tirer(interface, debut, fin, bpf=None):
        if appels["raise"]:
            raise appels["raise"]
        appels["fenetres"].append((interface, bpf, fin > debut))
        return b"\x0a\x0d\x0d\x0a" + b"\x00" * 60

    monkeypatch.setitem(api.live_captures._deps, "fetch_probe_window", tirer)
    return appels


def test_point_probe_capture_puis_analyse(actif, recorder, sonde_fenetre):
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(points=[{"name": "SONDE", "interface": PROBE}]), headers=CLE)
        etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "completed", etat
    assert sonde_fenetre["fenetres"] == [(PROBE, None, True)]
    assert recorder["start"] == []  # aucun enregistreur local : la sonde tamponne
    analyse = api.store.get(etat["analysis_id"])
    assert analyse["metadata"]["interfaces"] == {"SONDE": PROBE}


def test_point_probe_hors_liste_blanche_accepte(actif, recorder, sonde_fenetre, monkeypatch):
    """Une sonde n'est pas une interface locale du serveur : la liste
    blanche des interfaces ne s'applique pas (issue #1105) -- l'accès
    reste celui de la session (clé API) puis du mTLS avec la sonde."""
    monkeypatch.setenv("NETCROSS_API_LIVE_INTERFACES", "eth0")
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        rep = client.post("/live-captures", json=_corps(points=[{"name": "SONDE", "interface": PROBE}]), headers=CLE)
        etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "completed", etat


def test_point_probe_sonde_muette_echec_explicite(actif, recorder, sonde_fenetre):
    """Une sonde injoignable fait échouer la capture (erreur explicite,
    pas une analyse silencieusement vide)."""
    sonde_fenetre["raise"] = OSError("sonde injoignable (test)")
    rep = client.post("/live-captures", json=_corps(points=[{"name": "SONDE", "interface": PROBE}]), headers=CLE)
    etat = _attendre(rep.json()["capture_id"])
    assert etat["status"] == "failed"
    assert "SONDE" in etat["error"] and "sonde injoignable" in etat["error"]
    assert etat["analysis_id"] is None


def test_point_probe_ring_buffer_refuse(actif, recorder, sonde_fenetre):
    rep = client.post(
        "/live-captures",
        json=_corps(points=[{"name": "SONDE", "interface": PROBE}], ring_buffer={"files": 3, "seconds": 30}),
        headers=CLE,
    )
    assert rep.status_code == 400
    assert "ring_buffer incompatible avec une source probe://" in rep.json()["detail"]
    assert sonde_fenetre["fenetres"] == []


def test_point_probe_live_report_refuse(actif, recorder, sonde_fenetre):
    rep = client.post(
        "/live-captures",
        json=_corps(points=[{"name": "SONDE", "interface": PROBE}], live_report={"interval": 2.0}),
        headers=CLE,
    )
    assert rep.status_code == 400
    assert "live_report incompatible avec une source probe://" in rep.json()["detail"]
    assert sonde_fenetre["fenetres"] == []
