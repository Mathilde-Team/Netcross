# SPDX-License-Identifier: GPL-3.0-or-later
# ruff: noqa: F811 -- fixtures réutilisées des tests de capture en direct
"""Dernier relevé, authentification commune et formats analysés réellement."""

import importlib
import time
from unittest.mock import patch

import pytest
from prometheus_client.openmetrics.parser import text_string_to_metric_families as parse_openmetrics
from prometheus_client.parser import text_string_to_metric_families as parse_prometheus

from netcross_api.metrics_routes import LatestMetrics, MetricsReportWriter
from netcross_core.live_report import LiveAggregator, LiveReportWriter
from netcross_core.models import Report
from netcross_report.metrics_export import DEFAULT_MAX_POINTS, collect_live_samples
from tests.conftest import make_pkt
from tests.test_issue_902_api_live import CLE, _attendre, _pkts, actif, client, recorder  # noqa: F401
from tests.test_issue_907_live_report_api import flux  # noqa: F401

api = importlib.import_module("netcross_api.app")


@pytest.fixture(autouse=True)
def propre(monkeypatch):
    monkeypatch.setattr(api, "_API_TOKEN", "secret")
    monkeypatch.setattr(api.live_captures.metrics, "_samples", ())


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "incorrecte"}])
def test_refus_sans_cle_valide(headers):
    assert client.get("/metrics", headers=headers).status_code == 401
    assert client.get("/metrics?format=openmetrics", headers=headers).status_code == 401


def test_meme_mode_sans_authentification_que_api(monkeypatch):
    monkeypatch.setattr(api, "_API_TOKEN", None)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert list(parse_prometheus(response.text)) == []
    assert client.get("/metrics?format=inconnu").status_code == 422


def test_releves_remplaces_et_formats(tmp_path):
    latest = api.live_captures.metrics
    writer = MetricsReportWriter(tmp_path, None, 1, latest, "direct")
    aggregator = LiveAggregator(started_at=1000)
    aggregator.register("LAN")
    for expected in (1, 2):
        aggregator.add(make_pkt(point="LAN", ts=1000 + expected, is_retransmission=True))
        writer.publish(*aggregator.tick(now=1000 + expected))
        for format, parser in (("prometheus", parse_prometheus), ("openmetrics", parse_openmetrics)):
            response = client.get(f"/metrics?format={format}", headers=CLE)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert ("application/openmetrics-text" if format == "openmetrics" else "text/plain") in response.headers[
                "content-type"
            ]
            samples = [s for family in parser(response.text) for s in family.samples]
            packets = [s for s in samples if s.name == "netcross_point_packets_total"]
            assert len(packets) == 1
            assert packets[0].value == expected
            assert not any(s.name.startswith("netcross_segment_") for s in samples)
    before = latest.samples()
    aggregator.add(make_pkt(point="LAN", ts=1003))
    assert latest.samples() == before  # collecte passive, pas de tick implicite
    other = MetricsReportWriter(tmp_path / "autre", None, 1, latest, "suivant")
    other.publish(*aggregator.tick(now=1004))
    assert {s.label("run") for s in latest.samples()} == {"suivant"}
    assert len(before) == 2  # ancien tuple indépendant du remplacement


def test_borne_cardinalite_et_aucun_faux_score():
    samples = collect_live_samples(
        {"points": {f"P{i}": {"packets": 1, "retransmissions": 0} for i in range(100)}}, "direct"
    )
    assert len(samples) == 2 * DEFAULT_MAX_POINTS
    assert sum(s.value for s in samples if s.name == "netcross_point_packets_total") == 100
    assert {s.name for s in samples} == {
        "netcross_point_packets_total",
        "netcross_point_retransmissions_total",
    }
    assert collect_live_samples({"points": {}}, "vide") == []


def test_redaction_et_actualisation_meme_si_disque_en_echec(tmp_path, monkeypatch):
    latest = LatestMetrics()
    writer = MetricsReportWriter(tmp_path, None, 1, latest, "direct", redact=True)
    snapshot = {"points": {"10.23.45.67": {"packets": 3, "retransmissions": 1}}}

    def refuser(*args):
        raise OSError("disque plein")

    monkeypatch.setattr(LiveReportWriter, "publish", refuser)
    with pytest.raises(OSError, match="disque plein"):
        writer.publish(snapshot, {})
    assert all(s.label("point") != "10.23.45.67" for s in latest.samples())
    assert latest.samples()[0].value == 3


@pytest.mark.parametrize("redaction_map", [None, []])
def test_metriques_finales_mesurees(redaction_map):
    latest = api.live_captures.metrics
    report = Report(points=["10.23.45.67", "WAN"], pairs=[("10.23.45.67", "WAN")])
    report.packet_count["10.23.45.67"] = 100
    report.seen_count["10.23.45.67"] = 10
    report.loss_count["WAN"] = 2
    report.latency[("10.23.45.67", "WAN")] = [10, 20]
    latest.report({"report_obj": report, "findings": [], "redaction_map": redaction_map}, "analyse")
    samples = latest.samples()
    assert next(s.value for s in samples if s.name == "netcross_segment_loss_ratio") == 0.2
    assert next(
        s.value for s in samples if s.name == "netcross_segment_delay_seconds" and s.label("quantile") == "0.95"
    ) == pytest.approx(0.0195)
    labels = " ".join(value for s in samples for _, value in s.labels)
    assert ("10.23.45.67" in labels) is (redaction_map is None)


def test_branchement_reel_capture_puis_analyse(actif, recorder, flux):
    body = {
        "points": [{"name": "LAN", "interface": "eth0"}, {"name": "WAN", "interface": "eth1"}],
        "duration": 60,
        "live_report": {"interval": 1},
    }
    with patch("netcross_api.app.parse_capture", side_effect=_pkts):
        response = client.post("/live-captures", json=body, headers=CLE)
        assert response.status_code == 202
        capture_id = response.json()["capture_id"]
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                samples = api.live_captures.metrics.samples()
                if sum(s.value for s in samples if s.name == "netcross_point_packets_total") == 6:
                    break
                time.sleep(0.02)
            assert {s.label("run") for s in samples} == {capture_id}
            assert sum(s.value for s in samples if s.name == "netcross_point_packets_total") == 6
            assert client.get("/metrics", headers=CLE).status_code == 200
        finally:
            client.post(f"/live-captures/{capture_id}/stop", headers=CLE)
            final = _attendre(capture_id)
    assert final["status"] == "completed"
    assert {s.label("run") for s in api.live_captures.metrics.samples()} == {final["analysis_id"]}
    assert "netcross_segment_loss_ratio" in client.get("/metrics", headers=CLE).text
