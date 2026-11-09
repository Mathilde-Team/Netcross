# SPDX-License-Identifier: GPL-3.0-or-later
"""Restitutions réelles de la simulation ; aucune émission à l'export."""

import subprocess

import pytest
from test_active_surfaces import paquets

from netcross_core.active import paris_traceroute, twamp
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_report.active_confirmation import confirmer_rapport
from netcross_report.html_report import render_html_report
from netcross_report.json_report import build_json_report_document
from netcross_report.markdown_report import build_markdown_report_document
from netcross_report.pdf import generate_pdf


@pytest.fixture
def rapport(monkeypatch):
    def interdit(*_a, **_k):
        pytest.fail("une restitution ne doit jamais émettre")

    monkeypatch.setattr(paris_traceroute, "mesurer_proposition", interdit)
    monkeypatch.setattr(twamp, "mesurer", interdit)
    pkts = paquets("A", "") + paquets("B", "")
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts, collect_active_evidence=True)
    confirmer_rapport(r, flows, dry_run=True)
    return r


def test_html_markdown_simulation_et_echappement(rapport):
    doc = build_json_report_document(rapport)
    html = render_html_report(doc)
    markdown = build_markdown_report_document(rapport)
    for texte in (html, markdown):
        assert "Confirmation active" in texte
        assert "Simulation sans émission" in texte
        assert "scamper" in texte and "pmtud_blackhole" in texte
        assert "twamp_light" in texte and "loss_per_segment" in texte
    attaque = "<img src=x onerror=alert(1)>"
    rapport.active_confirmation["measurements"][0]["command"] = attaque
    doc = build_json_report_document(rapport)
    html = render_html_report(doc)
    markdown = build_markdown_report_document(rapport)
    assert attaque not in html and attaque not in markdown
    assert "&lt;img" in html and "&lt;img" in markdown


def test_pdf_reel_reextrait(rapport, tmp_path):
    pdf = tmp_path / "confirmation.pdf"
    generate_pdf(rapport, str(pdf))
    resultat = subprocess.run(["pdftotext", str(pdf), "-"], check=True, capture_output=True, text=True)
    assert "Confirmation active" in resultat.stdout
    assert "Simulation sans émission" in resultat.stdout
    assert "scamper" in resultat.stdout
    assert "pmtud_blackhole" in resultat.stdout
    assert "twamp_light" in resultat.stdout
    assert pdf.stat().st_size > 1000
