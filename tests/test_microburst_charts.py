# SPDX-License-Identifier: GPL-3.0-or-later
"""Profils réellement mesurés, preuves aval et rendu PDF des zooms (#1139)."""

import subprocess
from copy import deepcopy
from dataclasses import replace

import matplotlib.pyplot as plt
import pytest
from PIL import Image
from reportlab.platypus import SimpleDocTemplate

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.microburst import add_microburst_profiles, detect_microbursts
from netcross_core.models import Report
from netcross_report.json_report import build_json_report_document
from netcross_report.metric_charts import render_microburst
from netcross_report.pdf import _styles, microburst_section_story
from tests.test_microburst import SPEEDS, T0, traffic


def measured(bursts=(0.05,), window_ms=50):
    packets = traffic(bursts)
    report = Report(points=["A", "B"], pairs=[("A", "B")])
    report.microbursts = detect_microbursts(packets, SPEEDS)
    add_microburst_profiles(report, packets, window_ms)
    return report, packets


def test_profil_volume_exact_et_resolution_bornee():
    report, packets = measured()
    event = report.microbursts["A"]["events"][0]
    profile = event["profile"]
    assert 1 <= len(profile["bytes"]) <= 512
    low = profile["start_offset_s"]
    high = low + sum(profile["durations_s"])
    selected = [p for p in packets if low <= round((p.ts - T0) * 1e6) / 1e6 < high]
    assert sum(profile["bytes"]) == sum(p.length for p in selected)
    assert all(0 < duration <= profile["bin_s"] for duration in profile["durations_s"])
    assert profile["bin_s"] >= event["scale_s"]
    assert max(profile["bytes"]) * 8 / profile["bin_s"] > 800e6
    assert not profile["capture_limited"]


def test_profils_multipoints_independants_et_deterministes():
    report, packets = measured((0.05, 0.12))
    packets += [replace(p, point="B", length=p.length * 2) for p in packets]
    report.microbursts = detect_microbursts(packets)
    before = deepcopy(report.microbursts)
    add_microburst_profiles(report, reversed(packets), 50)
    first = deepcopy(report.microbursts)
    add_microburst_profiles(report, packets, 50)
    assert report.microbursts == first
    for event_a, event_b in zip(first["A"]["events"], first["B"]["events"]):
        assert sum(event_b["profile"]["bytes"]) == 2 * sum(event_a["profile"]["bytes"])
    assert "profile" not in before["A"]["events"][0]


def test_aucun_paquet_pas_de_profil_et_capture_tronquee():
    report, packets = measured(window_ms=1000)
    assert report.microbursts["A"]["events"][0]["profile"]["capture_limited"]
    report.microbursts["inconnu"] = {"events": [{"start": 0, "end": 1}]}
    add_microburst_profiles(report, packets, 1000)
    assert "profile" not in report.microbursts["inconnu"]["events"][0]
    report.microbursts = {}
    add_microburst_profiles(report, packets, 50)
    assert report.microbursts == {}


def test_bornes_initiales_duree_partielle_et_paquets_invalides():
    report, packets = measured()
    event = report.microbursts["A"]["events"][0]
    event["start"] = T0
    report.microbursts["vide"] = {"events": []}
    report.microbursts["hors_capture"] = {"events": [{"start": T0 + 999, "end": T0 + 1000}]}
    invalid = [
        replace(packets[0], ts=float("nan")),
        replace(packets[0], length=0),
        replace(packets[0], point="absent"),
        replace(packets[0], point="hors_capture"),
    ]
    add_microburst_profiles(report, packets + invalid, 50.003)
    assert event["profile"]["start_offset_s"] == 0
    assert event["profile"]["capture_limited"]
    assert 0 < event["profile"]["durations_s"][-1] < event["profile"]["bin_s"]
    assert "profile" not in report.microbursts["hors_capture"]["events"][0]


def association(event, *, losses=12, downstream="B"):
    return {
        "upstream": "A",
        "downstream": downstream,
        "burst_start": event["start"],
        "burst_end": event["end"],
        "losses": losses,
        "evidence": [
            {"kind": "losses", "upstream_ts": event["end"] + 0.001, "ts": event["end"] + 3600},
            {"kind": "retransmissions", "upstream_ts": event["end"] + 0.002},
        ],
    }


def test_rendu_png_reel_pertes_horloge_amont_et_pas_autres_episodes(tmp_path, monkeypatch):
    report, _ = measured()
    event = report.microbursts["A"]["events"][0]
    matching = association(event)
    other = association({**event, "start": event["start"] + 1})
    before = deepcopy(event)
    captured = []
    original = plt.Axes.scatter

    def spy(self, xs, ys, **kwargs):
        captured.append((list(xs), list(ys)))
        return original(self, xs, ys, **kwargs)

    monkeypatch.setattr(plt.Axes, "scatter", spy)
    path = str(tmp_path / "zoom.png")
    assert render_microburst(event, [matching, other], path) == path
    with Image.open(path) as image:
        assert image.width > 500 and image.height > 300
        assert image.getextrema()[0][0] < image.getextrema()[0][1]
    assert captured == [(pytest.approx([(event["end"] + 0.001 - event["start"]) * 1000]), [0])]
    assert event == before
    assert not plt.get_fignums()


def test_sans_profil_ancien_rapport_et_sans_perte(tmp_path):
    assert render_microburst({}, [], str(tmp_path / "absent.png")) is None
    report, _ = measured()
    assert render_microburst(report.microbursts["A"]["events"][0], [], str(tmp_path / "sans_perte.png"))
    assert not (tmp_path / "absent.png").exists()


def test_figure_fermee_meme_si_ecriture_echoue(tmp_path, monkeypatch):
    report, _ = measured()

    def fail(*args, **kwargs):
        raise OSError("disque indisponible")

    monkeypatch.setattr(plt.Figure, "savefig", fail)
    with pytest.raises(OSError, match="disque"):
        render_microburst(report.microbursts["A"]["events"][0], [], str(tmp_path / "erreur.png"))
    assert not plt.get_fignums()


def test_pdf_reel_un_zoom_par_rafale_et_anciens_rapports(tmp_path):
    report, _ = measured((0.05, 0.12))
    styles = _styles()
    report.microburst_correlations = [association(report.microbursts["A"]["events"][0])]
    story = microburst_section_story(report, styles, str(tmp_path))
    output = tmp_path / "rafales.pdf"
    SimpleDocTemplate(str(output)).build(story)
    text = subprocess.run(["pdftotext", str(output), "-"], capture_output=True, text=True, check=True).stdout
    assert text.count("Crete glissante") == 2
    assert "cause physique n'est pas prouvee" in " ".join(text.split())
    assert len(list(tmp_path.glob("microburst_*.png"))) == 2
    images = subprocess.run(["pdfimages", "-list", str(output)], capture_output=True, text=True, check=True).stdout
    assert images.count("image") >= 2
    report.microbursts["A"]["events"][0].pop("profile")
    report.microbursts["A"]["events"][1].pop("profile")
    assert microburst_section_story(report, styles, str(tmp_path)) == []


def test_analyse_complete_produit_profils():
    packets = traffic()
    report = analyse(correlate(packets), ["A"], packets, link_speeds=SPEEDS)
    assert report.microbursts["A"]["events"][0]["profile"]["bytes"]


def test_rapport_complet_avec_vraie_perte_et_json(tmp_path, monkeypatch):
    import json

    from netcross_report.pdf import generate_pdf
    from tests.test_microburst_causality import real_report

    monkeypatch.delenv("NETCROSS_MICROBURST_WINDOW_MS", raising=False)
    report = real_report()
    assert report.microburst_correlations[0]["losses"] == 1
    document = build_json_report_document(report)
    assert document["microbursts"]["A"]["events"][0]["profile"]["bytes"]
    json.dumps(document, allow_nan=False)
    plotted = []

    def spy(event, correlations, path):
        plotted.append((event["point"], len(correlations)))
        return render_microburst(event, correlations, path)

    monkeypatch.setattr("netcross_report.pdf.render_microburst", spy)
    path = tmp_path / "rapport_complet.pdf"
    generate_pdf(report, str(path))
    text = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True, check=True).stdout
    assert "Microrafales et pertes aval" in text
    assert len(plotted) == sum(len(record["events"]) for record in report.microbursts.values())
    assert ("A", 1) in plotted
