# SPDX-License-Identifier: GPL-3.0-or-later
"""Rafales, conservation de volume, résolution et intégration réelle (#1135)."""

from __future__ import annotations

import importlib
import json
import sys

import pytest

from netcross_core.analysis import analyse
from netcross_core.expert_rules import get_rule
from netcross_core.microburst import (
    MIN_PEAK_MEDIAN_RATIO,
    MIN_UTILISATION_PCT,
    MIN_WINDOW_PACKETS,
    _merge_episode,
    detect_microbursts,
    format_microburst,
)
from netcross_core.multiscale import SlidingWindowPeak
from netcross_core.redact import redact_packets
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import build_findings
from tests.conftest import make_pkt

T0 = 1_700_000_000.0
SPEEDS = {"A": {"speed_bps": 10**9, "ts_resolution": 1e-6, "speed_source": "if_speed"}}


def traffic(bursts=(0.05,)):
    """1 Gbit/s pendant 2 ms sur fond à 100 Mbit/s, paquets de 1000 o."""
    packets = []
    tick = 0
    while tick < 200_000:
        burst = any(start * 1e6 <= tick < (start + 0.002) * 1e6 for start in bursts)
        packets.append(
            make_pkt(
                ts=T0 + tick / 1e6,
                length=1000,
                src="10.42.0.1" if burst else "10.42.0.2",
                key_id=len(packets),
            )
        )
        tick += 8 if burst else 80
    return packets


def events(result, point="A"):
    return result[point]["events"]


def test_rafale_2ms_detectee_sur_fond_10_pour_cent_et_emetteurs():
    detected = events(detect_microbursts(traffic(), SPEEDS))
    assert len(detected) == 1
    event = detected[0]
    assert event["point"] == "A"
    assert event["start"] <= T0 + 0.05 <= event["end"]
    assert 0.002 <= event["duration_s"] <= 0.005
    assert event["peak_bps"] == pytest.approx(10**9, rel=0.1)
    assert event["utilisation_pct"] >= 80
    assert event["peak_median_ratio"] >= 4
    assert event["threshold_kind"] == "utilisation_and_relative"
    assert event["top_senders"][0]["src"] == "10.42.0.1"
    assert event["bytes"] == event["packets"] * 1000
    assert event["end"] - event["start"] == pytest.approx(event["duration_s"], abs=1e-6)
    assert "% de la vitesse d'interface" in format_microburst(event)


def test_trafic_lisse_meme_volume_aucune_detection():
    bursty = traffic()
    smooth = [make_pkt(ts=T0 + i * 0.2 / len(bursty), length=1000) for i in range(len(bursty))]
    assert sum(p.length for p in smooth) == sum(p.length for p in bursty)
    assert not events(detect_microbursts(smooth, SPEEDS))
    assert not events(detect_microbursts(smooth))


def test_vitesse_inconnue_seuil_relatif_explicite_sans_infini_json():
    event = events(detect_microbursts(traffic()))[0]
    assert event["speed_bps"] is None
    assert event["utilisation_pct"] is None
    assert event["threshold_kind"] == "relative"
    assert event["baseline_kind"] == "median_nonempty_windows"
    assert event["baseline_bps"] > 0
    assert "vitesse inconnue, seuil relatif" in format_microburst(event)
    json.dumps(event, allow_nan=False)


def test_vitesse_connue_refuse_pic_sous_80_pour_cent():
    # Même contraste, mais seulement ~10 % d'un lien à 10 Gbit/s.
    assert not events(detect_microbursts(traffic(), {"A": {"speed_bps": 10**10}}))


def test_resolution_grossiere_refus_visible_pas_de_fausse_precision():
    result = detect_microbursts(traffic(), {"A": {"speed_bps": 10**9, "ts_resolution": 0.002}})["A"]
    assert len(result["refused"]) == 2
    assert all("résolution" in refusal for refusal in result["refused"])
    assert result["scales_s"] == [0.01]
    assert not result["events"]


def test_toutes_echelles_refusees():
    result = detect_microbursts(traffic(), {"A": {"ts_resolution": 1.0}})["A"]
    assert len(result["refused"]) == 3
    assert result["scales_s"] == []
    assert result["events"] == []


def test_deux_rafales_points_isoles_et_capture_desordonnee():
    packets = traffic((0.05, 0.15))
    expected = detect_microbursts(packets, SPEEDS)
    assert len(events(expected)) == 2
    assert detect_microbursts(reversed(packets), SPEEDS) == expected
    second = [make_pkt(point="B", ts=p.ts, length=p.length, src=p.src) for p in packets]
    result = detect_microbursts(packets + second, SPEEDS)
    assert len(events(result, "B")) == 2
    assert all(e["utilisation_pct"] is None for e in events(result, "B"))


def test_vide_paquets_invalides_et_paquet_isole():
    assert detect_microbursts([]) == {}
    assert detect_microbursts([make_pkt(ts=float("nan")), make_pkt(length=0), make_pkt(length=-1)]) == {}
    assert not events(detect_microbursts([make_pkt(length=1_000_000)], SPEEDS))


def test_silence_long_ne_cree_pas_un_tableau_dense():
    packets = [make_pkt(ts=T0), make_pkt(ts=T0 + 365 * 86400)]
    assert not events(detect_microbursts(packets))


def test_fusion_chevauchement_conserve_la_reference_de_la_plus_haute_crete():
    rows = []
    low = {"start_ns": 0, "end_ns": 100, "peak_bps": 10, "scale_s": 0.01, "baseline_bps": 2, "peak_median_ratio": 5}
    high = {**low, "start_ns": 50, "end_ns": 200, "peak_bps": 20, "scale_s": 0.001, "baseline_bps": 4}
    _merge_episode(rows, low)
    _merge_episode(rows, high)
    assert len(rows) == 1
    assert rows[0] == {**high, "start_ns": 0}
    _merge_episode(rows, {**low, "start_ns": 300, "end_ns": 400})
    assert len(rows) == 2


def test_fenetre_courante_distincte_du_maximum_historique():
    window = SlidingWindowPeak(0.001)
    assert window.current_bytes == window.current_packets == 0
    window.update(0, 1000)
    window.update(1_000_000, 100)
    assert window.current_bytes == 100
    assert window.current_packets == 1
    assert window.peak_bytes == 1000


def test_analyse_findings_json_et_texte(capsys):
    report = analyse({}, ["A"], traffic(), link_speeds=SPEEDS)
    assert report.link_speeds == SPEEDS
    assert len(events(report.microbursts)) == 1
    findings = [f for f in build_findings(report) if f.rule_id == "microburst"]
    assert len(findings) == 1
    assert findings[0].severity == "a_surveiller"
    assert findings[0].segment == "A"
    document = build_json_report_document(report)
    assert document["microbursts"] == report.microbursts
    assert document["link_speeds"] == SPEEDS
    assert any(f.get("rule_id") == "microburst" for f in document["findings"])
    print_report(report)
    assert "Microrafales" in capsys.readouterr().out
    rule = get_rule("microburst")
    assert rule.thresholds == {
        "min_peak_median_ratio": MIN_PEAK_MEDIAN_RATIO,
        "min_utilisation_pct": MIN_UTILISATION_PCT,
        "min_window_packets": MIN_WINDOW_PACKETS,
    }


def test_analyse_sans_metadonnees_et_absence_de_fuite_apres_redaction():
    packets = traffic()
    redact_packets(packets)
    report = analyse({}, ["A"], packets)
    assert events(report.microbursts)[0]["threshold_kind"] == "relative"
    serialized = json.dumps(build_json_report_document(report), allow_nan=False)
    assert "10.42.0.1" not in serialized
    assert "10.42.0.2" not in serialized


def test_source_absente_signalee_sans_affecter_les_totaux():
    packets = traffic()
    for packet in packets:
        packet.src = None
    event = events(detect_microbursts(packets))[0]
    assert event["top_senders"] == [{"src": "indéterminé", "bytes": event["bytes"], "share_pct": 100.0}]


def test_cli_transmet_vitesse_avant_la_detection(monkeypatch, capsys, tmp_path):
    import cross_capture_analyzer_cli as cli
    import netcross_core.link_speed as link_speed

    capture = tmp_path / "capture.pcapng"
    capture.touch()
    monkeypatch.setattr(cli, "parse_capture", lambda *args, **kwargs: traffic())
    monkeypatch.setattr(cli, "read_capture_comments", lambda captures: [])
    monkeypatch.setattr(cli, "read_capture_infos", lambda captures: [])
    monkeypatch.setattr(link_speed, "resolve_link_speeds", lambda captures, overrides: SPEEDS)
    monkeypatch.setattr(sys, "argv", ["netcross", "--capture", f"A={capture}"])
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code
    text = capsys.readouterr().out
    assert "Microrafales" in text
    assert "% de la vitesse d'interface" in text
    assert "vitesse inconnue, seuil relatif" not in text


@pytest.mark.parametrize("surface", ["api", "gui"])
def test_pipeline_fichier_transmet_vitesse_et_resolution(surface, monkeypatch, tmp_path):
    import netcross_core.link_speed as link_speed

    capture = tmp_path / "capture.pcapng"
    capture.touch()
    captures = [("A", str(capture))]
    # Une résolution de 2 ms interdit les deux échelles fines : si les
    # métadonnées sont perdues par la surface, une rafale serait signalée.
    metadata = {"A": {"speed_bps": 10**9, "ts_resolution": 0.002}}
    monkeypatch.setattr(link_speed, "resolve_link_speeds", lambda captures: metadata)
    if surface == "api":
        api = importlib.import_module("netcross_api.app")

        monkeypatch.setattr(api, "_read_captures", lambda *args: traffic())
        outcome = api._analyse_captures(captures, None, False, options=api.ApiAnalysisOptions(redact=True))
        report = outcome[3]
        assert outcome[2]["microbursts"] == report.microbursts
    else:
        import netcross_gtk4.analysis_pipeline as pipeline

        monkeypatch.setattr(pipeline, "load_packets", lambda *args, **kwargs: traffic())
        outcome = pipeline.run_analysis_pipeline(captures, pipeline.AnalysisOptions(parallel=False))
        report = outcome.report
    assert report.link_speeds == metadata
    assert len(report.microbursts["A"]["refused"]) == 2
    assert not events(report.microbursts)


def test_comparaison_directe_ignore_metadonnees_des_fichiers_non_utilises(monkeypatch, tmp_path):
    import netcross_core.link_speed as link_speed
    import netcross_gtk4.analysis_pipeline as pipeline
    from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline

    captures = [("A", str(tmp_path / "baseline.pcapng"))]
    ignored = [("A", str(tmp_path / "ne-doit-pas-etre-lu.pcapng"))]
    reads = []

    def resolve(paths):
        reads.append(paths)
        return SPEEDS

    monkeypatch.setattr(link_speed, "resolve_link_speeds", resolve)
    monkeypatch.setattr(pipeline, "load_packets", lambda *args, **kwargs: traffic())
    run_diff_pipeline(captures, ignored, DiffOptions(), current_packets=traffic())
    assert reads == [captures]
