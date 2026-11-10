# SPDX-License-Identifier: GPL-3.0-or-later
"""Corrélation temporelle localisée, preuves et refus conservateurs (#1137)."""

import json
import math
from dataclasses import replace

import pytest

from netcross_core.analysis import analyse
from netcross_core.causality import MicroburstCorrelator
from netcross_core.clock_sync import EstimationHorloge
from netcross_core.correlate import correlate
from netcross_core.models import Report
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import build_findings
from tests.conftest import make_pkt
from tests.test_microburst import SPEEDS, T0, traffic


@pytest.fixture(autouse=True)
def default_window(monkeypatch):
    monkeypatch.delenv("NETCROSS_MICROBURST_WINDOW_MS", raising=False)


def detector(*, ordered=True, window=None, clock=None, burst_points=("A",), bounds=(0.0, 0.2)):
    report = Report(points=["A", "B", "C"], pairs=[("A", "B"), ("B", "C")])
    report.microbursts = {p: {"events": [{"point": p, "start": 0.01, "end": 0.02}]} for p in burst_points}
    if clock is not None:
        report.clock_offset_estimate[("A", "B")] = clock
    flows = {i: {p: [make_pkt(point=p, ts=ts)] for p in report.points} for i, ts in enumerate(bounds)}
    return MicroburstCorrelator(report, flows, ordered, window)


def retransmission_flow(ts=0.04, upstream_retrans=False, duplicate=False, flag="is_retransmission"):
    original = make_pkt(ts=0.005, payload_hash="charge")
    retrans = replace(original, point="B", ts=ts, frame_number=42, is_duplicate=duplicate, **{flag: True})
    return {
        "A": [original] + ([replace(retrans, point="A")] if upstream_retrans else []),
        "B": [replace(original, point="B"), retrans],
    }


def test_perte_dans_fenetre_segment_localise_et_preuve_exacte():
    engine = detector()
    engine.add_loss("A", "B", make_pkt(ts=0.04, frame_number=17))
    (record,) = engine.results()
    assert (record["upstream"], record["downstream"]) == ("A", "B")
    assert record["losses"] == 1 and record["retransmissions"] == 0
    assert record["association"] == "temporal"
    assert record["physical_cause_proven"] is False
    assert record["window_ms"] == 50
    assert record["evidence"][0]["frame_number"] == 17
    assert record["evidence"][0]["point"] == "A"
    json.dumps(record, allow_nan=False)


@pytest.mark.parametrize("ts", [0.005, 0.019, 0.071, -1, 1, math.nan, math.inf])
def test_pas_de_perte_avant_rafale_hors_fenetre_ou_hors_capture(ts):
    engine = detector()
    engine.add_loss("A", "B", make_pkt(ts=ts))
    assert engine.results() == []


@pytest.mark.parametrize("ts", [0.02, 0.02 + 50 / 1000])
def test_bornes_fenetre_inclusives(ts):
    engine = detector()
    engine.add_loss("A", "B", make_pkt(ts=ts))
    assert len(engine.results()) == 1


def test_aucun_constat_sans_impact_sans_ordre_sans_rafale_ou_sans_encadrement():
    assert detector().results() == []
    for engine in [
        detector(ordered=False),
        detector(burst_points=()),
        detector(bounds=()),
        detector(bounds=(0.0,)),
        detector(bounds=(0.04, 0.2)),
        detector(bounds=(math.nan,)),
    ]:
        engine.add_loss("A", "B", make_pkt(ts=0.04))
        assert engine.results() == []


def test_pas_de_propagation_a_un_segment_plus_loin():
    engine = detector()
    engine.add_loss("B", "C", make_pkt(point="B", ts=0.04))
    assert engine.results() == []
    engine = detector(burst_points=("A", "B"))
    engine.add_loss("B", "C", make_pkt(point="B", ts=0.04))
    assert [(r["upstream"], r["downstream"]) for r in engine.results()] == [("B", "C")]


def test_fenetre_configurable_commune_et_priorite_argument(monkeypatch):
    monkeypatch.setenv("NETCROSS_MICROBURST_WINDOW_MS", "10")
    short = detector()
    short.add_loss("A", "B", make_pkt(ts=0.04))
    assert short.results() == []
    explicit = detector(window=50)
    explicit.add_loss("A", "B", make_pkt(ts=0.04))
    assert explicit.results()[0]["window_ms"] == 50


@pytest.mark.parametrize("value", [0, -1, math.nan, math.inf, True, "invalide", []])
def test_fenetre_invalide_echoue_explicitement(value):
    with pytest.raises(ValueError, match="fini strictement positif"):
        detector(window=value)


def test_env_invalide_echoue_explicitement(monkeypatch):
    monkeypatch.setenv("NETCROSS_MICROBURST_WINDOW_MS", "invalide")
    with pytest.raises(ValueError, match="fini strictement positif"):
        detector()


def test_preuves_bornees_compteurs_exacts_et_ordre_deterministe():
    engine = detector(burst_points=("A", "B"))
    for _ in range(30):
        engine.add_loss("B", "C", make_pkt(point="B", ts=0.04))
        engine.add_loss("A", "B", make_pkt(ts=0.04))
    records = engine.results()
    assert [r["upstream"] for r in records] == ["A", "B"]
    assert all(r["losses"] == 30 and len(r["evidence"]) == 10 for r in records)


@pytest.mark.parametrize(
    "flag",
    [
        "is_retransmission",
        "is_fast_retransmission",
        "is_spurious_retransmission",
    ],
)
def test_retransmission_supplementaire_aval_avec_horloge(flag):
    engine = detector(clock=EstimationHorloge(0, manuel=True))
    engine.add_retransmissions(retransmission_flow(flag=flag))
    (record,) = engine.results()
    assert record["retransmissions"] == 1 and record["losses"] == 0
    assert record["evidence"][0]["point"] == "B"
    assert record["evidence"][0]["frame_number"] == 42


@pytest.mark.parametrize(
    "variant", ["amont", "doublon", "sans_horloge", "sans_A", "sans_B", "sans_charge", "udp", "sans_flag"]
)
def test_retransmission_non_localisable_ne_declenche_pas(variant):
    engine = detector(clock=None if variant == "sans_horloge" else EstimationHorloge(0))
    flow = retransmission_flow(upstream_retrans=variant == "amont", duplicate=variant == "doublon")
    if variant in {"sans_A", "sans_B"}:
        del flow[variant[-1]]
    if variant in {"sans_charge", "udp", "sans_flag"}:
        changes = {
            "sans_charge": {"payload_hash": None},
            "udp": {"proto": "UDP"},
            "sans_flag": {"is_retransmission": False},
        }[variant]
        flow = {point: [replace(p, **changes) for p in packets] for point, packets in flow.items()}
    engine.add_retransmissions(flow)
    assert engine.results() == []


def test_decalage_et_derive_inverses_avant_correlation():
    clock = EstimationHorloge(123, t0=0, derive_ppm=500, ic_decalage_ms=1, ic_derive_ppm=5)
    engine = detector(clock=clock)
    ts = 0.04
    engine.add_retransmissions(retransmission_flow(ts=ts + clock.decalage_a(ts) / 1000))
    sample = engine.results()[0]["evidence"][0]
    assert sample["upstream_ts"] == pytest.approx(ts)
    assert sample["clock_uncertainty_ms"] == pytest.approx((1 + ts * 5e-3) / 1.0005)


@pytest.mark.parametrize(
    "clock",
    [
        EstimationHorloge(0, ic_decalage_ms=30),
        EstimationHorloge(0, derive_ppm=-1_000_000),
        EstimationHorloge(0, derive_ppm=math.inf),
        EstimationHorloge(0, ic_decalage_ms=math.nan),
        EstimationHorloge(0, ic_decalage_ms=-1),
    ],
)
def test_horloge_inexploitable_ou_incertitude_hors_fenetre(clock):
    engine = detector(clock=clock)
    engine.add_retransmissions(retransmission_flow())
    assert engine.results() == []


def real_report(*, lost=True, ordered=True, off_path=False, window=None):
    upstream = traffic()
    target = next(i for i, p in enumerate(upstream) if p.ts > T0 + 0.06)
    if off_path:
        upstream[target] = replace(upstream[target], src="10.99.0.99")
    downstream = [
        replace(p, point="B", ts=p.ts + 0.001, ttl=63) for i, p in enumerate(upstream) if not lost or i != target
    ]
    packets = upstream + downstream
    return analyse(
        correlate(packets),
        ["A", "B"] if ordered else None,
        packets,
        link_speeds=SPEEDS,
        microburst_window_ms=window,
    )


def test_integration_detecteur_reel_perte_constat_preuve_json(capsys):
    report = real_report()
    assert report.loss_count["B"] == 1
    assert report.microbursts["A"]["events"]
    (record,) = report.microburst_correlations
    assert record["losses"] == 1
    (finding,) = [f for f in build_findings(report) if "Association temporelle établie" in f.message]
    assert finding.segment == "A -> B"
    assert "cause physique non prouvée" in finding.message
    assert finding.sample_size == 1 and finding.evidence
    document = build_json_report_document(report)
    assert document["microburst_correlations"] == [record]
    assert any("Association temporelle établie" in f["message"] for f in document["findings"])
    json.dumps(document, allow_nan=False)
    print_report(report)
    assert "Association temporelle établie" in capsys.readouterr().out


@pytest.mark.parametrize(
    "options",
    [
        {"lost": False},
        {"ordered": False},
        {"off_path": True},
        {"window": 1},
    ],
)
def test_integration_pas_de_faux_constat(options):
    report = real_report(**options)
    assert report.microbursts["A"]["events"]
    assert report.microburst_correlations == []
    assert not any("Association temporelle établie" in f.message for f in build_findings(report))


@pytest.mark.parametrize("already_upstream", [False, True])
def test_integration_retransmission_aval_avec_vraie_rafale(already_upstream):
    upstream = traffic()
    target = next(i for i, packet in enumerate(upstream) if packet.ts > T0 + 0.06)
    upstream[target] = replace(upstream[target], payload_hash="charge")
    downstream = [replace(p, point="B", ts=p.ts + 0.001) for p in upstream]
    retransmission = replace(
        downstream[target],
        ts=downstream[target].ts + 0.002,
        frame_number=9001,
        is_retransmission=True,
    )
    downstream.append(retransmission)
    if already_upstream:
        upstream.append(replace(retransmission, point="A", ts=retransmission.ts - 0.001))
    packets = upstream + downstream
    report = analyse(
        correlate(packets),
        ["A", "B"],
        packets,
        link_speeds=SPEEDS,
        clock_offsets={("A", "B"): 1.0},
    )
    assert report.microbursts["A"]["events"]
    if already_upstream:
        assert report.microburst_correlations == []
    else:
        (record,) = report.microburst_correlations
        assert record["retransmissions"] == 1 and record["losses"] == 0
        assert record["evidence"][0]["frame_number"] == 9001
