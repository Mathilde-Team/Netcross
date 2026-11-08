# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests du debit crete multi-echelle en fenetre glissante (issue #1133)."""

from __future__ import annotations

import tracemalloc

import pytest

from netcross_core.multiscale import (
    DEFAULT_SCALES,
    MultiScaleRates,
    ScaleTooFineError,
    SlidingWindowPeak,
    check_scale,
    format_scale,
    multiscale_peaks,
)
from tests.conftest import make_pkt

T0 = 1_700_000_000.0  # horodatage absolu realiste (precision flottante limitee)


def _feed(rates, events):
    for ts, length in events:
        rates.update(ts, length)
    return {row["scale"]: row for row in rates.results()}


# --- format_scale -----------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(100e-6, "100 µs"), (1e-3, "1 ms"), (10e-3, "10 ms"), (2.0, "2 s"), (1.5e-6, "1.5 µs"), (1e-9, "1 ns")],
)
def test_format_scale(seconds, text):
    assert format_scale(seconds) == text


# --- refus d'echelle --------------------------------------------------------


def test_check_scale_refuse_echelle_plus_fine_que_tsresol():
    with pytest.raises(ScaleTooFineError, match=r"100 µs refusée.*point R.*1 ms, if_tsresol"):
        check_scale(100e-6, 1e-3, "R")


def test_check_scale_sans_point_message_sans_point():
    with pytest.raises(ScaleTooFineError) as err:
        check_scale(10e-6, 1e-3)
    assert "du point" not in str(err.value)


def test_check_scale_accepte_egale_ou_plus_large():
    check_scale(1e-3, 1e-3)
    check_scale(10e-3, 1e-6)
    check_scale(1e-6, None)  # resolution inconnue : seul le plancher de 1 us


def test_check_scale_refuse_sous_la_microseconde():
    with pytest.raises(ScaleTooFineError, match="virgule flottante"):
        check_scale(500e-9, 1e-9)


def test_check_scale_resolution_binaire_egale():
    # if_tsresol en puissance de 2 (2^-10 s) : l'echelle egale est acceptee
    check_scale(2**-10, 2**-10)
    with pytest.raises(ScaleTooFineError):
        check_scale(2**-11, 2**-10)


def test_quantum_resolution_milliseconde():
    # resolution 1 ms : des paquets a 0,4 ms et 1,4 ms tombent a 0 et 1 ms
    rates = MultiScaleRates([1e-3], ts_resolution=1e-3)
    rows = _feed(rates, [(T0, 100), (T0 + 0.0004, 100), (T0 + 0.0014, 100)])
    assert rows["1 ms"]["peak_bytes"] == 200
    assert rows["1 ms"]["peak_end"] == pytest.approx(T0)


@pytest.mark.parametrize("bad", [0, -1e-3])
def test_check_scale_non_positive(bad):
    with pytest.raises(ValueError, match="non positive"):
        check_scale(bad, None)


def test_multiscale_rates_refuse_a_la_construction():
    with pytest.raises(ScaleTooFineError):
        MultiScaleRates(DEFAULT_SCALES, ts_resolution=1e-3, point="A")


def test_multiscale_rates_sans_echelle():
    with pytest.raises(ValueError, match="au moins une"):
        MultiScaleRates([])


def test_sliding_window_peak_non_positive():
    with pytest.raises(ValueError, match="non positive"):
        SlidingWindowPeak(0)


# --- valeurs exactes --------------------------------------------------------


def test_valeurs_exactes_jeu_connu():
    # trois rafales : 3 x 1000 o en 60 us, 5 x 1500 o en 800 us, puis du fond
    events = [(T0 + i * 20e-6, 1000) for i in range(3)]
    events += [(T0 + 0.005 + i * 200e-6, 1500) for i in range(5)]
    events += [(T0 + 0.050 + i * 0.004, 100) for i in range(5)]
    rows = _feed(MultiScaleRates(point="A"), events)

    fine = rows["100 µs"]
    assert fine["peak_bytes"] == 3000
    assert fine["peak_packets"] == 3
    assert fine["peak_bps"] == pytest.approx(3000 * 8 / 100e-6)
    assert fine["peak_start"] == pytest.approx(T0)
    assert fine["peak_end"] == pytest.approx(T0 + 40e-6)

    mid = rows["1 ms"]
    assert mid["peak_bytes"] == 7500
    assert mid["peak_packets"] == 5
    assert mid["peak_start"] == pytest.approx(T0 + 0.005)
    assert mid["peak_end"] == pytest.approx(T0 + 0.0058)

    large = rows["10 ms"]
    # fenetre ]T0+0.0058-0.01, T0+0.0058] : les deux rafales
    assert large["peak_bytes"] == 10500
    assert large["peak_packets"] == 8
    assert large["max_window_packets"] == 8
    assert large["utilisation_pct"] is None


def test_bord_de_fenetre_exclu_exactement():
    # deux paquets exactement a 1 ms d'ecart : jamais dans la meme fenetre de 1 ms
    rows = _feed(MultiScaleRates([1e-3]), [(T0, 500), (T0 + 1e-3, 500)])
    assert rows["1 ms"]["peak_bytes"] == 500
    # a 999 us d'ecart, ils y sont tous les deux
    rows = _feed(MultiScaleRates([1e-3]), [(T0, 500), (T0 + 999e-6, 500)])
    assert rows["1 ms"]["peak_bytes"] == 1000


def test_taux_occupation_interface():
    # 125 000 o en 1 ms = 1 Gbit/s sur un lien a 10 Gbit/s => 10 %
    events = [(T0 + i * 10e-6, 1250) for i in range(100)]
    rows = _feed(MultiScaleRates([1e-3], link_speed_bps=10**10), events)
    assert rows["1 ms"]["peak_bytes"] == 125_000
    assert rows["1 ms"]["peak_bps"] == pytest.approx(1e9)
    assert rows["1 ms"]["utilisation_pct"] == 10.0


def test_reordonnancement_compte_au_dernier_instant():
    rates = MultiScaleRates([1e-3])
    rows = _feed(rates, [(T0, 100), (T0 + 0.002, 100), (T0 + 0.0015, 100)])
    assert rates.reordered == 1
    assert rows["1 ms"]["peak_bytes"] == 200
    assert rates.packets == 3
    assert rates.bytes == 300


def test_sans_paquet():
    rows = MultiScaleRates([1e-3]).results()
    assert rows[0]["peak_bytes"] == 0
    assert rows[0]["peak_start"] is None
    assert rows[0]["peak_end"] is None


def test_echelles_dedoublonnees_et_triees():
    rates = MultiScaleRates([10e-3, 1e-3, 1e-3])
    assert [r["scale"] for r in rates.results()] == ["1 ms", "10 ms"]


def test_trafic_lisse_meme_volume_crete_plus_basse():
    burst = [(T0 + i * 1e-6, 1500) for i in range(100)]
    smooth = [(T0 + i * 1e-3, 1500) for i in range(100)]
    rb = _feed(MultiScaleRates(), burst)
    rs = _feed(MultiScaleRates(), smooth)
    assert rb["100 µs"]["peak_bytes"] == 150_000
    assert rs["100 µs"]["peak_bytes"] == 1500
    assert rs["10 ms"]["peak_bytes"] == 15_000


# --- memoire bornee ---------------------------------------------------------


def test_memoire_bornee_par_la_fenetre():
    # 200 000 paquets espaces de 100 us : la fenetre de 10 ms n'en garde que 100
    rates = MultiScaleRates()
    tracemalloc.start()
    for i in range(20_000):
        rates.update(T0 + i * 100e-6, 64)
    _, before = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    for i in range(20_000, 200_000):
        rates.update(T0 + i * 100e-6, 64)
    _, after = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rows = {r["scale"]: r for r in rates.results()}
    assert rows["10 ms"]["max_window_packets"] == 100
    assert rows["10 ms"]["peak_bytes"] == 6400
    assert after < before + 64 * 1024  # pas de croissance avec la capture


# --- multiscale_peaks -------------------------------------------------------


def test_multiscale_peaks_refus_par_point():
    packets = {
        "A": [make_pkt(point="A", ts=T0 + i * 10e-6, length=1000) for i in range(5)],
        "B": [make_pkt(point="B", ts=T0 + i * 10e-6, length=1000) for i in range(5)],
    }
    speeds = {
        "A": {"ts_resolution": 1e-6, "speed_bps": 10**9},
        "B": {"ts_resolution": 1e-3, "speed_bps": None},
    }
    res = multiscale_peaks(packets, speeds)
    a, b = res["A"], res["B"]
    assert a["refused"] == []
    assert [s["scale"] for s in a["scales"]] == ["100 µs", "1 ms", "10 ms"]
    assert a["scales"][0]["peak_bytes"] == 5000
    assert a["scales"][0]["utilisation_pct"] == pytest.approx(40.0)
    assert a["packets"] == 5
    assert [r["scale"] for r in b["refused"]] == ["100 µs"]
    assert "if_tsresol" in b["refused"][0]["reason"]
    assert [s["scale"] for s in b["scales"]] == ["1 ms", "10 ms"]
    assert b["scales"][0]["utilisation_pct"] is None


def test_multiscale_peaks_toutes_echelles_refusees():
    res = multiscale_peaks({"A": [make_pkt(ts=T0)]}, {"A": {"ts_resolution": 1.0}})
    assert res["A"]["scales"] == []
    assert res["A"]["packets"] == 0
    assert res["A"]["reordered"] == 0
    assert len(res["A"]["refused"]) == 3


def test_multiscale_peaks_sans_vitesses():
    res = multiscale_peaks({"A": iter([make_pkt(ts=T0, length=60)])})
    assert res["A"]["ts_resolution"] is None
    assert res["A"]["speed_bps"] is None
    assert res["A"]["scales"][0]["peak_bytes"] == 60
