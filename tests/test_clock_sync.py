"""Estimateur de décalage d'horloge extrait dans clock_sync (issue #1026).

Non-régression : les valeurs doivent être strictement identiques à celles
du code d'avant l'extraction (``_analyse_handshake``), recopié ci-dessous
comme référence.
"""

from __future__ import annotations

import random
import statistics
from collections import defaultdict

import pytest

from netcross_core.clock_sync import echantillon_ntp_ms, estimer_decalage, estimer_decalages


def _reference_echantillon(t1, t2, t3, t4):
    # code d'origine (analysis._analyse_handshake avant #1026)
    return ((t2 - t1) - (t4 - t3)) / 2 * 1000.0


def _reference_estimation(samples):
    mean_off = statistics.mean(samples)
    stdev_off = statistics.pstdev(samples) if len(samples) > 1 else 0.0
    return (mean_off, stdev_off, len(samples))


EXEMPLES_TEMPS = [
    (0.0, 0.010, 0.011, 0.021),  # symétrique, horloges alignées
    (100.0, 100.0153, 100.0160, 100.0013),  # aval en avance
    (1_700_000_000.123456, 1_700_000_000.120001, 1_700_000_000.120500, 1_700_000_000.130000),  # aval en retard
    (5.0, 5.0, 5.0, 5.0),
]


@pytest.mark.parametrize("temps", EXEMPLES_TEMPS)
def test_echantillon_identique_a_l_ancien_code(temps):
    assert echantillon_ntp_ms(*temps) == _reference_echantillon(*temps)


def test_echantillon_signe_et_valeur():
    # aller 10 ms, retour 10 ms, horloge aval +5 ms : t2 = t1 + 15 ms, t4 = t3 - 5 ms + 10 ms
    assert echantillon_ntp_ms(0.0, 0.015, 0.016, 0.021) == pytest.approx(5.0)
    assert echantillon_ntp_ms(0.0, 0.005, 0.006, 0.021) == pytest.approx(-5.0)


SERIES = [
    [3.25],
    [1.0, 2.0],
    [-4.5, 0.0, 4.5, 10.25],
    [0.1] * 7,
    [random.Random(1).gauss(12.0, 3.0) for _ in range(200)],
    [random.Random(2).uniform(-50.0, 50.0) for _ in range(1000)],
]


@pytest.mark.parametrize("serie", SERIES)
def test_estimation_identique_a_l_ancien_code(serie):
    assert estimer_decalage(serie) == _reference_estimation(serie)


def test_un_seul_echantillon_ecart_nul():
    assert estimer_decalage([7.5]) == (7.5, 0.0, 1)


def test_liste_vide_leve_comme_avant():
    with pytest.raises(statistics.StatisticsError):
        estimer_decalage([])


def test_estimer_decalages_par_paire_et_ordre():
    echantillons = defaultdict(list)
    echantillons[("B", "C")] += [2.0, 4.0]
    echantillons[("A", "B")] += [1.0]
    estimations = estimer_decalages(echantillons)
    assert list(estimations) == [("B", "C"), ("A", "B")]
    assert estimations == {("B", "C"): (3.0, 1.0, 2), ("A", "B"): (1.0, 0.0, 1)}
    assert estimer_decalages({}) == {}


def test_accepte_un_iterable():
    assert estimer_decalages({("A", "B"): (x for x in (1.0, 3.0))}) == {("A", "B"): (2.0, 1.0, 2)}
