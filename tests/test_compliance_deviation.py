# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_compliance_deviation.py -- tests du statut DEVIATION
(netcross_core.compliance, Job 11/issue #8).

Verifie : nuance DEVIATION entre CONFORME et VIOLATION, marge de
tolerance, scenarios multi-reference.
"""

from typing import ClassVar

from netcross_core.compliance import (
    evaluate_compliance,
)
from netcross_core.expert_model import ReferenceProfile


def _ref(metric="loss_rate_pct", threshold=1.0, deviation_margin=None, operator="<="):
    return ReferenceProfile(
        id=f"test-{metric}",
        metric=metric,
        operator=operator,
        threshold=threshold,
        unit="x",
        source="test",
        deviation_margin=deviation_margin,
    )


class _Report:
    """Report minimal configurable pour les tests de conformite."""

    pmtud_blackhole: ClassVar[dict] = {"A": 0}
    tcp_total_segments: ClassVar[dict] = {"A": 100}
    tcp_retransmissions: ClassVar[dict] = {"A": 0}
    rtt_ms: ClassVar[dict] = {"A": 10.0}
    total_bytes: ClassVar[dict] = {"A": 10000}
    capture_duration: ClassVar[dict] = {"A": 1.0}
    jitter_ms: ClassVar[dict] = {"A": 1.0}

    def __init__(self, loss_count=0, seen_count=100, latency_ms=5.0):
        self.loss_count = {"A": loss_count}
        self.seen_count = {"A": seen_count}
        self.latency_ms = {"A": latency_ms}


# -- DEVIATION statut -----------------------------------------------------


def test_deviation_statut_produit_quand_dans_marge():
    """Loss rate = 1.3% avec seuil 1.0% et marge 50% -> DEVIATION
    (seuil + marge = 1.5%, 1.3% est dans la marge)."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    report = _Report(loss_count=13, seen_count=1000)  # 1.3%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "DEVIATION"
    assert results[0].observed == 1.3


def test_violation_statut_quand_hors_marge():
    """Loss rate = 2.0% avec seuil 1.0% et marge 50% -> VIOLATION
    (seuil + marge = 1.5%, 2.0% est au-dela)."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    report = _Report(loss_count=20, seen_count=1000)  # 2.0%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "VIOLATION"


def test_conforme_statut_quand_sous_seuil():
    """Loss rate = 0.5% avec seuil 1.0% -> CONFORME."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    report = _Report(loss_count=5, seen_count=1000)  # 0.5%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "CONFORME"


def test_pas_de_deviation_sans_marge():
    """Sans deviation_margin, le statut est CONFORME ou VIOLATION
    (pas de nuance DEVIATION)."""
    ref = _ref(threshold=1.0, deviation_margin=None)
    report = _Report(loss_count=13, seen_count=1000)  # 1.3%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "VIOLATION"


def test_deviation_exact_a_la_limite():
    """Loss rate exactement a la limite de la marge -> DEVIATION
    (seuil + marge = 1.5%, 1.5% est dans la marge car <=)."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    report = _Report(loss_count=15, seen_count=1000)  # 1.5%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "DEVIATION"


def test_deviation_au_dela_limite_exacte():
    """Loss rate juste au-dela de la limite de la marge -> VIOLATION."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    report = _Report(loss_count=16, seen_count=1000)  # 1.6%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "VIOLATION"


# -- Scenarios multi-reference --------------------------------------------


def test_catalogue_par_defaut_produit_deviation_ou_violation():
    """Avec le catalogue enrichi, un report avec pertes doit produire
    au moins un DEVIATION ou VIOLATION."""
    report = _Report(loss_count=15, seen_count=1000)  # 1.5%
    results = evaluate_compliance(report)
    statuses = [r.status for r in results]
    assert any(s in ("DEVIATION", "VIOLATION") for s in statuses)


def test_catalogue_par_defaut_tous_conformes():
    """Un report parfait doit etre CONFORME sur toutes les references."""
    results = evaluate_compliance(_Report())
    for r in results:
        assert r.status in ("CONFORME", "INDETERMINE")


def test_deviation_avec_marge_nulle_pas_deviante():
    """Une deviation_margin de 0.0 ne produit jamais DEVIATION."""
    ref = _ref(threshold=1.0, deviation_margin=0.0)
    report = _Report(loss_count=11, seen_count=1000)  # 1.1%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "VIOLATION"


def test_deviation_seuil_zero_pas_deviante():
    """Un seuil de 0 avec deviation_margin ne produit pas DEVIATION
    (division par zero evitee)."""
    ref = _ref(threshold=0.0, deviation_margin=0.5)
    report = _Report(loss_count=1, seen_count=1000)  # 0.1%
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "VIOLATION"


def test_deviation_sur_rfc9544_latency():
    """RFC 9544 latency: seuil 100ms, marge 10% -> DEVIATION entre
    100 et 110ms."""
    report = _Report(latency_ms=105.0)
    ref = ReferenceProfile(
        id="test-latency",
        metric="latency_ms",
        operator="<=",
        threshold=100.0,
        unit="ms",
        source="RFC 9544",
        deviation_margin=0.1,
    )
    results = evaluate_compliance(report, references=[ref])
    assert results[0].status == "DEVIATION"


def test_compliance_result_status_valide():
    """ComplianceResult.status doit etre une des 4 valeurs valides."""
    ref = _ref(threshold=1.0, deviation_margin=0.5)
    for loss, expected in [(5, "CONFORME"), (13, "DEVIATION"), (20, "VIOLATION")]:
        report = _Report(loss_count=loss, seen_count=1000)
        results = evaluate_compliance(report, references=[ref])
        assert results[0].status == expected
