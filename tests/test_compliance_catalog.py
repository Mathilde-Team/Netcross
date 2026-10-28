# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_compliance_catalog.py -- tests du catalogue de referentiels
techniques enrichi (netcross_core.compliance, Job 10/issue #7).

Verifie : ReferenceProfile enrichi (champs optionnels), metriques RFC 6349
et RFC 9544, catalogue par defaut.
"""

from typing import ClassVar

from netcross_core.compliance import (
    _METRIC_FUNCS,
    DEFAULT_REFERENCES,
    evaluate_compliance,
)
from netcross_core.expert_model import ReferenceProfile

# -- ReferenceProfile enrichi ----------------------------------------------


def test_reference_profile_champs_optionnels_definis():
    """Les nouveaux champs optionnels ont des valeurs par defaut."""
    ref = ReferenceProfile(
        id="test",
        metric="loss_rate_pct",
        operator="<=",
        threshold=1.0,
        unit="%",
        source="test",
    )
    assert ref.provenance == "recommandee"
    assert ref.version is None
    assert ref.context is None
    assert ref.percentile is None
    assert ref.confidence == "medium"
    assert ref.deviation_margin is None


def test_reference_profile_champs_enrichis_assignables():
    ref = ReferenceProfile(
        id="test",
        metric="latency_ms",
        operator="<=",
        threshold=100.0,
        unit="ms",
        source="RFC 9544",
        provenance="normative",
        version="9544",
        context="wan",
        percentile=95.0,
        confidence="high",
        deviation_margin=0.1,
    )
    assert ref.provenance == "normative"
    assert ref.version == "9544"
    assert ref.context == "wan"
    assert ref.percentile == 95.0
    assert ref.confidence == "high"
    assert ref.deviation_margin == 0.1


# -- Catalogue par defaut --------------------------------------------------


def test_catalogue_contient_rfc6349():
    rfc6349 = [r for r in DEFAULT_REFERENCES if r.version == "6349"]
    assert len(rfc6349) >= 3  # pmtud, loss rate, retransmission rate, rtt
    for ref in rfc6349:
        assert ref.provenance == "normative"


def test_catalogue_contient_rfc9544():
    rfc9544 = [r for r in DEFAULT_REFERENCES if r.version == "9544"]
    assert len(rfc9544) >= 2  # latency, jitter
    for ref in rfc9544:
        assert ref.provenance == "normative"


def test_catalogue_contient_bonne_pratique():
    bp = [r for r in DEFAULT_REFERENCES if r.provenance == "recommandee"]
    assert len(bp) >= 1


def test_catalogue_tous_les_ids_uniques():
    ids = [r.id for r in DEFAULT_REFERENCES]
    assert len(ids) == len(set(ids))


def test_catalogue_toutes_metriques_enregistrees():
    """Toutes les metriques referencees dans le catalogue doivent etre
    dans le registre _METRIC_FUNCS."""
    for ref in DEFAULT_REFERENCES:
        assert ref.metric in _METRIC_FUNCS, f"Metric {ref.metric} not in registry"


# -- Metriques RFC 6349 ----------------------------------------------------


def test_metrique_tcp_retransmission_rate_enregistree():
    assert "tcp_retransmission_rate_pct" in _METRIC_FUNCS


def test_metrique_avg_rtt_ms_enregistree():
    assert "avg_rtt_ms" in _METRIC_FUNCS


def test_metrique_throughput_mbps_enregistree():
    assert "throughput_mbps" in _METRIC_FUNCS


# -- Metriques RFC 9544 ----------------------------------------------------


def test_metrique_latency_ms_enregistree():
    assert "latency_ms" in _METRIC_FUNCS


def test_metrique_jitter_ms_enregistree():
    assert "jitter_ms" in _METRIC_FUNCS


# -- evaluate_compliance avec catalogue enrichi ----------------------------


class _FakeReport:
    pmtud_blackhole: ClassVar[dict] = {"A": 0}
    loss_count: ClassVar[dict] = {"A": 0}
    seen_count: ClassVar[dict] = {"A": 100}
    tcp_total_segments: ClassVar[dict] = {"A": 100}
    tcp_retransmissions: ClassVar[dict] = {"A": 0}
    rtt_ms: ClassVar[dict] = {"A": 10.0}
    total_bytes: ClassVar[dict] = {"A": 10000}
    capture_duration: ClassVar[dict] = {"A": 1.0}
    latency_ms: ClassVar[dict] = {"A": 5.0}
    jitter_ms: ClassVar[dict] = {"A": 1.0}


def test_evaluate_compliance_avec_catalogue_par_defaut():
    """evaluate_compliance() avec le catalogue par defaut ne doit pas
    planter sur un Report minimal."""
    results = evaluate_compliance(_FakeReport())
    assert len(results) >= 7
    for r in results:
        assert r.status in ("CONFORME", "VIOLATION", "INDETERMINE", "DEVIATION")


def test_evaluate_compliance_metrique_absente_indefini():
    ref = ReferenceProfile(
        id="test-unknown",
        metric="nonexistent_metric",
        operator="<=",
        threshold=0.0,
        unit="x",
        source="test",
    )

    class _EmptyReport:
        pass

    results = evaluate_compliance(_EmptyReport(), references=[ref])
    assert len(results) == 1
    assert results[0].status == "INDETERMINE"


def test_deviation_margin_defini_sur_certains_profiles():
    """Certains profils RFC ont une deviation_margin definie."""
    with_margin = [r for r in DEFAULT_REFERENCES if r.deviation_margin is not None]
    assert len(with_margin) >= 3
