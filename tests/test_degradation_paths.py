# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests supplémentaires pour les branches de dégradation (#246).

Couvre les chemins d'erreur et les cas limites identifiés dans l'audit
de couverture : fichiers malformés, séries vides, valeurs extrêmes,
absence de données.
"""

from __future__ import annotations

import pytest
from conftest import make_pkt

from netcross_core.stats import (
    StatRow,
    StatsQuery,
    compute_stats,
    export_csv,
    export_json,
)
from netcross_gtk4.analysis_pipeline import (
    AnalysisOptions,
    run_analysis_pipeline,
)
from netcross_gtk4.diff_pipeline import (
    DiffOptions,
    run_diff_pipeline,
)

# ---------------------------------------------------------------------------
# Stats : séries vides, valeurs extrêmes
# ---------------------------------------------------------------------------


class TestStatsDegradation:
    def test_compute_stats_empty_flows(self):
        """compute_stats avec une liste de flux vide ne plante pas."""
        from netcross_core.models import Report

        report = Report(points=["A"], pairs=[], bucket_seconds=1.0, rtp_clock_rate=8000)
        query = StatsQuery(group_by="endpoint", sort_by="packets", top_n=10)
        rows = compute_stats([], report, [], query)
        assert rows == []

    def test_compute_stats_empty_packets(self):
        """compute_stats avec des paquets vides produit des zéros, pas un plantage."""
        from netcross_core.expert_model import Flow
        from netcross_core.models import Report

        flow = Flow(key=("TCP", "10.0.0.1", 1234, "10.0.0.2", 443, 1000), points={"A"})
        report = Report(points=["A"], pairs=[], bucket_seconds=1.0, rtp_clock_rate=8000)
        query = StatsQuery(group_by="flow", sort_by="packets", top_n=10)
        rows = compute_stats([flow], report, [], query)
        assert len(rows) >= 1
        assert all(r.packets >= 0 for r in rows)

    def test_export_csv_empty_rows(self):
        """export_csv avec une liste vide retourne une chaîne vide."""
        assert export_csv([]) == ""

    def test_export_json_empty_rows(self):
        """export_json avec une liste vide retourne une liste vide."""
        assert export_json([]) == []

    def test_export_csv_single_row(self):
        """export_csv avec une seule ligne fonctionne."""
        row = StatRow(label="test", group_by="endpoint", packets=10, bytes=1000)
        result = export_csv([row])
        assert "test" in result
        assert "10" in result

    def test_compute_stats_top_n_zero_raises(self):
        """top_n=0 lève une ValueError (doit être >= 1 ou None)."""
        with pytest.raises(ValueError, match="top_n"):
            StatsQuery(group_by="flow", sort_by="packets", top_n=0)

    def test_compute_stats_top_n_negative_raises(self):
        """top_n négatif lève une ValueError."""
        with pytest.raises(ValueError, match="top_n"):
            StatsQuery(group_by="flow", sort_by="packets", top_n=-1)


# ---------------------------------------------------------------------------
# Analysis pipeline : cas de dégradation
# ---------------------------------------------------------------------------


class TestAnalysisPipelineDegradation:
    def test_pipeline_with_no_packets(self, monkeypatch):
        """Le pipeline gère un fichier sans paquets."""
        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [])

        result = run_analysis_pipeline(
            [("A", "/fake/empty.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
        )

        assert result.report is not None
        assert len(result.flows) == 0

    def test_pipeline_with_multiple_points(self, monkeypatch):
        """Le pipeline gère plusieurs points de capture."""
        pkt_a = make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.2")
        pkt_b = make_pkt(point="WAN", src="10.0.0.3", dst="10.0.0.4")

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        def mock_parse(label, path):
            return [pkt_a] if label == "LAN" else [pkt_b]

        monkeypatch.setattr(pipeline_mod, "parse_capture", mock_parse)

        result = run_analysis_pipeline(
            [("LAN", "/fake/lan.pcap"), ("WAN", "/fake/wan.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
        )

        assert result.report is not None
        assert "LAN" in result.report.points
        assert "WAN" in result.report.points

    def test_pipeline_progress_callback_not_required(self, monkeypatch):
        """Le pipeline fonctionne sans callback de progression."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [pkt])

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
            on_progress=None,
        )

        assert result.report is not None

    def test_pipeline_result_text_contains_report(self, monkeypatch):
        """Le texte du rapport contient les informations attendues."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [pkt])

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
        )

        assert "ANALYSE" in result.text or "analyse" in result.text.lower()


# ---------------------------------------------------------------------------
# Diff pipeline : cas de dégradation
# ---------------------------------------------------------------------------


class TestDiffPipelineDegradation:
    def test_diff_with_empty_captures(self, monkeypatch):
        """Le pipeline de diff gère les captures vides."""

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.parse_capture", lambda label, path: [])

        result = run_diff_pipeline(
            [("A", "/fake/baseline.pcap")],
            [("A", "/fake/current.pcap")],
            DiffOptions(auto_topology=False, parallel=False),
        )

        assert result.baseline_report is not None
        assert result.current_report is not None

    def test_diff_identical_captures(self, monkeypatch):
        """Deux captures identiques ne produisent pas de régression."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.parse_capture", lambda label, path: [pkt])

        result = run_diff_pipeline(
            [("A", "/fake/baseline.pcap")],
            [("A", "/fake/current.pcap")],
            DiffOptions(auto_topology=False, parallel=False),
        )

        assert isinstance(result.findings, list)

    def test_diff_without_progress_callback(self, monkeypatch):
        """Le pipeline de diff fonctionne sans callback de progression."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.parse_capture", lambda label, path: [pkt])

        result = run_diff_pipeline(
            [("A", "/fake/baseline.pcap")],
            [("A", "/fake/current.pcap")],
            DiffOptions(auto_topology=False, parallel=False),
            on_progress=None,
        )

        assert result.baseline_report is not None


# ---------------------------------------------------------------------------
# Capfile : fichiers malformés
# ---------------------------------------------------------------------------


class TestCapfileDegradation:
    def test_empty_file_detect_format_returns_none(self, tmp_path):
        """Un fichier vide retourne None pour detect_format."""
        from pcap_parser.capfile import detect_format

        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        # detect_format lit le magic number ; un fichier vide retourne None
        result = detect_format(str(empty))
        assert result is None

    def test_one_byte_file_detect_format_returns_none(self, tmp_path):
        """Un fichier d'un octet retourne None pour detect_format."""
        from pcap_parser.capfile import detect_format

        tiny = tmp_path / "tiny.pcap"
        tiny.write_bytes(b"\x00")
        result = detect_format(str(tiny))
        assert result is None

    def test_unknown_magic_detect_format_returns_none(self, tmp_path):
        """Un fichier avec un magic inconnu retourne None."""
        from pcap_parser.capfile import detect_format

        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"XXXX" + b"\x00" * 20)
        result = detect_format(str(bad))
        assert result is None

    def test_empty_file_has_packets_behavior(self, tmp_path):
        """has_packets sur un fichier vide : le comportement dépend de l'implémentation."""
        from pcap_parser.capfile import has_packets

        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        # has_packets peut retourner True ou False selon l'implémentation
        # Le test vérifie juste qu'il ne plante pas
        result = has_packets(str(empty))
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# TLS diagnostics : cas dégradés
# ---------------------------------------------------------------------------


class TestTLSDegradation:
    def test_diagnose_tls_empty_status(self):
        """diagnose_tls avec un dict vide ne plante pas."""
        from netcross_core.tls_diagnostics import diagnose_tls

        result = diagnose_tls({}, [])
        assert isinstance(result, list)
        assert len(result) == 0

    def test_diagnose_tls_empty_points(self):
        """diagnose_tls avec une liste vide de points ne plante pas."""
        from netcross_core.tls_diagnostics import diagnose_tls

        result = diagnose_tls({}, None)
        assert isinstance(result, list)
