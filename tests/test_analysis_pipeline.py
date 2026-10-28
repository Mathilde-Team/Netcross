# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests pour les pipelines d'analyse et de diff extraits de app.py (#246, #285).

Ces tests vérifient la logique pure extraite de MainWindow._run_analysis_thread
et MainWindow._run_diff_thread, sans dépendance GTK ni display.

Les fixtures de paquets viennent de conftest.make_pkt().
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_gtk4.analysis_pipeline import (
    AnalysisOptions,
    AnalysisResult,
    load_packets,
    run_analysis_pipeline,
)
from netcross_gtk4.diff_pipeline import (
    DiffOptions,
    DiffResult,
    run_diff_pipeline,
)

# ---------------------------------------------------------------------------
# AnalysisOptions / AnalysisResult
# ---------------------------------------------------------------------------


class TestAnalysisOptions:
    def test_defaults(self):
        opts = AnalysisOptions()
        assert opts.bucket_ms == 1000.0
        assert opts.rtp_rate == 8000
        assert opts.nat_tolerant is False
        assert opts.parallel is True
        assert opts.auto_topology is True
        assert opts.triage is False
        assert opts.tls is False
        assert opts.quic is False
        assert opts.redact is False
        assert opts.detect_duplicates is False
        assert opts.exclude_duplicates is False

    def test_custom_values(self):
        opts = AnalysisOptions(
            bucket_ms=500.0,
            rtp_rate=16000,
            nat_tolerant=True,
            triage=True,
            tls=True,
            quic=True,
            redact=True,
        )
        assert opts.bucket_ms == 500.0
        assert opts.rtp_rate == 16000
        assert opts.nat_tolerant is True
        assert opts.triage is True
        assert opts.tls is True
        assert opts.quic is True
        assert opts.redact is True


class TestAnalysisResult:
    def test_defaults(self):
        result = AnalysisResult()
        assert result.mode == "single"
        assert result.report is None
        assert result.flows == []
        assert result.findings is None
        assert result.text == ""
        assert result.tls_findings is None
        assert result.quic_findings is None
        assert result.wireshark_expert_events == []

    def test_with_values(self):
        result = AnalysisResult(mode="single", text="rapport", flows=[1, 2])
        assert result.mode == "single"
        assert result.text == "rapport"
        assert len(result.flows) == 2


# ---------------------------------------------------------------------------
# load_packets
# ---------------------------------------------------------------------------


class TestLoadPackets:
    def test_empty_captures(self):
        packets = load_packets([], parallel=False)
        assert packets == []

    def test_progress_callback_called(self):
        calls = []
        load_packets(
            [],
            parallel=False,
            on_progress=lambda msg: calls.append(msg),
        )
        # Empty captures -> no progress calls
        assert calls == []

    def test_with_synthetic_packets(self, monkeypatch):
        """load_packets appelle parse_capture ; on mocke pour éviter tshark."""
        pkt_a = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")
        pkt_b = make_pkt(point="B", src="10.0.0.3", dst="10.0.0.4")

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        def mock_parse(label, path):
            if label == "A":
                return [pkt_a]
            return [pkt_b]

        monkeypatch.setattr(pipeline_mod, "parse_capture", mock_parse)

        packets = load_packets(
            [("A", "/fake/a.pcap"), ("B", "/fake/b.pcap")],
            parallel=False,
        )
        assert len(packets) == 2
        assert packets[0].point == "A"
        assert packets[1].point == "B"


# ---------------------------------------------------------------------------
# run_analysis_pipeline
# ---------------------------------------------------------------------------


class TestRunAnalysisPipeline:
    def test_empty_captures_produces_empty_report(self):
        """Un pipeline sans captures produit un rapport vide, pas une erreur."""
        opts = AnalysisOptions()
        result = run_analysis_pipeline([], opts)
        assert result.report is not None
        assert len(result.flows) == 0
        assert result.wireshark_expert_events == []

    def test_progress_messages(self, monkeypatch):
        """Le callback de progression reçoit les messages d'étape."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")
        progress = []

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod,
            "parse_capture",
            lambda label, path: [pkt],
        )

        run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
            on_progress=lambda msg: progress.append(msg),
        )

        # Le pipeline doit logger au moins la lecture et la fin
        assert any("Lecture" in p or "Chargement" in p for p in progress)
        assert any("terminée" in p for p in progress)

    def test_basic_analysis(self, monkeypatch):
        """Le pipeline produit un Report avec des flows."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")
        progress = []

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod,
            "parse_capture",
            lambda label, path: [pkt],
        )

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(auto_topology=False, parallel=False),
            on_progress=lambda msg: progress.append(msg),
        )

        assert isinstance(result, AnalysisResult)
        assert result.mode == "single"
        assert result.report is not None
        assert isinstance(result.flows, (list, dict))  # flows peut être un defaultdict
        assert isinstance(result.text, str)
        assert len(result.text) > 0

    def test_auto_topology(self, monkeypatch):
        """auto_topology=True -> points_order=None (déduction automatique)."""
        pkt = make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.2")

        import netcross_gtk4.analysis_pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod,
            "parse_capture",
            lambda label, path: [pkt],
        )

        result = run_analysis_pipeline(
            [("LAN", "/fake/lan.pcap")],
            AnalysisOptions(auto_topology=True, parallel=False),
        )

        assert result.report is not None

    def test_explicit_topology(self, monkeypatch):
        """auto_topology=False -> points_order explicite depuis les labels."""
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


# ---------------------------------------------------------------------------
# DiffOptions / DiffResult
# ---------------------------------------------------------------------------


class TestDiffOptions:
    def test_defaults(self):
        opts = DiffOptions()
        assert opts.bucket_ms == 1000.0
        assert opts.rtp_rate == 8000
        assert opts.nat_tolerant is False
        assert opts.parallel is True
        assert opts.auto_topology is True
        assert opts.loss_min_pp == 5.0
        assert opts.latency_min_ms == 2.0
        assert opts.redact is False
        assert opts.tls is False
        assert opts.quic is False

    def test_custom_values(self):
        opts = DiffOptions(
            bucket_ms=500.0,
            loss_min_pp=10.0,
            latency_min_ms=5.0,
            redact=True,
            tls=True,
        )
        assert opts.bucket_ms == 500.0
        assert opts.loss_min_pp == 10.0
        assert opts.latency_min_ms == 5.0
        assert opts.redact is True
        assert opts.tls is True


class TestDiffResult:
    def test_defaults(self):
        result = DiffResult()
        assert result.mode == "diff"
        assert result.findings == []
        assert result.baseline_report is None
        assert result.current_report is None
        assert result.text == ""
        assert result.tls_findings_baseline is None
        assert result.tls_findings_current is None


# ---------------------------------------------------------------------------
# run_diff_pipeline
# ---------------------------------------------------------------------------


class TestRunDiffPipeline:
    def test_basic_diff(self, monkeypatch):
        """Le pipeline de diff produit des findings et des rapports."""
        pkt_base = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")
        pkt_curr = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")

        def mock_parse(label, path):
            if "baseline" in path:
                return [pkt_base]
            return [pkt_curr]

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.parse_capture", mock_parse)

        result = run_diff_pipeline(
            [("A", "/fake/baseline.pcap")],
            [("A", "/fake/current.pcap")],
            DiffOptions(auto_topology=False, parallel=False),
        )

        assert isinstance(result, DiffResult)
        assert result.mode == "diff"
        assert result.baseline_report is not None
        assert result.current_report is not None
        assert isinstance(result.findings, list)
        assert isinstance(result.text, str)

    def test_progress_messages(self, monkeypatch):
        """Le callback de progression reçoit les étapes baseline et courant."""
        pkt = make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")
        progress = []

        monkeypatch.setattr(
            "netcross_gtk4.analysis_pipeline.parse_capture",
            lambda label, path: [pkt],
        )

        run_diff_pipeline(
            [("A", "/fake/baseline.pcap")],
            [("A", "/fake/current.pcap")],
            DiffOptions(auto_topology=False, parallel=False),
            on_progress=lambda msg: progress.append(msg),
        )

        assert any("BASELINE" in p for p in progress)
        assert any("COURANT" in p for p in progress)
        assert any("terminée" in p for p in progress)
