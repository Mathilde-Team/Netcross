# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests pour les branches optionnelles des pipelines (#246).

Couvre les chemins rarement exécutés :
- detect_duplicates / exclude_duplicates
- redact (anonymisation)
- triage
- tls (diagnostic TLS via tshark)
- quic (diagnostic QUIC via tshark)
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.diff_pipeline import DiffOptions, run_diff_pipeline
from tests.conftest import make_pkt


def _fake_report(points=None):
    """Mock de Report avec les attributs attendus par print_report."""
    r = MagicMock(name="report")
    r.points = points or ["A"]
    r.capture_comments = []
    r.capture_infos = []
    r.bucket_seconds = 0.1
    r.flows = []
    r.point_stats = {}
    r.flow_stats = []
    r.packet_stats = MagicMock()
    r.warnings = []
    r.global_loss = MagicMock()
    r.global_loss.source_total = 0
    r.global_loss.dest_total = 0
    r.global_loss.inter_point_total = 0
    r.global_loss.full_duplex_total = 0
    return r


def _patch_common(monkeypatch):
    """Patch commun : load_packets, analyse, print_report."""
    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.load_packets", lambda *a, **k: [])
    monkeypatch.setattr("netcross_core.analysis.analyse", lambda *a, **k: _fake_report())
    monkeypatch.setattr("netcross_gtk4.analysis_pipeline.print_report", lambda r: None)


class TestDetectDuplicatesBranch:
    """Branche detect_duplicates du pipeline d'analyse."""

    def test_detect_duplicates_enabled(self, monkeypatch):
        """detect_duplicates=True appelle detect_cross_capture_duplicates."""
        captured = {}

        def fake_detect(packets, threshold_ms):
            captured["called"] = True
            captured["threshold"] = threshold_ms
            return {"pkt1": 2}

        _patch_common(monkeypatch)
        monkeypatch.setattr(
            "netcross_core.forensic.detect_cross_capture_duplicates",
            fake_detect,
        )

        run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(detect_duplicates=True, duplicate_threshold_ms=50.0),
            on_progress=lambda msg: None,
        )

        assert captured["called"] is True
        assert captured["threshold"] == 50.0

    def test_exclude_duplicates_flag(self, monkeypatch):
        """exclude_duplicates=True est transmis à analyse()."""
        captured = {}

        def fake_analyse(*args, **kwargs):
            captured["exclude_duplicates"] = kwargs.get("exclude_duplicates")
            captured["duplicate_counts"] = kwargs.get("duplicate_counts")
            return _fake_report()

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.load_packets", lambda *a, **k: [])
        monkeypatch.setattr("netcross_core.analysis.analyse", fake_analyse)
        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.print_report", lambda r: None)
        monkeypatch.setattr(
            "netcross_core.forensic.detect_cross_capture_duplicates",
            lambda *a, **k: {"pkt1": 2},
        )

        run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(
                detect_duplicates=True,
                exclude_duplicates=True,
                duplicate_threshold_ms=10.0,
            ),
            on_progress=lambda msg: None,
        )

        assert captured["exclude_duplicates"] is True
        assert captured["duplicate_counts"] == {"pkt1": 2}


class TestRedactBranch:
    """Branche redact du pipeline d'analyse."""

    def test_redact_enabled_calls_redact_packets(self, monkeypatch):
        """redact=True appelle redact_packets sur les paquets."""
        captured = {}

        def fake_redact(packets):
            captured["called"] = True
            m = MagicMock()
            m.__len__ = lambda self: 3
            return m

        _patch_common(monkeypatch)
        monkeypatch.setattr("netcross_core.redact.redact_packets", fake_redact)

        run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(redact=True),
            on_progress=lambda msg: None,
        )

        assert captured["called"] is True

    def test_redact_disabled_does_not_call_redact(self, monkeypatch):
        """redact=False n'appelle pas redact_packets."""
        captured = {"called": False}

        _patch_common(monkeypatch)
        monkeypatch.setattr(
            "netcross_core.redact.redact_packets",
            lambda p: captured.__setitem__("called", True) or MagicMock(),
        )

        run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(redact=False),
            on_progress=lambda msg: None,
        )

        assert captured["called"] is False


class TestTriageBranch:
    """Branche triage du pipeline d'analyse."""

    def test_triage_enabled_builds_findings(self, monkeypatch):
        """triage=True appelle build_findings et rank_segments."""
        captured = {}
        _patch_common(monkeypatch)

        import netcross_report as nr

        monkeypatch.setattr(nr, "build_findings", lambda r: ["finding1", "finding2"])
        monkeypatch.setattr(nr, "rank_segments", lambda f: f)
        monkeypatch.setattr(nr, "print_triage", lambda r, t: captured.__setitem__("topn", t))
        monkeypatch.setattr(nr, "health_score", lambda r: 85)
        monkeypatch.setattr(nr, "format_health_line", lambda s: f"Score: {s}")

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(triage=True, triage_topn=5),
            on_progress=lambda msg: None,
        )

        assert captured.get("topn") == 5
        assert result.findings == ["finding1", "finding2"]

    def test_triage_disabled_no_findings(self, monkeypatch):
        """triage=False ne produit pas de findings."""
        _patch_common(monkeypatch)

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(triage=False),
            on_progress=lambda msg: None,
        )
        assert result.findings is None


class TestTLSBranch:
    """Branche tls du pipeline d'analyse."""

    def test_tls_enabled_calls_diagnostics(self, monkeypatch):
        """tls=True appelle parse_tls_capture et diagnose_tls."""
        captured = {}
        _patch_common(monkeypatch)

        import netcross_core.tls_diagnostics as tls_mod

        monkeypatch.setattr(
            tls_mod, "parse_tls_capture", lambda label, path: captured.setdefault("tls_calls", []).append(label) or []
        )
        monkeypatch.setattr(tls_mod, "build_handshake_status", lambda e: {})
        monkeypatch.setattr(tls_mod, "diagnose_tls", lambda s, p: ["tls_finding"])
        monkeypatch.setattr(tls_mod, "print_tls_diagnostics", lambda f: None)

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap"), ("B", "/fake/b.pcap")],
            AnalysisOptions(tls=True),
            on_progress=lambda msg: None,
        )

        assert "A" in captured.get("tls_calls", [])
        assert "B" in captured.get("tls_calls", [])
        assert result.tls_findings == ["tls_finding"]

    def test_tls_disabled_no_findings(self, monkeypatch):
        """tls=False ne produit pas de tls_findings."""
        _patch_common(monkeypatch)

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(tls=False),
            on_progress=lambda msg: None,
        )
        assert result.tls_findings is None


class TestQUICBranch:
    """Branche quic du pipeline d'analyse."""

    def test_quic_enabled_calls_diagnostics(self, monkeypatch):
        """quic=True appelle parse_quic_capture et diagnose_quic."""
        captured = {}
        _patch_common(monkeypatch)

        mock_quic = MagicMock()
        mock_quic.parse_quic_capture = lambda label, path: captured.setdefault("quic_calls", []).append(label) or []
        mock_quic.diagnose_quic = lambda events, points: captured.__setitem__("diagnose_quic", True) or ["quic_finding"]
        mock_quic.print_quic_diagnostics = lambda f: None
        monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", mock_quic)

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(quic=True),
            on_progress=lambda msg: None,
        )

        assert captured.get("diagnose_quic") is True
        assert result.quic_findings == ["quic_finding"]

    def test_quic_disabled_no_findings(self, monkeypatch):
        """quic=False ne produit pas de quic_findings."""
        _patch_common(monkeypatch)

        result = run_analysis_pipeline(
            [("A", "/fake/a.pcap")],
            AnalysisOptions(quic=False),
            on_progress=lambda msg: None,
        )
        assert result.quic_findings is None


class TestDiffPipelineOptionalBranches:
    """Branches optionnelles du pipeline de diff."""

    def test_diff_parallel_mode(self, monkeypatch):
        """parallel=True utilise load_packets avec parallel=True (pas parse_capture en boucle)."""
        captured = {"parallel_args": []}

        def fake_load(captures, parallel, on_progress=None):
            captured["parallel_args"].append(parallel)
            return [make_pkt(src="10.0.0.1", dst="10.0.0.2")]

        monkeypatch.setattr("netcross_gtk4.analysis_pipeline.load_packets", fake_load)

        run_diff_pipeline(
            [("A", "/fake/a.pcap")],
            [("B", "/fake/b.pcap")],
            DiffOptions(parallel=True),
            on_progress=lambda msg: None,
        )

        # load_packets doit etre appelee deux fois (baseline + courant),
        # chaque fois avec parallel=True
        assert len(captured["parallel_args"]) == 2
        assert all(captured["parallel_args"])

    def test_diff_redact_enabled(self, monkeypatch):
        """redact=True dans le diff utilise un AddressRedactor partagé."""
        captured = {}

        monkeypatch.setattr(
            "netcross_gtk4.analysis_pipeline.load_packets",
            lambda captures, parallel, on_progress=None: [make_pkt(src="10.0.0.1", dst="10.0.0.2")],
        )
        monkeypatch.setattr(
            "netcross_core.redact.AddressRedactor.redact",
            lambda self, packets: captured.__setitem__("redact_called", True),
        )

        run_diff_pipeline(
            [("A", "/fake/a.pcap")],
            [("B", "/fake/b.pcap")],
            DiffOptions(redact=True),
            on_progress=lambda msg: None,
        )

        assert captured.get("redact_called") is True

    def test_diff_tls_enabled(self, monkeypatch):
        """tls=True dans le diff appelle parse_tls_capture pour baseline et courant."""
        captured = {}

        import netcross_core.tls_diagnostics as tls_mod

        monkeypatch.setattr(
            "netcross_gtk4.analysis_pipeline.load_packets",
            lambda captures, parallel, on_progress=None: [make_pkt(src="10.0.0.1", dst="10.0.0.2")],
        )
        monkeypatch.setattr(
            tls_mod, "parse_tls_capture", lambda label, path: captured.setdefault("tls_calls", []).append(label) or []
        )
        monkeypatch.setattr(tls_mod, "build_handshake_status", lambda e: {})
        monkeypatch.setattr(tls_mod, "diagnose_tls", lambda s, p: ["tls_finding"])
        monkeypatch.setattr(tls_mod, "print_tls_diagnostics", lambda f: None)

        result = run_diff_pipeline(
            [("baseline", "/fake/base.pcap")],
            [("current", "/fake/cur.pcap")],
            DiffOptions(tls=True, auto_topology=False),
            on_progress=lambda msg: None,
        )

        assert "baseline" in captured.get("tls_calls", [])
        assert "current" in captured.get("tls_calls", [])
        assert result.tls_findings_baseline == ["tls_finding"]
        assert result.tls_findings_current == ["tls_finding"]


class TestDiffQUICBranch:
    """Branche quic du pipeline de diff (lines 163-191)."""

    def test_diff_quic_success(self, monkeypatch):
        """Lines 175-191 : quic=True avec import reussi -> diagnose_quic appele."""
        captured = {}

        monkeypatch.setattr(
            "netcross_gtk4.analysis_pipeline.load_packets",
            lambda captures, parallel, on_progress=None: [make_pkt(src="10.0.0.1", dst="10.0.0.2")],
        )

        mock_quic = MagicMock()
        mock_quic.parse_quic_capture = lambda label, path: captured.setdefault("quic_calls", []).append(label) or []
        mock_quic.diagnose_quic = lambda events, points: captured.__setitem__("diagnose_quic", True) or ["quic_finding"]
        mock_quic.print_quic_diagnostics = lambda f: None
        monkeypatch.setitem(sys.modules, "netcross_core.quic_diagnostics", mock_quic)

        result = run_diff_pipeline(
            [("baseline", "/fake/base.pcap")],
            [("current", "/fake/cur.pcap")],
            DiffOptions(quic=True, auto_topology=False),
            on_progress=lambda msg: None,
        )

        assert captured.get("diagnose_quic") is True
        assert result.quic_findings_baseline == ["quic_finding"]
        assert result.quic_findings_current == ["quic_finding"]

    def test_diff_quic_import_error(self, monkeypatch):
        """Lines 170-173 : quic=True mais ImportError -> message d'avertissement."""
        monkeypatch.setattr(
            "netcross_gtk4.analysis_pipeline.load_packets",
            lambda captures, parallel, on_progress=None: [make_pkt(src="10.0.0.1", dst="10.0.0.2")],
        )

        # Simule l'absence de cryptography : l'import de quic_diagnostics echoue
        import builtins

        original_import = builtins.__import__

        def blocking_import(name, *args, **kwargs):
            if name == "netcross_core.quic_diagnostics":
                raise ImportError("cryptography absent")
            return original_import(name, *args, **kwargs)

        # Retire quic_diagnostics du cache
        monkeypatch.delitem(sys.modules, "netcross_core.quic_diagnostics", raising=False)
        monkeypatch.setattr("builtins.__import__", blocking_import)

        result = run_diff_pipeline(
            [("baseline", "/fake/base.pcap")],
            [("current", "/fake/cur.pcap")],
            DiffOptions(quic=True, auto_topology=False),
            on_progress=lambda msg: None,
        )

        # Les findings QUIC restent None
        assert result.quic_findings_baseline is None
        assert result.quic_findings_current is None
        # Le texte contient le message d'avertissement
        assert "cryptography" in result.text
