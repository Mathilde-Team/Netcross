# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.siem_export -- tests (issue #170).

Teste l'export CEF : format des lignes, mapping sévérité, écriture fichier.
"""

from __future__ import annotations

from pathlib import Path

from netcross_core.models import Report
from netcross_report.siem_export import export_cef, write_cef


def _make_report(findings: list[dict] | None = None) -> Report:
    """Crée un Report avec des security_findings."""
    report = Report()
    report.security_findings = findings or []
    return report


def test_export_cef_empty():
    """export_cef avec un report vide doit retourner une liste vide."""
    report = _make_report([])
    lines = export_cef(report)
    assert lines == []


def test_export_cef_single():
    """export_cef avec un constat doit produire une ligne CEF valide."""
    report = _make_report(
        [
            {
                "severity": "elevee",
                "category": "exploit",
                "detail": "Test exploit detection",
                "point": "LAN",
            }
        ]
    )
    lines = export_cef(report)
    assert len(lines) == 1
    line = lines[0]
    assert line.startswith("CEF:0|Netcross|Netcross|1.0|")
    assert "|100|" in line  # SignatureID pour exploit
    assert "|8|" in line  # Severity CEF pour elevee


def test_export_cef_multiple():
    """export_cef avec plusieurs constats doit produire plusieurs lignes."""
    report = _make_report(
        [
            {"severity": "critique", "category": "exploit", "detail": "Exploit 1", "point": "LAN"},
            {"severity": "moyenne", "category": "anomalie", "detail": "Anomalie 1", "point": "WAN"},
            {"severity": "faible", "category": "dns_tunnel", "detail": "DNS tunnel", "point": None},
        ]
    )
    lines = export_cef(report)
    assert len(lines) == 3
    # Vérifier que chaque ligne a le bon SignatureID
    assert "|100|" in lines[0]  # exploit
    assert "|200|" in lines[1]  # anomalie
    assert "|201|" in lines[2]  # dns_tunnel


def test_export_cef_severity_mapping():
    """Le mapping sévérité doit convertir correctement."""
    test_cases = [
        ("critique", 10),
        ("elevee", 8),
        ("haute", 8),
        ("moyenne", 6),
        ("faible", 3),
        ("inconnue", 5),  # défaut
    ]
    for severity, expected_cef in test_cases:
        report = _make_report([{"severity": severity, "category": "anomalie", "detail": "test", "point": None}])
        lines = export_cef(report)
        assert f"|{expected_cef}|" in lines[0], f"Failed for severity={severity}"


def test_export_cef_escapes_pipe():
    """Les pipes dans les détails doivent être échappés."""
    report = _make_report([{"severity": "moyenne", "category": "anomalie", "detail": "a|b|c", "point": None}])
    lines = export_cef(report)
    # Le pipe dans le détail doit être échappé, pas le pipe séparateur CEF
    assert "\\|" in lines[0]


def test_export_cef_extension_has_timestamp():
    """L'extension CEF doit contenir un timestamp (rt=)."""
    report = _make_report([{"severity": "faible", "category": "anomalie", "detail": "test", "point": "LAN"}])
    lines = export_cef(report)
    assert "rt=" in lines[0]
    assert "shost=LAN" in lines[0]


def test_export_cef_no_point():
    """Sans point, l'extension ne doit pas avoir shost."""
    report = _make_report([{"severity": "faible", "category": "anomalie", "detail": "test", "point": None}])
    lines = export_cef(report)
    assert "shost=" not in lines[0]
    assert "rt=" in lines[0]


def test_write_cef_creates_file(tmp_path):
    """write_cef doit créer un fichier avec les lignes CEF."""
    report = _make_report(
        [
            {"severity": "elevee", "category": "exploit", "detail": "Test", "point": "LAN"},
            {"severity": "faible", "category": "anomalie", "detail": "Anomalie", "point": None},
        ]
    )
    output = tmp_path / "report.cef"
    result_path = write_cef(report, output)

    assert Path(result_path).exists()
    content = output.read_text()
    lines = content.strip().split("\n")
    assert len(lines) == 2
    assert lines[0].startswith("CEF:0|")


def test_write_cef_creates_parent_dirs(tmp_path):
    """write_cef doit créer les répertoires parents si nécessaires."""
    report = _make_report([{"severity": "faible", "category": "anomalie", "detail": "test", "point": None}])
    output = tmp_path / "subdir" / "report.cef"
    result_path = write_cef(report, output)
    assert Path(result_path).exists()
