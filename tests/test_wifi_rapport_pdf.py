# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1148 : section Wi-Fi du rapport PDF et couverture documentée."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import make_pkt
from reportlab.platypus import Paragraph
from test_wifi_clients import STA, _capture_perte_air, _pkt

import netcross_core.parsing as parsing
from netcross_core import wifi
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_report import pdf
from pcap_parser.radio import RadioInfo

RACINE = Path(__file__).resolve().parent.parent


def _texte_pdf(chemin: Path) -> str:
    if shutil.which("pdftotext") is None:
        pytest.skip("pdftotext non installe : contenu du PDF non verifiable")
    return subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, text=True, check=True).stdout


def _cellules(table) -> list[list[str]]:
    return [[c.text if isinstance(c, Paragraph) else str(c) for c in ligne] for ligne in table._cellvalues]


def test_table_wifi_une_ligne_par_station():
    pkts = [_pkt(0.0, radio=RadioInfo(rssi_dbm=-70, data_rate_mbps=6.0), radio_retries=1), _pkt(0.2)]
    sans = [_pkt(0.0, point="B", wlan_station=("02:00:00:00:00:09", "02:00:00:00:00:01", False))]
    table = pdf._wifi_table(wifi.metriques_clients(pkts + sans), pdf._styles())
    entete, ligne, ligne_sans = _cellules(table)
    assert entete[0] == "Point" and entete[-1] == "Constats"
    assert ligne == [
        "AIR",
        STA,
        "-70 dBm",
        "6.0 Mbit/s",
        "33.3%",
        "0",
        f"{pkts[0].length * 8 * 2 / 6e6 * 1000:.2f} ms",
        f"{wifi.PERTE_AIR}, {wifi.DEBIT_PHY_BAS}",
    ]
    assert ligne_sans[2:4] == ["\u2014", "\u2014"] and ligne_sans[-1] == "\u2014"


def test_pdf_sans_wifi_sans_section(tmp_path):
    pkts = [make_pkt(point="A", ts=0.0)]
    chemin = tmp_path / "r.pdf"
    pdf.generate_pdf(analyse(correlate(pkts), ["A"], pkts), str(chemin))
    assert "Wi-Fi : métriques radio" not in _texte_pdf(chemin)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
def test_pdf_section_wifi_jeu_dedie(tmp_path):
    pkts = parsing.parse_capture("AIR", str(_capture_perte_air(tmp_path / "perte-air.pcap")))
    chemin = tmp_path / "r.pdf"
    pdf.generate_pdf(analyse(correlate(pkts), ["AIR"], pkts), str(chemin))
    texte = _texte_pdf(chemin)
    assert "Wi-Fi : métriques radio par client" in texte
    assert STA in texte
    assert wifi.PERTE_AIR in texte


def test_readme_documente_la_couverture_wifi():
    readme = (RACINE / "README.md").read_text(encoding="utf-8")
    assert "hors périmètre\nde cet outil, qui travaille sur du trafic filaire encapsulé" not in readme
    assert "Pas encore de constats radio" not in readme
    for limite in ("un canal par interface", "802.11ax MU partiel", "WPA3-SAE"):
        assert limite in readme
    detecteurs = (RACINE / "docs" / "detectors.md").read_text(encoding="utf-8")
    assert "## Wi-Fi : métriques radio par client" in detecteurs
    assert "un canal par interface de capture" in detecteurs
