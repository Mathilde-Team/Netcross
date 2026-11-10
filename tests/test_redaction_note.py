# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.redaction_note -- encart « Anonymisation » du rapport
(#1159, sous-issue 5/5 du chantier #1007) : le rapport certifie ce qui a
été masqué. L'encart doit être présent et exact pour chaque
``--redact-scope`` (adresses, noms, tout), dans le Markdown, le JSON et le
PDF.
"""

import json
import struct
from pathlib import Path

from netcross_core.models import Report
from netcross_core.redact import SCOPE_ADDRESSES, SCOPE_ALL, SCOPE_LABELS, SCOPE_NAMES, AddressRedactor
from netcross_report.json_report import build_json_report_document
from netcross_report.markdown_report import build_markdown_report_document
from netcross_report.redaction_note import (
    build_redaction_info,
    lignes_encart_markdown,
)

try:
    import reportlab  # noqa: F401

    REPORTLAB_DISPONIBLE = True
except ImportError:
    REPORTLAB_DISPONIBLE = False


def _redactor(scope: str) -> AddressRedactor:
    redactor = AddressRedactor(scope=scope)
    redactor.pseudonymize_address("10.0.0.5")
    redactor.pseudonymize_address("10.0.0.6")
    redactor.pseudonymize_address("02:00:00:00:00:01")
    redactor.pseudonymize_name("www.example.com")
    return redactor


def _report() -> Report:
    return Report(points=["A", "B"], pairs=[("A", "B")])


# ---------------------------------------------------------------------
# build_redaction_info : périmètre exact pour chaque --redact-scope
# ---------------------------------------------------------------------


def test_info_exacte_pour_chaque_scope():
    for scope in (SCOPE_ADDRESSES, SCOPE_NAMES, SCOPE_ALL):
        redactor = _redactor(scope)
        info = build_redaction_info(
            redactor,
            scope,
            redact_map="table.csv",
            pcapng=["/x/A.pcapng"],
            garder_payload=True,
        )
        assert info["portee_code"] == scope
        assert info["portee"] == SCOPE_LABELS[scope]
        assert info["adresses"] == len(redactor)
        assert info["noms"] == len(redactor.names)
        assert info["table"] == "table.csv"
        assert info["pcapng"] == ["/x/A.pcapng"]
        assert info["garde_charges_utiles"] is True


def test_info_sans_options_facultatives():
    info = build_redaction_info(_redactor(SCOPE_ALL), SCOPE_ALL)
    assert info["table"] is None
    assert info["pcapng"] == []
    assert info["garde_charges_utiles"] is False


def test_encart_markdown_liste_le_perimetre():
    for scope in (SCOPE_ADDRESSES, SCOPE_NAMES, SCOPE_ALL):
        info = build_redaction_info(_redactor(scope), scope)
        lignes = lignes_encart_markdown(info)
        assert lignes[0].startswith("> **Anonymisation — périmètre appliqué**")
        assert any(SCOPE_LABELS[scope] in ligne for ligne in lignes)
        assert any("3 adresse(s) IP/MAC et 1 nom(s)" in ligne for ligne in lignes)
        assert any("constats" in ligne for ligne in lignes)


def test_encart_markdown_mentionne_pcaps_et_charges():
    info = build_redaction_info(_redactor(SCOPE_ALL), SCOPE_ALL, pcapng=["/x/A.pcapng"], garder_payload=False)
    texte = "\n".join(lignes_encart_markdown(info))
    assert "`/x/A.pcapng`" in texte
    assert "zéroées" in texte
    info_garde = build_redaction_info(_redactor(SCOPE_ALL), SCOPE_ALL, pcapng=["/x/A.pcapng"], garder_payload=True)
    texte_garde = "\n".join(lignes_encart_markdown(info_garde))
    assert "conservées" in texte_garde


# ---------------------------------------------------------------------
# Rapports : l'encart est présent avec --redact, absent sinon
# ---------------------------------------------------------------------


def test_markdown_encart_present_avec_redaction_absent_sans():
    info = build_redaction_info(_redactor(SCOPE_ALL), SCOPE_ALL)
    avec = build_markdown_report_document(_report(), redaction=info)
    assert "Anonymisation — périmètre appliqué" in avec
    assert SCOPE_LABELS[SCOPE_ALL] in avec
    sans = build_markdown_report_document(_report())
    assert "Anonymisation — périmètre appliqué" not in sans


def test_json_redaction_presente_avec_redaction_absente_sans():
    info = build_redaction_info(_redactor(SCOPE_ADDRESSES), SCOPE_ADDRESSES)
    avec = build_json_report_document(_report(), redaction=info)
    assert avec["redaction"] == info
    sans = build_json_report_document(_report())
    assert sans["redaction"] is None


def test_pdf_encart_ne_leve_pas(tmp_path):
    if not REPORTLAB_DISPONIBLE:
        import pytest

        pytest.skip("reportlab absent")
    from netcross_report import generate_pdf

    info = build_redaction_info(_redactor(SCOPE_ALL), SCOPE_ALL)
    sortie = tmp_path / "rapport.pdf"
    generate_pdf(_report(), str(sortie), redaction=info)
    assert sortie.exists() and sortie.stat().st_size > 0


# ---------------------------------------------------------------------
# CLI : l'encart est servi par un vrai run --redact
# ---------------------------------------------------------------------


def _trame_tcp() -> bytes:
    """Trame Ethernet/IPv4/TCP minimale, sommes de contrôle justes."""

    def somme(donnees: bytes) -> int:
        if len(donnees) % 2:
            donnees += b"\x00"
        total = sum(struct.unpack(f"!{len(donnees) // 2}H", donnees))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF

    tcp = struct.pack("!HHIIBBHHH", 44000, 443, 1000, 0, 5 << 4, 0x18, 65535, 0, 0) + b"charge"
    pseudo = b"\x0a\x00\x00\x05" + b"\x5d\xb8\xd8\x22" + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", somme(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        b"\x0a\x00\x00\x05",
        b"\x5d\xb8\xd8\x22",
    )
    ip = ip[:10] + struct.pack("!H", somme(ip)) + ip[12:]
    return b"\x3c\x22\xfb\x44\x55\x66" + b"\x3c\x22\xfb\x11\x22\x33" + b"\x08\x00" + ip + tcp


def _ecrire_pcap(capture: Path) -> None:
    trame = _trame_tcp()
    with capture.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1_700_000_000, 0, len(trame), len(trame)))
        f.write(trame)


def test_cli_encart_dans_md_et_json(monkeypatch, tmp_path):
    import shutil
    import sys

    if shutil.which("tshark") is None:
        import pytest

        pytest.skip("tshark absent")
    import cross_capture_analyzer_cli as cli

    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture)
    md = tmp_path / "r.md"
    js = tmp_path / "r.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            f"A={capture}",
            "--redact",
            "--md-report",
            str(md),
            "--json-report",
            str(js),
        ],
    )
    code = cli.main()
    assert code in (0, None)
    contenu_md = md.read_text(encoding="utf-8")
    assert "Anonymisation — périmètre appliqué" in contenu_md
    assert "adresse(s) IP/MAC" in contenu_md
    doc = json.loads(js.read_text(encoding="utf-8"))
    assert doc["redaction"]["portee_code"] == "tout"
    assert doc["redaction"]["adresses"] >= 2
    assert doc["redaction"]["noms"] >= 0


def test_cli_sans_redact_pas_dencart(monkeypatch, tmp_path):
    import shutil
    import sys

    if shutil.which("tshark") is None:
        import pytest

        pytest.skip("tshark absent")
    import cross_capture_analyzer_cli as cli

    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture)
    js = tmp_path / "r.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            f"A={capture}",
            "--json-report",
            str(js),
        ],
    )
    code = cli.main()
    assert code in (0, None)
    doc = json.loads(js.read_text(encoding="utf-8"))
    assert doc["redaction"] is None
