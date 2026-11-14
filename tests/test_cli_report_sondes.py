# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1103 : les métadonnées de sonde remontent jusqu'au rapport.

Chaîne testée : les pertes DÉCLARÉES (ISB) et l'horloge ANNONCÉE, lues
par la sonde, sont consommées par la CLI (``--sonde-meta POINT=JSON``)
puis rendues dans les trois formats de rapport (texte, Markdown, JSON) --
à distinguer des pertes réseau estimées, la section reste absente sans
``--sonde-meta`` (sortie historique inchangée).
"""

from __future__ import annotations

import json
import sys

import pytest

from netcross_core.models import Report
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from netcross_report.markdown_report import build_markdown_report_document

PERTES_SONDE = {
    "packets_received": 3000,
    "packets_dropped": 9,
    "ifdrop": 6,
    "osdrop": 3,
}
HORLOGE_SONDE = {
    "source": "chrony",
    "synchronized": True,
    "offset_ms": 0.3,
    "dispersion_ms": 0.5,
    "reference": "192.168.0.1",
    "measured_at": 1_791_000_000.0,
}


def _rapport_avec_sondes() -> Report:
    r = Report(points=["A", "B"])
    r.pertes_sondes = {"A": dict(PERTES_SONDE)}
    r.horloges_sondes = {"A": dict(HORLOGE_SONDE)}
    return r


# -- rapport texte ---------------------------------------------------------------------------


def test_rapport_texte_sans_sonde_meta_inchange(capsys):
    r = Report(points=["A", "B"])
    print_report(r)
    out = capsys.readouterr().out
    assert "Sondes" not in out  # section absente sans métadonnées de sonde


def test_rapport_texte_affiche_pertes_declarees_et_horloge_annoncee(capsys):
    print_report(_rapport_avec_sondes())
    out = capsys.readouterr().out
    assert "-- Sondes (pertes déclarées, horloge annoncée) --" in out
    # 9 perdus sur 3009 annoncés = 0,3 % -- « la sonde a perdu », pas le réseau
    assert "A : 0.3 % de pertes de capture (9 perdu(s) sur 3009 annoncés" in out
    assert "ifdrop 6 / osdrop 3" in out
    # horloge annoncée : source, synchronisation, décalage, dispersion, référence
    assert "A : horloge chrony (synchronisée, décalage annoncé 0.3 ms" in out
    assert "dispersion 0.5 ms" in out
    assert "référence 192.168.0.1" in out
    # B n'a rien déclaré : rien d'affiché pour B (pas de ligne inventée)
    assert "B : " not in out.split("-- Sondes")[1].split("\n\n")[0]


# -- rapport Markdown ------------------------------------------------------------------------


def test_rapport_markdown_affiche_les_sondes():
    document = build_markdown_report_document(_rapport_avec_sondes())
    assert "### Sondes — pertes de capture déclarées, horloge annoncée" in document
    assert "0.3 % de pertes de capture" in document
    assert "ifdrop 6 / osdrop 3" in document
    assert "horloge chrony (synchronisée, décalage annoncé 0.3 ms" in document


def test_rapport_markdown_sans_sonde_meta_sans_section():
    document = build_markdown_report_document(Report(points=["A", "B"]))
    assert "Sondes — pertes de capture déclarées" not in document


# -- rapport JSON -----------------------------------------------------------------------------


def test_rapport_json_expose_sondes_et_annonce():
    r = _rapport_avec_sondes()
    # une estimation d'horloge pour confronter l'annonce à l'estimation
    from netcross_core.models import EstimationHorloge

    estimation = EstimationHorloge(
        decalage_ms=0.25,
        t0=1_791_000_000.0,
        derive_ppm=1.0,
        ic_decalage_ms=0.15,
        ic_derive_ppm=0.5,
        n_echantillons=100,
        n_conserves=90,
        methode="bidirectionnel",
        manuel=False,
    )
    r.clock_offset_estimate = {("A", "B"): estimation}
    document = build_json_report_document(r)
    assert document["sondes"]["capture_loss"]["A"] == PERTES_SONDE
    assert document["sondes"]["clock"]["A"] == HORLOGE_SONDE
    # l'annonce accompagne l'estimation de la paire concernée
    entree = document["clock_offsets"][0]
    assert entree["offset_ms"] == 0.25
    assert entree["annonce"]["A"] == HORLOGE_SONDE
    assert "B" not in entree["annonce"]


def test_rapport_json_sans_sonde_meta_sans_cle():
    document = build_json_report_document(Report(points=["A", "B"]))
    assert "sondes" not in document


# -- CLI --sonde-meta -------------------------------------------------------------------------


def test_charger_sondes_meta_remplit_le_rapport(tmp_path):
    import cross_capture_analyzer_cli as cli

    meta = tmp_path / "sonde.json"
    meta.write_text(json.dumps({"capture_loss": PERTES_SONDE, "clock": HORLOGE_SONDE}), encoding="utf-8")
    pertes, horloges = cli._charger_sondes_meta([f"A={meta}"], ["A", "B"])
    assert pertes == {"A": PERTES_SONDE}
    assert horloges == {"A": HORLOGE_SONDE}


def test_charger_sondes_meta_point_inconnu_refuse(tmp_path):
    """Un point inconnu est refusé (exit 1) : une métadonnée ignorée
    silencieusement laisserait croire que la sonde n'a rien perdu."""
    import cross_capture_analyzer_cli as cli

    meta = tmp_path / "sonde.json"
    meta.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli._charger_sondes_meta([f"Z={meta}"], ["A", "B"])
    assert exc.value.code == 1


def test_charger_sondes_meta_format_invalide_refuse():
    import cross_capture_analyzer_cli as cli

    with pytest.raises(SystemExit) as exc:
        cli._charger_sondes_meta(["sans-egale"], ["A"])
    assert exc.value.code == 1


def test_charger_sondes_meta_json_illisible_refuse(tmp_path):
    import cross_capture_analyzer_cli as cli

    meta = tmp_path / "sonde.json"
    meta.write_text("{pas du tout du json", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli._charger_sondes_meta([f"A={meta}"], ["A"])
    assert exc.value.code == 1


def test_charger_sondes_meta_fichier_absent_refuse(tmp_path):
    import cross_capture_analyzer_cli as cli

    with pytest.raises(SystemExit) as exc:
        cli._charger_sondes_meta([f"A={tmp_path / 'absent.json'}"], ["A"])
    assert exc.value.code == 1


# -- bout en bout CLI : les pertes déclarées remontent jusqu'au rapport ------------------------


def test_cli_sonde_meta_remonte_jusqu_au_rapport(monkeypatch, capsys, tmp_path):
    """Bout en bout dans le processus : --sonde-meta A=JSON alimente le
    rapport texte (critère d'acceptation de l'issue : les pertes déclarées
    dans l'ISB remontent jusqu'au rapport)."""
    from conftest import make_pkt

    import cross_capture_analyzer_cli as cli

    capture = tmp_path / "a.pcapng"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # en-tête pcap factice
    meta = tmp_path / "sonde.json"
    meta.write_text(json.dumps({"capture_loss": PERTES_SONDE, "clock": HORLOGE_SONDE}), encoding="utf-8")
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: [make_pkt(point=label)])
    monkeypatch.setattr(
        sys,
        "argv",
        ["netcross", "--capture", f"A={capture}", "--sonde-meta", f"A={meta}"],
    )
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code
    out = capsys.readouterr().out
    assert "0.3 % de pertes de capture" in out
    assert "horloge chrony (synchronisée, décalage annoncé 0.3 ms" in out


def test_cli_sonde_meta_sans_donnees_rapport_inchange(monkeypatch, capsys, tmp_path):
    """Sans --sonde-meta, la section Sondes n'apparaît pas."""
    from conftest import make_pkt

    import cross_capture_analyzer_cli as cli

    capture = tmp_path / "a.pcapng"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: [make_pkt(point=label)])
    monkeypatch.setattr(sys, "argv", ["netcross", "--capture", f"A={capture}"])
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code
    out = capsys.readouterr().out
    assert "pertes de capture" not in out
