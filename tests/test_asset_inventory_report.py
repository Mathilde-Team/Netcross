# SPDX-License-Identifier: GPL-3.0-or-later
"""
Issue #350 : l'inventaire d'actifs (#151) est calcule, compare a la
baseline d'hotes connus (--known-hosts) et rendu partout -- rapport de
securite texte, HTML, JSON, export SIEM (CEF/LEEF, via les constats
« nouvel hote »).
"""

from __future__ import annotations

import html
import json
import sys

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_core.security.findings import apply_security_findings, new_host_findings
from netcross_report.json_report import generate_json_report
from netcross_report.security_html import render_security_html
from netcross_report.security_report import build_security_report, format_security_report, security_report_to_dict
from netcross_report.siem_export import export_cef, export_leef

LINUX = "10.0.0.1"  # connu
WINDOWS = "10.0.0.9"  # absent de la baseline
CLIENT = "10.0.0.2"  # connu


def _packets():
    return [
        # Linux (TTL initial 64, 3 sauts) repond SYN-ACK sur 22 : port expose
        make_pkt(src=CLIENT, dst=LINUX, sport=50000, dport=22, flags="S.......", ttl=64, ts=1.0),
        make_pkt(src=LINUX, dst=CLIENT, sport=22, dport=50000, flags="SA......", ttl=61, ts=1.1),
        # Windows (TTL initial 128) : nouvel hote, expose 445
        make_pkt(src=CLIENT, dst=WINDOWS, sport=50001, dport=445, flags="S.......", ttl=64, ts=2.0),
        make_pkt(src=WINDOWS, dst=CLIENT, sport=445, dport=50001, flags="SA......", ttl=125, ts=2.1),
    ]


def _report(known_hosts=frozenset({LINUX, CLIENT})) -> Report:
    r = Report(points=["A"])
    apply_security_findings(r, _packets(), known_hosts=known_hosts)
    return r


def _asset(r: Report, ip: str) -> dict:
    return next(a for a in r.asset_inventory if a["ip"] == ip)


# -- inventaire et baseline ----------------------------------------------------


def test_nouvel_hote_detecte_par_rapport_a_la_baseline():
    r = _report()
    assert r.asset_baseline_size == 2
    assert _asset(r, WINDOWS)["is_new"] is True
    assert _asset(r, LINUX)["is_new"] is False
    assert _asset(r, CLIENT)["is_new"] is False
    new = [f for f in r.security_findings if f.get("detector") == "asset_inventory"]
    assert [f["host"] for f in new] == [WINDOWS]
    assert new[0]["severity"] == "moyenne"
    assert new[0]["category"] == "anomalie"
    assert f"nouvel hote {WINDOWS}" in new[0]["detail"]
    assert "Windows" in new[0]["detail"] and "tcp/445" in new[0]["detail"]
    assert new[0]["point"] == "A"


def test_os_deduit_du_ttl_linux_et_windows():
    r = _report()
    assert _asset(r, LINUX)["os_guess"]["family"] == "Linux/BSD/macOS"
    assert _asset(r, WINDOWS)["os_guess"]["family"] == "Windows"
    assert [p["port"] for p in _asset(r, LINUX)["ports"]] == [22]


def test_sans_baseline_aucun_hote_nouveau():
    r = _report(known_hosts=None)
    assert r.asset_baseline_size == 0
    assert r.asset_inventory and not any(a["is_new"] for a in r.asset_inventory)
    assert not [f for f in r.security_findings if f.get("detector") == "asset_inventory"]


def test_new_host_findings_ignore_les_hotes_connus():
    assert new_host_findings([{"ip": "1.2.3.4", "is_new": False}]) == []
    (f,) = new_host_findings([{"ip": "1.2.3.4", "is_new": True, "points": []}])
    assert f["point"] is None and "OS inconnu" in f["detail"] and "aucun port expose" in f["detail"]


# -- rendus ---------------------------------------------------------------------


def test_section_texte_inventaire():
    sr = build_security_report(_report())
    text = "\n".join(format_security_report(sr))
    assert "hotes inventories : 3 (dont 1 nouveau(x), baseline de 2 hote(s))" in text
    assert "-- Inventaire d'actifs (decouverte passive) --" in text
    section = text.split("Inventaire d'actifs (decouverte passive)")[1]
    lignes = [line for line in section.splitlines() if line.startswith("  10.")]
    # nouveaux hotes en tete
    assert lignes[0].startswith(f"  {WINDOWS} [NOUVEAU] -- Windows")
    assert any(line.startswith(f"  {LINUX} -- Linux/BSD/macOS") and "tcp/22" in line for line in lignes)
    # le constat apparait aussi dans les anomalies, sous le bon libelle
    assert "Inventaire d'actifs (nouveaux hotes)" in text


def test_section_texte_sans_baseline():
    text = "\n".join(format_security_report(build_security_report(_report(known_hosts=None))))
    assert "(dont 0 nouveau(x), sans baseline)" in text
    assert "[NOUVEAU]" not in text


def test_serialisation_json_et_html(tmp_path):
    r = _report()
    sr = build_security_report(r)
    d = security_report_to_dict(sr)
    assert d["dashboard"]["assets_total"] == 3
    assert d["dashboard"]["assets_new"] == 1
    assert d["dashboard"]["assets_baseline_size"] == 2
    assert {a["ip"] for a in d["assets"] if a["is_new"]} == {WINDOWS}
    out = tmp_path / "r.json"
    generate_json_report(r, str(out), security_report=sr)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert {a["ip"] for a in doc["security_report"]["assets"]} == {LINUX, WINDOWS, CLIENT}
    page = html.unescape(render_security_html(sr))
    assert "<h2>Inventaire d'actifs (decouverte passive)</h2>" in page
    assert "t-actifs" in page and ">nouveau</span>" in page
    assert "hotes inventories, dont 1 nouveau(x)" in page


def test_export_siem_contient_le_nouvel_hote():
    r = _report()
    cef = "\n".join(export_cef(r))
    leef = "\n".join(export_leef(r))
    assert f"nouvel hote {WINDOWS}" in cef
    assert f"nouvel hote {WINDOWS}" in leef
    assert f"nouvel hote {LINUX}" not in cef


# -- CLI --------------------------------------------------------------------------


def _analyzer(monkeypatch, *argv):
    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *map(str, argv)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_known_hosts_sans_security_report(tmp_path, monkeypatch, capsys):
    f = tmp_path / "h.json"
    f.write_text('["10.0.0.1"]')
    assert _analyzer(monkeypatch, "--capture", "A=x.pcap", "--known-hosts", f) == 1
    assert "--known-hosts necessite --security-report" in capsys.readouterr().err


def test_cli_known_hosts_fichier_absent(tmp_path, monkeypatch, capsys):
    code = _analyzer(monkeypatch, "--capture", "A=x.pcap", "--security-report", "--known-hosts", tmp_path / "no.json")
    assert code == 1
    assert "--known-hosts : fichier introuvable" in capsys.readouterr().err


def test_cli_known_hosts_liste_vide_refusee(tmp_path, monkeypatch, capsys):
    f = tmp_path / "h.json"
    f.write_text("[]")
    assert _analyzer(monkeypatch, "--capture", "A=x.pcap", "--security-report", "--known-hosts", f) == 1
    assert "--known-hosts : aucune IP lue" in capsys.readouterr().err
