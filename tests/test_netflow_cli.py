# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #362 : ingestion NetFlow accessible depuis le CLI, avec sortie JSON."""

from __future__ import annotations

import json
import sys

import pytest
from test_netflow_v5 import _build_packet

import cross_capture_analyzer_cli as cli
from netcross_core.netflow import iter_netflow_v5_file, summarize_flow_records
from netcross_core.netflow.summary import format_flow_summary


def _export(tmp_path, name="r1.nf5"):
    """Deux datagrammes concatenes : un gros transfert HTTPS, du DNS, un ping."""
    first = _build_packet(
        [
            {"src_addr": "10.0.0.5", "dst_addr": "93.184.216.34", "dst_port": 443, "packets": 900, "octets": 1_200_000},
            {"src_addr": "10.0.0.5", "dst_addr": "93.184.216.34", "dst_port": 443, "packets": 100, "octets": 300_000},
            {
                "src_addr": "10.0.0.7",
                "dst_addr": "9.9.9.9",
                "dst_port": 53,
                "protocol": 17,
                "packets": 4,
                "octets": 300,
            },
        ]
    )
    second = _build_packet(
        [{"src_addr": "10.0.0.7", "dst_addr": "10.0.0.1", "src_port": 0, "dst_port": 0, "protocol": 1, "octets": 840}],
        unix_secs=1_700_000_100,
        flow_sequence=4,
    )
    path = tmp_path / name
    path.write_bytes(first + second)
    return path


def _cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *map(str, argv)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_resume_agrege_et_classe(tmp_path):
    s = summarize_flow_records(iter_netflow_v5_file(str(_export(tmp_path)), exporter="R1"))
    assert s["totals"] == {"flows": 4, "packets": 1014, "octets": 1_501_140}
    assert s["netflow_versions"] == [5]
    assert [e["exporter"] for e in s["exporters"]] == ["R1"]
    assert [p["protocol"] for p in s["protocols"]] == ["TCP", "ICMP", "UDP"]
    assert s["top_talkers"][0] == {"address": "10.0.0.5", "flows": 2, "packets": 1000, "octets": 1_500_000}
    conv = s["top_conversations"][0]
    assert (conv["src"], conv["dst"], conv["dst_port"], conv["protocol"], conv["flows"]) == (
        "10.0.0.5",
        "93.184.216.34",
        443,
        "TCP",
        2,
    )
    assert [(p["protocol"], p["port"]) for p in s["top_dst_ports"]] == [("TCP", 443), ("UDP", 53)]  # ICMP sans port
    assert s["start"] < s["end"]


def test_top_borne_les_classements(tmp_path):
    s = summarize_flow_records(iter_netflow_v5_file(str(_export(tmp_path))), top=1)
    assert len(s["top_talkers"]) == len(s["top_conversations"]) == len(s["top_dst_ports"]) == 1
    assert len(s["protocols"]) == 3  # non borne : liste courte et complete


def test_resume_vide():
    s = summarize_flow_records([])
    assert s["totals"]["flows"] == 0
    assert "Aucun flux" in "\n".join(format_flow_summary(s))


def test_cli_netflow_texte_et_json(tmp_path, monkeypatch, capsys):
    out = tmp_path / "nf.json"
    assert _cli(monkeypatch, "--netflow", f"R1={_export(tmp_path)}", "--json-report", out) == 0
    text = capsys.readouterr().out
    assert "=== Resume NetFlow ===" in text
    assert "4 flux, 1014 paquets" in text
    assert "TCP   10.0.0.5:12345 -> 93.184.216.34:443" in text
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["netflow"]["version"] == 1
    assert data["netflow"]["totals"]["flows"] == 4
    assert data["netflow"]["exporters"][0]["exporter"] == "R1"


def test_cli_netflow_plusieurs_exportateurs(tmp_path, monkeypatch, capsys):
    a, b = _export(tmp_path, "a.nf5"), _export(tmp_path, "b.nf5")
    assert _cli(monkeypatch, "--netflow", f"R1={a}", "--netflow", str(b)) == 0
    text = capsys.readouterr().out
    assert "8 flux" in text
    assert "R1" in text and str(b) in text  # sans EXPORTATEUR= : le chemin etiquette la source


def test_cli_netflow_fichier_tronque(tmp_path, monkeypatch, capsys):
    path = tmp_path / "t.nf5"
    path.write_bytes(_export(tmp_path).read_bytes()[:-10])
    assert _cli(monkeypatch, "--netflow", path) == 1
    assert "tronque" in capsys.readouterr().err


def test_cli_netflow_fichier_absent(tmp_path, monkeypatch, capsys):
    assert _cli(monkeypatch, "--netflow", tmp_path / "absent.nf5") == 1
    assert "absent.nf5" in capsys.readouterr().err


def test_cli_netflow_incompatible_avec_capture(tmp_path, monkeypatch, capsys):
    assert _cli(monkeypatch, "--netflow", _export(tmp_path), "--capture", "A=x.pcap") == 1
    assert "incompatible avec --capture" in capsys.readouterr().err


@pytest.mark.parametrize("spec", ["=f.nf5", "R1="])
def test_cli_netflow_format_invalide(monkeypatch, capsys, spec):
    assert _cli(monkeypatch, "--netflow", spec) == 1
    assert "Format invalide pour --netflow" in capsys.readouterr().err


def test_cli_netflow_top_invalide(tmp_path, monkeypatch, capsys):
    assert _cli(monkeypatch, "--netflow", _export(tmp_path), "--netflow-top", "0") == 1
    assert "--netflow-top" in capsys.readouterr().err
