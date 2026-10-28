# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de la CLI --export-pcap (Job 36, issue #156) : verification des
flags, mutual exclusion et dispatch. tshark est simule (monkeypatch).
"""

from __future__ import annotations

import sys

import pytest


def _run_cli(argv, monkeypatch):
    """Lance cross_capture_analyzer_cli.main() avec argv simule."""
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *argv])
    import cross_capture_analyzer_cli as cli

    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


def _fake_export(monkeypatch):
    """Monkeypatch export_filtered pour ne pas lancer tshark."""
    calls = []

    def fake_export(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr("pcap_parser.capture.export_filtered", fake_export)
    monkeypatch.setattr("cross_capture_analyzer_cli.export_filtered", fake_export, raising=False)
    # Le CLI importe export_filtered depuis netcross_core
    monkeypatch.setattr("netcross_core.export_filtered", fake_export, raising=False)
    return calls


def test_export_pcap_necessite_capture(monkeypatch, capsys):
    code = _run_cli(["--export-pcap", "out.pcap"], monkeypatch)
    assert code == 1
    out = capsys.readouterr().err
    assert "--capture" in out


def test_export_pcap_necessite_pas_live(monkeypatch, capsys):
    code = _run_cli(["--export-pcap", "out.pcap", "--live", "eth0"], monkeypatch)
    assert code == 1
    out = capsys.readouterr().err
    assert "--capture" in out


def test_export_pcap_refuse_plusieurs_fichiers(monkeypatch, capsys):
    code = _run_cli(
        ["--export-pcap", "out.pcap", "--capture", "A=a.pcap", "--capture", "B=b.pcap"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "UN fichier" in out or "fusionnez" in out


def test_export_pcap_refuse_options_d_analyse(monkeypatch, capsys):
    code = _run_cli(
        ["--export-pcap", "out.pcap", "--capture", "A=a.pcap", "--triage"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "incompatible" in out


def test_export_pcap_exclusif_avec_merge(monkeypatch, capsys):
    code = _run_cli(
        ["--export-pcap", "out.pcap", "--capture", "A=a.pcap", "--merge", "m.pcap"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "exclusif" in out


def test_export_pcap_exclusif_avec_split(monkeypatch, capsys):
    code = _run_cli(
        ["--export-pcap", "out.pcap", "--capture", "A=a.pcap", "--split", "count:100"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "exclusif" in out


def test_export_bpf_necessite_export_pcap(monkeypatch, capsys):
    code = _run_cli(
        ["--capture", "A=a.pcap", "--export-bpf", "tcp port 80"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "--export-pcap" in out


def test_export_endpoints_necessite_export_pcap(monkeypatch, capsys):
    code = _run_cli(
        ["--capture", "A=a.pcap", "--export-endpoints", "192.168.1.1"],
        monkeypatch,
    )
    assert code == 1
    out = capsys.readouterr().err
    assert "--export-pcap" in out


def test_export_pcap_dispatch_appelle_export_filtered(monkeypatch, tmp_path):
    """Verifie que --export-pcap appelle export_filtered avec les bons
    arguments."""
    # Creer un fichier pcap factice
    src = tmp_path / "cap.pcap"
    src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\x00" * 24)  # header pcap + 1 record vide

    calls = _fake_export(monkeypatch)
    out = str(tmp_path / "out.pcap")
    code = _run_cli(
        [
            "--capture",
            f"A={src}",
            "--export-pcap",
            out,
            "--export-bpf",
            "tcp port 80",
            "--export-time-start",
            "10",
            "--export-time-end",
            "60",
            "--export-endpoints",
            "192.168.1.1,10.0.0.1",
        ],
        monkeypatch,
    )
    assert code == 0
    assert len(calls) == 1
    args, kwargs = calls[0]
    # Le premier arg positionnel est path_in
    assert str(src) in args[0] or str(src) in args[0]
    # Le deuxieme est path_out
    assert out in args[1] or out == args[1]
    assert kwargs.get("bpf_filter") == "tcp port 80"
    assert kwargs.get("time_start") == 10.0
    assert kwargs.get("time_end") == 60.0
    assert kwargs.get("endpoints") == ["192.168.1.1", "10.0.0.1"]
