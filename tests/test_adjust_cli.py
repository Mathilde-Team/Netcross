# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de l'integration CLI de --adjust-time-output (issue #165, Job 45).
On simule editcap (absente dans le CI) et on verifie la logique de
validation et de dispatch, sans lancer le VRAI binaire.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

import pytest
from pcap_builders import synthetic_packets, write_pcap


def _run_cli(argv, monkeypatch):
    """Lance cross_capture_analyzer_cli.main() avec argv simule.
    Renvoie le code de sortie (0 = OK, 1 = erreur)."""

    def fake_which(name):
        if name in ("editcap", "tshark"):
            return f"/usr/bin/{name}"
        return shutil.which(name)

    def fake_run(args, **kw):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *argv])
    import cross_capture_analyzer_cli as cli

    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


@pytest.fixture
def fake_adjust(monkeypatch):
    """adjust_timestamps simule : enregistre les appels, cree le fichier
    de sortie vide pour que le print ne leve pas."""
    calls = []

    def fake(path_in, path_out, offset_seconds=0.0, normalize=False, align_to=None):
        calls.append(
            {
                "path_in": path_in,
                "path_out": path_out,
                "offset_seconds": offset_seconds,
                "normalize": normalize,
                "align_to": align_to,
            }
        )
        open(path_out, "w").close()

    monkeypatch.setattr("cross_capture_analyzer_cli.adjust_timestamps", fake)
    return calls


def test_adjust_time_necessite_pas_live(monkeypatch):
    """--adjust-time n'est jamais compatible avec --live."""
    code = _run_cli(
        ["--live", "eth0", "--adjust-time-output", "/tmp/out.pcap"],
        monkeypatch,
    )
    assert code == 1


def test_adjust_time_refuse_plusieurs_fichiers(monkeypatch, tmp_path):
    cap1 = tmp_path / "a.pcap"
    cap2 = tmp_path / "b.pcap"
    write_pcap(cap1, synthetic_packets(3))
    write_pcap(cap2, synthetic_packets(3))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap1}",
            "--capture",
            f"B={cap2}",
            "--adjust-time-output",
            str(out),
            "--time-offset",
            "10",
        ],
        monkeypatch,
    )
    assert code == 1


def test_adjust_time_refuse_options_d_analyse(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--adjust-time-output",
            str(out),
            "--time-offset",
            "10",
            "--triage",
        ],
        monkeypatch,
    )
    assert code == 1


def test_adjust_time_exclusif_avec_merge(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--merge",
            str(tmp_path / "merged.pcap"),
            "--adjust-time-output",
            str(out),
            "--time-offset",
            "10",
        ],
        monkeypatch,
    )
    assert code == 1


def test_adjust_time_exclusif_avec_split(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--split",
            f"size:{out}",
            "--adjust-time-output",
            str(tmp_path / "adj.pcap"),
            "--time-offset",
            "10",
        ],
        monkeypatch,
    )
    assert code == 1


def test_time_offset_necessite_adjust_time_output(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    code = _run_cli(
        ["--capture", f"A={cap}", "--time-offset", "10"],
        monkeypatch,
    )
    assert code == 1


def test_normalize_time_necessite_adjust_time_output(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    code = _run_cli(
        ["--capture", f"A={cap}", "--normalize-time"],
        monkeypatch,
    )
    assert code == 1


def test_align_to_necessite_adjust_time_output(monkeypatch, tmp_path):
    cap = tmp_path / "cap.pcap"
    ref = tmp_path / "ref.pcap"
    write_pcap(cap, synthetic_packets(3))
    write_pcap(ref, synthetic_packets(3))
    code = _run_cli(
        ["--capture", f"A={cap}", "--align-to", str(ref)],
        monkeypatch,
    )
    assert code == 1


def test_modes_mutuellement_exclusifs(monkeypatch, tmp_path):
    """--time-offset et --normalize-time ne peuvent pas etre utilises ensemble."""
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(3))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--adjust-time-output",
            str(out),
            "--time-offset",
            "10",
            "--normalize-time",
        ],
        monkeypatch,
    )
    assert code == 1


def test_adjust_time_dispatch_appelle_adjust_timestamps(monkeypatch, tmp_path, fake_adjust):
    """Verifie que --adjust-time-output --time-offset lance bien
    adjust_timestamps avec le bon offset."""
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(5))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--adjust-time-output",
            str(out),
            "--time-offset",
            "10.5",
        ],
        monkeypatch,
    )
    assert code == 0
    assert len(fake_adjust) == 1
    assert fake_adjust[0]["offset_seconds"] == 10.5
    assert fake_adjust[0]["normalize"] is False
    assert fake_adjust[0]["align_to"] is None


def test_adjust_time_dispatch_normalize(monkeypatch, tmp_path, fake_adjust):
    """Verifie que --normalize-time passe normalize=True."""
    cap = tmp_path / "cap.pcap"
    write_pcap(cap, synthetic_packets(5))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--adjust-time-output",
            str(out),
            "--normalize-time",
        ],
        monkeypatch,
    )
    assert code == 0
    assert fake_adjust[0]["normalize"] is True


def test_adjust_time_dispatch_align_to(monkeypatch, tmp_path, fake_adjust):
    """Verifie que --align-to passe le chemin de reference."""
    cap = tmp_path / "cap.pcap"
    ref = tmp_path / "ref.pcap"
    write_pcap(cap, synthetic_packets(5))
    write_pcap(ref, synthetic_packets(5))
    out = tmp_path / "out.pcap"
    code = _run_cli(
        [
            "--capture",
            f"A={cap}",
            "--adjust-time-output",
            str(out),
            "--align-to",
            str(ref),
        ],
        monkeypatch,
    )
    assert code == 0
    assert fake_adjust[0]["align_to"] == str(ref)
