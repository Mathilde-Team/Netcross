# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.capture.replay_capture (Job 44, issue #164) -- rejeu de
trafic controle via tcpreplay. Meme discipline que pour merge_captures
(_wireshark_tool_path/_run_wireshark_tool) : on monkeypatch
shutil.which et subprocess.run, jamais un vrai binaire tcpreplay.
"""

import pytest

import pcap_parser.capture as capture_mod
from pcap_parser.capture import TcpreplayError, TcpreplayNotFoundError, replay_capture


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


@pytest.fixture
def pcap_file(tmp_path):
    p = tmp_path / "capture.pcapng"
    p.write_bytes(b"\x00")
    return str(p)


# -- validation des parametres (avant tout appel a tcpreplay) ----------------


def test_replay_capture_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        replay_capture(str(tmp_path / "absent.pcapng"), "eth0")


def test_replay_capture_refuse_speed_negatif_ou_nul(pcap_file, monkeypatch):
    # aucun appel a tcpreplay ne doit avoir lieu : la validation doit
    # echouer avant meme de chercher le binaire dans le PATH
    def _boom(name):
        raise AssertionError("ne doit pas etre appele")

    monkeypatch.setattr(capture_mod.shutil, "which", _boom)
    with pytest.raises(ValueError):
        replay_capture(pcap_file, "eth0", speed=0)
    with pytest.raises(ValueError):
        replay_capture(pcap_file, "eth0", speed=-1.5)


def test_replay_capture_refuse_speed_non_numerique(pcap_file):
    with pytest.raises(ValueError):
        replay_capture(pcap_file, "eth0", speed="tres-vite")


def test_replay_capture_refuse_loop_inferieur_a_un(pcap_file):
    with pytest.raises(ValueError):
        replay_capture(pcap_file, "eth0", loop=0)
    with pytest.raises(ValueError):
        replay_capture(pcap_file, "eth0", loop=-3)


# -- tcpreplay absent du PATH -------------------------------------------------


def test_replay_capture_leve_tcpreplaynotfounderror_si_absent(pcap_file, monkeypatch):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)
    with pytest.raises(TcpreplayNotFoundError):
        replay_capture(pcap_file, "eth0")


# -- construction des arguments (mock subprocess) -----------------------------


def test_replay_capture_construit_les_arguments_par_defaut(pcap_file, monkeypatch):
    captured = {}

    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/tcpreplay" if name == "tcpreplay" else None)

    def fake_run(args, capture_output, text, check):
        captured["args"] = args
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(capture_mod.subprocess, "run", fake_run)

    replay_capture(pcap_file, "eth0")

    args = captured["args"]
    assert args[0] == "/usr/bin/tcpreplay"
    assert "--intf1=eth0" in args
    assert "--loop=1" in args
    assert "--multiplier=1.0" in args
    assert args[-1] == pcap_file  # le fichier de capture est le dernier argument


def test_replay_capture_transmet_speed_et_loop(pcap_file, monkeypatch):
    captured = {}
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/tcpreplay")

    def fake_run(args, capture_output, text, check):
        captured["args"] = args
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(capture_mod.subprocess, "run", fake_run)

    replay_capture(pcap_file, "eth1", speed=0.5, loop=3)

    args = captured["args"]
    assert "--intf1=eth1" in args
    assert "--loop=3" in args
    assert "--multiplier=0.5" in args
    assert not any(a == "--topspeed" for a in args)


def test_replay_capture_topspeed_prioritaire_sur_speed(pcap_file, monkeypatch):
    captured = {}
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/tcpreplay")

    def fake_run(args, capture_output, text, check):
        captured["args"] = args
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(capture_mod.subprocess, "run", fake_run)

    replay_capture(pcap_file, "eth0", speed="TopSpeed", loop=2)

    args = captured["args"]
    assert "--topspeed" in args
    assert not any(a.startswith("--multiplier=") for a in args)
    assert "--loop=2" in args


# -- echec de tcpreplay --------------------------------------------------------


def test_replay_capture_leve_tcpreplayerror_si_echec(pcap_file, monkeypatch):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/tcpreplay")
    monkeypatch.setattr(
        capture_mod.subprocess,
        "run",
        lambda *a, **kw: _FakeCompletedProcess(returncode=1, stderr="eth0: No such device"),
    )

    with pytest.raises(TcpreplayError) as exc_info:
        replay_capture(pcap_file, "eth0")

    assert exc_info.value.returncode == 1
    assert "No such device" in exc_info.value.stderr
