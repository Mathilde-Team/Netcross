# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.capture.convert_capture / export_csv / export_json
(Job 49, issue #169) -- conversion de formats et export structure.
Meme discipline que test_replay.py : on monkeypatch shutil.which et
subprocess.run, jamais un vrai binaire tshark.
"""

import sys

import pytest

import pcap_parser.capture as capture_mod
from pcap_parser.capture import convert_capture, export_csv, export_json
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


@pytest.fixture
def pcap_file(tmp_path):
    p = tmp_path / "capture.pcapng"
    p.write_bytes(b"\x00")
    return str(p)


# -- validation des parametres (avant tout appel a tshark) ---------------------


def test_convert_capture_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        convert_capture(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.pcap"))


def test_convert_capture_format_non_supporte(pcap_file, tmp_path):
    with pytest.raises(ValueError, match="format non supporte"):
        convert_capture(pcap_file, str(tmp_path / "out.txt"), fmt="txt")


def test_convert_capture_format_insensible_casse(pcap_file, tmp_path, monkeypatch):
    """PCAPNG, Pcapng, pcapng doivent tous etre acceptes."""
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    convert_capture(pcap_file, str(tmp_path / "out.pcap"), fmt="PCAPNG")
    convert_capture(pcap_file, str(tmp_path / "out2.pcap"), fmt="Pcap")
    assert len(calls) == 2


# -- tshark absent du PATH ----------------------------------------------------


def test_convert_capture_tshark_absent(pcap_file, tmp_path, monkeypatch):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        convert_capture(pcap_file, str(tmp_path / "out.pcap"))


# -- conversion reussie (mock subprocess) -------------------------------------


def test_convert_capture_pcap_vers_pcapng(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "converted.pcapng")
    convert_capture(pcap_file, out, fmt="pcapng")

    assert len(calls) == 1
    args = calls[0]
    assert "-r" in args
    assert pcap_file in args
    assert "-F" in args
    assert "pcapng" in args
    assert "-w" in args
    assert out in args


def test_convert_capture_erf(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "converted.erf")
    convert_capture(pcap_file, out, fmt="erf")

    args = calls[0]
    assert "erf" in args


def test_convert_capture_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="unknown format")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="conversion"):
        convert_capture(pcap_file, str(tmp_path / "out.pcap"))


# -- export CSV ---------------------------------------------------------------


def test_export_csv_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_csv(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.csv"))


def test_export_csv_reussi(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess(stdout="frame.time_epoch,ip.src,ip.dst\n")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "export.csv")
    export_csv(pcap_file, out)

    assert len(calls) == 1
    args = calls[0]
    assert "-T" in args
    assert "fields" in args
    assert "-e" in args
    assert "frame.time_epoch" in args
    assert "ip.src" in args
    assert "ip.dst" in args
    assert "frame.len" in args


def test_export_csv_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="cannot read")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="export CSV"):
        export_csv(pcap_file, str(tmp_path / "out.csv"))


# -- export JSON --------------------------------------------------------------


def test_export_json_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_json(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.json"))


def test_export_json_reussi(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess(stdout='[{"_index": "packets"}]')

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "export.json")
    export_json(pcap_file, out)

    assert len(calls) == 1
    args = calls[0]
    assert "-T" in args
    assert "json" in args


def test_export_json_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="cannot read")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="export JSON"):
        export_json(pcap_file, str(tmp_path / "out.json"))


# -- appels subprocess reels (sans tshark) : validite des arguments -----------


@pytest.mark.parametrize("export", [export_csv, export_json])
def test_export_arguments_subprocess_valides(export, pcap_file, tmp_path, monkeypatch):
    """Regression : capture_output=True + stdout=fichier leve ValueError dans
    subprocess.run. On garde le vrai subprocess.run et on remplace seulement
    la commande tshark par un python qui ecrit sur stdout."""
    real_run = capture_mod.subprocess.run

    def _run(args, **kwargs):
        return real_run([sys.executable, "-c", "print('ok,1')"], **kwargs)

    monkeypatch.setattr(capture_mod.subprocess, "run", _run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    out = tmp_path / "export.out"
    export(pcap_file, str(out))
    assert out.read_text() == "ok,1\n"


@pytest.mark.parametrize(
    "call",
    [
        lambda p: convert_capture(p, p, fmt="pcap"),
        lambda p: export_csv(p, p),
        lambda p: export_json(p, p),
    ],
)
def test_sortie_identique_a_la_source_refusee(call, pcap_file):
    with pytest.raises(ValueError, match="fichier source"):
        call(pcap_file)
    with open(pcap_file, "rb") as fh:
        assert fh.read() == b"\x00"  # source intacte


def test_export_csv_options_de_quotage(pcap_file, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(capture_mod.subprocess, "run", lambda args, **kw: calls.append(args) or _FakeCompletedProcess())
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    export_csv(pcap_file, str(tmp_path / "o.csv"))
    assert "quote=d" in calls[0] and "occurrence=f" in calls[0] and "ipv6.src" in calls[0]


def test_cli_convert_lit_la_spec_capture(tmp_path, monkeypatch, capsys):
    """Regression : --convert recoit les specs --capture brutes (NOM=fichier),
    pas des dicts -- la spec doit etre decodee comme pour --merge."""
    import cross_capture_analyzer_cli as analyzer_cli

    src = tmp_path / "in.pcap"
    src.write_bytes(b"\xd4\xc3\xb2\xa1")
    calls = []
    monkeypatch.setattr(analyzer_cli, "convert_capture", lambda i, o, fmt=None: calls.append((i, o, fmt)))
    out = tmp_path / "out.pcapng"
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"A={src}", "--convert", str(out)])
    analyzer_cli.main()
    assert calls and calls[0][0] == str(src) and calls[0][1] == str(out)


def test_cli_convert_refuse_plusieurs_fichiers(tmp_path, monkeypatch, capsys):
    import cross_capture_analyzer_cli as analyzer_cli

    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    a.write_bytes(b"x")
    b.write_bytes(b"x")
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"A={a}", "--capture", f"B={b}", "--convert", "o.pcapng"])
    with pytest.raises(SystemExit):
        analyzer_cli.main()
    assert "UN fichier a la fois" in capsys.readouterr().err
