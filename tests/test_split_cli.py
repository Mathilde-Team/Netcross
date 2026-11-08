# SPDX-License-Identifier: GPL-3.0-or-later
"""
--split / --split-output-dir de cross_capture_analyzer_cli.py -- Job 35,
issue #155. split_capture est monkeypatche (son comportement reel est
teste dans test_split_capture.py) : on verifie ici uniquement le cablage
de la CLI -- syntaxe MODE:VALEUR, unites de taille, sous-repertoire par
label, refus des combinaisons incompatibles, code de sortie.
"""

import os
import sys

import pytest

import cross_capture_analyzer_cli as cli
from pcap_parser import TsharkNotFoundError

# -- _parse_size ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("123", 123),
        ("500k", 500_000),
        ("500K", 500_000),
        ("100M", 100_000_000),  # decimal, comme tcpdump -C 100
        ("100Mo", 100_000_000),
        ("100MB", 100_000_000),
        ("1.5G", 1_500_000_000),
        ("1,5G", 1_500_000_000),  # virgule decimale francaise
        (" 2 g ", 2_000_000_000),
    ],
)
def test_parse_size_valide(text, expected):
    assert cli._parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "10MiB", "10Mio", "-5M", "M", "1e3"])
def test_parse_size_invalide(text):
    assert cli._parse_size(text) is None  # binaire refuse, jamais lu comme decimal


# -- _parse_split_spec ------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("time:60", ("time", 60.0)),
        ("time:0.5", ("time", 0.5)),
        ("TIME:2,5", ("time", 2.5)),
        ("count:10000", ("count", 10000)),
        ("size:100M", ("size", 100_000_000)),
        ("size:4096", ("size", 4096)),
    ],
)
def test_parse_split_spec_valide(spec, expected):
    assert cli._parse_split_spec(spec) == expected


@pytest.mark.parametrize(
    "spec",
    ["60", "time", "time:", "jour:5", "time:abc", "time:0", "time:-3", "count:1.5", "count:0", "size:0", "size:10MiB"],
)
def test_parse_split_spec_invalide(spec, capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli._parse_split_spec(spec)
    assert exc_info.value.code == 1
    assert "--split" in capsys.readouterr().err


# -- main() -----------------------------------------------------------------------


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


@pytest.fixture
def fake_split(monkeypatch):
    """split_capture simule : enregistre les appels, renvoie 2 segments
    par fichier. Toute tentative d'analyse fait echouer le test."""
    calls = []

    def fake(path, output_dir, by, value):
        calls.append((path, output_dir, by, value))
        stem = os.path.splitext(os.path.basename(path))[0]
        return [os.path.join(output_dir, f"{stem}_{i:05d}.pcapng") for i in range(2)]

    def no_analysis(*a, **k):
        raise AssertionError("--split ne doit lancer aucune analyse")

    monkeypatch.setattr(cli, "split_capture", fake)
    monkeypatch.setattr(cli, "parse_capture", no_analysis)
    monkeypatch.setattr(cli, "parse_captures_parallel", no_analysis)
    return calls


def test_split_repertoire_par_defaut_et_sous_repertoire_par_label(monkeypatch, fake_split, capsys):
    code = _run(monkeypatch, "--capture", "LAN=lan.pcapng", "--capture", "WAN=wan.pcapng", "--split", "time:60")

    assert code == 0
    assert fake_split == [
        ("lan.pcapng", os.path.join("captures_split", "LAN"), "time", 60.0),
        ("wan.pcapng", os.path.join("captures_split", "WAN"), "time", 60.0),
    ]
    out = capsys.readouterr().out
    assert "[LAN] 2 segment(s)" in out and "[WAN] 2 segment(s)" in out
    assert "paste -sd," in out  # la commande pour rejouer les segments est indiquee


def test_split_size_avec_repertoire_de_sortie(monkeypatch, fake_split):
    code = _run(monkeypatch, "--capture", "LAN=a.pcap", "--split", "size:100M", "--split-output-dir", "seg")
    assert code == 0
    assert fake_split == [("a.pcap", os.path.join("seg", "LAN"), "size", 100_000_000)]


def test_split_label_avec_plusieurs_fichiers(monkeypatch, fake_split, capsys):
    code = _run(monkeypatch, "--capture", "LAN=a.pcap,b.pcap", "--split", "count:1000")
    assert code == 0
    assert [c[0] for c in fake_split] == ["a.pcap", "b.pcap"]  # meme sous-repertoire, fichiers decoupes un par un
    assert "[LAN] 4 segment(s)" in capsys.readouterr().out


def test_split_neutralise_un_label_qui_sortirait_du_repertoire(monkeypatch, fake_split):
    _run(monkeypatch, "--capture", "../evil=a.pcap", "--split", "count:10", "--split-output-dir", "seg")
    (_path, sortie, _by, _value) = fake_split[0]
    assert os.path.dirname(sortie) == "seg"  # jamais de ".." ni de separateur dans le nom du sous-repertoire
    assert ".." not in os.path.basename(sortie)


def test_split_un_echec_est_rapporte_les_autres_fichiers_continuent(monkeypatch, capsys):
    def fake(path, output_dir, by, value):
        if path == "casse.pcap":
            raise TsharkNotFoundError("editcap introuvable")
        return [os.path.join(output_dir, "ok_00000.pcap")]

    monkeypatch.setattr(cli, "split_capture", fake)
    code = _run(monkeypatch, "--capture", "A=casse.pcap", "--capture", "B=bon.pcap", "--split", "time:10")

    assert code == 1  # au moins un echec
    captured = capsys.readouterr()
    assert "[A] ECHEC du decoupage : editcap introuvable" in captured.err
    assert "[B] 1 segment(s)" in captured.out  # B a quand meme ete traite


def test_split_capture_sans_paquet(monkeypatch, capsys):
    monkeypatch.setattr(cli, "split_capture", lambda *a: [])
    assert _run(monkeypatch, "--capture", "LAN=vide.pcap", "--split", "count:10") == 0
    assert "aucun paquet" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("extra", "attendu"),
    [
        (["--triage"], "--triage"),
        (["--pdf-report", "r.pdf", "--json-report", "r.json"], "--json-report, --pdf-report"),
        (["--order", "LAN"], "--order"),
        (["--bucket-ms", "500"], "--bucket-ms"),
        (["--parallel"], "--parallel"),
    ],
)
def test_split_refuse_les_options_d_analyse_au_lieu_de_les_ignorer(monkeypatch, fake_split, capsys, extra, attendu):
    code = _run(monkeypatch, "--capture", "LAN=a.pcap", "--split", "count:10", *extra)
    assert code == 1
    assert attendu in capsys.readouterr().err
    assert fake_split == []  # rien n'a ete decoupe


def test_split_exclusif_avec_merge(monkeypatch, fake_split, capsys):
    assert _run(monkeypatch, "--capture", "LAN=a.pcap", "--split", "count:10", "--merge", "f.pcapng") == 1
    assert "exclusifs" in capsys.readouterr().err
    assert fake_split == []


def test_split_incompatible_avec_live(monkeypatch, fake_split, capsys):
    assert _run(monkeypatch, "--live", "LAN:eth0", "--split", "count:10") == 1
    assert "--live" in capsys.readouterr().err


def test_split_output_dir_sans_split(monkeypatch, fake_split, capsys):
    assert _run(monkeypatch, "--capture", "LAN=a.pcap", "--split-output-dir", "seg") == 1
    assert "necessite --split" in capsys.readouterr().err


def test_split_sans_capture(monkeypatch, fake_split, capsys):
    assert _run(monkeypatch, "--split", "count:10") == 1
    assert "--capture" in capsys.readouterr().err
