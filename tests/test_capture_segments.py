# SPDX-License-Identifier: GPL-3.0-or-later
"""
Captures segmentees (rotation tcpdump/tshark) sur --capture
(cross_capture_analyzer_cli.py) et --baseline/--current
(cross_capture_diff_cli.py) -- Session 27.

NOM=chemin1[,chemin2,...] : plusieurs chemins pour un meme point de
capture sont lus separement puis simplement concatenes (aucune nouvelle
machinerie de decodage, le mecanisme "plusieurs entrees (label, chemin)
sous le meme label" existait deja implicitement -- voir docstring de
_parse_capture_spec/_parse_capture_args). Comme pour --live-current
(Session 16), chaque CLI garde sa propre copie de cette logique
(independance assumee entre les deux, voir leurs docstrings de module) --
donc deux jeux de tests miroirs ci-dessous, un par CLI.
"""

import sys

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as analyzer_cli
import cross_capture_diff_cli as diff_cli

# ---------------------------------------------------------------------
# cross_capture_analyzer_cli._parse_capture_spec -- fonction pure
# ---------------------------------------------------------------------


def test_parse_capture_spec_un_seul_chemin():
    assert analyzer_cli._parse_capture_spec("LAN=a.pcap", "--capture") == ("LAN", ["a.pcap"])


def test_parse_capture_spec_plusieurs_chemins():
    label, paths = analyzer_cli._parse_capture_spec("LAN=a.pcap,b.pcap,c.pcap", "--capture")
    assert label == "LAN"
    assert paths == ["a.pcap", "b.pcap", "c.pcap"]


def test_parse_capture_spec_tolere_les_espaces_autour_des_virgules():
    _label, paths = analyzer_cli._parse_capture_spec("LAN=a.pcap, b.pcap , c.pcap", "--capture")
    assert paths == ["a.pcap", "b.pcap", "c.pcap"]


def test_parse_capture_spec_format_invalide_sans_egal():
    with pytest.raises(SystemExit) as exc_info:
        analyzer_cli._parse_capture_spec("LAN", "--capture")
    assert exc_info.value.code == 1


def test_parse_capture_spec_label_vide_refuse():
    with pytest.raises(SystemExit) as exc_info:
        analyzer_cli._parse_capture_spec("=a.pcap", "--capture")
    assert exc_info.value.code == 1


def test_parse_capture_spec_segment_vide_refuse():
    # virgule en trop en fin de liste -> un segment de chemin vide
    with pytest.raises(SystemExit) as exc_info:
        analyzer_cli._parse_capture_spec("LAN=a.pcap,", "--capture")
    assert exc_info.value.code == 1


def test_parse_capture_spec_segment_vide_au_milieu_refuse():
    with pytest.raises(SystemExit) as exc_info:
        analyzer_cli._parse_capture_spec("LAN=a.pcap,,b.pcap", "--capture")
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------
# cross_capture_diff_cli._parse_capture_args -- meme logique, copiee
# ---------------------------------------------------------------------


def test_parse_capture_args_un_seul_chemin_par_entree():
    assert diff_cli._parse_capture_args(["LAN=a.pcap"], "--baseline") == [("LAN", "a.pcap")]


def test_parse_capture_args_plusieurs_chemins_aplatis():
    result = diff_cli._parse_capture_args(["LAN=a.pcap,b.pcap"], "--baseline")
    assert result == [("LAN", "a.pcap"), ("LAN", "b.pcap")]


def test_parse_capture_args_plusieurs_entrees_et_segments_combines():
    result = diff_cli._parse_capture_args(["LAN=a.pcap,b.pcap", "WAN=w.pcap"], "--current")
    assert result == [("LAN", "a.pcap"), ("LAN", "b.pcap"), ("WAN", "w.pcap")]


def test_parse_capture_args_segment_vide_refuse():
    with pytest.raises(SystemExit) as exc_info:
        diff_cli._parse_capture_args(["LAN=a.pcap,"], "--baseline")
    assert exc_info.value.code == 1


def test_parse_capture_args_format_invalide_sort_avec_le_bon_flag_dans_le_message(capsys):
    with pytest.raises(SystemExit):
        diff_cli._parse_capture_args(["LAN"], "--current")
    assert "--current" in capsys.readouterr().err


# ---------------------------------------------------------------------
# Bout en bout : les segments d'un meme label sont bien concatenes
# dans l'analyse finale (r.seen_count), pas seulement dans la liste
# `captures` intermediaire.
# ---------------------------------------------------------------------


def test_analyzer_cli_capture_segmentee_bout_en_bout(monkeypatch, capsys):
    segments = {
        "seg1.pcap": [make_pkt(point="LAN", ts=0.0, key_id=1)],
        "seg2.pcap": [make_pkt(point="LAN", ts=1.0, key_id=2), make_pkt(point="LAN", ts=2.0, key_id=3)],
        "wan.pcap": [make_pkt(point="WAN", ts=0.0, key_id=1)],
    }

    def fake_parse_capture(label, path, raise_on_error=False):
        return list(segments[path])

    monkeypatch.setattr(analyzer_cli, "parse_capture", fake_parse_capture)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            "LAN=seg1.pcap,seg2.pcap",
            "--capture",
            "WAN=wan.pcap",
            "--order",
            "LAN,WAN",
        ],
    )

    analyzer_cli.main()

    out = capsys.readouterr().out
    # chaque segment est lu et rapporte separement (deux appels distincts)
    assert "[LAN] 1 paquets" in out
    assert "[LAN] 2 paquets" in out
    assert "[WAN] 1 paquets" in out
    # mais l'analyse finale voit bien les 3 paquets LAN concatenes, pas
    # seulement le dernier segment charge
    assert "LAN             : 3" in out
    assert "WAN             : 1" in out


def test_diff_cli_baseline_et_current_segmentes_bout_en_bout(monkeypatch, capsys):
    segments = {
        "base1.pcap": [make_pkt(point="LAN", ts=0.0, key_id=1, seq=1000)],
        "base2.pcap": [make_pkt(point="LAN", ts=1.0, key_id=1, seq=2000)],
        "cur1.pcap": [make_pkt(point="LAN", ts=0.0, key_id=1, seq=1000)],
        "cur2.pcap": [make_pkt(point="LAN", ts=1.0, key_id=1, seq=2000)],
        "cur3.pcap": [make_pkt(point="LAN", ts=2.0, key_id=1, seq=3000)],
    }

    def fake_parse_capture(label, path, raise_on_error=False):
        return list(segments[path])

    monkeypatch.setattr(diff_cli, "parse_capture", fake_parse_capture)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_diff_cli.py",
            "--baseline",
            "LAN=base1.pcap,base2.pcap",
            "--current",
            "LAN=cur1.pcap,cur2.pcap,cur3.pcap",
        ],
    )

    # le courant a un paquet de plus que le baseline sur ce seul point --
    # rien a corriger cote diff (pas de segment amont/aval), juste une
    # confirmation que les 2 puis 3 segments sont bien tous charges.
    diff_cli.main()

    out = capsys.readouterr().out
    assert out.count("[baseline/LAN]") == 2
    assert out.count("[courant/LAN]") == 3
