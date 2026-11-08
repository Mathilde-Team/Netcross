# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests supplementaires pour cross_capture_analyzer_cli.py -- issue #287.

Couvre les validations d'arguments dans main() : --convert, --replay,
--names, --live + --parallel/--tls/--quic, --redact-map/--redact, et
--history-label/--history-show.
"""

import sys

import pytest

import cross_capture_analyzer_cli as cli


def _run_main(monkeypatch, argv):
    """Lance main() avec argv donne, retourne le code de sortie."""
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


# -- --convert (lignes 1269-1303) --------------------------------------------
# Note : main() exige --capture OU --live avant d'arriver a --convert.
# Pour tester "--convert sans --capture", on passe --live pour passer
# la premiere validation, puis --convert intercepte.


def test_convert_sans_capture_refuse(monkeypatch, capsys):
    """--convert avec --live mais sans --capture : refuse."""
    code = _run_main(monkeypatch, ["--convert", "out.pcapng", "--live", "A:eth0"])
    assert code == 1
    assert "--convert necessite --capture" in capsys.readouterr().err


def test_convert_avec_option_analyse_refuse(monkeypatch, capsys):
    """--convert + --pdf-report : refuse (options ignorees en silence)."""
    code = _run_main(
        monkeypatch,
        ["--convert", "out.pcapng", "--capture", "A=x.pcap", "--pdf-report", "r.pdf"],
    )
    assert code == 1
    assert "incompatible avec --pdf-report" in capsys.readouterr().err


def test_convert_avec_json_report_refuse(monkeypatch, capsys):
    """--convert + --json-report : refuse."""
    code = _run_main(
        monkeypatch,
        ["--convert", "out.pcapng", "--capture", "A=x.pcap", "--json-report", "r.json"],
    )
    assert code == 1
    assert "incompatible avec --json-report" in capsys.readouterr().err


# -- --replay (lignes 1371-1402) ---------------------------------------------


def test_replay_sans_capture_refuse(monkeypatch, capsys):
    """--replay avec --live mais sans --capture : refuse."""
    code = _run_main(monkeypatch, ["--replay", "eth0", "--live", "A:eth0"])
    assert code == 1
    assert "--replay necessite --capture" in capsys.readouterr().err


def test_replay_avec_option_analyse_refuse(monkeypatch, capsys):
    """--replay + --json-report : refuse."""
    code = _run_main(
        monkeypatch,
        ["--replay", "eth0", "--capture", "x.pcap", "--json-report", "r.json"],
    )
    assert code == 1
    assert "incompatible avec --json-report" in capsys.readouterr().err


def test_replay_avec_security_report_refuse(monkeypatch, capsys):
    """--replay + --security-report : refuse."""
    code = _run_main(
        monkeypatch,
        ["--replay", "eth0", "--capture", "x.pcap", "--security-report"],
    )
    assert code == 1
    assert "incompatible avec --security-report" in capsys.readouterr().err


# -- --live + --parallel/--tls/--quic (lignes 1463-1484) ---------------------


def test_live_avec_parallel_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--live", "A:eth0", "--parallel"])
    assert code == 1
    assert "--parallel n'a pas de sens avec --live" in capsys.readouterr().err


def test_live_avec_tls_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--live", "A:eth0", "--tls"])
    assert code == 1
    assert "--tls/--quic ne sont pas disponibles avec --live" in capsys.readouterr().err


def test_live_avec_quic_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--live", "A:eth0", "--quic"])
    assert code == 1
    assert "--tls/--quic ne sont pas disponibles avec --live" in capsys.readouterr().err


# -- --redact-map / --redact (lignes 1486-1503) ------------------------------


def test_redact_map_sans_redact_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--redact-map", "map.csv"])
    assert code == 1
    assert "--redact-map necessite --redact" in capsys.readouterr().err


def test_redact_avec_tls_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--redact", "--tls"])
    assert code == 1
    assert "--redact n'est pas disponible avec --tls/--quic" in capsys.readouterr().err


def test_redact_avec_client_group_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--redact", "--client-group", "10.0.0.1"])
    assert code == 1
    assert "--redact n'est pas disponible avec" in capsys.readouterr().err


# -- --history-label / --history-show (lignes 1505-1507) ---------------------


def test_history_label_sans_history_db_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--history-label", "run1"])
    assert code == 1
    assert "--history-label/--history-show necessitent --history-db" in capsys.readouterr().err


def test_history_show_sans_history_db_refuse(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--history-show", "5"])
    assert code == 1
    assert "--history-label/--history-show necessitent --history-db" in capsys.readouterr().err


# -- --split sans --capture (lignes 1310-1316) ------------------------------


def test_split_avec_live_refuse(monkeypatch, capsys):
    """--split + --live : refuse."""
    code = _run_main(monkeypatch, ["--split", "100MB", "--live", "A:eth0"])
    assert code == 1
    assert "--split decoupe des fichiers" in capsys.readouterr().err


def test_split_output_dir_sans_split_refuse(monkeypatch, capsys):
    """--split-output-dir sans --split : refuse."""
    code = _run_main(monkeypatch, ["--capture", "A=x.pcap", "--split-output-dir", "/tmp/splits"])
    assert code == 1
    assert "--split-output-dir necessite --split" in capsys.readouterr().err
