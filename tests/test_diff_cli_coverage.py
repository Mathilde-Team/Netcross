# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests supplementaires pour cross_capture_diff_cli.py -- issue #287.

Couvre les branches non testees de _load_packets (parallel + erreurs
sequentielles) et les validations d'arguments dans main() (--redact-map,
--redact + --tls/--quic, --history-label sans --history-db).
"""

import sys

import pytest
from conftest import make_pkt

import cross_capture_diff_cli as cli

# -- _load_packets : branche parallel (lignes 132-174) -----------------------


def test_load_packets_parallel_avec_un_seul_worker_avertit(monkeypatch, capsys):
    """--parallel avec un seul CPU : message d'avertissement sur le manque
    de gain (lignes 138-145)."""
    monkeypatch.setattr("os.cpu_count", lambda: 1)
    monkeypatch.setattr(
        cli,
        "parse_captures_parallel",
        lambda captures, workers: (
            [make_pkt(point="A", ts=0.0, key_id=1)],
            [{"label": "A", "path": "x.pcap", "count": 1, "seconds": 0.1, "error": None}],
        ),
    )
    result = cli._load_packets("test", [("A", "x.pcap")], parallel=True, parallel_workers=None)
    assert len(result) == 1
    out = capsys.readouterr().out
    assert "1 worker(s) effectif(s)" in out
    assert "aucun gain de temps" in out


def test_load_packets_parallel_trop_de_workers_avertit(monkeypatch, capsys):
    """--parallel avec plus de workers que de CPUs : avertissement (lignes
    146-153)."""
    monkeypatch.setattr("os.cpu_count", lambda: 2)
    monkeypatch.setattr(
        cli,
        "parse_captures_parallel",
        lambda captures, workers: (
            [make_pkt(point="A", ts=0.0, key_id=1)],
            [{"label": "A", "path": "x.pcap", "count": 1, "seconds": 0.1, "error": None}],
        ),
    )
    result = cli._load_packets("test", [("A", "x.pcap")], parallel=True, parallel_workers=8)
    assert len(result) == 1
    out = capsys.readouterr().out
    assert "8 workers demandes" in out
    assert "2 coeur(s) CPU" in out


def test_load_packets_parallel_avec_erreur_rapporte_echec(monkeypatch, capsys):
    """--parallel avec un fichier en echec : message ECHEC + ATTENTION
    (lignes 155-173)."""
    monkeypatch.setattr("os.cpu_count", lambda: 4)
    monkeypatch.setattr(
        cli,
        "parse_captures_parallel",
        lambda captures, workers: (
            [make_pkt(point="A", ts=0.0, key_id=1)],
            [{"label": "A", "path": "bad.pcap", "count": 0, "seconds": 0.0, "error": "fichier introuvable"}],
        ),
    )
    result = cli._load_packets("test", [("A", "bad.pcap")], parallel=True, parallel_workers=4)
    assert len(result) == 1  # le paquet valide est quand meme charge
    err = capsys.readouterr().err
    assert "ECHEC sur bad.pcap" in err
    assert "ATTENTION" in err


def test_load_packets_parallel_succes_normal(monkeypatch, capsys):
    """--parallel nominal : paquets charges, pas d'avertissement (lignes
    154-167)."""
    monkeypatch.setattr("os.cpu_count", lambda: 4)
    pkts = [make_pkt(point="A", ts=0.0, key_id=1), make_pkt(point="A", ts=0.01, key_id=2)]
    monkeypatch.setattr(
        cli,
        "parse_captures_parallel",
        lambda captures, workers: (
            pkts,
            [{"label": "A", "path": "x.pcap", "count": 2, "seconds": 0.05, "error": None}],
        ),
    )
    result = cli._load_packets("test", [("A", "x.pcap")], parallel=True, parallel_workers=4)
    assert len(result) == 2
    out = capsys.readouterr().out
    assert "2 paquets charges" in out


# -- _load_packets : branche sequentielle avec erreurs (lignes 188-199) ------


def test_load_packets_sequentiel_erreur_rapporte_echec(monkeypatch, capsys):
    """Branche sequentielle : un fichier introuvable est rapporte comme
    ECHEC + ATTENTION (lignes 188-199), pas comme '0 paquets charges'."""
    from pcap_parser.ek_source import TsharkNotFoundError

    good_pkts = [make_pkt(point="A", ts=0.0, key_id=1)]

    def fake_parse_capture(label, path, raise_on_error=False):
        if "bad" in path:
            raise TsharkNotFoundError("tshark absent")
        return list(good_pkts)

    monkeypatch.setattr(cli, "parse_capture", fake_parse_capture)
    result = cli._load_packets("test", [("A", "good.pcap"), ("A", "bad.pcap")], parallel=False, parallel_workers=None)
    assert len(result) == 1  # seul le fichier valide a ete charge
    err = capsys.readouterr().err
    assert "ECHEC sur" in err
    assert "ATTENTION" in err


# -- Validations dans main() (lignes 539-556) --------------------------------


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["cross_capture_diff_cli.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


def test_redact_map_sans_redact_refuse(monkeypatch, capsys):
    """--redact-map sans --redact : refuse (lignes 539-541)."""
    code = _run_main(monkeypatch, ["--baseline", "A=x.pcap", "--current", "A=y.pcap", "--redact-map", "map.csv"])
    assert code == 1
    assert "--redact-map necessite --redact" in capsys.readouterr().err


def test_redact_avec_tls_refuse(monkeypatch, capsys):
    """--redact + --tls : refuse (lignes 542-552)."""
    code = _run_main(
        monkeypatch,
        ["--baseline", "A=x.pcap", "--current", "A=y.pcap", "--redact", "--tls"],
    )
    assert code == 1
    assert "--redact n'est pas disponible avec --tls/--quic" in capsys.readouterr().err


def test_redact_avec_quic_refuse(monkeypatch, capsys):
    """--redact + --quic : refuse (lignes 542-552)."""
    code = _run_main(
        monkeypatch,
        ["--baseline", "A=x.pcap", "--current", "A=y.pcap", "--redact", "--quic"],
    )
    assert code == 1
    assert "--redact n'est pas disponible avec --tls/--quic" in capsys.readouterr().err


def test_history_label_sans_history_db_refuse(monkeypatch, capsys):
    """--history-label sans --history-db : refuse (lignes 554-556)."""
    code = _run_main(
        monkeypatch,
        ["--baseline", "A=x.pcap", "--current", "A=y.pcap", "--history-label", "run1"],
    )
    assert code == 1
    assert "--history-label/--history-show necessitent --history-db" in capsys.readouterr().err


def test_history_show_sans_history_db_refuse(monkeypatch, capsys):
    """--history-show sans --history-db : refuse (lignes 554-556)."""
    code = _run_main(
        monkeypatch,
        ["--baseline", "A=x.pcap", "--current", "A=y.pcap", "--history-show", "5"],
    )
    assert code == 1
    assert "--history-label/--history-show necessitent --history-db" in capsys.readouterr().err
