# SPDX-License-Identifier: GPL-3.0-or-later
"""
cross_capture_diff_cli.py -- --live-current (Session 16).

Le module CLI lui-meme n'etait pas teste jusqu'ici (voir FEATURES.md
section 5.2 : seuls pcap_parser/netcross_core/netcross_report sont
couverts). --live-current introduit de la logique pure (parsing de
spec, validations d'arguments mutuellement exclusifs) suffisamment
autonome pour etre testee sans tshark ni vrai sniffing reseau : on
monkeypatch `parse_capture`/`parse_live` avec des fabriques
synthetiques (memes `Pkt` que `conftest.make_pkt`, meme discipline que
le reste de la suite) et on capture stdout/stderr/SystemExit comme le
fait deja `cross_capture_analyzer_cli.py` pour son propre `--live`
(non teste non plus -- seule sa logique de bas niveau, dupliquee ici,
l'est desormais via ce fichier).
"""

import sys

import pytest
from conftest import make_pkt

import cross_capture_diff_cli as cli

# ---------------------------------------------------------------------
# _parse_live_spec -- fonction pure, copie de celle de
# cross_capture_analyzer_cli.py (voir sa docstring pour la raison de
# la duplication : chaque CLI reste independante).
# ---------------------------------------------------------------------


def test_parse_live_spec_label_interface_seuls():
    assert cli._parse_live_spec("LAN:eth0") == ("LAN", "eth0", None)


def test_parse_live_spec_avec_filtre_bpf():
    assert cli._parse_live_spec("LAN:eth0:tcp port 443") == ("LAN", "eth0", "tcp port 443")


def test_parse_live_spec_filtre_bpf_contenant_des_deux_points():
    # maxsplit=2 : une adresse IPv6 dans le filtre BPF ne doit pas casser
    # le split (meme cas que documente dans cross_capture_analyzer_cli.py)
    label, iface, bpf = cli._parse_live_spec("LAN:eth0:host ::1")
    assert (label, iface) == ("LAN", "eth0")
    assert bpf == "host ::1"


def test_parse_live_spec_format_invalide_sort_en_erreur():
    with pytest.raises(SystemExit) as exc_info:
        cli._parse_live_spec("LAN")  # pas de ':'
    assert exc_info.value.code == 1


def test_parse_live_spec_label_vide_sort_en_erreur():
    with pytest.raises(SystemExit) as exc_info:
        cli._parse_live_spec(":eth0")
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------
# Validation des arguments dans main() -- mutuelle exclusion
# --current/--live-current, et refus --parallel/--tls/--quic avec
# --live-current (memes limitations assumees que --live sur
# cross_capture_analyzer_cli.py, voir claude.md Session 16).
# ---------------------------------------------------------------------


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["cross_capture_diff_cli.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


def test_ni_current_ni_live_current_refuse(monkeypatch, capsys):
    code = _run(monkeypatch, ["--baseline", "LAN=x.pcap"])
    assert code == 1
    assert "au moins un --current ou un --live-current" in capsys.readouterr().err


def test_current_et_live_current_mutuellement_exclusifs(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ["--baseline", "LAN=x.pcap", "--current", "LAN=y.pcap", "--live-current", "LAN:eth0"],
    )
    assert code == 1
    assert "mutuellement exclusifs" in capsys.readouterr().err


def test_live_current_refuse_parallel(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ["--baseline", "LAN=x.pcap", "--live-current", "LAN:eth0", "--parallel"],
    )
    assert code == 1
    assert "--parallel n'a pas de sens" in capsys.readouterr().err


def test_live_current_refuse_tls(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ["--baseline", "LAN=x.pcap", "--live-current", "LAN:eth0", "--tls"],
    )
    assert code == 1
    assert "--tls/--quic ne sont pas disponibles" in capsys.readouterr().err


def test_live_current_refuse_quic(monkeypatch, capsys):
    code = _run(
        monkeypatch,
        ["--baseline", "LAN=x.pcap", "--live-current", "LAN:eth0", "--quic"],
    )
    assert code == 1
    assert "--tls/--quic ne sont pas disponibles" in capsys.readouterr().err


# ---------------------------------------------------------------------
# Bout en bout : --baseline (fichier, monkeypatch parse_capture) +
# --live-current (monkeypatch parse_live, generateur synthetique --
# pas de vrai thread reseau ni tshark).
# ---------------------------------------------------------------------


def test_live_current_bout_en_bout(monkeypatch, capsys):
    baseline_pkts = [
        make_pkt(point="LAN", ts=0.0, src="10.0.0.1", dst="10.0.0.2", key_id=1, seq=1000),
        make_pkt(point="LAN", ts=0.01, src="10.0.0.2", dst="10.0.0.1", key_id=1, seq=2000),
    ]
    live_pkts = [
        make_pkt(point="LAN", ts=0.0, src="10.0.0.1", dst="10.0.0.2", key_id=1, seq=1000),
    ]

    def fake_parse_capture(label, path, raise_on_error=False):
        return list(baseline_pkts)

    def fake_parse_live(label, iface, bpf_filter=None, stop_event=None):
        yield from live_pkts

    monkeypatch.setattr(cli, "parse_capture", fake_parse_capture)
    monkeypatch.setattr(cli, "parse_live", fake_parse_live)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_diff_cli.py",
            "--baseline",
            "LAN=baseline.pcap",
            "--live-current",
            "LAN:eth0",
            "--live-duration",
            "1",
        ],
    )

    # pas de regression detectee dans ce scenario -> pas de sys.exit(1)
    cli.main()

    out = capsys.readouterr().out
    assert "CAPTURE EN DIRECT DU RUN COURANT" in out
    assert "CHARGEMENT DU RUN COURANT" not in out
    assert "1 paquet(s) captures au total" in out
    assert "[courant/LAN] capture demarree sur eth0" in out


def test_live_current_plusieurs_points_simultanes(monkeypatch, capsys):
    def fake_parse_capture(label, path, raise_on_error=False):
        return [make_pkt(point=label, ts=0.0, key_id=1)]

    def fake_parse_live(label, iface, bpf_filter=None, stop_event=None):
        yield make_pkt(point=label, ts=0.0, key_id=1)

    monkeypatch.setattr(cli, "parse_capture", fake_parse_capture)
    monkeypatch.setattr(cli, "parse_live", fake_parse_live)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_diff_cli.py",
            "--baseline",
            "LAN=baseline_lan.pcap",
            "--baseline",
            "WAN=baseline_wan.pcap",
            "--live-current",
            "LAN:eth0",
            "--live-current",
            "WAN:eth1:tcp port 443",
            "--order",
            "LAN,WAN",
        ],
    )

    cli.main()

    out = capsys.readouterr().out
    assert "[courant/LAN] capture demarree sur eth0" in out
    assert "[courant/WAN] capture demarree sur eth1 (filtre BPF: tcp port 443)" in out
    assert "2 paquet(s) captures au total" in out
