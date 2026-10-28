# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de l'estimation memoire et de l'avertissement avant analyse (issue
#283, Etape 2), et de --max-packets/--sample (Etape 3).

Fonctions pures uniquement (memes principes que test_capinfos_source.py) :
_available_memory_bytes est le seul point d'E/S (lecture de
/proc/meminfo), monkeypatche pour ne jamais dependre de la machine qui
execute la suite -- une CI genereuse en RAM ne doit jamais faire
disparaitre silencieusement ces tests. read_capture_info (capinfos) est de
la meme facon monkeypatche plutot qu'invoque reellement : capinfos n'est
disponible dans aucun des environnements de developpement de ce projet
(voir claude.md et test_capinfos_source.py).
"""

from dataclasses import dataclass

import cross_capture_analyzer_cli as cli
from netcross_core.models import Pkt, Report


def make_pkt(**overrides) -> Pkt:
    """Meme fabrique minimale que tests/conftest.make_pkt, dupliquee ici a
    dessein : ce module ne teste que les champs point/ts pour
    _apply_packet_limits, aucune raison d'importer toute la fixture
    partagee pour ca."""
    import dataclasses as dc

    defaults = {}
    for f in dc.fields(Pkt):
        if f.name in ("point", "ts"):
            continue
        text = f.type if isinstance(f.type, str) else str(f.type)
        if "None" in text:
            defaults[f.name] = None
        elif text.startswith("tuple"):
            defaults[f.name] = ()
        elif text == "bool":
            defaults[f.name] = False
        elif text == "int":
            defaults[f.name] = 0
        elif text == "float":
            defaults[f.name] = 0.0
        else:
            defaults[f.name] = ""
    point = overrides.pop("point", "A")
    ts = overrides.pop("ts", 0.0)
    defaults.update(overrides)
    return Pkt(point=point, ts=ts, **defaults)


# -- _format_go / _format_paquets -------------------------------------------


def test_format_go():
    assert cli._format_go(4_200_000_000) == "4.2 Go"
    assert cli._format_go(3_100_000_000) == "3.1 Go"
    assert cli._format_go(6_000_000_000) == "6.0 Go"


def test_format_paquets_millions():
    assert cli._format_paquets(18_300_000) == "18,3 M paquets"


def test_format_paquets_sous_le_million():
    assert cli._format_paquets(500) == "500 paquets"


# -- _available_memory_bytes -------------------------------------------------


def test_available_memory_bytes_lit_mem_available(tmp_path, monkeypatch):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       16384000 kB\nMemAvailable:    3100000 kB\nMemFree:          500000 kB\n")
    original_open = open

    def _fake_open(path, *a, **kw):
        if path == "/proc/meminfo":
            return original_open(str(meminfo))
        return original_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", _fake_open)
    assert cli._available_memory_bytes() == 3_100_000 * 1024


def test_available_memory_bytes_absent_sans_meminfo(monkeypatch):
    def _raise(path, *a, **kw):
        raise OSError("introuvable")

    monkeypatch.setattr("builtins.open", _raise)
    assert cli._available_memory_bytes() is None


def test_available_memory_bytes_ligne_mal_formee(tmp_path, monkeypatch):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemAvailable:\n")
    original_open = open

    def _fake_open(path, *a, **kw):
        if path == "/proc/meminfo":
            return original_open(str(meminfo))
        return original_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", _fake_open)
    assert cli._available_memory_bytes() is None


# -- _estimate_memory_bytes ---------------------------------------------------


def test_estimate_memory_bytes_croit_avec_le_nombre_de_paquets():
    petite = cli._estimate_memory_bytes(1_000)
    grande = cli._estimate_memory_bytes(1_000_000)
    assert grande > petite
    assert grande == 1_000_000 * cli._ESTIMATED_BYTES_PER_PACKET * 4


def test_estimate_memory_bytes_zero_paquet():
    assert cli._estimate_memory_bytes(0) == 0


# -- _memory_warning : le message doit matcher l'exemple de l'issue #283 -----


def test_memory_warning_depasse_la_memoire_disponible(monkeypatch):
    # 18.3 M paquets -> estimation largement superieure a 3.1 Go disponibles.
    monkeypatch.setattr(cli, "_available_memory_bytes", lambda: 3_100_000_000)
    message = cli._memory_warning("POINT_A", 4_200_000_000, 18_300_000)
    assert message is not None
    assert "POINT_A" in message
    assert "4.2 Go" in message
    assert "18,3 M paquets" in message
    assert "3.1 Go disponibles" in message
    assert "--max-packets" in message
    assert "--sample" in message
    assert "--stream" in message


def test_memory_warning_absent_si_memoire_suffisante(monkeypatch):
    monkeypatch.setattr(cli, "_available_memory_bytes", lambda: 100_000_000_000)
    assert cli._memory_warning("POINT_A", 1_000_000, 1_000) is None


def test_memory_warning_absent_si_memoire_indeterminable(monkeypatch):
    monkeypatch.setattr(cli, "_available_memory_bytes", lambda: None)
    assert cli._memory_warning("POINT_A", 4_200_000_000, 18_300_000) is None


# -- _check_memory_before_analysis : orchestration, capinfos monkeypatche ----


@dataclass
class _FakeCaptureInfo:
    file_size: int | None
    packet_count: int | None


def test_check_memory_before_analysis_avertit_sur_gros_fichier(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_available_memory_bytes", lambda: 3_100_000_000)
    monkeypatch.setattr(
        "pcap_parser.capinfos_source.read_capture_info",
        lambda path: _FakeCaptureInfo(file_size=4_200_000_000, packet_count=18_300_000),
    )
    cli._check_memory_before_analysis([("POINT_A", "grosse_capture.pcapng")])
    stderr = capsys.readouterr().err
    assert "POINT_A" in stderr
    assert "4.2 Go" in stderr
    assert "ATTENTION memoire" in stderr


def test_check_memory_before_analysis_silence_si_capinfos_absent(monkeypatch, capsys):
    monkeypatch.setattr("pcap_parser.capinfos_source.read_capture_info", lambda path: None)
    cli._check_memory_before_analysis([("POINT_A", "quelconque.pcapng")])
    assert capsys.readouterr().err == ""


def test_check_memory_before_analysis_silence_si_petite_capture(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_available_memory_bytes", lambda: 100_000_000_000)
    monkeypatch.setattr(
        "pcap_parser.capinfos_source.read_capture_info",
        lambda path: _FakeCaptureInfo(file_size=1_000_000, packet_count=1_000),
    )
    cli._check_memory_before_analysis([("POINT_A", "petite_capture.pcapng")])
    assert capsys.readouterr().err == ""


# -- _parse_sample_spec -------------------------------------------------------


def test_parse_sample_spec_valide():
    assert cli._parse_sample_spec("1/50") == 50


def test_parse_sample_spec_avec_espaces():
    assert cli._parse_sample_spec(" 1 / 100 ") == 100


def test_parse_sample_spec_invalide_sort_en_erreur(monkeypatch):
    import pytest

    monkeypatch.setattr(cli.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))
    with pytest.raises(SystemExit):
        cli._parse_sample_spec("2/50")
    with pytest.raises(SystemExit):
        cli._parse_sample_spec("1/0")
    with pytest.raises(SystemExit):
        cli._parse_sample_spec("n'importe quoi")


# -- _apply_packet_limits -----------------------------------------------------


def test_apply_packet_limits_max_packets_tronque():
    packets = [make_pkt(ts=float(i)) for i in range(100)]
    kept, note = cli._apply_packet_limits(packets, max_packets=10, sample_n=None)
    assert len(kept) == 10
    assert kept == packets[:10]
    assert note is not None
    assert "10" in note
    assert "100" in note


def test_apply_packet_limits_max_packets_sans_effet_si_capture_plus_petite():
    packets = [make_pkt(ts=float(i)) for i in range(5)]
    kept, note = cli._apply_packet_limits(packets, max_packets=1000, sample_n=None)
    assert kept == packets
    assert note is None


def test_apply_packet_limits_sample_garde_un_paquet_sur_n():
    packets = [make_pkt(ts=float(i)) for i in range(100)]
    kept, note = cli._apply_packet_limits(packets, max_packets=None, sample_n=10)
    assert len(kept) == 10
    assert kept == packets[::10]
    assert note is not None


def test_apply_packet_limits_sample_egal_1_est_un_no_op():
    packets = [make_pkt(ts=float(i)) for i in range(10)]
    kept, note = cli._apply_packet_limits(packets, max_packets=None, sample_n=1)
    assert kept == packets
    assert note is None


def test_apply_packet_limits_sample_puis_max_packets_combines():
    packets = [make_pkt(ts=float(i)) for i in range(1000)]
    # 1 paquet sur 10 -> 100 paquets, puis plafonne a 5.
    kept, note = cli._apply_packet_limits(packets, max_packets=5, sample_n=10)
    assert kept == packets[::10][:5]
    assert len(kept) == 5
    assert note is not None
    assert "echantillonnage" in note
    assert "limitee" in note


def test_apply_packet_limits_aucune_limite_est_no_op():
    packets = [make_pkt(ts=float(i)) for i in range(10)]
    kept, note = cli._apply_packet_limits(packets, max_packets=None, sample_n=None)
    assert kept == packets
    assert note is None


# -- Report.truncated / Report.truncation_note (models.py) -------------------


def test_report_truncated_defaults_false():
    r = Report()
    assert r.truncated is False
    assert r.truncation_note == ""


def test_report_truncated_peut_etre_positionne():
    r = Report()
    r.truncated = True
    r.truncation_note = "analyse limitee aux 10 premiers paquets sur 100"
    assert r.truncated is True
    assert "10" in r.truncation_note
