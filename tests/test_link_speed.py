"""Issue #1132 : vitesse d'interface (if_speed) et resolution d'horodatage
(if_tsresol) par interface pcapng, repli --link-speed POINT=VITESSE."""

from __future__ import annotations

import struct
import sys

import pytest
from pcap_builders import IDB, block, epb, frame, shb, write_bytes, write_pcap

from netcross_core.link_speed import (
    SOURCE_IF_SPEED,
    SOURCE_OPTION,
    format_speed,
    parse_link_speed,
    parse_link_speed_specs,
    resolve_link_speeds,
)
from netcross_core.models import Report
from pcap_parser.capfile import first_timestamp, read_structure, tsresol_seconds


def _opt(code: int, value: bytes, endian: str = "<") -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def _idb(*, speed=None, tsresol=None, name=None, endian="<", raw_opts=b"") -> bytes:
    opts = raw_opts
    if name is not None:
        opts += _opt(2, name.encode(), endian)
    if speed is not None:
        opts += _opt(8, struct.pack(endian + "Q", speed), endian)
    if tsresol is not None:
        opts += _opt(9, bytes([tsresol]), endian)
    if opts:
        opts += struct.pack(endian + "HH", 0, 0)
    return block(IDB, struct.pack(endian + "HHI", 1, 0, 65535) + opts, endian)


def _epb_ticks(ticks: int, interface: int = 0, endian: str = "<") -> bytes:
    # epb() prend un entier 64 bits brut : ici en ticks de l'interface.
    return epb(frame(0), ts_us=ticks, interface=interface, endian=endian)


# -- capfile : if_tsresol / if_speed -------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(6, 1e-6), (9, 1e-9), (3, 1e-3), (0, 1.0), (0x80 | 10, 2.0**-10), (0x80, 1.0)],
)
def test_tsresol_seconds_puissance_de_10_ou_de_2(value, expected):
    assert tsresol_seconds(value) == pytest.approx(expected)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_avec_if_speed_et_if_tsresol(tmp_path, endian):
    path = tmp_path / "a.pcapng"
    write_bytes(
        path,
        shb(endian),
        _idb(speed=10**9, tsresol=9, name="eth0", endian=endian),
        _idb(endian=endian),
        _epb_ticks(1_700_000_000_123_456_789, endian=endian),
    )
    interfaces = read_structure(str(path)).interfaces
    assert (interfaces[0].name, interfaces[0].speed_bps, interfaces[0].ts_resolution) == ("eth0", 10**9, 1e-9)
    assert (interfaces[1].speed_bps, interfaces[1].ts_resolution) == (None, 1e-6)
    assert first_timestamp(str(path)) == pytest.approx(1_700_000_000.123456789)


def test_pcapng_sans_if_speed_options_de_taille_inattendue_ignorees(tmp_path):
    path = tmp_path / "a.pcapng"
    bad = _opt(8, b"\x01\x02") + _opt(9, b"")
    write_bytes(path, shb(), _idb(raw_opts=bad), _epb_ticks(5_000_000))
    iface = read_structure(str(path)).interfaces[0]
    assert (iface.speed_bps, iface.ts_resolution) == (None, 1e-6)
    assert first_timestamp(str(path)) == pytest.approx(5.0)


def test_first_timestamp_utilise_la_resolution_de_l_interface_de_l_epb(tmp_path):
    path = tmp_path / "a.pcapng"
    write_bytes(path, shb(), _idb(tsresol=6), _idb(tsresol=3), _epb_ticks(2500, interface=1))
    assert first_timestamp(str(path)) == pytest.approx(2.5)


def test_first_timestamp_interface_inconnue_ou_nouvelle_section(tmp_path):
    # interface_id hors IDB -> defaut 1e-6 ; un nouveau SHB remet a zero.
    path = tmp_path / "a.pcapng"
    write_bytes(path, shb(), _idb(tsresol=9), shb(), _epb_ticks(3_000_000))
    assert first_timestamp(str(path)) == pytest.approx(3.0)


def test_pcap_classique_resolution_selon_le_magic(tmp_path):
    us, ns = tmp_path / "us.pcap", tmp_path / "ns.pcap"
    write_pcap(us, [(1_700_000_000_000_000, frame(0))])
    write_pcap(ns, [(1_700_000_000_000_000_000, frame(0))], nsec=True)
    assert read_structure(str(us)).interfaces[0].ts_resolution == 1e-6
    assert read_structure(str(ns)).interfaces[0].ts_resolution == 1e-9
    assert read_structure(str(us)).interfaces[0].speed_bps is None


# -- netcross_core.link_speed -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "bps"),
    [("1G", 10**9), ("2.5g", 2_500_000_000), ("100M", 10**8), ("10k", 10**4), ("1500", 1500), (" 40Gbps ", 4 * 10**10)],
)
def test_parse_link_speed(text, bps):
    assert parse_link_speed(text) == bps


@pytest.mark.parametrize("text", ["", "vite", "1X", "-1G", "0", "0.0M"])
def test_parse_link_speed_refuse(text):
    with pytest.raises(ValueError):
        parse_link_speed(text)


def test_parse_link_speed_specs():
    assert parse_link_speed_specs(None, ["A"]) == {}
    assert parse_link_speed_specs(["A=1G", " B =100M"], ["A", "B"]) == {"A": 10**9, "B": 10**8}
    for specs, msg in (
        (["A"], "POINT=VITESSE"),
        (["=1G"], "POINT=VITESSE"),
        (["Z=1G"], "point inconnu"),
        (["A=1G", "A=2G"], "plusieurs fois"),
        (["A=lent"], "illisible"),
    ):
        with pytest.raises(ValueError, match=msg):
            parse_link_speed_specs(specs, ["A", "B"])


def test_resolve_if_speed_prioritaire_puis_option_puis_inconnu(tmp_path):
    with_speed, without = tmp_path / "a.pcapng", tmp_path / "b.pcapng"
    write_bytes(with_speed, shb(), _idb(), _idb(speed=10**10, tsresol=9), _idb(speed=10**9), _epb_ticks(1))
    write_bytes(without, shb(), _idb(), _epb_ticks(1))
    captures = [("A", str(with_speed)), ("B", str(without)), ("C", str(without)), ("D", str(tmp_path / "absent"))]
    result = resolve_link_speeds(captures, {"A": 10**8, "B": 10**8, "D": 10**6})
    assert (result["A"]["speed_bps"], result["A"]["speed_source"]) == (10**10, SOURCE_IF_SPEED)
    assert result["A"]["ts_resolution"] == 1e-9
    assert [i["speed_bps"] for i in result["A"]["interfaces"]] == [None, 10**10, 10**9]
    assert (result["B"]["speed_bps"], result["B"]["speed_source"]) == (10**8, SOURCE_OPTION)
    assert (result["C"]["speed_bps"], result["C"]["speed_source"], result["C"]["ts_resolution"]) == (None, None, 1e-6)
    assert result["D"] == {"speed_bps": 10**6, "speed_source": SOURCE_OPTION, "ts_resolution": None, "interfaces": []}


def test_resolve_option_egale_a_if_speed_et_format_inconnu(tmp_path):
    path, other = tmp_path / "a.pcapng", tmp_path / "x.bin"
    write_bytes(path, shb(), _idb(speed=10**9), _epb_ticks(1))
    other.write_bytes(b"pas une capture")
    result = resolve_link_speeds([("A", str(path)), ("X", str(other))], {"A": 10**9})
    assert result["A"]["speed_source"] == SOURCE_IF_SPEED
    assert result["X"]["interfaces"] == [] and result["X"]["speed_bps"] is None


def test_resolve_pcapng_tronque_struct_error(tmp_path, monkeypatch):
    import netcross_core.link_speed as mod

    def boom(_path):
        raise struct.error("tronque")

    monkeypatch.setattr(mod, "read_structure", boom)
    assert resolve_link_speeds([("A", "x")])["A"]["speed_bps"] is None


@pytest.mark.parametrize(
    ("bps", "text"),
    [
        (10**9, "1 Gbit/s"),
        (2_500_000_000, "2.5 Gbit/s"),
        (10**8, "100 Mbit/s"),
        (1500, "1.5 kbit/s"),
        (12, "12 bit/s"),
        (4 * 10**12, "4 Tbit/s"),
    ],
)
def test_format_speed(bps, text):
    assert format_speed(bps) == text


# -- rapport texte ------------------------------------------------------------


def test_rapport_texte_section_vitesse_des_liens(capsys):
    from netcross_core.report_text import print_report

    r = Report(points=["A", "B"])
    print_report(r)
    assert "Vitesse des liens" not in capsys.readouterr().out
    r.link_speeds = {
        "A": {"speed_bps": 10**9, "speed_source": SOURCE_IF_SPEED, "ts_resolution": 1e-9, "interfaces": []},
        "B": {"speed_bps": None, "speed_source": None, "ts_resolution": None, "interfaces": []},
    }
    print_report(r)
    out = capsys.readouterr().out
    assert "-- Vitesse des liens --" in out
    assert "A : 1 Gbit/s (source : if_speed), horodatage au 1e-09 s" in out
    assert "B : inconnue\n" in out


# -- CLI --link-speed ----------------------------------------------------------


def test_cli_link_speed_point_inconnu_refuse_avant_lecture(monkeypatch, capsys, tmp_path):
    import cross_capture_analyzer_cli as cli

    path = tmp_path / "a.pcapng"
    write_bytes(path, shb(), _idb(), _epb_ticks(1))

    def interdit(*_args, **_kwargs):
        raise AssertionError("aucune lecture de paquets attendue")

    monkeypatch.setattr(cli, "parse_capture", interdit)
    monkeypatch.setattr(sys, "argv", ["netcross", "--capture", f"A={path}", "--link-speed", "Z=1G"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "point inconnu" in capsys.readouterr().err


def test_cli_link_speed_repli_affiche_dans_le_rapport(monkeypatch, capsys, tmp_path):
    """Bout en bout dans le processus : A porte if_speed (prioritaire sur
    --link-speed), B ne le porte pas (repli sur --link-speed)."""
    from conftest import make_pkt

    import cross_capture_analyzer_cli as cli

    a, b = tmp_path / "a.pcapng", tmp_path / "b.pcapng"
    write_bytes(a, shb(), _idb(speed=10**10), _epb_ticks(1))
    write_bytes(b, shb(), _idb(), _epb_ticks(1))
    monkeypatch.setattr(cli, "parse_capture", lambda label, path, raise_on_error=False: [make_pkt(point=label)])
    monkeypatch.setattr(
        sys,
        "argv",
        ["netcross", "--capture", f"A={a}", "--capture", f"B={b}", "--link-speed", "A=1G", "--link-speed", "B=100M"],
    )
    try:
        cli.main()
    except SystemExit as exc:
        assert not exc.code
    out = capsys.readouterr().out
    assert "A : 10 Gbit/s (source : if_speed)" in out
    assert "B : 100 Mbit/s (source : --link-speed)" in out
