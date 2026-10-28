# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #169 : conversion et exports sur un vrai tshark (CI uniquement).

La capture source est construite octet par octet (tests/pcap_builders) ;
le format produit est verifie par son magic number, pas par l'outil teste.
"""

from __future__ import annotations

import csv
import json
import shutil
import struct
import sys

import pytest
from pcap_builders import write_pcap

import cross_capture_analyzer_cli as cli
from pcap_parser.capture import convert_capture, export_csv, export_json
from pcap_parser.ek_source import TsharkError

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")

N = 7


def _udp_frame(i: int, v6: bool = False) -> bytes:
    payload = b"netcross,%d" % i  # virgule : verifie le quotage CSV
    udp = struct.pack(">HHHH", 40000 + i, 53, 8 + len(payload), 0) + payload
    if v6:
        ip = struct.pack(">IHBB", 6 << 28, len(udp), 17, 64) + bytes(15) + b"\x01" + bytes(15) + b"\x02"
        ethertype = 0x86DD
    else:
        src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0, src, dst)
        ethertype = 0x0800
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack(">H", ethertype) + ip + udp


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "source.pcap"
    frames = [_udp_frame(i, v6=(i == N - 1)) for i in range(N)]
    write_pcap(path, [(1_700_000_000_000_000 + i * 1000, f) for i, f in enumerate(frames)])
    return str(path)


@pytest.mark.parametrize(
    ("fmt", "magics"),
    [
        ("pcapng", {b"\x0a\x0d\x0d\x0a"}),
        ("pcap", {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}),
    ],
)
def test_conversion_format_de_sortie(source, tmp_path, fmt, magics):
    out = tmp_path / f"out.{fmt}"
    convert_capture(source, str(out), fmt=fmt)
    assert out.read_bytes()[:4] in magics


def test_conversion_erf_relisible(source, tmp_path):
    erf = tmp_path / "out.erf"
    try:
        convert_capture(source, str(erf), fmt="erf")
    except TsharkError as exc:
        # certaines versions de tshark ne savent pas ecrire de l'Ethernet
        # en ERF : l'erreur doit alors remonter clairement (pas de fichier vide)
        assert "erf" in str(exc)
        pytest.skip(f"ERF non supporte par ce tshark : {exc}")
    back = tmp_path / "back.csv"
    export_csv(str(erf), str(back))  # tshark relit l'ERF produit
    with open(back, newline="") as fh:
        assert len(list(csv.DictReader(fh))) == N


def test_export_csv_une_ligne_par_paquet(source, tmp_path):
    out = tmp_path / "out.csv"
    export_csv(source, str(out))
    with open(out, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == N
    assert rows[0]["ip.src"] == "10.0.0.1" and rows[0]["frame.len"] == str(len(_udp_frame(0)))
    assert rows[-1]["ipv6.src"] == "::1" and rows[-1]["ip.src"] == ""


def test_export_json_un_objet_par_paquet(source, tmp_path):
    out = tmp_path / "out.json"
    export_json(source, str(out))
    packets = json.loads(out.read_text())
    assert len(packets) == N and "udp" in packets[0]["_source"]["layers"]


def test_cli_convert(source, tmp_path, monkeypatch, capsys):
    out = tmp_path / "cli.pcapng"
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"A={source}", "--convert", str(out)])
    cli.main()  # mode utilitaire : retour normal apres la conversion
    assert out.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"
    assert "Converti" in capsys.readouterr().out
