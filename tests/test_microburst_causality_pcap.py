# SPDX-License-Identifier: GPL-3.0-or-later
"""Rafales et pertes aval : vrais PCAP, vrai TShark, CLI JSON (#1137)."""

import json
import shutil
import struct
import sys

import pytest
from pcap_builders import write_pcap
from test_content_extraction_pcap import _udp
from test_microburst import T0, traffic

import cross_capture_analyzer_cli as cli


@pytest.mark.parametrize("dropped", [False, True])
def test_cli_trois_points_association_seulement_sur_segment_avec_perte(
    tmp_path,
    monkeypatch,
    capsys,
    dropped,
):
    assert shutil.which("tshark"), "TShark est requis pour vérifier les PCAP et la CLI"
    monkeypatch.delenv("NETCROSS_MICROBURST_WINDOW_MS", raising=False)
    source = traffic()
    target = next(i for i, packet in enumerate(source) if packet.ts > T0 + 0.06)
    arguments = ["netcross", "--order", "A,B,C"]
    for n, point in enumerate(("A", "B", "C")):
        frames = []
        for i, packet in enumerate(source):
            if point == "C" and dropped and i == target:
                continue
            payload = i.to_bytes(4, "big") + b"x" * 954
            frame = bytearray(_udp(packet.src, packet.dst, 40000, 40001, payload))
            # IP ID unique, inchangé entre les trois sondes : vraie clé UDP.
            struct.pack_into("!H", frame, 18, i + 1)
            frames.append((round(packet.ts * 1_000_000) + n * 1_000, bytes(frame)))
        path = tmp_path / f"{point}.pcap"
        write_pcap(path, frames)
        arguments.extend(["--capture", f"{point}={path}", "--link-speed", f"{point}=1G"])
    output = tmp_path / "rapport.json"
    arguments.extend(["--json-report", str(output)])
    monkeypatch.setattr(sys, "argv", arguments)
    cli.main()
    document = json.loads(output.read_text())
    records = document["microburst_correlations"]
    assert document["microbursts"]["B"]["events"]
    assert [(r["upstream"], r["downstream"]) for r in records] == ([("B", "C")] if dropped else [])
    if dropped:
        assert records[0]["losses"] == 1
        assert records[0]["physical_cause_proven"] is False
        assert records[0]["evidence"][0]["point"] == "B"
        assert records[0]["evidence"][0]["frame_number"] == target + 1
    assert ("Association temporelle établie" in capsys.readouterr().out) is dropped
