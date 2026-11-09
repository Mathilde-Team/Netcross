# SPDX-License-Identifier: GPL-3.0-or-later
"""PCAP synthétiques réellement décodés par TShark, sans trafic réseau."""

import json
import shutil

import pytest
from pcap_builders import write_pcap
from test_content_extraction import rtp
from test_content_extraction_pcap import _udp

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.parsing import parse_capture
from netcross_core.redact import redact_packets
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import build_findings


@pytest.mark.parametrize("redacted", [False, True])
@pytest.mark.parametrize("dropped", [(), (12, 13)])
def test_pcaps_trois_points_pertes_seulement_sur_le_dernier_segment(tmp_path, dropped, redacted):
    assert shutil.which("tshark"), "TShark est requis pour vérifier la vraie chaîne de décodage"
    packets = []
    for n, point in enumerate(("A", "B", "C")):
        frames = [
            (
                1_700_000_000_000_000 + i * 20_000 + n * 5_000,
                _udp("10.1.0.1", "10.2.0.2", 40000, 50000, rtp(1000 + i, i * 160)),
            )
            for i in range(40)
            if point != "C" or i not in dropped
        ]
        path = tmp_path / f"{point}.pcap"
        write_pcap(path, frames)
        decoded = parse_capture(point, str(path), raise_on_error=True)
        assert len(decoded) == len(frames)
        assert all(packet.is_rtp for packet in decoded)
        packets.extend(decoded)
    if redacted:
        redact_packets(packets)
    report = analyse(
        correlate(packets),
        ["A", "B", "C"],
        packets,
        clock_offsets={("A", "B"): 0.0, ("B", "C"): 0.0},
    )
    assert [segment["lost"] for segment in report.rtp_segments] == [0, len(dropped)]
    assert [segment["delay_ms"] for segment in report.rtp_segments] == pytest.approx([5, 5], abs=0.001)
    findings = [f for f in build_findings(report) if "Dégradation de transport" in f.message]
    assert [f.segment for f in findings] == (["B -> C"] if dropped else [])
    document = json.dumps(build_json_report_document(report))
    assert ("10.1.0.1" in document) is not redacted
    assert ("10.2.0.2" in document) is not redacted
