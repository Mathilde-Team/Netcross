# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #278 de bout en bout sur une vraie capture (tshark requis, CI) :
SIP/SDP + RTP G.711 avec pertes, et un PDF telecharge en HTTP."""

from __future__ import annotations

import json
import shutil
import socket
import struct
import sys
import wave

import pytest
from pcap_builders import write_pcap
from test_content_extraction import rtp
from test_security_report_pcap import ACK, PSH_ACK, SYN, SYN_ACK, _frame

import cross_capture_analyzer_cli as cli

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")

A, B = "10.0.0.1", "10.0.0.2"
START_US = 1_700_000_000_000_000
PDF = b"%PDF-1.4\n" + b"x" * 200 + b"\n%%EOF\n"


def _udp(src, dst, sport, dport, data):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst)
    )
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + udp


def _capture(path):
    ts = START_US
    pkts = []
    sdp = (
        b"v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n"
        b"m=audio 50000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
    invite = (
        b"INVITE sip:b@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
        b"From: <sip:a@10.0.0.1>;tag=1\r\nTo: <sip:b@10.0.0.2>\r\nCall-ID: c1@10.0.0.1\r\nCSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\nContent-Length: " + str(len(sdp)).encode() + b"\r\n\r\n" + sdp
    )
    pkts.append((ts, _udp(A, B, 5060, 5060, invite)))
    for i in range(100):
        if i in range(30, 36):  # rafale de 6 pertes
            continue
        pkts.append((ts + 100_000 + i * 20_000, _udp(A, B, 40000, 50000, rtp(1000 + i, i * 160))))

    ts += 3_000_000
    seq_c, seq_s = 1000, 5000
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: %d\r\n\r\n" % len(PDF) + PDF
    req = b"GET /rapport.pdf HTTP/1.1\r\nHost: example.com\r\n\r\n"
    for src, dst, sp, dp, seq, ack, flags, data in [
        (A, B, 40001, 80, seq_c, 0, SYN, b""),
        (B, A, 80, 40001, seq_s, seq_c + 1, SYN_ACK, b""),
        (A, B, 40001, 80, seq_c + 1, seq_s + 1, ACK, b""),
        (A, B, 40001, 80, seq_c + 1, seq_s + 1, PSH_ACK, req),
        (B, A, 80, 40001, seq_s + 1, seq_c + 1 + len(req), PSH_ACK, resp),
    ]:
        ts += 10_000
        pkts.append((ts, _frame(src, dst, sp, dp, seq, ack, flags, data)))
    write_pcap(path, pkts)


def test_pcap_extraction_audio_et_document(monkeypatch, capsys, tmp_path):
    pcap = tmp_path / "appel.pcap"
    _capture(pcap)
    out = tmp_path / "contenus"
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"LAN={pcap}", "--extract-contents", str(out)])
    cli.main()
    captured = capsys.readouterr()
    assert "Rappel d'usage raisonne" in captured.err
    assert "audio PCMU : degradation" in captured.out
    assert "pertes 6.0 % (rafale max 6)" in captured.out

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    (media,) = manifest["media"]
    assert (media["lost"], media["expected"]) == (6, 100)
    with wave.open(media["exported"]) as w:
        assert w.getnframes() == 100 * 160
    pdfs = [d for d in manifest["documents"] if d["protocol"] == "http"]
    assert pdfs and pdfs[0]["detected_type"] == "pdf" and pdfs[0]["size"] == len(PDF)


def test_pcap_analyse_qualitative_seule(monkeypatch, capsys, tmp_path):
    pcap = tmp_path / "appel.pcap"
    _capture(pcap)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"LAN={pcap}", "--media-quality"])
    cli.main()
    captured = capsys.readouterr()
    assert "MOS estime" in captured.out
    assert "Rappel d'usage raisonne" not in captured.err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["appel.pcap"]
