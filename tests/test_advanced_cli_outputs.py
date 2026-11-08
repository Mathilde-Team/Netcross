# SPDX-License-Identifier: GPL-3.0-or-later
"""Issues #359, #360, #361 : chronologie des flux, recherche forensique et
statistiques tshark accessibles depuis le CLI, avec sortie JSON.

Les captures sont remplacees par des Pkt synthetiques (parse_capture
monkeypatche) : le test porte sur le raccordement CLI, pas sur tshark."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
import netcross_core.tshark_stats as tshark_stats
from netcross_core.flow_timeline import build_flow_timelines
from netcross_core.tshark_stats import TsharkUnavailableError
from netcross_core.tshark_stats.models import ConversationStat, MetricSeries


def _handshake(point, t0, **kw):
    """SYN, SYN-ACK (+20 ms), ACK, requete HTTP : une conversation, deux sens."""
    c = {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 50000, "dport": 80}
    s = {"src": "10.0.0.2", "dst": "10.0.0.1", "sport": 80, "dport": 50000}
    return [
        make_pkt(point=point, ts=t0, flags="SYN", frame_number=1, **c, **kw),
        make_pkt(point=point, ts=t0 + 0.020, flags="SYN,ACK", frame_number=2, **s, **kw),
        make_pkt(point=point, ts=t0 + 0.021, flags="ACK", frame_number=3, **c, **kw),
        make_pkt(point=point, ts=t0 + 0.022, frame_number=4, http_method="GET", http_uri="/admin/login", **c, **kw),
    ]


PKTS = [
    *_handshake("A", 100.0),
    *_handshake("B", 100.005),
    make_pkt(
        point="A",
        ts=101.0,
        proto="DNS",
        src="10.0.0.1",
        dst="9.9.9.9",
        sport=5353,
        dport=53,
        dns_qry_name="example.org",
    ),
]


def _run(monkeypatch, *argv, pkts=PKTS):
    monkeypatch.setattr(
        cli, "parse_capture", lambda label, path, raise_on_error=False: [p for p in pkts if p.point == label]
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--capture", "B=b.pcap", *map(str, argv)],
    )
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


# -- #359 chronologie des flux ------------------------------------------------


def test_chronologie_par_point_et_bidirectionnelle():
    data = build_flow_timelines(PKTS)
    tcp = [f for f in data["flows"] if f["protocol"] == "TCP"]
    # une chronologie par point : les copies du point B ne sont pas melangees a A
    assert [(f["point"], f["packets"]) for f in tcp] == [("A", 4), ("B", 4)]
    # les deux sens forment une seule conversation : le RTT SYN/SYN-ACK est mesure
    assert tcp[0]["rtt_estimate_ms"] == pytest.approx(20.0)
    assert tcp[0]["inter_arrival_stats"]["min_ms"] == pytest.approx(1.0)
    # le DNS a un seul paquet : pas d'inter-arrivee, omis
    assert all(f["protocol"] != "DNS" for f in data["flows"])


def test_cli_flow_timeline_json(tmp_path, monkeypatch):
    out = tmp_path / "tl.json"
    assert _run(monkeypatch, "--flow-timeline", out, "--flow-timeline-window", "0.01") == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == 1 and data["window_s"] == 0.01
    assert {f["point"] for f in data["flows"]} == {"A", "B"}
    assert data["flows"][0]["endpoints"] == [
        {"address": "10.0.0.1", "port": 50000},
        {"address": "10.0.0.2", "port": 80},
    ]


def test_cli_flow_timeline_window_invalide(tmp_path, monkeypatch, capsys):
    assert _run(monkeypatch, "--flow-timeline", tmp_path / "x.json", "--flow-timeline-window", "0") == 1
    assert "--flow-timeline-window" in capsys.readouterr().err


# -- #360 recherche forensique ------------------------------------------------


def test_cli_forensic_search_filtres_combines(tmp_path, monkeypatch):
    out = tmp_path / "fs.json"
    rc = _run(
        monkeypatch, "--forensic-search", out, "--search-field", "uri", "--search-value", "admin", "--search-point", "B"
    )
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["query"] == {"point": "B", "field": "uri", "field_value": "admin"}
    assert data["count"] == 1
    assert data["results"][0]["point"] == "B" and data["results"][0]["matched_fields"] == ["uri"]


def test_cli_forensic_search_texte_et_port(tmp_path, monkeypatch):
    out = tmp_path / "fs.json"
    assert _run(monkeypatch, "--forensic-search", out, "--search-text", "EXAMPLE", "--search-port", "53") == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [r["snippet"] for r in data["results"] if r["kind"] == "packet"] and data["count"] >= 1


def test_cli_forensic_search_resultat_vide_interpretable(tmp_path, monkeypatch):
    out = tmp_path / "fs.json"
    assert _run(monkeypatch, "--forensic-search", out, "--search-address", "203.0.113.9") == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data == {"version": 1, "query": {"address": "203.0.113.9"}, "count": 0, "results": []}


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--search-text", "x"], "--search-text necessite --forensic-search"),
        (["--forensic-search", "o.json", "--search-field", "nope"], "champ inconnu 'nope'"),
        (["--forensic-search", "o.json", "--search-port", "70000"], "--search-port"),
    ],
)
def test_cli_forensic_search_options_invalides(monkeypatch, capsys, argv, message):
    assert _run(monkeypatch, *argv) == 1
    assert message in capsys.readouterr().err


# -- #361 statistiques tshark -------------------------------------------------


def _fake_stats(monkeypatch, fail_on=None):
    def conv(path, protocol="tcp"):
        if path == fail_on:
            raise subprocess.CalledProcessError(2, ["tshark"])
        return [
            ConversationStat(
                protocol=protocol,
                endpoint_a="10.0.0.1:50000",
                endpoint_b="10.0.0.2:80",
                packets_total=3,
                bytes_total=300,
            )
        ]

    monkeypatch.setattr(tshark_stats, "collect_conversations", conv)
    monkeypatch.setattr(tshark_stats, "collect_endpoints", lambda path, protocol="tcp": [])
    monkeypatch.setattr(tshark_stats, "collect_protocol_hierarchy", lambda path: [])
    monkeypatch.setattr(tshark_stats, "collect_io_stat", lambda path: MetricSeries(name="io_stat"))


def test_cli_tshark_stats_json(tmp_path, monkeypatch):
    _fake_stats(monkeypatch)
    out = tmp_path / "ts.json"
    assert _run(monkeypatch, "--tshark-stats", out) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert [c["label"] for c in data["captures"]] == ["A", "B"]
    assert set(data["captures"][0]["conversations"]) == {"tcp", "udp"}
    assert data["captures"][0]["conversations"]["tcp"][0]["bytes_total"] == 300


def test_cli_tshark_stats_echec_isole_et_signale(tmp_path, monkeypatch, capsys):
    _fake_stats(monkeypatch, fail_on="b.pcap")
    out = tmp_path / "ts.json"
    assert _run(monkeypatch, "--tshark-stats", out) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "conversations" in data["captures"][0]
    assert set(data["captures"][1]) == {"label", "path", "error"}
    assert "--tshark-stats B (b.pcap)" in capsys.readouterr().err


def test_cli_tshark_stats_tshark_absent(tmp_path, monkeypatch, capsys):
    def missing(*a, **k):
        raise TsharkUnavailableError("tshark introuvable")

    _fake_stats(monkeypatch)
    monkeypatch.setattr(tshark_stats, "collect_conversations", missing)
    out = tmp_path / "ts.json"
    assert _run(monkeypatch, "--tshark-stats", out) == 0
    assert all(c["error"] == "tshark introuvable" for c in json.loads(out.read_text())["captures"])
    assert "tshark introuvable" in capsys.readouterr().err


def test_cli_tshark_stats_refuse_en_live_seul(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--live", "A=eth0", "--tshark-stats", "x.json"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "--tshark-stats" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_tshark_stats_reel(tmp_path):
    from pcap_builders import synthetic_packets, write_pcap

    path = tmp_path / "c.pcap"
    write_pcap(path, synthetic_packets(5))
    data = cli._collect_tshark_stats([("A", str(path))])
    assert "error" not in data["captures"][0], data
    assert data["captures"][0]["protocol_hierarchy"]


def test_options_avancees_refusees_avec_merge(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            "A=a.pcap",
            "--merge",
            str(tmp_path / "m.pcap"),
            "--flow-timeline",
            "t.json",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "--flow-timeline" in capsys.readouterr().err
