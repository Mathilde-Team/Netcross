# SPDX-License-Identifier: GPL-3.0-or-later
"""Appariement des flux RTP entre points malgre NAT/SBC (issue #1121)."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.rtp_match import MIN_COMMON, SEQ_MOD, TS_MOD, match_rtp_streams
from netcross_report.json_report import build_json_report_document

DOC = Path(__file__).resolve().parent.parent / "docs" / "appariement-rtp.md"


def _rtp(
    point,
    n=50,
    t0=0.0,
    src="10.0.0.1",
    sport=40000,
    dst="10.0.0.2",
    dport=50000,
    ssrc=0x1234,
    seq0=100,
    ts0=8000,
    transit=0.01,
    perdus=(),
):
    return [
        make_pkt(
            point=point,
            ts=t0 + i * 0.02 + transit,
            proto="UDP",
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            is_rtp=True,
            rtp_seq=(seq0 + i) % SEQ_MOD,
            rtp_ts=(ts0 + 160 * i) % TS_MOD,
            rtp_ssrc=ssrc,
            ip_id=i,
            key_id=i,
        )
        for i in range(n)
        if i not in perdus
    ]


def test_ports_reecrits_par_un_nat_meme_ssrc():
    lan = _rtp("LAN", src="192.168.1.10", sport=40000, transit=0.0)
    wan = _rtp("WAN", src="203.0.113.5", sport=61000, transit=0.012, perdus=(10, 11, 30))
    flux = match_rtp_streams(lan + wan, ["LAN", "WAN"])
    assert len(flux) == 1
    f = flux[0]
    assert f["method"] == "ssrc"
    assert f["nat_rewritten"] is True
    assert [j["point"] for j in f["legs"]] == ["LAN", "WAN"]
    assert [j["sport"] for j in f["legs"]] == [40000, 61000]
    assert f["lost_between"] == {"LAN -> WAN": 3}
    assert "SSRC=0x00001234" in f["label"]


def test_sbc_qui_reecrit_seulement_le_ssrc():
    a = _rtp("A", ssrc=1)
    b = _rtp("B", ssrc=2, src="198.51.100.1", dport=20000)
    (f,) = match_rtp_streams(a + b, ["A", "B"])
    assert f["method"] == "ssrc_rewritten"
    assert f["legs"][1]["seq_offset"] == 0


def test_sbc_qui_reemet_le_media_avec_decalage():
    a = _rtp("A", ssrc=0xAAAA, seq0=65530, ts0=TS_MOD - 400)  # passages a zero
    b = _rtp("B", ssrc=0xBBBB, seq0=7, ts0=123456, src="198.51.100.1", sport=30000, dport=30002, perdus=(5,))
    (f,) = match_rtp_streams(a + b, ["A", "B"])
    assert f["method"] == "sbc_offset"
    jb = f["legs"][1]
    assert jb["seq_offset"] == (7 - 65530) % SEQ_MOD
    assert jb["ts_offset"] == (123456 - (TS_MOD - 400)) % TS_MOD
    assert f["lost_between"] == {"A -> B": 1}


def test_trois_points_nat_puis_sbc():
    a = _rtp("A", ssrc=5, transit=0.0)
    b = _rtp("B", ssrc=5, src="203.0.113.5", sport=1111, transit=0.005)
    c = _rtp("C", ssrc=9, seq0=900, ts0=1, src="198.51.100.9", sport=2222, transit=0.01)
    (f,) = match_rtp_streams(c + a + b, ["A", "B", "C"])
    assert [j["point"] for j in f["legs"]] == ["A", "B", "C"]
    assert f["method"] == "mixed"
    assert f["legs"][2]["seq_offset"] == 800
    assert f["lost_between"] == {"A -> B": 0, "B -> C": 0}


def test_flux_simultanes_non_confondus():
    paquets = []
    for k, ssrc in enumerate((0x10, 0x20)):
        paquets += _rtp("A", ssrc=ssrc, sport=40000 + k, seq0=1000 * k, ts0=50000 * k)
        paquets += _rtp("B", ssrc=ssrc, sport=60000 + k, seq0=1000 * k, ts0=50000 * k, src="203.0.113.5")
    flux = match_rtp_streams(paquets, ["A", "B"])
    assert len(flux) == 2
    for f in flux:
        assert f["method"] == "ssrc"
        assert len({j["ssrc"] for j in f["legs"]}) == 1


def test_jambes_disjointes_dans_le_temps_non_appariees():
    a = _rtp("A", t0=0.0)
    b = _rtp("B", t0=100.0, src="203.0.113.5")
    assert match_rtp_streams(a + b, ["A", "B"], window_seconds=5.0) == []


def test_flux_sans_rapport_non_apparie():
    a = _rtp("A", ssrc=1, seq0=0, ts0=0)
    b = [
        make_pkt(
            point="B",
            ts=0.01 + i * 0.02,
            proto="UDP",
            is_rtp=True,
            rtp_seq=(i * 7919) % SEQ_MOD,
            rtp_ts=(i * 104729) % TS_MOD,
            rtp_ssrc=2,
            src="203.0.113.5",
        )
        for i in range(50)
    ]
    assert match_rtp_streams(a + b, ["A", "B"]) == []


def test_meme_point_jamais_apparie_avec_lui_meme():
    a = _rtp("A", sport=1)
    a2 = _rtp("A", sport=2)
    assert match_rtp_streams(a + a2) == []


def test_une_jambe_par_point_et_meilleur_score():
    a = _rtp("A", n=50)
    b_long = _rtp("B", n=50, sport=1)
    b_court = _rtp("B", n=MIN_COMMON, sport=2)
    (f,) = match_rtp_streams(a + b_long + b_court, ["A", "B"])
    assert [j["sport"] for j in f["legs"]] == [40000, 1]


def test_jambe_tardive_cote_aval():
    # l'aval commence 40 paquets apres l'amont : le decalage est cherche
    # autour du debut de l'aval, et le debut de l'amont n'est pas une perte
    a = _rtp("A", n=100, ssrc=1, transit=0.0)
    b = _rtp("B", n=100, ssrc=2, seq0=5000, ts0=9, src="198.51.100.1", transit=0.0)
    b = [pk for pk in b if pk.ts >= 0.8]
    (f,) = match_rtp_streams(a + b, ["A", "B"])
    assert f["method"] == "sbc_offset"
    assert f["lost_between"] == {"A -> B": 0}


def test_courte_jambe_exige_toute_la_jambe():
    a = _rtp("A", n=3)
    b = _rtp("B", n=3, src="203.0.113.5")
    (f,) = match_rtp_streams(a + b, ["A", "B"])
    assert f["method"] == "ssrc"


def test_paquets_non_rtp_ou_incomplets_ignores():
    a = _rtp("A")
    a.append(make_pkt(point="A", proto="UDP", is_rtp=True, rtp_seq=None, rtp_ts=None, rtp_ssrc=1))
    a.append(make_pkt(point="A", proto="TCP"))
    assert match_rtp_streams(a) == []


def test_ordre_par_premier_paquet_sans_order():
    a = _rtp("Z", transit=0.0)
    b = _rtp("A", transit=0.03, src="203.0.113.5")
    (f,) = match_rtp_streams(a + b)
    assert [j["point"] for j in f["legs"]] == ["Z", "A"]


def test_branche_dans_analyse_et_json():
    paquets = _rtp("LAN", src="192.168.1.10", transit=0.0) + _rtp("WAN", src="203.0.113.5", sport=61000)
    paquets.sort(key=lambda pk: pk.ts)
    r = analyse(correlate(paquets), ["LAN", "WAN"], paquets)
    assert len(r.rtp_matches) == 1
    # _analyse_rtp, lui, voit toujours deux flux distincts
    assert len(r.rtp_streams) == 2
    doc = build_json_report_document(r)
    assert doc["rtp_matches"][0]["nat_rewritten"] is True
    vide = analyse(correlate([]), ["LAN", "WAN"], [])
    assert "rtp_matches" not in build_json_report_document(vide)


@pytest.mark.parametrize("mot", ["ssrc_rewritten", "sbc_offset", "nat_rewritten", "lost_between", "MIN_COMMON"])
def test_documentation(mot):
    assert mot in DOC.read_text(encoding="utf-8")
