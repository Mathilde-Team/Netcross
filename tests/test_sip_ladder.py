# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagramme d'echelle SIP multi-points (issue #1125)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core import sip_ladder
from netcross_core.analysis import analyse
from netcross_core.models import Report
from netcross_core.redact import AddressRedactor
from netcross_core.sip_ladder import build_sip_ladders
from netcross_report import pdf
from netcross_report.html_report import _labels, _sip_cell, _static_sip, render_html_report
from netcross_report.json_report import build_json_report_document
from pcap_parser.packet import build_packet
from pcap_parser.protocols import SIP_HEADER_MAX_LEN, extract_sip_route_headers

RENDU = Path(__file__).resolve().parent / "js" / "rendu_headless.js"
NODE = shutil.which("node")
avec_node = pytest.mark.skipif(NODE is None, reason="node absent")

SDP_A = (("10.0.0.1", 40000),)
SDP_ALG = (("192.0.2.9", 50000),)


def _sip(point, ts, msg, cseq="1 INVITE", call_id="appel-1", sdp=(), via=None, contact=None, frame=None):
    return make_pkt(
        point=point,
        ts=ts,
        proto="UDP",
        sport=5060,
        dport=5060,
        frame_number=frame,
        sip_call_id=call_id,
        sip_msg_type=msg,
        sip_cseq=cseq,
        sip_sdp_media=sdp,
        sip_via=via,
        sip_contact=contact,
    )


def _appel_alg():
    """INVITE vu en A, B et C, reecrit par un ALG entre A et B ; 100 Trying
    seulement en A ; 200 OK retransmis en C ; BYE perdu entre A et B."""
    return [
        _sip("A", 0.000, "INVITE", sdp=SDP_A, via="SIP/2.0/UDP 10.0.0.1", contact="<sip:a@10.0.0.1>", frame=1),
        _sip("B", 0.002, "INVITE", sdp=SDP_ALG, via="SIP/2.0/UDP 10.0.0.1", contact="<sip:a@192.0.2.9>", frame=7),
        _sip("C", 0.004, "INVITE", sdp=SDP_ALG, via="SIP/2.0/UDP 10.0.0.1", contact="<sip:a@192.0.2.9>"),
        _sip("A", 0.001, "100 Trying"),
        _sip("C", 0.100, "200 OK"),
        _sip("C", 0.600, "200 OK"),
        _sip("B", 0.102, "200 OK"),
        _sip("A", 0.104, "200 OK"),
        _sip("A", 5.000, "BYE", cseq="2 BYE"),
    ]


def _par_message(echelle):
    return {(m["message"], m["cseq"]): m for m in echelle["messages"]}


# -- noyau ------------------------------------------------------------------


def test_echelle_message_perdu_retransmis_et_reecrit():
    (echelle,) = build_sip_ladders(_appel_alg(), ["A", "B", "C"])
    assert echelle["call_id"] == "appel-1"
    assert echelle["points"] == ["A", "B", "C"]
    assert [m["message"] for m in echelle["messages"]] == ["INVITE", "100 Trying", "200 OK", "BYE"]
    msgs = _par_message(echelle)

    invite = msgs[("INVITE", "1 INVITE")]
    assert invite["lost_at"] == [] and invite["retransmitted_at"] == []
    assert invite["cells"]["A"] == {"count": 1, "rel_ms": 0.0, "frame_number": 1, "rewritten": []}
    assert invite["cells"]["B"]["rewritten"] == ["sdp", "contact"]
    assert invite["cells"]["B"]["rel_ms"] == pytest.approx(2.0)
    assert invite["rewritten"] == [
        {"point": "B", "fields": ["sdp", "contact"]},
        {"point": "C", "fields": ["sdp", "contact"]},
    ]

    trying = msgs[("100 Trying", "1 INVITE")]
    assert trying["hop_by_hop"] is True and trying["lost_at"] == []

    ok = msgs[("200 OK", "1 INVITE")]
    assert ok["retransmitted_at"] == ["C"] and ok["cells"]["C"]["count"] == 2

    bye = msgs[("BYE", "2 BYE")]
    assert bye["lost_at"] == ["B", "C"] and bye["hop_by_hop"] is False
    assert (echelle["lost"], echelle["retransmitted"], echelle["rewritten"]) == (1, 1, 1)
    assert (echelle["total_messages"], echelle["truncated"]) == (4, 0)
    assert "_start" not in echelle


def test_point_sans_aucun_message_de_l_appel_n_a_pas_de_colonne():
    paquets = [_sip("A", 0.0, "INVITE"), _sip("C", 0.01, "INVITE")]
    (echelle,) = build_sip_ladders(paquets, ["A", "B", "C"])
    assert echelle["points"] == ["A", "C"]
    assert echelle["messages"][0]["lost_at"] == []


def test_sans_ordre_de_chemin_les_points_suivent_la_premiere_observation():
    paquets = [_sip("Z", 0.0, "INVITE"), _sip("B", 0.5, "INVITE"), _sip("Y", 0.2, "INVITE")]
    (echelle,) = build_sip_ladders(paquets)
    assert echelle["points"] == ["Z", "Y", "B"]


def test_via_et_contact_inconnus_ne_sont_pas_une_reecriture():
    paquets = [
        _sip("A", 0.0, "INVITE", via="SIP/2.0/UDP h1", contact="<sip:a@h1>"),
        _sip("B", 0.1, "INVITE"),
        _sip("C", 0.2, "INVITE", via="SIP/2.0/UDP h2", contact="<sip:a@h1>"),
    ]
    (echelle,) = build_sip_ladders(paquets, ["A", "B", "C"])
    invite = echelle["messages"][0]
    assert invite["cells"]["B"]["rewritten"] == []
    assert invite["cells"]["C"]["rewritten"] == ["via"]


def test_sdp_supprime_est_une_reecriture():
    paquets = [_sip("A", 0.0, "INVITE", sdp=SDP_A), _sip("B", 0.1, "INVITE")]
    (echelle,) = build_sip_ladders(paquets, ["A", "B"])
    assert echelle["messages"][0]["cells"]["B"]["rewritten"] == ["sdp"]


def test_appels_avec_constat_en_tete_et_plafond(monkeypatch):
    sain = [_sip("A", 0.0, "INVITE", call_id="sain"), _sip("B", 0.1, "INVITE", call_id="sain")]
    perte = [_sip("A", 1.0, "INVITE", call_id="perte")]
    tardif = [_sip("A", 2.0, "INVITE", call_id="tardif"), _sip("B", 2.1, "INVITE", call_id="tardif")]
    echelles = build_sip_ladders(sain + perte + tardif + [_sip("B", 1.5, "200 OK", call_id="perte")], ["A", "B"])
    assert [e["call_id"] for e in echelles] == ["perte", "sain", "tardif"]
    assert [e["call_id"] for e in build_sip_ladders(sain + tardif, ["A", "B"], max_calls=1)] == ["sain"]
    assert build_sip_ladders(sain, ["A", "B"], max_calls=-3) == []


def test_messages_tronques(monkeypatch):
    monkeypatch.setattr(sip_ladder, "MAX_MESSAGES", 2)
    paquets = [_sip("A", float(i), "INFO", cseq=f"{i} INFO") for i in range(5)]
    (echelle,) = build_sip_ladders(paquets)
    assert len(echelle["messages"]) == 2
    assert (echelle["total_messages"], echelle["truncated"]) == (5, 3)


def test_call_id_tronque_et_paquets_non_sip_ignores():
    long_id = "x" * 200
    paquets = [_sip("A", 0.0, "INVITE", call_id=long_id), make_pkt(), _sip("A", 0.1, None)]
    (echelle,) = build_sip_ladders(paquets)
    assert echelle["call_id"] == "x" * sip_ladder.CALL_ID_MAX_LEN
    assert build_sip_ladders([make_pkt()]) == []
    assert build_sip_ladders(None) == []


def test_cseq_absent():
    (echelle,) = build_sip_ladders([_sip("A", 0.0, "INVITE", cseq=None)])
    assert echelle["messages"][0]["cseq"] == ""


def test_analyse_remplit_sip_ladders_et_le_json():
    paquets = _appel_alg()
    r = analyse({}, ["A", "B", "C"], paquets)
    assert [e["call_id"] for e in r.sip_ladders] == ["appel-1"]
    assert r.sip_ladders[0]["points"] == ["A", "B", "C"]
    doc = build_json_report_document(r, findings=[])
    assert doc["sip_ladders"] == r.sip_ladders
    assert "sip_ladders" not in build_json_report_document(Report(points=["A"]), findings=[])


# -- parseur ----------------------------------------------------------------


def test_extract_sip_route_headers_formes_longues_et_compactes():
    longues = (
        b"INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z1\r\nVia: SIP/2.0/UDP p2\r\n"
        b"Contact: <sip:a@10.0.0.1>\r\n\r\nm=audio 4000 RTP/AVP 0\r\nContact: corps\r\n"
    )
    assert extract_sip_route_headers(longues) == ("SIP/2.0/UDP 10.0.0.1;branch=z1", "<sip:a@10.0.0.1>")
    compactes = b"SIP/2.0 200 OK\nv: SIP/2.0/TCP h\nligne sans deux-points\nm: <sip:b@h>\n"
    assert extract_sip_route_headers(compactes) == ("SIP/2.0/TCP h", "<sip:b@h>")
    assert extract_sip_route_headers(b"BYE sip:b@x SIP/2.0\r\nCSeq: 2 BYE\r\n") == (None, None)
    assert extract_sip_route_headers(b"") == (None, None)
    long_via = b"INVITE x SIP/2.0\r\nVia: " + b"a" * 500 + b"\r\n"
    assert len(extract_sip_route_headers(long_via)[0]) == SIP_HEADER_MAX_LEN


def test_build_packet_porte_via_et_contact():
    from netcross_core.parsing import _to_pkt

    sip = (
        b"INVITE sip:b@x SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h\r\nContact: <sip:a@h>\r\n\r\n"
    )
    layers = {
        "frame": {"frame_frame_len": "200", "frame_frame_number": "1"},
        "ip": {"ip_ip_src": "1.1.1.1", "ip_ip_dst": "2.2.2.2"},
        "udp": {"udp_udp_srcport": "5060", "udp_udp_dstport": "5060", "udp_udp_payload": sip.hex(":")},
    }
    raw = build_packet(0.0, layers)
    assert (raw.sip_via, raw.sip_contact) == ("SIP/2.0/UDP h", "<sip:a@h>")
    pk = _to_pkt("A", raw)
    assert (pk.sip_via, pk.sip_contact) == ("SIP/2.0/UDP h", "<sip:a@h>")


# -- anonymisation ----------------------------------------------------------


def test_redact_pseudonymise_les_adresses_de_via_et_contact():
    pk1 = _sip("A", 0.0, "INVITE", via="SIP/2.0/UDP 10.0.0.1:5060;branch=z", contact="<sip:a@[2001:db8:5::1]>")
    pk2 = _sip("B", 0.1, "INVITE", via="SIP/2.0/UDP 10.0.0.1:5060;branch=z", contact="<sip:a@host.example>")
    pk1.src = "10.0.0.1"
    red = AddressRedactor()
    red.redact([pk1, pk2])
    assert "10.0.0.1" not in pk1.sip_via
    assert pk1.sip_via == pk2.sip_via == f"SIP/2.0/UDP {pk1.src}:5060;branch=z"
    assert pk1.sip_contact.startswith("<sip:a@[2001:db8::") and "2001:db8:5::1" not in pk1.sip_contact
    assert pk2.sip_contact == "<sip:a@host.example>"


def test_redact_laisse_un_faux_ipv6_entre_crochets():
    pk = _sip("A", 0.0, "INVITE", contact="<sip:a@[zz:zz]>", via="SIP/2.0/UDP 999.1.1.1")
    AddressRedactor().redact([pk])
    assert pk.sip_contact == "<sip:a@[zz:zz]>"
    assert pk.sip_via == "SIP/2.0/UDP 999.1.1.1"


# -- PDF --------------------------------------------------------------------


def test_section_pdf_vide_sans_sip():
    assert pdf.sip_ladder_section_story([], pdf._styles()) == []
    assert pdf.sip_ladder_section_story([{"messages": []}], pdf._styles()) == []
    assert pdf.sip_ladder_section_story(None, pdf._styles()) == []


def test_cellules_pdf():
    (echelle,) = build_sip_ladders(_appel_alg(), ["A", "B", "C"])
    msgs = _par_message(echelle)
    assert pdf._sip_cell_text(msgs[("BYE", "2 BYE")], "B") == ("ABSENT", pdf._SIP_LOST_BG)
    assert pdf._sip_cell_text(msgs[("100 Trying", "1 INVITE")], "B") == ("\u2014 (saut par saut)", None)
    assert pdf._sip_cell_text(msgs[("200 OK", "1 INVITE")], "C") == ("100.0 ms ; x2 (retransmis)", pdf._SIP_RETRANS_BG)
    assert pdf._sip_cell_text(msgs[("INVITE", "1 INVITE")], "B") == (
        "2.0 ms ; reecrit : SDP, Contact",
        pdf._SIP_REWRITTEN_BG,
    )
    assert pdf._sip_cell_text(msgs[("INVITE", "1 INVITE")], "A") == ("0.0 ms", None)


def test_section_pdf_et_rapport_complet(tmp_path):
    paquets = [*_appel_alg(), _sip("A", 9.0, "INFO", cseq="3 INFO", call_id="<id&special>")]
    r = analyse({}, ["A", "B", "C"], paquets)
    story = pdf.sip_ladder_section_story(r.sip_ladders, pdf._styles())
    textes = [getattr(f, "text", "") for f in story]
    assert "Echelle SIP multi-points" in textes
    assert any("Call-ID &lt;id&amp;special&gt;" in t for t in textes)
    assert any("1 perdu(s), 1 retransmis, 1 reecrit(s)." in t for t in textes)
    sortie = tmp_path / "r.pdf"
    pdf.generate_pdf(r, str(sortie))
    assert sortie.stat().st_size > 0


def test_section_pdf_mentionne_la_troncature(monkeypatch):
    monkeypatch.setattr(sip_ladder, "MAX_MESSAGES", 1)
    echelles = build_sip_ladders(_appel_alg(), ["A", "B", "C"])
    textes = [getattr(f, "text", "") for f in pdf.sip_ladder_section_story(echelles, pdf._styles())]
    assert any("3 non represente(s)." in t for t in textes)


# -- HTML -------------------------------------------------------------------


def _doc_html(echelles):
    doc = build_json_report_document(Report(points=["A", "B", "C"]), title="T", findings=[])
    doc["sip_ladders"] = echelles
    return doc


def test_html_statique_echelle():
    (echelle,) = build_sip_ladders(_appel_alg(), ["A", "B", "C"])
    statique = re.search(r"<noscript>(.*)</noscript>", render_html_report(_doc_html([echelle])), re.S).group(1)
    assert "<h2>Echelle SIP multi-points</h2>" in statique and "<h3>Call-ID appel-1</h3>" in statique
    assert '<span class="sip-perdu">ABSENT</span>' in statique
    assert '<span class="sip-reecrit">2,0 ms ; reecrit : SDP, Contact</span>' in statique
    assert '<span class="sip-retransmis">100,0 ms ; x2 (retransmis)</span>' in statique
    assert "\u2014 (saut par saut)" in statique
    assert "4 message(s) : 1 perdu(s), 1 retransmis, 1 reecrit(s)." in statique
    assert "BYE (2 BYE)" in statique


def test_html_statique_sans_sip_et_troncature():
    labels = _labels()
    assert _static_sip({}, labels) == ""
    echelle = {
        "call_id": "<x>",
        "points": ["A"],
        "messages": [],
        "total_messages": 9,
        "truncated": 9,
        "lost": 0,
        "retransmitted": 0,
        "rewritten": 0,
    }
    statique = _static_sip({"sip_ladders": [echelle]}, labels)
    assert "Call-ID &lt;x&gt;" in statique and "9 message(s) non represente(s)." in statique
    assert "Aucun message SIP pour cet appel." in statique
    assert _sip_cell({"cells": {"A": {"rel_ms": 1.25, "count": 1}}}, "A", labels) == ("1,2 ms", "")


def _rendre(page: str):
    def brut(element_id):
        return re.search(rf'<script type="application/json" id="{element_id}">(.*?)</script>', page, re.S).group(1)

    elements = {"rapport": "", "netcross-data": brut("netcross-data"), "netcross-labels": brut("netcross-labels")}
    (script,) = re.findall(r"<script>(.*?)</script>", page, re.S)
    entree = json.dumps({"script": script, "elements": elements, "actions": []})
    sortie = subprocess.run([NODE, str(RENDU)], input=entree, capture_output=True, text=True, check=True, timeout=60)
    return json.loads(sortie.stdout)["rapport"]


def _noeuds(n, predicat, trouves=None):
    trouves = [] if trouves is None else trouves
    if predicat(n):
        trouves.append(n)
    for c in n["children"]:
        _noeuds(c, predicat, trouves)
    return trouves


def _texte(n):
    return n["text"] + "".join(_texte(c) for c in n["children"])


@avec_node
def test_html_js_echelle():
    paquets = [*_appel_alg(), _sip("B", 9.0, "INFO", cseq="3 INFO", call_id="autre")]
    echelles = build_sip_ladders(paquets, ["A", "B", "C"])
    echelles[1]["truncated"] = 2
    arbre = _rendre(render_html_report(_doc_html(echelles)))
    (section,) = _noeuds(arbre, lambda n: n["attrs"].get("id") == "echelle-sip")
    assert _texte(section).startswith("Echelle SIP multi-points")
    tables = _noeuds(section, lambda n: n["tag"] == "table")
    assert [t["attrs"]["data-call-id"] for t in tables] == ["appel-1", "autre"]
    spans = {(s["attrs"].get("class", ""), _texte(s)) for s in _noeuds(tables[0], lambda n: n["tag"] == "span")}
    assert ("sip-perdu", "ABSENT") in spans
    assert ("sip-reecrit", "2,0 ms ; reecrit : SDP, Contact") in spans
    assert ("sip-retransmis", "100,0 ms ; x2 (retransmis)") in spans
    assert ("", "\u2014 (saut par saut)") in spans
    assert ("", "0,0 ms") in spans
    resumes = [_texte(p) for p in _noeuds(section, lambda n: n["attrs"].get("class") == "sip-resume")]
    assert resumes[0] == "4 message(s) : 1 perdu(s), 1 retransmis, 1 reecrit(s)."
    assert resumes[1].endswith(" 2 message(s) non represente(s).")


@avec_node
def test_html_js_sans_sip_pas_de_section():
    arbre = _rendre(render_html_report(_doc_html([])))
    assert _noeuds(arbre, lambda n: n["attrs"].get("id") == "echelle-sip") == []
