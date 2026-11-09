# SPDX-License-Identifier: GPL-3.0-or-later
"""Constats filtrables et preuves cliquables du rapport HTML (issue #1077).

Exemple multi-constats sur trois points A -> B -> C : une conversation TCP
correlee (5 trames, la 4e perdue entre B et C), trois constats de severite,
segment et protocole differents. Le JavaScript embarque est execute sous
Node (``tests/js/rendu_headless.js``, comme #1075).
"""

from __future__ import annotations

from conftest import make_pkt
from test_html_report_chemin import _noeuds, _rendre, _texte, avec_node

from netcross_core.clock_sync import EstimationHorloge
from netcross_core.expert_model import EvidenceLink, PacketEvidence
from netcross_core.models import Report
from netcross_report import evidence_frames as ef
from netcross_report.html_report import render_html_report
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import Finding

POINTS = ["A", "B", "C"]
# Decalage au point B (horloge en avance de 5 ms) pour verifier la correction.
DECALAGE_B = 0.005


def _flows():
    """Cle -> {point: [Pkt]} : trames A 1..5, B 11..15, C 21..25 (sans la 4e)."""
    flows = {}
    for i in range(5):
        par_point = {}
        for j, point in enumerate(POINTS):
            if point == "C" and i == 3:
                continue
            ts = 10.0 + i * 0.1 + j * 0.002 + (DECALAGE_B if point == "B" else 0.0)
            par_point[point] = [
                make_pkt(point=point, ts=ts, frame_number=1 + i + 10 * j, key_id=i, flags="...A...", length=60 + i)
            ]
        flows[("k", i)] = par_point
    # Bruit d'une autre conversation au point A : jamais dans le contexte.
    flows[("autre", 0)] = {"A": [make_pkt(point="A", ts=10.15, frame_number=99, sport=5555, dport=53, proto="UDP")]}
    return flows


def _preuve(point, frame):
    return EvidenceLink(point, f"trame {frame}", packet=PacketEvidence(point, frame))


def _findings():
    return [
        Finding("anomalie", "TCP", "A -> B", "Retransmissions", evidence=[_preuve("A", 3)]),
        Finding("info", "DNS", "B", "Resolution lente"),
        Finding(
            "a_surveiller",
            "PMTUD",
            "B -> C",
            "Trou noir PMTUD",
            evidence=[_preuve("B -> C", 14), _preuve("C", 999)],
        ),
    ]


def _doc(flows=True, decalage=True, ci_ms=0.0):
    r = Report(points=list(POINTS))
    if decalage:
        r.clock_offset_estimate = {("A", "B"): EstimationHorloge(decalage_ms=DECALAGE_B * 1000.0, ic_decalage_ms=ci_ms)}
    return build_json_report_document(r, title="T", findings=_findings(), packet_flows=_flows() if flows else None)


# -- evidence_frames ----------------------------------------------------------------------------


def test_protocole_par_categorie():
    assert ef.finding_protocol("TCP") == "TCP"
    assert ef.finding_protocol("VLAN") == "802.1Q"
    assert ef.finding_protocol("PMTUD") == "ICMP"
    assert ef.finding_protocol("Pertes") == "IP"
    assert ef.finding_protocol(None) == "IP"


def test_ancre_et_point_de_capture():
    assert ef.evidence_anchor("A -> B", 3) == "preuve-A_-__B-3"
    assert ef.evidence_anchor("edge-1", 7) == "preuve-edge-1-7"
    assert ef.capture_point("A -> B") == "A"
    assert ef.capture_point("B") == "B"


def test_cle_absente_sans_packet_flows():
    assert "evidence_frames" not in _doc(flows=False)


def test_preuve_vue_a_chaque_point():
    preuves = {p["ref"]: p for p in _doc()["evidence_frames"]}
    assert list(preuves) == ["A#3", "B -> C#14", "C#999"]
    p = preuves["A#3"]
    assert p["found"] and p["point"] == "A" and p["proto"] == "TCP"
    assert p["points"] == POINTS
    assert [r["frame_number"] for r in p["rows"]] == [1, 2, 3, 4, 5]
    centre = next(r for r in p["rows"] if r["evidence"])
    assert centre["frame_number"] == 3
    assert {pt: c["frame_number"] for pt, c in centre["cells"].items()} == {"A": 3, "B": 13, "C": 23}
    assert centre["cells"]["A"]["rel_ms"] == 0.0
    perdue = p["rows"][3]
    assert set(perdue["cells"]) == {"A", "B"}
    assert "10.0.0.1:1234 -> 10.0.0.2:443 [...A...] 62 o" in centre["summary"]


def test_transit_corrige_du_decalage():
    p = _doc()["evidence_frames"][0]
    ab, bc = p["transits"]
    assert ab["segment"] == "A -> B" and ab["corrected"]
    assert ab["raw_ms"] == 7.0 and ab["transit_ms"] == 2.0
    assert bc["segment"] == "B -> C" and not bc["corrected"] and bc["transit_ms"] == bc["raw_ms"] == -3.0
    brut = _doc(decalage=False)["evidence_frames"][0]["transits"][0]
    assert not brut["corrected"] and brut["transit_ms"] == 7.0


@avec_node
def test_transit_incertain_auditable_mais_non_mesurable_dans_les_deux_rendus():
    doc = _doc(ci_ms=8.0)
    transit = doc["evidence_frames"][0]["transits"][0]
    assert transit["clock_ci_ms"] == 8.0
    assert transit["latency_measurable"] is False
    assert transit["raw_ms"] == 7.0 and transit["transit_ms"] == 2.0
    page = render_html_report(doc)
    static = page.split("<noscript>")[1].split("</noscript>")[0]
    assert "Transit A -&gt; B : latence non mesurable (IC95% 8,000 ms)" in static
    assert "Transit A -&gt; B : 2,000 ms" not in static
    _, (state,) = _rendre(page, [{"type": "clic", "attr": "data-preuve", "valeur": "A#3"}])
    assert "Transit A -> Blatence non mesurable (IC95% 8,000 ms)" in state["preuve"]
    assert "Transit A -> B2,000 ms" not in state["preuve"]
    assert "Transit B -> C-3,000 ms (non corrige" in state["preuve"]


def test_preuve_de_segment_et_preuve_introuvable():
    preuves = {p["ref"]: p for p in _doc()["evidence_frames"]}
    seg = preuves["B -> C#14"]
    assert seg["point"] == "B" and seg["anchor"] == "preuve-B_-__C-14"
    assert seg["points"] == ["A", "B"]  # trame 4 jamais vue en C
    assert preuves["C#999"] == {
        "ref": "C#999",
        "anchor": "preuve-C-999",
        "point": "C",
        "frame_number": 999,
        "found": False,
    }


def test_contexte_borne_et_limite():
    constats = [
        {
            "evidence": [
                {"point": "A", "frame_number": 3},
                {"point": "A", "frame_number": 3},
                {"point": "A", "frame_number": 1},
                {"point": None},
            ]
        }
    ]
    (seul,) = ef.build_evidence_frames(constats, _flows(), POINTS, context=1, limit=1)
    assert [r["frame_number"] for r in seul["rows"]] == [2, 3, 4]
    assert ef.build_evidence_frames([{"message": "sans preuve"}], _flows(), POINTS) == []


def test_trame_sans_numero_ignoree():
    flows = {"k": {"A": [make_pkt(point="A", frame_number=None)], "B": [make_pkt(point="B", frame_number=4)]}}
    (p,) = ef.build_evidence_frames([{"evidence": [{"point": "B", "frame_number": 4}]}], flows, POINTS)
    assert p["points"] == ["B"] and p["transits"] == []


# -- rendu statique -----------------------------------------------------------------------------


def test_rendu_statique_colonnes_et_diagrammes():
    page = render_html_report(_doc())
    statique = page.split("<noscript>")[1].split("</noscript>")[0]
    assert '<th scope="col">Protocole</th>' in statique and '<th scope="col">Preuves</th>' in statique
    assert '<a href="#preuve-A-3">A #3</a>' in statique
    assert '<a href="#preuve-B_-__C-14">B -&gt; C #14</a>' in statique
    assert "C #999" in statique and 'href="#preuve-C-999"' not in statique
    assert '<h3 id="preuve-A-3">Preuve : trame 3 au point A</h3>' in statique
    assert "Transit A -&gt; B : 2,000 ms (IC95% 0,000 ms)</li>" in statique
    assert "Transit B -&gt; C : -3,000 ms (non corrige du decalage d&#x27;horloge)" in statique
    assert "<td>non vue</td>" in statique


def test_rendu_statique_sans_preuves():
    page = render_html_report(_doc(flows=False))
    assert "Preuves vues a chaque point" not in page.split("</noscript>")[0]


def test_protocole_existant_conserve():
    doc = _doc(flows=False)
    doc["findings"][0]["protocol"] = "QUIC"
    assert '"protocol": "QUIC"' in render_html_report(doc)


# -- rendu JavaScript ---------------------------------------------------------------------------


def _lignes_visibles(arbre):
    (table,) = _noeuds(arbre, lambda n: n["attrs"].get("id") == "table-constats")
    corps = table["children"][-1]
    return [_texte(tr) for tr in corps["children"] if "hidden" not in tr["attrs"]]


@avec_node
def test_menus_de_filtre():
    arbre, _ = _rendre(render_html_report(_doc()))
    menus = {
        n["attrs"]["id"]: [o["attrs"]["value"] for o in n["children"]]
        for n in _noeuds(arbre, lambda n: n["tag"] == "select")
    }
    assert menus == {
        "filtre-severite": ["", "anomalie", "a_surveiller", "info"],
        "filtre-segment": ["", "A -> B", "B", "B -> C"],
        "filtre-protocole": ["", "DNS", "ICMP", "TCP"],
    }
    (compteur,) = _noeuds(arbre, lambda n: n["attrs"].get("id") == "compteur-constats")
    assert compteur["text"] == "3 / 3 constat(s) affiche(s)" and compteur["attrs"]["aria-live"] == "polite"


@avec_node
def test_tableaux_constats_et_preuves_defilent_dans_une_region_accessible():
    page = render_html_report(_doc())
    arbre, _ = _rendre(page, [{"type": "clic", "attr": "data-preuve", "valeur": "A#3"}])
    regions = _noeuds(arbre, lambda n: n["attrs"].get("class") == "table-defilante")
    assert len(regions) == 2
    for region in regions:
        assert region["attrs"]["role"] == "region"
        assert region["attrs"]["tabindex"] == "0"
        assert region["attrs"]["aria-label"]
        assert region["children"][0]["tag"] == "table"
    assert 'class="table-defilante" role="region"' in page.split("<noscript>")[1]


@avec_node
def test_filtres_combines():
    actions = [
        {"type": "choix", "id": "filtre-severite", "value": "anomalie"},
        {"type": "choix", "id": "filtre-protocole", "value": "DNS"},
        {"type": "choix", "id": "filtre-severite", "value": ""},
        {"type": "choix", "id": "filtre-segment", "value": "B -> C"},
        {"type": "choix", "id": "filtre-protocole", "value": ""},
    ]
    arbre, etats = _rendre(render_html_report(_doc()), actions)
    assert [e["compteur"] for e in etats] == [f"{n} / 3 constat(s) affiche(s)" for n in (1, 0, 1, 0, 1)]
    visibles = _lignes_visibles(arbre)
    assert len(visibles) == 1 and "Trou noir PMTUD" in visibles[0]


@avec_node
def test_clic_sur_une_preuve_ouvre_le_diagramme():
    actions = [
        {"type": "clic", "attr": "data-preuve", "valeur": "A#3"},
        {"type": "clic", "attr": "data-preuve", "valeur": "C#999"},
        {"type": "clic", "attr": "data-preuve", "valeur": "B -> C#14"},
    ]
    arbre, (a3, c999, seg) = _rendre(render_html_report(_doc()), actions)
    assert a3["preuve"].startswith("Preuve : trame 3 au point A")
    assert "#3 (0,000 ms)#13 (7,000 ms)#23 (4,000 ms)" in a3["preuve"]
    assert "non vue" in a3["preuve"]
    assert "Transit A -> B2,000 ms" in a3["preuve"] and "Transit B -> C-3,000 ms (non corrige" in a3["preuve"]
    assert "Trame introuvable" in c999["preuve"]
    assert seg["preuve"].startswith("Preuve : trame 14 au point B -> C")
    (detail,) = _noeuds(arbre, lambda n: n["attrs"].get("id") == "detail-preuve")
    assert detail["attrs"]["data-preuve"] == "B -> C#14" and detail["attrs"]["aria-live"] == "polite"
    (titre,) = _noeuds(detail, lambda n: n["tag"] == "h3")
    assert titre["attrs"]["id"] == "preuve-B_-__C-14"
    (centre,) = _noeuds(detail, lambda n: n["attrs"].get("class") == "trame-preuve")
    assert centre["attrs"]["aria-current"] == "true"
    presses = {
        b["attrs"]["data-preuve"]: b["attrs"]["aria-pressed"]
        for b in _noeuds(arbre, lambda n: n["tag"] == "button" and "data-preuve" in n["attrs"])
    }
    assert presses == {"A#3": "false", "B -> C#14": "true", "C#999": "false"}


@avec_node
def test_preuve_sans_diagramme_sans_packet_flows():
    arbre, (etat,) = _rendre(
        render_html_report(_doc(flows=False)), [{"type": "clic", "attr": "data-preuve", "valeur": "A#3"}]
    )
    assert "Trame introuvable" in etat["preuve"]
    (titre,) = _noeuds(arbre, lambda n: n["tag"] == "h3" and "Preuve" in _texte(n))
    assert "id" not in titre["attrs"]


@avec_node
def test_sans_constat_ni_filtre_ni_panneau():
    doc = build_json_report_document(Report(points=["A"]), title="T", findings=[], packet_flows={})
    arbre, _ = _rendre(render_html_report(doc))
    assert not _noeuds(arbre, lambda n: n["tag"] == "select")
    assert not _noeuds(arbre, lambda n: n["attrs"].get("id") == "detail-preuve")
