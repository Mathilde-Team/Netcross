# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de netcross_report.sequence_view, du diagramme matplotlib et de la
section PDF "Sequence des echanges" (Job 14/issue #11).

Le point le plus important est verifie explicitement : **un meme paquet vu
a deux points de capture produit DEUX lignes**. C'est contre-intuitif
(cela ressemble a un doublon), donc c'est exactement le genre de
comportement qu'une relecture bien intentionnee "corrige" par erreur --
d'ou un test qui le fige, avec la raison dans son nom.
"""

import pytest
from conftest import make_pkt

from netcross_report.sequence_view import (
    DEFAULT_MAX_STEPS,
    build_sequence_view,
    flow_title,
    top_flow_views,
)


def _flux_deux_points():
    """Un aller-retour vu en amont (A) puis en aval (B) : 4 lignes pour
    2 paquets physiques."""
    return {
        "A": [
            make_pkt(point="A", ts=1.000, frame_number=1, src="10.0.0.1", dst="10.0.0.2", flags="......S."),
            make_pkt(point="A", ts=1.030, frame_number=4, src="10.0.0.2", dst="10.0.0.1", flags="......SA"),
        ],
        "B": [
            make_pkt(point="B", ts=1.010, frame_number=2, src="10.0.0.1", dst="10.0.0.2", flags="......S."),
            make_pkt(point="B", ts=1.020, frame_number=3, src="10.0.0.2", dst="10.0.0.1", flags="......SA"),
        ],
    }


# -- construction de la vue ----------------------------------------------


def test_un_paquet_vu_a_deux_points_donne_deux_lignes():
    view = build_sequence_view(_flux_deux_points())
    assert len(view.steps) == 4
    assert [step.point for step in view.steps] == ["A", "B", "B", "A"]  # tri temporel, tous points confondus
    assert view.points == ["A", "B"]


def test_dates_relatives_au_premier_paquet_et_deltas_successifs():
    view = build_sequence_view(_flux_deux_points())
    assert view.steps[0].rel_ms == pytest.approx(0.0)
    assert view.steps[0].delta_ms == pytest.approx(0.0)
    assert view.steps[1].rel_ms == pytest.approx(10.0)
    assert view.steps[1].delta_ms == pytest.approx(10.0)
    assert view.steps[3].rel_ms == pytest.approx(30.0)
    assert view.steps[3].delta_ms == pytest.approx(10.0)


def test_hotes_dans_lordre_dapparition_pas_alphabetique():
    packets = {
        "A": [
            make_pkt(ts=1.0, src="10.0.0.9", dst="10.0.0.1"),
            make_pkt(ts=1.1, src="10.0.0.1", dst="10.0.0.9"),
        ]
    }
    assert build_sequence_view(packets).hosts == ["10.0.0.9", "10.0.0.1"]


def test_ordre_deterministe_a_timestamp_egal():
    packets = {
        "Z": [make_pkt(point="Z", ts=5.0, frame_number=2)],
        "A": [make_pkt(point="A", ts=5.0, frame_number=1)],
    }
    assert [s.point for s in build_sequence_view(packets).steps] == ["A", "Z"]


def test_troncature_garde_le_debut_de_lechange():
    packets = {"A": [make_pkt(ts=i / 10.0, frame_number=i) for i in range(10)]}
    view = build_sequence_view(packets, max_steps=3)
    assert [s.frame_number for s in view.steps] == [0, 1, 2]
    assert view.truncated == 7
    assert view.total_steps == 10


def test_max_steps_nul_ou_negatif_ne_tronque_pas():
    packets = {"A": [make_pkt(ts=i / 10.0) for i in range(5)]}
    assert len(build_sequence_view(packets, max_steps=0).steps) == 5
    assert build_sequence_view(packets, max_steps=0).truncated == 0


def test_vue_vide_sans_paquet():
    for entree in (None, {}, {"A": []}):
        view = build_sequence_view(entree)
        assert view.steps == [] and view.hosts == [] and view.total_steps == 0


def test_libelle_de_ligne_porte_ports_drapeaux_et_retransmission():
    packets = {"A": [make_pkt(ts=1.0, proto="TCP", sport=443, dport=51000, flags="...A..", is_retransmission=True)]}
    label = build_sequence_view(packets).steps[0].label
    assert "TCP" in label and "443->51000" in label and "[...A..]" in label and "retr." in label


def test_numero_de_trame_absent_reste_none():
    assert build_sequence_view({"A": [make_pkt(ts=1.0, frame_number=None)]}).steps[0].frame_number is None


# -- choix des flux ------------------------------------------------------


def test_top_flow_views_trie_par_volume_de_paquets():
    flows = {
        ("TCP", "a"): {"A": [make_pkt(ts=1.0)]},
        ("TCP", "b"): {"A": [make_pkt(ts=1.0), make_pkt(ts=1.1), make_pkt(ts=1.2)]},
    }
    views = top_flow_views(flows, max_flows=2)
    assert [len(v.steps) for v in views] == [3, 1]


def test_top_flow_views_respecte_la_limite_et_les_cas_vides():
    flows = {("TCP", "a"): {"A": [make_pkt(ts=1.0)]}}
    assert len(top_flow_views(flows, max_flows=1)) == 1
    assert top_flow_views(flows, max_flows=0) == []
    assert top_flow_views(None) == []


def test_titre_de_flux_lisible_et_repli_sur_la_cle():
    class _Flow:
        def __init__(self, key, endpoints=None):
            self.key = key
            self.endpoints = endpoints

    assert flow_title(_Flow(("TCP", "x"), ("10.0.0.1", "10.0.0.2"))) == "TCP 10.0.0.1 <-> 10.0.0.2"
    assert "NAT" in flow_title(_Flow(("NAT", "TCP", "h", 3)))  # cle --nat-tolerant : forme non supposee
    assert flow_title(_Flow(("TCP", "x"))) == "('TCP', 'x')"


def test_titre_utilise_pour_intituler_les_diagrammes():
    class _Flow:
        key = ("UDP", "z")
        endpoints = ("10.0.0.5", "10.0.0.6")

    flows = {("UDP", "z"): {"A": [make_pkt(ts=1.0, proto="UDP")]}}
    assert top_flow_views(flows, flow_objects=[_Flow()])[0].title == "UDP 10.0.0.5 <-> 10.0.0.6"


def test_plafond_par_defaut_documente():
    packets = {"A": [make_pkt(ts=i / 100.0) for i in range(DEFAULT_MAX_STEPS + 5)]}
    assert len(build_sequence_view(packets).steps) == DEFAULT_MAX_STEPS


# -- rendu ---------------------------------------------------------------

pdf = pytest.importorskip("netcross_report.pdf")


def test_diagramme_produit_un_png(tmp_path):
    from netcross_report.charts import chart_sequence_diagram

    out = tmp_path / "seq.png"
    assert chart_sequence_diagram(build_sequence_view(_flux_deux_points()), str(out)) == str(out)
    assert out.stat().st_size > 0


def test_diagramme_none_si_un_seul_hote(tmp_path):
    """Une fleche qui part et revient au meme hote ne dessine rien de
    lisible : mieux vaut pas d'image que du vide."""
    from netcross_report.charts import chart_sequence_diagram

    packets = {"A": [make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.1")]}
    assert chart_sequence_diagram(build_sequence_view(packets), str(tmp_path / "x.png")) is None
    assert chart_sequence_diagram(None, str(tmp_path / "y.png")) is None


def test_section_pdf_absente_sans_vue():
    assert pdf.sequence_section_story([], pdf._styles()) == []
    assert pdf.sequence_section_story([build_sequence_view({})], pdf._styles()) == []


def test_section_pdf_une_ligne_de_table_par_paquet_et_par_point():
    story = pdf.sequence_section_story([build_sequence_view(_flux_deux_points())], pdf._styles())
    table = next(f for f in story if hasattr(f, "_cellvalues"))
    assert len(table._cellvalues) == 5  # en-tete + 4 lignes
    trames = [row[0].text for row in table._cellvalues[1:]]
    assert trames == ["1", "2", "3", "4"]


def test_section_pdf_annonce_la_troncature():
    packets = {"A": [make_pkt(ts=i / 10.0, dst="10.0.0.3") for i in range(10)]}
    view = build_sequence_view(packets, max_steps=2)
    textes = [f.text for f in pdf.sequence_section_story([view], pdf._styles()) if hasattr(f, "text")]
    assert any("sur 10" in txt for txt in textes)


def test_section_pdf_sans_image_quand_le_diagramme_na_pas_ete_produit():
    """chart_sequence_diagram() peut retourner None (un seul hote) : la
    table doit rester, sans Image fantome."""
    from reportlab.platypus import Image

    view = build_sequence_view(_flux_deux_points())
    story = pdf.sequence_section_story([view], pdf._styles(), chart_paths=[None])
    assert not [f for f in story if isinstance(f, Image)]
    assert any(hasattr(f, "_cellvalues") for f in story)
