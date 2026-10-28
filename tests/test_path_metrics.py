# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de netcross_report.path_metrics et de la section PDF
"Chemin observe" (Job 16/issue #12).

Trois choses sont verifiees ici, et il faut les distinguer :

1. le REGROUPEMENT (les chiffres du tableau sont bien ceux de Report,
   avec les memes formules que la console et le triage) ;
2. l'ORDRE (les segments sortent dans l'ordre du chemin deduit, pas dans
   celui du dict) ;
3. le CLASSEMENT des degradations (pertes avant delai -- c'est une
   decision de produit, donc elle est testee explicitement).

Le rendu PDF n'est verifie que structurellement (nombre de lignes, section
absente quand il n'y a rien a dire) : reportlab produit un binaire, et
comparer des octets rendrait le test illisible au premier changement de
police.
"""

import statistics

import pytest

from netcross_core.models import Report
from netcross_report.path_metrics import (
    SegmentMetrics,
    build_path_metrics,
    degradation_summary,
    rank_path_segments,
)


def _report(points=("A", "B", "C"), pairs=(("A", "B"), ("B", "C"))):
    r = Report(points=list(points))
    r.pairs = list(pairs)
    return r


# -- regroupement --------------------------------------------------------


def test_delai_et_gigue_reprennent_les_formules_de_la_console():
    r = _report()
    delays = [10.0, 12.0, 30.0, 11.0]
    r.latency[("A", "B")] = list(delays)
    seg = build_path_metrics(r)[0]
    assert seg.samples == 4
    assert seg.delay_avg_ms == pytest.approx(statistics.mean(delays))
    assert seg.jitter_ms == pytest.approx(statistics.pstdev(delays))
    assert seg.delay_p50_ms <= seg.delay_p95_ms <= seg.delay_p99_ms
    assert seg.delay_p99_ms <= max(delays)


def test_taux_de_perte_compte_au_point_aval():
    r = _report()
    r.loss_count["B"] = 5
    r.seen_count["B"] = 200
    r.loss_count["A"] = 999  # amont : ne doit PAS remonter sur le segment A -> B
    seg = build_path_metrics(r)[0]
    assert seg.loss_count == 5
    assert seg.loss_pct == pytest.approx(2.5)


def test_metriques_non_mesurees_restent_none_et_pas_zero():
    seg = build_path_metrics(_report())[0]
    assert seg.delay_avg_ms is None
    assert seg.delay_p95_ms is None
    assert seg.jitter_ms is None
    assert seg.throughput_bps is None
    assert seg.loss_pct is None  # seen_count vide : taux indefini, pas 0%
    assert seg.loss_count == 0  # compteur, lui, vaut bien zero


def test_gigue_nulle_quand_un_seul_echantillon():
    r = _report()
    r.latency[("A", "B")] = [7.0]
    seg = build_path_metrics(r)[0]
    assert seg.jitter_ms == 0.0
    assert seg.delay_avg_ms == pytest.approx(7.0)


def test_debit_moyen_converti_en_bits_par_seconde():
    r = _report()
    r.bucket_seconds = 2.0
    r.throughput["B"] = {0: 1000, 1: 1000}  # 2000 octets sur 2 tranches de 2 s
    seg = build_path_metrics(r)[0]
    assert seg.throughput_bps == pytest.approx(2000 * 8 / 4.0)


def test_compteurs_par_segment_et_sauts_medians():
    r = _report()
    r.qos_change[("A", "B")] = 3
    r.frag_new[("A", "B")] = 2
    r.pmtud_blackhole[("A", "B")] = 1
    r.retrans["B"] = 8
    r.hop_delta[("A", "B")] = [1, 1, 5]
    r.hop_delta_outliers[("A", "B")] = 1
    seg = build_path_metrics(r)[0]
    assert (seg.dscp_changes, seg.frag_new, seg.pmtud_blackhole, seg.retrans) == (3, 2, 1, 8)
    assert seg.hops == 1  # mediane, pas moyenne : un flux ECMP ne deplace pas le chemin majoritaire
    assert seg.hop_outliers == 1


def test_libelle_identique_a_celui_des_findings():
    assert SegmentMetrics(upstream="Coeur", downstream="WAN").label == "Coeur -> WAN"


# -- ordre le long du chemin ---------------------------------------------


def test_segments_ordonnes_selon_la_topologie_deduite():
    r = _report(pairs=(("B", "C"), ("A", "B")))
    r.topology_edges = [("A", "B", {"confidence": 0.9}), ("B", "C", {"confidence": 0.8})]
    assert [seg.label for seg in build_path_metrics(r)] == ["A -> B", "B -> C"]


def test_ordre_des_pairs_conserve_sans_topologie():
    r = _report(pairs=(("B", "C"), ("A", "B")))
    assert [seg.label for seg in build_path_metrics(r)] == ["B -> C", "A -> B"]


def test_topologie_cyclique_retombe_sur_lordre_des_pairs():
    r = _report(pairs=(("B", "C"), ("A", "B")))
    r.topology_edges = [("A", "B", {}), ("B", "A", {})]
    assert [seg.label for seg in build_path_metrics(r)] == ["B -> C", "A -> B"]


def test_la_topologie_najoute_aucun_segment():
    """topology_edges peut contenir des arcs sans couple de points associe
    (deduction sans ordre fourni) : ils ne doivent pas apparaitre comme des
    lignes du tableau."""
    r = _report(pairs=(("A", "B"),))
    r.topology_edges = [("A", "B", {}), ("B", "C", {}), ("C", "D", {})]
    assert [seg.label for seg in build_path_metrics(r)] == ["A -> B"]


# -- classement des degradations -----------------------------------------


def test_les_pertes_passent_devant_le_delai():
    r = _report()
    r.latency[("A", "B")] = [500.0]  # tres lent, aucune perte
    r.loss_count["C"] = 1
    r.seen_count["C"] = 100  # 1% de perte, delai inconnu
    ranked = rank_path_segments(build_path_metrics(r))
    assert ranked[0].label == "B -> C"


def test_le_delai_p95_tranche_a_perte_egale():
    r = _report()
    r.latency[("A", "B")] = [10.0]
    r.latency[("B", "C")] = [80.0]
    ranked = rank_path_segments(build_path_metrics(r))
    assert [seg.label for seg in ranked] == ["B -> C", "A -> B"]


def test_les_segments_non_mesures_sont_exclus_du_classement():
    r = _report()
    r.latency[("A", "B")] = [10.0]
    ranked = rank_path_segments(build_path_metrics(r))
    assert [seg.label for seg in ranked] == ["A -> B"]


def test_resume_cite_le_segment_le_plus_degrade():
    r = _report()
    r.loss_count["C"] = 4
    r.seen_count["C"] = 100
    r.latency[("B", "C")] = [20.0, 40.0]
    resume = degradation_summary(build_path_metrics(r))
    assert "B -> C" in resume
    assert "4.0%" in resume


def test_resume_sans_segment_exploitable():
    r = Report(points=["A"])
    assert "topologie" in degradation_summary(build_path_metrics(r))


def test_resume_quand_rien_nest_mesurable():
    resume = degradation_summary(build_path_metrics(_report()))
    assert "Aucune metrique de qualite mesurable" in resume


# -- rendu PDF -----------------------------------------------------------

pdf = pytest.importorskip("netcross_report.pdf")


def _rows(table):
    return table._cellvalues if hasattr(table, "_cellvalues") else []


def test_section_pdf_absente_sans_segment():
    assert pdf.path_section_story([], pdf._styles()) == []


def test_section_pdf_une_ligne_par_segment():
    r = _report()
    r.latency[("A", "B")] = [10.0, 12.0]
    story = pdf.path_section_story(build_path_metrics(r), pdf._styles())
    tables = [f for f in story if hasattr(f, "_cellvalues")]
    assert len(tables) == 1
    assert len(_rows(tables[0])) == 3  # en-tete + 2 segments


def test_section_pdf_surligne_le_segment_le_plus_degrade():
    r = _report()
    r.loss_count["C"] = 9
    r.seen_count["C"] = 100
    story = pdf.path_section_story(build_path_metrics(r), pdf._styles())
    table = next(f for f in story if hasattr(f, "_cellvalues"))
    # la mise en evidence porte sur la 2e ligne de donnees (B -> C), en
    # premiere colonne, comme la colonne de gravite des autres tables
    degrade = table._cellvalues[2][0].text  # ligne 2 = B -> C
    sain = table._cellvalues[1][0].text
    assert "#b91c1c" in degrade and "<b>" in degrade
    assert "#b91c1c" not in sain


def test_formatage_des_valeurs_absentes_et_des_debits():
    assert pdf._fmt_num(None) == "\u2014"
    assert pdf._fmt_num(0.0) == "0.0"
    assert pdf._fmt_bps(None) == "\u2014"
    assert pdf._fmt_bps(999) == "999 bit/s"
    assert pdf._fmt_bps(2_500_000) == "2.50 Mbit/s"
    assert pdf._fmt_bps(3_000_000_000) == "3.00 Gbit/s"


def test_graphique_de_chemin_produit_un_fichier(tmp_path):
    from netcross_report.charts import chart_path_quality

    r = _report()
    r.latency[("A", "B")] = [10.0, 30.0]
    r.loss_count["C"] = 2
    r.seen_count["C"] = 100
    out = tmp_path / "path.png"
    assert chart_path_quality(build_path_metrics(r), str(out)) == str(out)
    assert out.stat().st_size > 0


def test_graphique_de_chemin_none_sans_segment(tmp_path):
    from netcross_report.charts import chart_path_quality

    assert chart_path_quality([], str(tmp_path / "vide.png")) is None
