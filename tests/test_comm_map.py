# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de netcross_report.comm_map (cartographie des communications,
issue #15) et du rendu charts.chart_comm_map.

Le coeur de ces tests n'est pas "la carte se construit" mais les deux
conventions de comptage du module, faciles a casser sans s'en apercevoir :
un paquet vu a plusieurs points ne doit pas doubler les volumes, et les
aretes restent orientees.
"""

import pytest
from conftest import make_pkt

from netcross_report.comm_map import (
    DEFAULT_TOP_N,
    available_protocols,
    build_comm_map,
    format_comm_map,
)


def _flow(*packets, cle=("TCP", "10.0.0.1", 1234, "10.0.0.2", 443)):
    """Un flux au format de correlate() : {cle: {point: [Pkt, ...]}}."""
    par_point = {}
    for pk in packets:
        par_point.setdefault(pk.point, []).append(pk)
    return {cle: par_point}


def test_carte_vide_sans_flux():
    cmap = build_comm_map({})
    assert cmap.edges == []
    assert cmap.nodes == []
    assert cmap.total_edges == 0


def test_carte_vide_si_flows_none():
    # La GUI appelle le module avant toute analyse : None doit passer.
    assert build_comm_map(None).edges == []
    assert available_protocols(None) == []


def test_une_arete_orientee_par_sens():
    flows = _flow(
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2"),
        make_pkt(point="A", src="10.0.0.2", dst="10.0.0.1"),
    )
    cmap = build_comm_map(flows)
    assert {e.label for e in cmap.edges} == {"10.0.0.1 -> 10.0.0.2", "10.0.0.2 -> 10.0.0.1"}
    # Deux aretes, mais deux hotes seulement.
    assert {n.host for n in cmap.nodes} == {"10.0.0.1", "10.0.0.2"}


def test_un_paquet_vu_a_deux_points_ne_double_pas_le_volume():
    """Convention de comptage no 1 : le volume d'une arete est celui du
    point d'observation le plus complet, jamais la somme des points.

    Contrairement au diagramme de sequence (ou chaque observation est une
    ligne, c'est tout l'interet), additionner ici les points gonflerait les
    volumes d'un facteur egal au nombre de points de capture -- et le
    graphe mentirait d'autant.
    """
    flows = _flow(
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", length=100),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", length=100),
    )
    (arete,) = build_comm_map(flows).edges
    assert arete.packets == 1
    assert arete.bytes == 100


def test_point_le_plus_complet_retenu():
    # 2 paquets vus en A, 1 seul en B (perte) : la carte doit montrer 2.
    flows = _flow(
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", length=100, frame_number=1),
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", length=100, frame_number=2),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", length=100, frame_number=3),
    )
    (arete,) = build_comm_map(flows).edges
    assert arete.packets == 2
    assert arete.bytes == 200


def test_volumes_et_protocoles_du_noeud():
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=200)]
        },
        ("UDP", "10.0.0.1", 2, "10.0.0.3", 53): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="UDP", length=80)]
        },
    }
    cmap = build_comm_map(flows)
    noeud = next(n for n in cmap.nodes if n.host == "10.0.0.1")
    assert noeud.bytes == 280
    assert noeud.protocols == {"TCP", "UDP"}
    # Noeud le plus volumineux en tete (tri par octets decroissants).
    assert cmap.nodes[0].host == "10.0.0.1"


def test_comptage_des_flux_par_arete():
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {"A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")]},
        ("TCP", "10.0.0.1", 2, "10.0.0.2", 443): {"A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")]},
    }
    (arete,) = build_comm_map(flows).edges
    assert arete.flows == 2
    assert arete.packets == 2


def test_filtre_protocole():
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP")]
        },
        ("UDP", "10.0.0.1", 2, "10.0.0.3", 53): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="UDP")]
        },
    }
    cmap = build_comm_map(flows, protocols=["UDP"])
    assert [e.label for e in cmap.edges] == ["10.0.0.1 -> 10.0.0.3"]
    # Les protocoles DISPONIBLES restent complets : la liste deroulante de
    # la GUI ne doit pas se vider a mesure qu'on filtre.
    assert cmap.protocols == ["TCP", "UDP"]


def test_filtre_protocole_au_niveau_du_paquet():
    # Un meme flux peut porter deux protocoles (tunnel, changement de
    # dissecteur) : le filtre garde les paquets, pas le flux entier.
    flows = _flow(
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100),
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TLS", length=300, frame_number=2),
    )
    (arete,) = build_comm_map(flows, protocols=["TLS"]).edges
    assert arete.packets == 1
    assert arete.bytes == 300


def test_filtre_protocole_vide_equivaut_a_tous():
    flows = _flow(make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2"))
    assert len(build_comm_map(flows, protocols=[]).edges) == 1
    assert len(build_comm_map(flows, protocols=[None]).edges) == 1


def test_top_n_garde_les_aretes_les_plus_volumineuses():
    flows = {
        ("TCP", f"10.0.0.{i}", i, "10.0.0.99", 443): {
            "A": [make_pkt(point="A", src=f"10.0.0.{i}", dst="10.0.0.99", length=i * 100)]
        }
        for i in range(1, 6)
    }
    cmap = build_comm_map(flows, top_n=2)
    assert [e.src for e in cmap.edges] == ["10.0.0.5", "10.0.0.4"]
    # total_edges reste le total AVANT filtrage : la GUI annonce "2 sur 5".
    assert cmap.total_edges == 5
    assert cmap.total_hosts == 6


def test_top_n_zero_ou_none_garde_tout():
    flows = {
        ("TCP", f"10.0.0.{i}", i, "10.0.0.99", 443): {"A": [make_pkt(point="A", src=f"10.0.0.{i}", dst="10.0.0.99")]}
        for i in range(1, 4)
    }
    assert len(build_comm_map(flows, top_n=0).edges) == 3
    assert len(build_comm_map(flows, top_n=None).edges) == 3


def test_noeuds_recalcules_apres_filtrage():
    """Un hote dont toutes les aretes ont ete filtrees disparait : un noeud
    isole laisserait croire a une communication masquee."""
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", length=900)]
        },
        ("TCP", "10.0.0.8", 2, "10.0.0.9", 443): {
            "A": [make_pkt(point="A", src="10.0.0.8", dst="10.0.0.9", length=10)]
        },
    }
    cmap = build_comm_map(flows, top_n=1)
    assert {n.host for n in cmap.nodes} == {"10.0.0.1", "10.0.0.2"}


def test_filtre_anomalies_retransmission():
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", is_retransmission=True)]
        },
        ("TCP", "10.0.0.3", 2, "10.0.0.4", 443): {"A": [make_pkt(point="A", src="10.0.0.3", dst="10.0.0.4")]},
    }
    cmap = build_comm_map(flows, only_anomalies=True)
    assert [e.label for e in cmap.edges] == ["10.0.0.1 -> 10.0.0.2"]
    assert cmap.edges[0].anomalies == 1
    assert cmap.nodes[0].anomalies == 1


def test_filtre_anomalies_expert_flags():
    flows = _flow(make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", expert_flags=("tcp.analysis.zero_window",)))
    assert len(build_comm_map(flows, only_anomalies=True).edges) == 1


def test_filtre_anomalies_peut_tout_retirer():
    flows = _flow(make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2"))
    cmap = build_comm_map(flows, only_anomalies=True)
    assert cmap.edges == []
    assert cmap.nodes == []
    # ... sans effacer le total, sinon la GUI afficherait "0 sur 0" et
    # laisserait penser qu'aucune communication n'a ete observee.
    assert cmap.total_edges == 1


def test_filtres_combines():
    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", is_retransmission=True)]
        },
        ("UDP", "10.0.0.1", 2, "10.0.0.3", 53): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="UDP", is_retransmission=True)]
        },
    }
    cmap = build_comm_map(flows, protocols=["TCP"], top_n=5, only_anomalies=True)
    assert [e.label for e in cmap.edges] == ["10.0.0.1 -> 10.0.0.2"]


def test_flux_sans_paquet_ignore():
    assert build_comm_map({("TCP", "a", 1, "b", 2): {"A": []}}).edges == []
    assert build_comm_map({("TCP", "a", 1, "b", 2): {}}).edges == []
    assert build_comm_map({("TCP", "a", 1, "b", 2): None}).edges == []


def test_determinisme_a_volume_egal():
    """Deux aretes de meme volume : l'ordre doit venir du libelle, sinon le
    graphe change d'une execution a l'autre sur la meme capture."""
    flows = {
        ("TCP", "10.0.0.9", 1, "10.0.0.2", 443): {"A": [make_pkt(point="A", src="10.0.0.9", dst="10.0.0.2")]},
        ("TCP", "10.0.0.1", 2, "10.0.0.2", 443): {"A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2")]},
    }
    labels = [e.label for e in build_comm_map(flows).edges]
    assert labels == sorted(labels)


def test_available_protocols_trie_et_dedoublonne():
    flows = {
        ("TCP", "a", 1, "b", 2): {
            "A": [make_pkt(point="A", proto="TCP"), make_pkt(point="A", proto="TCP", frame_number=2)],
            "B": [make_pkt(point="B", proto="QUIC")],
        },
        ("UDP", "a", 3, "b", 4): {"A": [make_pkt(point="A", proto="DNS")]},
    }
    assert available_protocols(flows) == ["DNS", "QUIC", "TCP"]


def test_format_comm_map_vide():
    assert "Aucune communication" in format_comm_map(build_comm_map({}))


def test_format_comm_map_annonce_le_filtrage():
    flows = {
        ("TCP", f"10.0.0.{i}", i, "10.0.0.99", 443): {
            "A": [make_pkt(point="A", src=f"10.0.0.{i}", dst="10.0.0.99", length=i * 10)]
        }
        for i in range(1, 6)
    }
    texte = format_comm_map(build_comm_map(flows, top_n=2))
    assert "2 arete(s) affichee(s) sur 5" in texte
    assert "10.0.0.5 -> 10.0.0.99" in texte


def test_format_comm_map_tronque_le_detail():
    flows = {
        ("TCP", f"10.0.0.{i}", i, "10.0.0.99", 443): {"A": [make_pkt(point="A", src=f"10.0.0.{i}", dst="10.0.0.99")]}
        for i in range(1, 8)
    }
    texte = format_comm_map(build_comm_map(flows), top_n=3)
    assert "4 arete(s) supplementaire(s)" in texte


def test_default_top_n_raisonnable():
    assert 5 <= DEFAULT_TOP_N <= 50


# --------------------------- rendu ---------------------------


def test_chart_comm_map_produit_une_image(tmp_path):
    pytest.importorskip("matplotlib")
    pytest.importorskip("networkx")
    from netcross_report.charts import chart_comm_map

    flows = {
        ("TCP", "10.0.0.1", 1, "10.0.0.2", 443): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=500)]
        },
        ("UDP", "10.0.0.1", 2, "10.0.0.3", 53): {
            "A": [make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="DNS", length=90, is_retransmission=True)]
        },
    }
    cible = tmp_path / "carte.png"
    rendu = chart_comm_map(build_comm_map(flows), str(cible))
    assert rendu == str(cible)
    assert cible.exists() and cible.stat().st_size > 0


def test_chart_comm_map_none_si_vide(tmp_path):
    pytest.importorskip("matplotlib")
    from netcross_report.charts import chart_comm_map

    cible = tmp_path / "vide.png"
    assert chart_comm_map(build_comm_map({}), str(cible)) is None
    assert chart_comm_map(None, str(cible)) is None
    # Pas d'image fantome : un PNG vide laisse en place serait affiche par
    # la GUI au lieu du message d'absence.
    assert not cible.exists()


# ------------------- integration GUI (source) -------------------
# GTK 4 n'est pas installable partout (cf. tests/test_gui_json_parity.py) :
# ces assertions verifient au niveau du SOURCE que la GUI branche bien la
# cartographie, ce qui reste utile meme quand l'import de app.py echoue.

APP_SOURCE = "src/netcross_gtk4/app.py"


def _app_source():
    with open(APP_SOURCE, encoding="utf-8") as fh:
        return fh.read()


def test_gui_expose_la_cartographie():
    src = _app_source()
    assert "comm_map_expander" in src
    assert "Cartographie des communications" in src
    assert "chart_comm_map" in src


def test_gui_branche_les_trois_filtres():
    """Les trois widgets de filtre existent et alimentent bien les trois cles
    attendues par le rendu de la carte.

    Les cles etaient cherchees comme sous-chaines litterales dans app.py.
    L'extraction de #285 (lot 3) a deplace leur construction vers
    `netcross_gtk4.panel_state.comm_map_filters`, ce qui a rendu cette
    verification fausse alors que le comportement est intact. Elle porte
    desormais sur la fonction elle-meme : c'est plus fiable qu'une recherche
    de texte, qui ne disait rien de la forme reellement produite.
    """
    src = _app_source()
    for widget in ("comm_proto_drop", "comm_topn_spin", "comm_anomalies_check"):
        assert widget in src, widget
    assert "comm_map_filters(" in src, "app.py ne construit plus les filtres"

    from netcross_gtk4.panel_state import comm_map_filters

    filtres = comm_map_filters("TLS", 15, True)
    assert set(filtres) == {"protocols", "top_n", "only_anomalies"}
    assert filtres == {"protocols": ["TLS"], "top_n": 15, "only_anomalies": True}


def test_gui_reinitialise_la_carte_apres_analyse():
    # Sans cela, une nouvelle analyse (ou une comparaison) laisserait
    # affichee la carte de la precedente.
    # Deux appels attendus : fin d'analyse simple ET fin de comparaison
    # (ou last_flows est None, ce qui desactive la vue).
    assert _app_source().count("_reset_comm_map_filters()") >= 2
