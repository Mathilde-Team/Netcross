# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_gtk4.live_capture_points -- eclatement d'une ligne du panneau de
capture live en un point par interface (Job 48, issue #168).

Module sans GTK : teste ici sans interface graphique, comme stats_view.py.
"""

import pytest

from netcross_gtk4.live_capture_points import duplicate_labels, expand_live_points, split_interfaces


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("eth0", ["eth0"]),
        ("eth0, eth1", ["eth0", "eth1"]),
        ("eth0,eth1,eth2", ["eth0", "eth1", "eth2"]),
        ("eth0;eth1", ["eth0", "eth1"]),
        ("  eth0 ,, eth1 , ", ["eth0", "eth1"]),  # entrees vides et espaces ignores
        ("eth1, eth0, eth1", ["eth1", "eth0"]),  # doublon retire, premier ordre conserve
        ("Wi-Fi 2, eth0", ["Wi-Fi 2", "eth0"]),  # l'espace n'est pas un separateur
        ("", []),
        ("   ", []),
        (",;", []),
    ],
)
def test_split_interfaces(text, expected):
    assert split_interfaces(text) == expected


def test_expand_une_interface_conserve_le_nom_de_la_ligne():
    # comportement historique : rien ne change pour une ligne a une interface
    assert expand_live_points([("LAN", "eth0", None)]) == [("LAN", "eth0", None)]
    assert expand_live_points([("LAN", "  eth0  ", "tcp")]) == [("LAN", "eth0", "tcp")]


def test_expand_plusieurs_interfaces_donne_un_point_par_interface():
    assert expand_live_points([("GW", "eth0, eth1", "tcp")]) == [
        ("GW:eth0", "eth0", "tcp"),
        ("GW:eth1", "eth1", "tcp"),
    ]


def test_expand_conserve_l_ordre_des_lignes_puis_des_interfaces():
    rows = [("LAN", "eth0", None), ("GW", "eth2, eth1", None), ("WAN", "eth3", "udp")]
    assert expand_live_points(rows) == [
        ("LAN", "eth0", None),
        ("GW:eth2", "eth2", None),
        ("GW:eth1", "eth1", None),
        ("WAN", "eth3", "udp"),
    ]


def test_expand_ligne_sans_interface_reste_signalable_comme_manquante():
    # l'appelant (GUI) detecte "interface manquante" sur interface vide
    assert expand_live_points([("LAN", "  ", None), ("WAN", ",;", "tcp")]) == [
        ("LAN", "", None),
        ("WAN", "", "tcp"),
    ]


def test_expand_interface_repetee_dans_une_ligne_ne_cree_pas_de_second_point():
    assert expand_live_points([("A", "eth0, eth0", None)]) == [("A", "eth0", None)]


def test_expand_ne_modifie_pas_son_entree():
    rows = [("GW", "eth0, eth1", None)]
    expand_live_points(rows)
    assert rows == [("GW", "eth0, eth1", None)]


def test_duplicate_labels_aucun_doublon():
    assert duplicate_labels([("LAN", "eth0", None), ("WAN", "eth1", None)]) == []
    assert duplicate_labels([]) == []


def test_duplicate_labels_trie_sans_repetition():
    points = [("WAN", "a", None), ("LAN", "b", None), ("WAN", "c", None), ("LAN", "d", None), ("WAN", "e", None)]
    assert duplicate_labels(points) == ["LAN", "WAN"]


def test_duplicate_labels_detecte_une_collision_apres_eclatement():
    # la ligne "A" a deux interfaces produit "A:eth0", que la ligne "A:eth0" usurpe
    points = expand_live_points([("A", "eth0, eth1", None), ("A:eth0", "eth2", None)])
    assert duplicate_labels(points) == ["A:eth0"]
