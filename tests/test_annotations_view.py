# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_annotations_view.py -- tests du module
netcross_gtk4.annotations_view (Job 40/issue #160).

Logique de presentation pour l'etiquetage/signets sur paquets. Testable
sans display GTK : aucun import Gtk dans annotations_view.py, meme
discipline que test_stats_view.py.
"""

from __future__ import annotations

import pytest

from netcross_core.models import PacketAnnotation
from netcross_gtk4.annotations_view import (
    add_annotation,
    available_tags,
    filter_by_tags,
    format_annotation_row,
    remove_annotation,
)


def _annotations() -> list[PacketAnnotation]:
    return [
        PacketAnnotation(frame_number=1, tag="suspect", comment="retransmission"),
        PacketAnnotation(frame_number=2, tag="suspect"),
        PacketAnnotation(frame_number=3, tag="ok"),
    ]


# -- available_tags -----------------------------------------------------


def test_available_tags_triee_et_deduplique():
    assert available_tags(_annotations()) == ["ok", "suspect"]


def test_available_tags_liste_vide():
    assert available_tags([]) == []


# -- filter_by_tags -------------------------------------------------------


def test_filter_by_tags_aucun_filtre_retourne_tout():
    result = filter_by_tags(_annotations(), set())
    assert len(result) == 3


def test_filter_by_tags_filtre_un_tag():
    result = filter_by_tags(_annotations(), {"suspect"})
    assert len(result) == 2
    assert all(a.tag == "suspect" for a in result)


def test_filter_by_tags_plusieurs_tags():
    result = filter_by_tags(_annotations(), {"suspect", "ok"})
    assert len(result) == 3


def test_filter_by_tags_tag_absent_retourne_liste_vide():
    assert filter_by_tags(_annotations(), {"inconnu"}) == []


# -- format_annotation_row -------------------------------------------------


def test_format_annotation_row_avec_commentaire():
    row = format_annotation_row(PacketAnnotation(frame_number=5, tag="suspect", comment="a revoir"))
    assert row == "[suspect] trame #5 -- a revoir"


def test_format_annotation_row_sans_commentaire():
    row = format_annotation_row(PacketAnnotation(frame_number=5, tag="suspect"))
    assert row == "[suspect] trame #5"


# -- add_annotation ---------------------------------------------------------


def test_add_annotation_retourne_nouvelle_liste_sans_muter_original():
    original = _annotations()
    result = add_annotation(original, frame_number=9, tag="nouveau")
    assert len(original) == 3
    assert len(result) == 4
    assert result[-1].frame_number == 9
    assert result[-1].tag == "nouveau"


def test_add_annotation_tag_vide_leve_value_error():
    with pytest.raises(ValueError):
        add_annotation(_annotations(), frame_number=9, tag="   ")


def test_add_annotation_strip_le_tag():
    result = add_annotation([], frame_number=1, tag="  suspect  ")
    assert result[0].tag == "suspect"


# -- remove_annotation -------------------------------------------------------


def test_remove_annotation_supprime_la_bonne_entree():
    result = remove_annotation(_annotations(), frame_number=2, tag="suspect")
    assert len(result) == 2
    assert all(not (a.frame_number == 2 and a.tag == "suspect") for a in result)


def test_remove_annotation_absente_ne_leve_pas():
    result = remove_annotation(_annotations(), frame_number=999, tag="inconnu")
    assert len(result) == 3


def test_remove_annotation_ne_mute_pas_original():
    original = _annotations()
    remove_annotation(original, frame_number=2, tag="suspect")
    assert len(original) == 3
