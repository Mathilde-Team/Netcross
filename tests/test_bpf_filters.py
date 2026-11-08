# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de netcross_core.bpf_filters et de BPFFilter (Job 47 / issue #167) :
sauvegarde/rechargement de filtres BPF dans un fichier JSON sidecar,
catalogue de filtres predefinis, regles de nommage.

Aucun test n'ecrit dans le vrai ~/.netcross : chemins explicites sous
tmp_path, ou HOME redirige par monkeypatch pour le chemin par defaut.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from netcross_core import bpf_filters
from netcross_core.bpf_filters import (
    PREDEFINED_BPF_FILTERS,
    available_bpf_filters,
    default_bpf_filters_path,
    load_bpf_filters,
    save_bpf_filters,
    upsert_bpf_filter,
)
from netcross_core.models import BPFFilter

# -- BPFFilter ---------------------------------------------------------------


def test_bpf_filter_champs_et_description_optionnelle():
    flt = BPFFilter("web", "tcp port 80")
    assert (flt.name, flt.expression, flt.description) == ("web", "tcp port 80", "")


def test_bpf_filter_est_immuable():
    flt = BPFFilter("web", "tcp port 80", "HTTP")
    with pytest.raises(dataclasses.FrozenInstanceError):
        flt.name = "autre"  # type: ignore[misc]


@pytest.mark.parametrize("name, expression", [("", "tcp"), ("   ", "tcp"), ("web", ""), ("web", "  ")])
def test_bpf_filter_nom_et_expression_requis(name, expression):
    with pytest.raises(ValueError):
        BPFFilter(name, expression)


# -- Persistance : sauvegarder puis recharger --------------------------------


def _sample() -> list[BPFFilter]:
    return [
        BPFFilter("web interne", "tcp port 8080", "Portail interne"),
        BPFFilter("voix", "udp portrange 10000-20000"),
        BPFFilter("accents", "host 10.0.0.1", "Réseau d'accès — été"),
    ]


def test_sauvegarde_puis_rechargement_conserve_les_filtres(tmp_path):
    path = tmp_path / "bpf.json"
    save_bpf_filters(_sample(), path)
    assert load_bpf_filters(path) == _sample()


def test_persistance_survit_a_une_nouvelle_lecture_independante(tmp_path):
    """Le fichier est du JSON lisible, pas un format opaque : c'est ce qui
    rend le partage possible (copie du fichier)."""
    path = tmp_path / "bpf.json"
    save_bpf_filters(_sample(), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == 1
    assert doc["filters"][0] == {
        "name": "web interne",
        "expression": "tcp port 8080",
        "description": "Portail interne",
    }
    # ensure_ascii=False : les accents restent lisibles dans le fichier.
    assert "Réseau d'accès" in path.read_text(encoding="utf-8")


def test_sauvegarde_renvoie_le_chemin_ecrit(tmp_path):
    path = tmp_path / "bpf.json"
    assert save_bpf_filters([], path) == path


def test_sauvegarde_cree_le_dossier_parent(tmp_path):
    path = tmp_path / "nouveau" / "sous-dossier" / "bpf.json"
    save_bpf_filters(_sample(), path)
    assert path.is_file()


def test_sauvegarde_remplace_le_contenu_precedent(tmp_path):
    path = tmp_path / "bpf.json"
    save_bpf_filters(_sample(), path)
    save_bpf_filters([BPFFilter("seul", "arp")], path)
    assert load_bpf_filters(path) == [BPFFilter("seul", "arp")]


def test_sauvegarde_ne_laisse_aucun_fichier_temporaire(tmp_path):
    save_bpf_filters(_sample(), tmp_path / "bpf.json")
    assert [p.name for p in tmp_path.iterdir()] == ["bpf.json"]


def test_sauvegarde_atomique_echec_laisse_l_ancien_fichier_intact(tmp_path, monkeypatch):
    path = tmp_path / "bpf.json"
    save_bpf_filters([BPFFilter("ancien", "arp")], path)

    def boom(*_args, **_kwargs):
        raise OSError("disque plein simule")

    monkeypatch.setattr(bpf_filters.os, "replace", boom)
    with pytest.raises(OSError, match="disque plein"):
        save_bpf_filters(_sample(), path)
    monkeypatch.undo()
    assert load_bpf_filters(path) == [BPFFilter("ancien", "arp")]
    assert [p.name for p in tmp_path.iterdir()] == ["bpf.json"]  # temporaire nettoye


# -- Chargement : cas limites -------------------------------------------------


def test_chargement_fichier_absent_donne_liste_vide(tmp_path):
    assert load_bpf_filters(tmp_path / "absent.json") == []


def test_chargement_accepte_une_simple_liste(tmp_path):
    path = tmp_path / "bpf.json"
    path.write_text(json.dumps([{"name": "a", "expression": "arp"}]), encoding="utf-8")
    assert load_bpf_filters(path) == [BPFFilter("a", "arp")]


def test_chargement_description_absente_ou_nulle_donne_chaine_vide(tmp_path):
    path = tmp_path / "bpf.json"
    doc = [{"name": "a", "expression": "arp"}, {"name": "b", "expression": "icmp", "description": None}]
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert [f.description for f in load_bpf_filters(path)] == ["", ""]


def test_chargement_normalise_les_espaces_de_bordure(tmp_path):
    path = tmp_path / "bpf.json"
    path.write_text(json.dumps([{"name": " a ", "expression": " arp ", "description": " d "}]), encoding="utf-8")
    assert load_bpf_filters(path) == [BPFFilter("a", "arp", "d")]


def test_chargement_nom_en_double_garde_la_derniere_valeur_a_la_premiere_position(tmp_path):
    path = tmp_path / "bpf.json"
    doc = [
        {"name": "a", "expression": "arp"},
        {"name": "b", "expression": "icmp"},
        {"name": "A", "expression": "tcp"},
    ]
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert load_bpf_filters(path) == [BPFFilter("A", "tcp"), BPFFilter("b", "icmp")]


@pytest.mark.parametrize(
    "content, fragment",
    [
        ("{pas du json", "illisible"),
        ('{"version": 1}', "'filters' absente"),
        ('{"filters": 3}', "une liste est attendue"),
        ('"texte"', "une liste est attendue"),
        ("[42]", "entree #0: objet JSON attendu"),
        ('[{"expression": "arp"}]', "entree #0: 'name'"),
        ('[{"name": "a"}]', "entree #0: 'expression'"),
        ('[{"name": "a", "expression": "  "}]', "entree #0: 'expression'"),
        ('[{"name": 5, "expression": "arp"}]', "entree #0: 'name'"),
        ('[{"name": "a", "expression": "arp"}, {"name": "b", "expression": "tcp", "description": 1}]', "entree #1"),
    ],
)
def test_chargement_contenu_invalide_leve_valueerror_explicite(tmp_path, content, fragment):
    path = tmp_path / "bpf.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=fragment):
        load_bpf_filters(path)


def test_chargement_fichier_non_utf8_leve_valueerror(tmp_path):
    path = tmp_path / "bpf.json"
    path.write_bytes(b"\xff\xfe\x00 pas de l'utf-8")
    with pytest.raises(ValueError, match="illisible"):
        load_bpf_filters(path)


# -- Chemin par defaut ---------------------------------------------------------


def test_chemin_par_defaut_est_sous_le_dossier_utilisateur(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert default_bpf_filters_path() == tmp_path / ".netcross" / "bpf_filters.json"


def test_sans_chemin_les_fonctions_utilisent_le_chemin_par_defaut(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert load_bpf_filters() == []  # premier lancement : rien, sans erreur
    save_bpf_filters(_sample())
    assert (tmp_path / ".netcross" / "bpf_filters.json").is_file()
    assert load_bpf_filters() == _sample()


# -- Catalogue predefini --------------------------------------------------------


def test_catalogue_contient_les_filtres_de_base():
    by_name = {f.name: f for f in PREDEFINED_BPF_FILTERS}
    assert by_name["HTTP"].expression == "tcp port 80"
    assert by_name["HTTPS"].expression == "tcp port 443"
    assert by_name["DNS"].expression == "port 53"
    assert by_name["ARP"].expression == "arp"
    assert by_name["TCP (retransmissions)"].expression == "tcp"


def test_catalogue_est_bien_forme():
    names = [f.name.strip().casefold() for f in PREDEFINED_BPF_FILTERS]
    assert len(names) == len(set(names)), "noms du catalogue uniques (casse ignoree)"
    for flt in PREDEFINED_BPF_FILTERS:
        assert flt.expression == flt.expression.strip()
        assert flt.description, f"{flt.name}: une description est attendue dans le catalogue"


def test_catalogue_est_immuable():
    assert isinstance(PREDEFINED_BPF_FILTERS, tuple)


# -- available_bpf_filters -------------------------------------------------------


def test_disponibles_sans_fichier_donne_le_catalogue(tmp_path):
    assert available_bpf_filters(tmp_path / "absent.json") == list(PREDEFINED_BPF_FILTERS)


def test_disponibles_place_le_catalogue_puis_les_filtres_sauvegardes(tmp_path):
    path = tmp_path / "bpf.json"
    save_bpf_filters(_sample(), path)
    assert available_bpf_filters(path) == [*PREDEFINED_BPF_FILTERS, *_sample()]


def test_disponibles_ignore_une_entree_qui_collisionne_avec_le_catalogue(tmp_path):
    path = tmp_path / "bpf.json"
    save_bpf_filters([BPFFilter("dns", "port 5353"), BPFFilter("perso", "arp")], path)
    dispo = available_bpf_filters(path)
    assert dispo == [*PREDEFINED_BPF_FILTERS, BPFFilter("perso", "arp")]
    assert sum(1 for f in dispo if f.name.casefold() == "dns") == 1


def test_disponibles_propage_l_erreur_d_un_fichier_illisible(tmp_path):
    path = tmp_path / "bpf.json"
    path.write_text("{pas du json", encoding="utf-8")
    with pytest.raises(ValueError):
        available_bpf_filters(path)


# -- upsert_bpf_filter ------------------------------------------------------------


def test_upsert_ajoute_et_persiste(tmp_path):
    path = tmp_path / "bpf.json"
    dispo = upsert_bpf_filter(BPFFilter("perso", "host 10.0.0.1", "mon serveur"), path)
    assert dispo == [*PREDEFINED_BPF_FILTERS, BPFFilter("perso", "host 10.0.0.1", "mon serveur")]
    assert load_bpf_filters(path) == [BPFFilter("perso", "host 10.0.0.1", "mon serveur")]


def test_upsert_remplace_le_filtre_de_meme_nom_sans_tenir_compte_de_la_casse(tmp_path):
    path = tmp_path / "bpf.json"
    upsert_bpf_filter(BPFFilter("perso", "host 10.0.0.1"), path)
    upsert_bpf_filter(BPFFilter("autre", "arp"), path)
    upsert_bpf_filter(BPFFilter("  PERSO ", "host 10.0.0.2", "maj"), path)
    assert load_bpf_filters(path) == [BPFFilter("PERSO", "host 10.0.0.2", "maj"), BPFFilter("autre", "arp")]


def test_upsert_normalise_les_espaces(tmp_path):
    path = tmp_path / "bpf.json"
    upsert_bpf_filter(BPFFilter(" perso ", " arp ", " d "), path)
    assert load_bpf_filters(path) == [BPFFilter("perso", "arp", "d")]


@pytest.mark.parametrize("name", ["HTTP", "http", "  Dns ", "TCP (retransmissions)"])
def test_upsert_refuse_un_nom_reserve_au_catalogue(tmp_path, name):
    path = tmp_path / "bpf.json"
    with pytest.raises(ValueError, match="reserve"):
        upsert_bpf_filter(BPFFilter(name, "tcp port 8080"), path)
    assert not path.exists()


def test_upsert_n_ecrase_jamais_un_fichier_illisible(tmp_path):
    path = tmp_path / "bpf.json"
    path.write_text("{pas du json, mais precieux", encoding="utf-8")
    with pytest.raises(ValueError, match="illisible"):
        upsert_bpf_filter(BPFFilter("perso", "arp"), path)
    assert path.read_text(encoding="utf-8") == "{pas du json, mais precieux"


def test_partage_un_fichier_copie_est_rechargeable_ailleurs(tmp_path):
    """Partage = copier le fichier JSON : le collegue le recharge tel quel
    via un autre chemin (ou en le deposant dans son ~/.netcross)."""
    moi = tmp_path / "moi" / "bpf.json"
    lui = tmp_path / "lui" / "bpf.json"
    upsert_bpf_filter(BPFFilter("perso", "host 10.0.0.1", "mon serveur"), moi)
    lui.parent.mkdir()
    lui.write_bytes(moi.read_bytes())
    assert available_bpf_filters(lui)[-1] == BPFFilter("perso", "host 10.0.0.1", "mon serveur")
