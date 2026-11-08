# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.ek_fields -- couche la plus basse, aucune connaissance
protocolaire. Couvre la normalisation couche-unique vs couche-empilee
(GRE double IP, QinQ double VLAN, MPLS empile...) et la conversion des
valeurs numeriques hex/decimal renvoyees par tshark -T ek.
"""

from pcap_parser.ek_fields import (
    all_occurrences,
    as_bool,
    as_bytes_from_hex_dump,
    as_float,
    as_int,
    expert_flag_details,
    expert_flag_names,
    g,
    has_expert_flag,
    hex_or_dec_to_int,
    innermost,
    layer,
)


def test_layer_couche_unique():
    assert layer({"ip": {"a": 1}}, "ip") == {"a": 1}


def test_layer_couche_absente():
    assert layer({}, "ip") is None


def test_layer_premiere_occurrence_sur_liste():
    assert layer({"ip": [{"a": "outer"}, {"a": "inner"}]}, "ip") == {"a": "outer"}


def test_innermost_derniere_occurrence_sur_liste():
    assert innermost({"ip": [{"a": "outer"}, {"a": "inner"}]}, "ip") == {"a": "inner"}


def test_innermost_couche_unique_identique_a_layer():
    assert innermost({"ip": {"a": 1}}, "ip") == {"a": 1}


def test_innermost_absente():
    assert innermost({}, "ip") is None


def test_all_occurrences_normalise_toujours_en_liste():
    assert all_occurrences({"vlan": {"a": 1}}, "vlan") == [{"a": 1}]
    assert all_occurrences({"vlan": [{"a": 1}, {"a": 2}]}, "vlan") == [
        {"a": 1},
        {"a": 2},
    ]


def test_all_occurrences_absente_renvoie_liste_vide():
    assert all_occurrences({}, "vlan") == []


def test_g_lit_une_cle_avec_defaut():
    assert g({"x": 1}, "x") == 1
    assert g({"x": 1}, "y") is None
    assert g({"x": 1}, "y", "defaut") == "defaut"


def test_g_sur_dict_none_renvoie_le_defaut():
    assert g(None, "x") is None
    assert g(None, "x", 42) == 42


def test_as_int_decimal_et_binaire():
    assert as_int("64") == 64
    assert as_int(64) == 64
    assert as_int("1010", base=2) == 10


def test_as_int_valeur_invalide_renvoie_none():
    assert as_int("pas-un-nombre") is None
    assert as_int(None) is None


def test_hex_or_dec_to_int_prefixe_hex():
    assert hex_or_dec_to_int("0x0800") == 0x0800
    assert hex_or_dec_to_int("0X64") == 0x64


def test_hex_or_dec_to_int_decimal_sans_prefixe():
    assert hex_or_dec_to_int("64") == 64


def test_hex_or_dec_to_int_absent():
    assert hex_or_dec_to_int(None) is None


def test_as_bool_booleen_natif():
    # format reel tshark 4.2.2 pour ip.flags.df/mf -- voir claude.md Session 9
    assert as_bool(True) is True
    assert as_bool(False) is False


def test_as_bool_absent_vaut_faux():
    assert as_bool(None) is False


def test_as_bool_tolere_une_representation_en_chaine():
    assert as_bool("1") is True
    assert as_bool("0") is False
    assert as_bool("true") is True
    assert as_bool("false") is False
    assert as_bool("") is False


def test_has_expert_flag_present_sous_ws_expert():
    # format reel tshark 4.2.2 : la cle d'expertise est niche sous
    # "_ws_expert", pas au meme niveau que les champs de protocole
    # ordinaires -- voir claude.md Session 10
    tcp_layer = {
        "tcp_tcp_srcport": "1234",
        "_ws_expert": {
            "tcp_tcp_analysis_retransmission": None,
            "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
        },
    }
    assert has_expert_flag(tcp_layer, "tcp_tcp_analysis_retransmission") is True


def test_has_expert_flag_absent():
    tcp_layer = {"tcp_tcp_srcport": "1234"}
    assert has_expert_flag(tcp_layer, "tcp_tcp_analysis_retransmission") is False


def test_has_expert_flag_sans_ws_expert_du_tout():
    tcp_layer = {"tcp_tcp_srcport": "1234", "_ws_expert": {"autre_cle": None}}
    assert has_expert_flag(tcp_layer, "tcp_tcp_analysis_retransmission") is False


def test_has_expert_flag_layer_none():
    assert has_expert_flag(None, "tcp_tcp_analysis_retransmission") is False


def test_has_expert_flag_tolere_ws_expert_en_liste():
    # plusieurs conditions d'expertise simultanees -> _ws_expert pourrait
    # devenir une liste (meme normalisation que layer()/innermost() pour
    # les couches empilees) ; pas confirme necessaire par la capture de
    # test mais gere par prudence, cout nul
    tcp_layer = {
        "_ws_expert": [
            {"tcp_tcp_checksum_bad": None},
            {"tcp_tcp_analysis_fast_retransmission": None},
        ]
    }
    assert has_expert_flag(tcp_layer, "tcp_tcp_analysis_fast_retransmission") is True
    assert has_expert_flag(tcp_layer, "tcp_tcp_analysis_spurious_retransmission") is False


def test_expert_flag_names_plusieurs_flags_tries():
    # generalisation de has_expert_flag (Session 1) : tous les noms de
    # CONDITION presents sous _ws_expert, tries, plutot qu'un seul teste
    # a la fois -- "_ws_expert__ws_expert_message" est un champ
    # descriptif generique (voir test ci-dessous), pas un troisieme nom
    # de condition, donc absent du resultat attendu.
    tcp_layer = {
        "_ws_expert": {
            "tcp_tcp_analysis_retransmission": None,
            "tcp_tcp_analysis_duplicate_ack": None,
            "_ws_expert__ws_expert_message": "peu importe pour ce test",
        }
    }
    assert expert_flag_names(tcp_layer) == (
        "tcp_tcp_analysis_duplicate_ack",
        "tcp_tcp_analysis_retransmission",
    )


def test_expert_flag_names_exclut_les_champs_meta_severite_groupe_message():
    # BUG CORRIGE dans cette session (voir claude.md Session 39) : avant
    # cette correction, les trois champs descriptifs generiques qui
    # accompagnent TOUJOURS un nom de condition (verifie empiriquement
    # avec un vrai tshark 4.2.2) remontaient comme s'ils etaient eux-memes
    # des noms de condition independants -- avec un vrai tshark, TOUT
    # signal d'expertise reel aurait donc fait remonter ces trois entrees
    # parasites en plus du vrai nom (voir build_wireshark_expert_events,
    # qui aurait alors construit un "evenement" bidon par entree parasite).
    tcp_layer = {
        "_ws_expert": {
            "tcp_tcp_analysis_retransmission": None,
            "_ws_expert__ws_expert_severity": "4194304",
            "_ws_expert__ws_expert_group": "33554432",
            "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
        }
    }
    assert expert_flag_names(tcp_layer) == ("tcp_tcp_analysis_retransmission",)


def test_expert_flag_names_absente_renvoie_tuple_vide():
    assert expert_flag_names({"tcp_tcp_srcport": "1234"}) == ()


def test_expert_flag_names_layer_none():
    assert expert_flag_names(None) == ()


def test_expert_flag_names_tolere_ws_expert_en_liste():
    # meme normalisation liste que has_expert_flag ci-dessus -- union des
    # cles de toutes les occurrences, dedupliquee et triee
    tcp_layer = {
        "_ws_expert": [
            {"tcp_tcp_checksum_bad": None},
            {"tcp_tcp_analysis_fast_retransmission": None, "tcp_tcp_checksum_bad": None},
        ]
    }
    assert expert_flag_names(tcp_layer) == ("tcp_tcp_analysis_fast_retransmission", "tcp_tcp_checksum_bad")


def test_expert_flag_names_ignore_les_elements_non_dict():
    # defensif : un _ws_expert qui ne serait ni dict ni liste de dicts
    # (jamais observe en pratique) ne doit jamais lever, juste ne rien
    # rapporter -- meme philosophie de tolerance que has_expert_flag.
    assert expert_flag_names({"_ws_expert": "texte-inattendu"}) == ()


def test_expert_flag_details_severite_et_groupe_reconnus():
    # Fixture EXACTE observee avec un vrai tshark 4.2.2 (pcap scapy
    # synthetique rejouant une vraie retransmission TCP, voir claude.md
    # Session 39) : severite/groupe sont rendus en code numerique
    # decimal, traduits ici via les tables authentiques "tshark -G
    # values" plutot que devines.
    tcp_layer = {
        "_ws_expert": {
            "tcp_tcp_analysis_retransmission": None,
            "_ws_expert__ws_expert_severity": "4194304",
            "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
            "_ws_expert__ws_expert_group": "33554432",
        }
    }
    assert expert_flag_details(tcp_layer) == (
        (
            "tcp_tcp_analysis_retransmission",
            "Note",
            "Sequence",
            "This frame is a (suspected) retransmission",
        ),
    )


def test_expert_flag_details_code_numerique_inconnu_repli_chaine_brute():
    # Code absent de _SEVERITY_LABELS/_GROUP_LABELS (nouvelle valeur
    # d'une future version de tshark, jamais rencontree ici) -- la chaine
    # brute est gardee telle quelle, jamais une supposition de libelle.
    tcp_layer = {
        "_ws_expert": {
            "tcp_tcp_analysis_retransmission": None,
            "_ws_expert__ws_expert_severity": "999",
            "_ws_expert__ws_expert_group": "888",
        }
    }
    assert expert_flag_details(tcp_layer) == (("tcp_tcp_analysis_retransmission", "999", "888", None),)


def test_expert_flag_details_message_absent():
    tcp_layer = {"_ws_expert": {"tcp_tcp_analysis_retransmission": None}}
    assert expert_flag_details(tcp_layer) == (("tcp_tcp_analysis_retransmission", None, None, None),)


def test_expert_flag_details_plusieurs_occurrences_independantes():
    # Fixture EXACTE observee avec un vrai tshark 4.2.2 (checksum TCP
    # invalide ET retransmission simultanes sur le meme paquet, voir
    # claude.md Session 39) : deux occurrences INDEPENDANTES dans la
    # liste, chacune avec sa propre severite/son propre groupe/message --
    # jamais un melange ambigu entre les deux conditions.
    tcp_layer = {
        "_ws_expert": [
            {
                "tcp_tcp_checksum_bad_expert": None,
                "_ws_expert__ws_expert_severity": "8388608",
                "_ws_expert__ws_expert_message": "Bad checksum [should be 0x8cfa]",
                "_ws_expert__ws_expert_group": "16777216",
            },
            {
                "tcp_tcp_analysis_retransmission": None,
                "_ws_expert__ws_expert_severity": "4194304",
                "_ws_expert__ws_expert_message": "This frame is a (suspected) retransmission",
                "_ws_expert__ws_expert_group": "33554432",
            },
        ]
    }
    assert expert_flag_details(tcp_layer) == (
        ("tcp_tcp_analysis_retransmission", "Note", "Sequence", "This frame is a (suspected) retransmission"),
        ("tcp_tcp_checksum_bad_expert", "Error", "Checksum", "Bad checksum [should be 0x8cfa]"),
    )


def test_expert_flag_details_absente_renvoie_tuple_vide():
    assert expert_flag_details({"tcp_tcp_srcport": "1234"}) == ()


def test_expert_flag_details_layer_none():
    assert expert_flag_details(None) == ()


def test_expert_flag_details_ignore_les_elements_non_dict():
    assert expert_flag_details({"_ws_expert": "texte-inattendu"}) == ()


def test_as_bytes_from_hex_dump_format_tshark():
    assert as_bytes_from_hex_dump("aa:bb:cc") == b"\xaa\xbb\xcc"


def test_as_bytes_from_hex_dump_vide_ou_absent():
    assert as_bytes_from_hex_dump("") == b""
    assert as_bytes_from_hex_dump(None) == b""


def test_as_bytes_from_hex_dump_invalide_ne_leve_pas():
    assert as_bytes_from_hex_dump("pas-du-hex") == b""


def test_as_float_chaine_decimale():
    # format reel tshark 4.2.2 pour http.time -- voir claude.md Session 17
    assert as_float("0.000467410") == 0.000467410
    assert as_float("0.300742305") == 0.300742305


def test_as_float_tolere_un_flottant_deja_natif():
    assert as_float(1.5) == 1.5


def test_as_float_entier():
    assert as_float("3") == 3.0


def test_as_float_absent_ou_invalide_renvoie_none():
    assert as_float(None) is None
    assert as_float("pas-un-nombre") is None
