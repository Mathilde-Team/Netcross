# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.wireshark_expert -- build_wireshark_expert_events() (Session 1,
FEATURES.md section 13.3 : "exploitation de l'expertise Wireshark/TShark").
Verifie le regroupement par (point, flag), le plafond d'exemples, la table
de severite de repli, la restauration du nom de champ tshark lisible, la
priorite de la severite NATIVE tshark sur cette table quand elle est
disponible (second lot de la Session 1, voir claude.md Session 39), que
source/cause/impact respectent le contrat documente sur ExpertEvent (voir
test_expert_model.py pour le contrat generique, ce fichier ne teste que ce
que build_wireshark_expert_events() ajoute par-dessus), confidence/
first_seen/last_seen (Session 40), layer/protocol (Session 41, lus
depuis le prefixe du nom de flag EK brut -- voir
_layer_and_protocol_for), flow_keys (Session 43, troisieme lot de la
Session 2, calcule via netcross_core.correlate.flow_key() sur TOUTES
les occurrences, dedoublonne dans l'ordre de premiere rencontre),
packet_evidence (Session 44, quatrieme lot de la Session 2, un
PacketEvidence par occurrence avec frame_number disponible, sur TOUTES
les occurrences, pas seulement les exemples plafonnes) et remediation
(Session 45, cinquieme et dernier lot de la Session 2, texte redige lu
depuis _REMEDIATION pour les onze flags connus de _KNOWN_FLAGS, None
pour tout flag absent de cette table).
"""

from conftest import make_pkt

from netcross_core.expert_model import PacketEvidence
from netcross_core.wireshark_expert import build_wireshark_expert_events


def test_build_wireshark_expert_events_liste_vide_sans_signal():
    pkts = [make_pkt(point="A"), make_pkt(point="A")]  # expert_flags=() par defaut, voir conftest
    assert build_wireshark_expert_events(pkts) == []


def test_build_wireshark_expert_events_un_evenement_par_point_et_flag():
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_duplicate_ack",)) for _ in range(3)]
    events = build_wireshark_expert_events(pkts)
    assert len(events) == 1
    assert "3 occurrence(s)" in events[0].message


def test_build_wireshark_expert_events_regroupe_par_point_distinct():
    pkts = [
        make_pkt(point="A", expert_flags=("tcp_tcp_analysis_duplicate_ack",)),
        make_pkt(point="B", expert_flags=("tcp_tcp_analysis_duplicate_ack",)),
    ]
    events = build_wireshark_expert_events(pkts)
    assert {ev.segment for ev in events} == {"A", "B"}
    assert len(events) == 2


def test_build_wireshark_expert_events_flags_distincts_meme_point():
    pkts = [
        make_pkt(point="A", expert_flags=("tcp_tcp_analysis_duplicate_ack",)),
        make_pkt(point="A", expert_flags=("tcp_tcp_analysis_window_full",)),
    ]
    events = build_wireshark_expert_events(pkts)
    assert len(events) == 2
    assert all(ev.segment == "A" for ev in events)


def test_build_wireshark_expert_events_un_paquet_peut_porter_plusieurs_flags():
    # RawPacket.expert_flags est un tuple qui peut porter plusieurs noms
    # simultanement (voir test_packet.py) -- chacun doit produire son
    # propre ExpertEvent, pas seulement le premier.
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_duplicate_ack", "tcp_tcp_analysis_window_full"))]
    events = build_wireshark_expert_events(pkts)
    labels = {ev.message.split(" : ")[0] for ev in events}
    assert labels == {"tcp.analysis.duplicate_ack", "tcp.analysis.window_full"}


def test_build_wireshark_expert_events_severite_connue():
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_lost_segment",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "anomalie"


def test_build_wireshark_expert_events_severite_par_defaut_si_flag_inconnu():
    # tshark introduit regulierement de nouveaux noms de champ d'expertise
    # au fil de ses versions -- jamais surestimer une severite non
    # confirmee (voir docstring _KNOWN_FLAGS).
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_un_flag_futur_inconnu",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "info"


def test_build_wireshark_expert_events_flag_inconnu_garde_le_nom_ek_brut():
    # Un flag absent de _KNOWN_FLAGS n'a pas de libelle fiable a
    # reconstruire (voir docstring de module -- une reconstruction
    # algorithmique generique s'est averee fausse dans le cas general) :
    # le nom EK brut est affiche tel quel, jamais devine.
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_un_flag_futur_inconnu",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.message.startswith("tcp_tcp_analysis_un_flag_futur_inconnu : ")


def test_build_wireshark_expert_events_categorie_wireshark_tshark():
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.category == "Wireshark/TShark"


def test_build_wireshark_expert_events_source_toujours_tshark():
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.source == "tshark"


def test_build_wireshark_expert_events_cause_impact_toujours_none():
    # Meme contrat que tout ExpertEvent (voir test_expert_model.py) :
    # aucune correlation, aucune deduction faite ici.
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.cause is None
    assert ev.impact is None


def test_build_wireshark_expert_events_label_restaure_les_points():
    # "tcp_tcp_analysis_fast_retransmission" (nom de champ EK) ->
    # "tcp.analysis.fast_retransmission" (nom de champ tshark lisible)
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_fast_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.message.startswith("tcp.analysis.fast_retransmission : ")


def test_build_wireshark_expert_events_evidence_plafonnee_a_cinq_exemples():
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(7)]
    ev = build_wireshark_expert_events(pkts)[0]
    assert len(ev.evidence) == 5
    assert "7 occurrence(s)" in ev.message


def test_build_wireshark_expert_events_evidence_porte_le_packet_evidence_si_frame_number():
    pkt = make_pkt(point="A", frame_number=42, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.evidence[0].packet == PacketEvidence(point="A", frame_number=42)


def test_build_wireshark_expert_events_evidence_packet_none_si_frame_number_absent():
    pkt = make_pkt(point="A", frame_number=None, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.evidence[0].packet is None


def test_build_wireshark_expert_events_evidence_mentionne_src_dst():
    pkt = make_pkt(
        point="A",
        src="10.0.0.5",
        dst="10.0.0.9",
        sport=1111,
        dport=443,
        expert_flags=("tcp_tcp_analysis_retransmission",),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert "10.0.0.5:1111" in ev.evidence[0].text
    assert "10.0.0.9:443" in ev.evidence[0].text


# --- Severite/groupe/message natifs (second lot de la Session 1, voir
# claude.md Session 39) --------------------------------------------------


def test_build_wireshark_expert_events_severite_native_prioritaire_sur_la_table():
    # Flag ABSENT de _KNOWN_FLAGS (severite de repli "info" par defaut) --
    # une severite native "Error" doit neanmoins produire "anomalie" : la
    # native prime sur le repli des qu'elle est disponible.
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_checksum_bad_expert",),
        expert_details=(("tcp_tcp_checksum_bad_expert", "Error", "Checksum", "Bad checksum [should be 0x8cfa]"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "anomalie"


def test_build_wireshark_expert_events_severite_native_ecrase_la_table_meme_flag_connu():
    # Ici le flag EST connu de _KNOWN_FLAGS (severite de table
    # "a_surveiller"), mais la severite native ("Error") doit tout de
    # meme l'emporter -- la native est toujours prioritaire, jamais
    # seulement un repli pour les flags inconnus.
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_spurious_retransmission",),
        expert_details=(("tcp_tcp_analysis_spurious_retransmission", "Error", "Sequence", "peu importe"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "anomalie"


def test_build_wireshark_expert_events_severite_repli_table_si_pas_de_detail_natif():
    # Regression explicite : sans expert_details (paquet d'avant cette
    # session, ou make_pkt() par defaut), le comportement precedent
    # (table _KNOWN_FLAGS) est inchange.
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_lost_segment",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "anomalie"


def test_build_wireshark_expert_events_severite_native_note_chat_comment_vers_info():
    # Flag choisi CONNU de _KNOWN_FLAGS avec une severite de repli
    # DIFFERENTE ("a_surveiller") -- pour que le resultat "info" prouve
    # bien que la valeur NATIVE a ete utilisee, plutot que de coincider
    # par hasard avec le repli (qui donnerait aussi "info" pour un flag
    # inconnu, ce qui ne distinguerait pas les deux chemins).
    for native in ("Note", "Chat", "Comment"):
        pkt = make_pkt(
            point="A",
            expert_flags=("tcp_tcp_analysis_spurious_retransmission",),
            expert_details=(("tcp_tcp_analysis_spurious_retransmission", native, "Sequence", "peu importe"),),
        )
        ev = build_wireshark_expert_events([pkt])[0]
        assert ev.severity == "info", native


def test_build_wireshark_expert_events_evidence_inclut_le_message_natif():
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_retransmission",),
        expert_details=(
            (
                "tcp_tcp_analysis_retransmission",
                "Note",
                "Sequence",
                "This frame is a (suspected) retransmission",
            ),
        ),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert "This frame is a (suspected) retransmission" in ev.evidence[0].text
    # le format precedent (adresses + libelle) reste present, enrichi --
    # pas remplace.
    assert "tcp.analysis.retransmission" in ev.evidence[0].text


def test_build_wireshark_expert_events_message_agrege_inchange_par_le_natif():
    # Le message NATIF (potentiellement parametre par paquet, voir
    # docstring de module) va dans l'evidence, jamais dans le message
    # agrege -- qui reste construit a partir du seul nom de flag, comme
    # avant cette session (voir test_..._label_restaure_les_points
    # ci-dessus, qui verifie deja ce prefixe sans expert_details).
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_fast_retransmission",),
        expert_details=(("tcp_tcp_analysis_fast_retransmission", "Note", "Sequence", "un message natif"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.message.startswith("tcp.analysis.fast_retransmission : ")


def test_build_wireshark_expert_events_message_agrege_mentionne_le_groupe_natif():
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_retransmission",),
        expert_details=(
            ("tcp_tcp_analysis_retransmission", "Note", "Sequence", "This frame is a (suspected) retransmission"),
        ),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert "[groupe tshark : Sequence]" in ev.message


def test_build_wireshark_expert_events_sans_detail_natif_evidence_et_message_inchanges():
    # Regression explicite (egalite stricte, pas seulement "in") : sans
    # expert_details, ni l'evidence ni le message agrege ne gagnent de
    # texte supplementaire.
    pkt = make_pkt(
        point="A",
        src="10.0.0.5",
        dst="10.0.0.9",
        sport=1111,
        dport=443,
        expert_flags=("tcp_tcp_analysis_retransmission",),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.evidence[0].text == "10.0.0.5:1111 -> 10.0.0.9:443 (tcp.analysis.retransmission)"
    assert ev.message == (
        "tcp.analysis.retransmission : 1 occurrence(s) (signal brut tshark, pas un diagnostic Netcross)"
    )


# -- confiance / premiere-derniere occurrence (Session 40, premier lot
# de la Session 2 de FEATURES.md section 13.3) --------------------------


def test_build_wireshark_expert_events_confidence_maximale_si_severite_native():
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_checksum_bad_expert",),
        expert_details=(("tcp_tcp_checksum_bad_expert", "Error", "Checksum", "peu importe"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.confidence == 1.0


def test_build_wireshark_expert_events_confidence_intermediaire_si_flag_connu_sans_natif():
    # Flag present dans _KNOWN_FLAGS mais aucun expert_details -- table
    # de repli maintenue a la main par ce projet, jamais confirmee tshark.
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_lost_segment",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.confidence == 0.7


def test_build_wireshark_expert_events_confidence_basse_si_flag_inconnu_sans_natif():
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_un_flag_futur_inconnu",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.confidence == 0.4


def test_build_wireshark_expert_events_confidence_native_prime_meme_flag_connu():
    # Le flag EST connu de _KNOWN_FLAGS (donnerait 0.7 par defaut), mais
    # une severite native disponible doit tout de meme produire 1.0 --
    # meme priorite que pour la severite elle-meme (voir tests plus haut).
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_lost_segment",),
        expert_details=(("tcp_tcp_analysis_lost_segment", "Warning", "Sequence", "peu importe"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.confidence == 1.0


def test_build_wireshark_expert_events_first_seen_last_seen_un_seul_paquet():
    pkt = make_pkt(point="A", ts=100.5, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.first_seen == 100.5
    assert ev.last_seen == 100.5


def test_build_wireshark_expert_events_first_seen_last_seen_plusieurs_paquets():
    pkts = [make_pkt(point="A", ts=t, expert_flags=("tcp_tcp_analysis_retransmission",)) for t in (5.0, 1.0, 3.0)]
    ev = build_wireshark_expert_events(pkts)[0]
    assert ev.first_seen == 1.0
    assert ev.last_seen == 5.0


def test_build_wireshark_expert_events_first_seen_last_seen_couvrent_toutes_les_occurrences():
    # Au-dela de _MAX_EXAMPLES (5) : first_seen/last_seen doivent rester
    # exacts sur la TOTALITE des occurrences, pas seulement les exemples
    # plafonnes conserves dans evidence.
    pkts = [make_pkt(point="A", ts=float(i), expert_flags=("tcp_tcp_analysis_retransmission",)) for i in range(7)]
    ev = build_wireshark_expert_events(pkts)[0]
    assert len(ev.evidence) == 5
    assert ev.first_seen == 0.0
    assert ev.last_seen == 6.0


def test_build_wireshark_expert_events_first_seen_last_seen_independants_par_point_et_flag():
    pkts = [
        make_pkt(point="A", ts=1.0, expert_flags=("tcp_tcp_analysis_retransmission",)),
        make_pkt(point="B", ts=99.0, expert_flags=("tcp_tcp_analysis_retransmission",)),
    ]
    events = build_wireshark_expert_events(pkts)
    by_segment = {ev.segment: ev for ev in events}
    assert by_segment["A"].first_seen == 1.0
    assert by_segment["B"].first_seen == 99.0


def test_build_wireshark_expert_events_detail_natif_pour_un_autre_flag_est_ignore():
    # Defensif : expert_details ne portant AUCUNE entree pour le flag
    # traite ici (nom different) -- doit se comporter comme si
    # expert_details etait vide pour ce flag, pas planter ni confondre.
    pkt = make_pkt(
        point="A",
        expert_flags=("tcp_tcp_analysis_retransmission",),
        expert_details=(("un_autre_flag_sans_rapport", "Error", "Checksum", "sans rapport"),),
    )
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.severity == "info"  # repli table _KNOWN_FLAGS (retransmission connue "info")
    assert "sans rapport" not in ev.evidence[0].text


# -- layer/protocol (Session 41, deuxieme lot de la Session 2 de
# FEATURES.md section 13.3) ---------------------------------------------


def test_build_wireshark_expert_events_layer_protocol_tcp():
    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "transport"
    assert ev.protocol == "TCP"


def test_build_wireshark_expert_events_layer_protocol_udp():
    pkt = make_pkt(point="A", expert_flags=("udp_udp_checksum_bad",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "transport"
    assert ev.protocol == "UDP"


def test_build_wireshark_expert_events_layer_protocol_ip():
    pkt = make_pkt(point="A", expert_flags=("ip_ip_checksum_bad",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "reseau"
    assert ev.protocol == "IPv4"


def test_build_wireshark_expert_events_layer_protocol_ipv6():
    pkt = make_pkt(point="A", expert_flags=("ipv6_ipv6_hopopts_not_implemented",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "reseau"
    assert ev.protocol == "IPv6"


def test_build_wireshark_expert_events_layer_protocol_icmp():
    pkt = make_pkt(point="A", expert_flags=("icmp_icmp_undecoded",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "reseau"
    assert ev.protocol == "ICMP"


def test_build_wireshark_expert_events_layer_protocol_icmpv6():
    pkt = make_pkt(point="A", expert_flags=("icmpv6_icmpv6_undecoded",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "reseau"
    assert ev.protocol == "ICMPv6"


def test_build_wireshark_expert_events_layer_protocol_arp():
    pkt = make_pkt(point="A", expert_flags=("arp_arp_duplicate_address_detected",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "liaison"
    assert ev.protocol == "ARP"


def test_build_wireshark_expert_events_layer_protocol_stp():
    pkt = make_pkt(point="A", expert_flags=("stp_stp_flags_tc",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer == "liaison"
    assert ev.protocol == "STP"


def test_build_wireshark_expert_events_layer_protocol_prefixe_inconnu_none():
    # Defensif : un prefixe qui ne correspond a aucune des huit cles EK
    # connues (ne devrait jamais arriver en pratique, voir docstring de
    # _layer_and_protocol_for) -- repli (None, None), jamais une
    # supposition.
    pkt = make_pkt(point="A", expert_flags=("dtls_dtls_unknown_flag",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.layer is None
    assert ev.protocol is None


def test_build_wireshark_expert_events_layer_protocol_constants_par_point_et_flag():
    # Meme (point, flag) sur plusieurs paquets -- layer/protocol ne
    # varient pas d'un exemple a l'autre (proprietes du flag lui-meme,
    # pas du paquet).
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(3)]
    ev = build_wireshark_expert_events(pkts)[0]
    assert ev.layer == "transport"
    assert ev.protocol == "TCP"


# -- flow_keys (Session 43, troisieme lot de la Session 2 de FEATURES.md
# section 13.3) ----------------------------------------------------------


def test_build_wireshark_expert_events_flow_keys_un_seul_flux():
    from netcross_core.correlate import flow_key

    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.flow_keys == [flow_key(pkt)]


def test_build_wireshark_expert_events_flow_keys_dedoublonnes_meme_flux():
    # Trois paquets du meme flux (memes src/sport/dst/dport/key_id) -- un
    # seul flow_key, pas trois, meme si le compteur d'occurrences (message)
    # reste bien 3.
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(3)]
    ev = build_wireshark_expert_events(pkts)[0]
    assert len(ev.flow_keys) == 1
    assert "3 occurrence(s)" in ev.message


def test_build_wireshark_expert_events_flow_keys_plusieurs_flux_distincts():
    from netcross_core.correlate import flow_key

    pkt1 = make_pkt(point="A", sport=1111, expert_flags=("tcp_tcp_analysis_retransmission",))
    pkt2 = make_pkt(point="A", sport=2222, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt1, pkt2])[0]
    assert ev.flow_keys == [flow_key(pkt1), flow_key(pkt2)]


def test_build_wireshark_expert_events_flow_keys_au_dela_du_plafond_exemples():
    # flow_keys est calcule sur TOUTES les occurrences, pas seulement les
    # _MAX_EXAMPLES premieres conservees dans evidence -- un flux qui
    # n'apparait que dans le dernier paquet (au-dela du plafond) doit
    # quand meme figurer dans flow_keys.
    from netcross_core.correlate import flow_key
    from netcross_core.wireshark_expert import _MAX_EXAMPLES

    pkts = [
        make_pkt(point="A", sport=1000 + i, expert_flags=("tcp_tcp_analysis_retransmission",))
        for i in range(_MAX_EXAMPLES + 2)
    ]
    ev = build_wireshark_expert_events(pkts)[0]
    assert len(ev.evidence) == _MAX_EXAMPLES
    assert flow_key(pkts[-1]) in ev.flow_keys
    assert len(ev.flow_keys) == _MAX_EXAMPLES + 2


def test_build_wireshark_expert_events_flow_keys_vide_par_defaut_source_netcross():
    from netcross_report.expert_events import build_expert_events

    class FauxFinding:
        def __init__(self):
            self.category = "Pertes"
            self.severity = "anomalie"
            self.segment = "A -> B"
            self.message = "20% de pertes"
            self.evidence = []

    ev = build_expert_events([FauxFinding()])[0]
    assert ev.source == "netcross"
    assert ev.flow_keys == []


# -- packet_evidence (Session 44, quatrieme lot de la Session 2 de
# FEATURES.md section 13.3) -----------------------------------------------


def test_build_wireshark_expert_events_packet_evidence_un_seul_paquet():
    pkt = make_pkt(point="A", frame_number=7, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.packet_evidence == [PacketEvidence(point="A", frame_number=7)]


def test_build_wireshark_expert_events_packet_evidence_au_dela_du_plafond_exemples():
    # packet_evidence est calcule sur TOUTES les occurrences, pas
    # seulement les _MAX_EXAMPLES premieres conservees dans evidence -- un
    # paquet au-dela du plafond doit quand meme y figurer.
    from netcross_core.wireshark_expert import _MAX_EXAMPLES

    pkts = [
        make_pkt(point="A", frame_number=100 + i, expert_flags=("tcp_tcp_analysis_retransmission",))
        for i in range(_MAX_EXAMPLES + 2)
    ]
    ev = build_wireshark_expert_events(pkts)[0]
    assert len(ev.evidence) == _MAX_EXAMPLES
    assert len(ev.packet_evidence) == _MAX_EXAMPLES + 2
    assert PacketEvidence(point="A", frame_number=100 + _MAX_EXAMPLES + 1) in ev.packet_evidence


def test_build_wireshark_expert_events_packet_evidence_absent_si_frame_number_absent():
    # Meme garde defensive que EvidenceLink.packet : un Pkt sans
    # frame_number (ancien format) ne doit pas produire de PacketEvidence
    # invente.
    pkt = make_pkt(point="A", frame_number=None, expert_flags=("tcp_tcp_analysis_retransmission",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.packet_evidence == []


def test_build_wireshark_expert_events_packet_evidence_independant_par_point_et_flag():
    pkt_a = make_pkt(point="A", frame_number=1, expert_flags=("tcp_tcp_analysis_retransmission",))
    pkt_b = make_pkt(point="B", frame_number=1, expert_flags=("tcp_tcp_analysis_retransmission",))
    events = build_wireshark_expert_events([pkt_a, pkt_b])
    by_point = {ev.segment: ev for ev in events}
    assert by_point["A"].packet_evidence == [PacketEvidence(point="A", frame_number=1)]
    assert by_point["B"].packet_evidence == [PacketEvidence(point="B", frame_number=1)]


def test_build_wireshark_expert_events_packet_evidence_vide_par_defaut_source_netcross():
    from netcross_report.expert_events import build_expert_events

    class FauxFinding:
        def __init__(self):
            self.category = "Pertes"
            self.severity = "anomalie"
            self.segment = "A -> B"
            self.message = "20% de pertes"
            self.evidence = []

    ev = build_expert_events([FauxFinding()])[0]
    assert ev.source == "netcross"
    assert ev.packet_evidence == []


# -- remediation (Session 45, cinquieme et dernier lot de la Session 2 de
# FEATURES.md section 13.3) -----------------------------------------------


def test_build_wireshark_expert_events_remediation_flag_connu():
    from netcross_core.wireshark_expert import _REMEDIATION

    pkt = make_pkt(point="A", expert_flags=("tcp_tcp_analysis_zero_window",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.remediation == _REMEDIATION["tcp_tcp_analysis_zero_window"]


def test_build_wireshark_expert_events_remediation_none_si_flag_inconnu():
    # Meme discipline defensive que _flag_label/_flag_severity : un flag
    # jamais repertorie n'a pas de piste de verification inventee.
    pkt = make_pkt(point="A", expert_flags=("tcp_un_flag_jamais_vu",))
    ev = build_wireshark_expert_events([pkt])[0]
    assert ev.remediation is None


def test_build_wireshark_expert_events_remediation_couvre_les_onze_flags_connus():
    # Chaque flag deja repertorie dans _KNOWN_FLAGS doit produire un
    # texte de remediation non vide -- aucun oubli silencieux.
    from netcross_core.wireshark_expert import _KNOWN_FLAGS

    for flag_name in _KNOWN_FLAGS:
        pkt = make_pkt(point="A", expert_flags=(flag_name,))
        ev = build_wireshark_expert_events([pkt])[0]
        assert ev.remediation, f"remediation manquante pour {flag_name}"


def test_build_wireshark_expert_events_remediation_constante_par_point_et_flag():
    # Meme (point, flag) sur plusieurs paquets -- remediation ne varie
    # pas d'un exemple a l'autre (propriete du flag lui-meme, comme
    # layer/protocol).
    pkts = [make_pkt(point="A", expert_flags=("tcp_tcp_analysis_retransmission",)) for _ in range(3)]
    ev = build_wireshark_expert_events(pkts)[0]
    from netcross_core.wireshark_expert import _REMEDIATION

    assert ev.remediation == _REMEDIATION["tcp_tcp_analysis_retransmission"]


def test_build_wireshark_expert_events_remediation_none_par_defaut_source_netcross():
    from netcross_report.expert_events import build_expert_events

    class FauxFinding:
        def __init__(self):
            self.category = "Pertes"
            self.severity = "anomalie"
            self.segment = "A -> B"
            self.message = "20% de pertes"
            self.evidence = []

    ev = build_expert_events([FauxFinding()])[0]
    assert ev.source == "netcross"
    assert ev.remediation is None
