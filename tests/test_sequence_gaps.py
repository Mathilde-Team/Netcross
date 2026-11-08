# SPDX-License-Identifier: GPL-3.0-or-later
"""
Job 42 (issue #162) -- detection des trous de sequence TCP.

Couvre : le suivi des numeros de sequence par connexion et par point
(netcross_core.forensic.detect_sequence_gaps), la classification
capture/reseau/indetermine d'apres les ACK du recepteur, l'alimentation de
Report.sequence_gaps par analyse(), la section "Integrite de capture" du
rapport texte et la lecture de tcp.len par le parseur (RawPacket.tcp_len ->
Pkt.tcp_len), indispensable pour calculer le numero de sequence attendu.
"""

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.forensic import detect_sequence_gaps
from netcross_core.models import (
    SEQ_GAP_CAPTURE_DROP,
    SEQ_GAP_INDETERMINATE,
    SEQ_GAP_NETWORK_LOSS,
    SequenceGap,
)
from netcross_core.parsing import _to_pkt
from netcross_core.report_text import print_report
from pcap_parser.packet import build_packet

C, S = "10.0.0.1", "10.0.0.2"


def _seg(seq, length, ts, *, flags="A", point="A", sport=40000, frame=None):
    """Segment client -> serveur : le sens suivi par detect_sequence_gaps."""
    return make_pkt(
        point=point,
        proto="TCP",
        src=C,
        dst=S,
        sport=sport,
        dport=443,
        seq=seq,
        tcp_len=length,
        flags=flags,
        ts=ts,
        frame_number=frame,
    )


def _ack(ack, ts, *, point="A", sport=40000):
    """ACK pur serveur -> client : le retour du recepteur, preuve (ou non) de reception."""
    return make_pkt(
        point=point,
        proto="TCP",
        src=S,
        dst=C,
        sport=443,
        dport=sport,
        seq=9000,
        tcp_len=0,
        flags="A",
        ack=ack,
        ts=ts,
    )


# -- Suivi des numeros de sequence ----------------------------------------


def test_flux_contigu_ne_signale_aucun_trou():
    pkts = [_seg(1000, 100, 1.0), _seg(1100, 100, 1.1), _seg(1200, 50, 1.2)]
    assert detect_sequence_gaps(pkts) == []


def test_aucun_paquet_aucun_trou():
    assert detect_sequence_gaps([]) == []


def test_trou_detecte_avec_ses_bornes_et_le_segment_qui_le_revele():
    pkts = [_seg(1000, 100, 1.0, frame=1), _seg(1200, 100, 1.1, frame=3)]
    (gap,) = detect_sequence_gaps(pkts)
    assert (gap.start_seq, gap.end_seq, gap.missing_bytes) == (1100, 1200, 100)
    assert (gap.point, gap.src, gap.sport, gap.dst, gap.dport) == ("A", C, 40000, S, 443)
    assert gap.frame_number == 3
    assert gap.ts == 1.1


def test_retransmission_qui_comble_le_trou_l_annule():
    # Le segment 1100 est retransmis apres coup : ce n'est plus un trou.
    pkts = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _seg(1100, 100, 1.5)]
    assert detect_sequence_gaps(pkts) == []


def test_paquet_hors_ordre_ne_cree_pas_de_trou():
    pkts = [_seg(1000, 100, 1.000), _seg(1200, 100, 1.001), _seg(1100, 100, 1.002), _seg(1300, 100, 1.003)]
    assert detect_sequence_gaps(pkts) == []


def test_trou_partiellement_comble_ne_garde_que_le_reste():
    # Trou [1100, 1400) ; une retransmission couvre le debut [1100, 1200).
    pkts = [_seg(1000, 100, 1.0), _seg(1400, 100, 1.1), _seg(1100, 100, 1.2)]
    (gap,) = detect_sequence_gaps(pkts)
    assert (gap.start_seq, gap.end_seq, gap.missing_bytes) == (1200, 1400, 200)


def test_comblement_au_milieu_scinde_le_trou_en_deux():
    pkts = [_seg(1000, 100, 1.0), _seg(1400, 100, 1.1), _seg(1200, 100, 1.2)]
    gaps = detect_sequence_gaps(pkts)
    assert [(g.start_seq, g.end_seq) for g in gaps] == [(1100, 1200), (1300, 1400)]


def test_ack_pur_avec_seq_en_avance_ne_prouve_aucun_trou():
    pkts = [_seg(1000, 100, 1.0), _seg(5000, 0, 1.1)]
    assert detect_sequence_gaps(pkts) == []


def test_syn_consomme_un_numero_de_sequence():
    assert detect_sequence_gaps([_seg(1000, 0, 1.0, flags="S"), _seg(1001, 100, 1.1)]) == []
    (gap,) = detect_sequence_gaps([_seg(1000, 0, 1.0, flags="S"), _seg(1002, 100, 1.1)])
    assert (gap.start_seq, gap.missing_bytes) == (1001, 1)


def test_fin_consomme_un_numero_de_sequence():
    pkts = [_seg(1000, 100, 1.0), _seg(1100, 0, 1.1, flags="FA"), _seg(1102, 10, 1.2)]
    (gap,) = detect_sequence_gaps(pkts)
    assert (gap.start_seq, gap.missing_bytes) == (1101, 1)


def test_retour_a_zero_du_compteur_32_bits():
    top = (1 << 32) - 100
    assert detect_sequence_gaps([_seg(top, 100, 1.0), _seg(0, 100, 1.1)]) == []
    (gap,) = detect_sequence_gaps([_seg(top, 100, 1.0), _seg(100, 100, 1.1)])
    assert (gap.start_seq, gap.end_seq, gap.missing_bytes) == (0, 100, 100)


def test_nouvelle_connexion_sur_le_meme_5_uplet_ne_cree_pas_de_trou():
    pkts = [
        _seg(1000, 0, 1.0, flags="S"),
        _seg(1001, 100, 1.1),
        _seg(9_000_000, 0, 5.0, flags="S"),  # meme 5-uplet, autre numero de sequence initial
        _seg(9_000_001, 100, 5.1),
    ]
    assert detect_sequence_gaps(pkts) == []


def test_syn_retransmis_ne_reinitialise_pas_le_suivi():
    pkts = [
        _seg(1000, 0, 1.0, flags="S"),
        _seg(1001, 100, 1.1),
        _seg(1201, 100, 1.2),  # trou [1101, 1201)
        _seg(1000, 0, 1.3, flags="S"),  # SYN retransmis (meme numero initial)
    ]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.start_seq == 1101


def test_ecart_implausible_est_une_resynchronisation_pas_un_trou():
    # Au-dela de 2**30 octets, ce ne peut pas etre une perte au sein d'une fenetre TCP.
    assert detect_sequence_gaps([_seg(1000, 100, 1.0), _seg(1000 + (1 << 30) + 500, 100, 1.1)]) == []


def test_longueur_tcp_inconnue_ne_produit_aucun_faux_positif():
    pkts = [make_pkt(seq=1000, flags="A", ts=1.0), make_pkt(seq=5000, flags="A", ts=1.1)]
    assert pkts[0].tcp_len is None
    assert detect_sequence_gaps(pkts) == []


def test_udp_et_protocoles_non_tcp_sont_ignores():
    pkts = [
        make_pkt(proto="UDP", seq=1000, tcp_len=100, ts=1.0),
        make_pkt(proto="UDP", seq=9000, tcp_len=100, ts=1.1),
    ]
    assert detect_sequence_gaps(pkts) == []


def test_paquets_fournis_dans_le_desordre_sont_ranges_par_horodatage():
    pkts = [_seg(1200, 100, 1.2), _seg(1000, 100, 1.0), _seg(1100, 100, 1.1)]
    assert detect_sequence_gaps(pkts) == []


def test_chaque_point_et_chaque_sens_sont_suivis_independamment():
    forward_a = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1)]  # trou vu en A
    forward_b = [_seg(1000, 100, 1.0, point="B"), _seg(1100, 100, 1.05, point="B"), _seg(1200, 100, 1.1, point="B")]
    reverse_a = [
        make_pkt(src=S, dst=C, sport=443, dport=40000, seq=7000, tcp_len=100, flags="A", ts=1.0),
        make_pkt(src=S, dst=C, sport=443, dport=40000, seq=7100, tcp_len=100, flags="A", ts=1.1),
    ]
    gaps = detect_sequence_gaps(forward_a + forward_b + reverse_a)
    assert [(g.point, g.start_seq) for g in gaps] == [("A", 1100)]


# -- Classification : capture / reseau / indetermine -------------------------


def test_trou_acquitte_sans_retransmission_est_un_trou_de_capture():
    pkts = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _ack(1300, 1.2)]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.cause == SEQ_GAP_CAPTURE_DROP
    assert "1300" in gap.evidence


def test_trou_non_acquitte_avec_ack_dupliques_est_une_perte_reseau():
    pkts = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _ack(1100, 1.15), _ack(1100, 1.16), _ack(1100, 1.17)]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.cause == SEQ_GAP_NETWORK_LOSS
    assert "1100" in gap.evidence


def test_trou_sans_retour_du_recepteur_est_indetermine():
    (gap,) = detect_sequence_gaps([_seg(1000, 100, 1.0), _seg(1200, 100, 1.1)])
    assert gap.cause == SEQ_GAP_INDETERMINATE


def test_ack_en_retard_sur_le_trou_reste_indetermine():
    # ACK 1000 < debut du trou (1100) : le recepteur n'a meme pas rattrape le trou.
    pkts = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _ack(1000, 1.2)]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.cause == SEQ_GAP_INDETERMINATE


def test_ack_anterieur_au_trou_ne_prouve_pas_la_reception():
    pkts = [_ack(1300, 0.5), _seg(1000, 100, 1.0), _seg(1200, 100, 1.1)]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.cause == SEQ_GAP_INDETERMINATE


def test_ack_d_une_connexion_ulterieure_ne_compte_pas():
    pkts = [
        _seg(1000, 0, 0.9, flags="S"),
        _seg(1001, 100, 1.0),
        _seg(1201, 100, 1.1),  # trou [1101, 1201)
        _seg(50_000, 0, 5.0, flags="S"),  # nouvelle connexion : les ACK suivants ne concernent plus ce trou
        _ack(999_999, 5.1),
    ]
    (gap,) = detect_sequence_gaps(pkts)
    assert gap.cause == SEQ_GAP_INDETERMINATE


def test_ack_vu_a_un_autre_point_n_est_pas_une_preuve_pour_ce_point():
    pkts = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _ack(1300, 1.2, point="B")]
    (gap,) = detect_sequence_gaps(pkts)
    assert (gap.point, gap.cause) == ("A", SEQ_GAP_INDETERMINATE)


def test_plusieurs_connexions_sont_classees_independamment():
    conn1 = [_seg(1000, 100, 1.0), _seg(1200, 100, 1.1), _ack(1300, 1.2)]
    conn2 = [
        _seg(1000, 100, 2.0, sport=40001),
        _seg(1200, 100, 2.1, sport=40001),
        _ack(1100, 2.2, sport=40001),
    ]
    gaps = detect_sequence_gaps(conn1 + conn2)
    assert {g.sport: g.cause for g in gaps} == {40000: SEQ_GAP_CAPTURE_DROP, 40001: SEQ_GAP_NETWORK_LOSS}


# -- Integration : analyse() et rapport texte ------------------------------


def _report_with_one_capture_drop():
    pkts = [_seg(1000, 100, 1.0, frame=1), _seg(1200, 100, 1.1, frame=3), _ack(1300, 1.2)]
    return analyse(correlate(pkts), points_order=["A", "B"], all_packets=pkts)


def test_analyse_alimente_sequence_gaps():
    r = _report_with_one_capture_drop()
    assert [(g.start_seq, g.cause) for g in r.sequence_gaps] == [(1100, SEQ_GAP_CAPTURE_DROP)]


def test_analyse_sans_paquet_ne_signale_aucun_trou():
    r = analyse(correlate([]), points_order=["A", "B"], all_packets=[])
    assert r.sequence_gaps == []


def test_rapport_texte_sans_trou(capsys):
    r = analyse(correlate([]), points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "-- Integrite de capture : trous de sequence TCP --" in out
    assert "aucun trou de sequence TCP detecte" in out


def test_rapport_texte_detaille_les_trous_par_point(capsys):
    print_report(_report_with_one_capture_drop())
    out = capsys.readouterr().out
    assert "-- Integrite de capture : trous de sequence TCP --" in out
    assert "1 trou(s), 100 octet(s) manquant(s) (1 de capture, 0 perte(s) reseau, 0 indetermine(s))" in out
    assert "10.0.0.1:40000 -> 10.0.0.2:443 seq 1100..1200 (100 octets, trame 3) -- trou de capture" in out
    assert "aucun trou de sequence TCP detecte" not in out


def test_rapport_texte_plafonne_les_exemples_par_point(capsys):
    r = analyse(correlate([]), points_order=["A", "B"], all_packets=[])
    r.sequence_gaps = [
        SequenceGap(
            point="A",
            src=C,
            sport=40000 + i,
            dst=S,
            dport=443,
            start_seq=1000 * i,
            end_seq=1000 * i + 10,
            missing_bytes=10,
            ts=float(i),
            frame_number=None,
            cause=SEQ_GAP_NETWORK_LOSS,
            evidence="ACK bloque",
        )
        for i in range(7)
    ]
    print_report(r)
    out = capsys.readouterr().out
    assert "7 trou(s), 70 octet(s) manquant(s) (0 de capture, 7 perte(s) reseau, 0 indetermine(s))" in out
    assert out.count("      ex: ") == 5
    assert "... et 2 autre(s) trou(s)" in out


# -- Parseur : tcp.len -> RawPacket.tcp_len -> Pkt.tcp_len -------------------


def _tcp_layers(**tcp_fields):
    return {
        "frame": {"frame_frame_len": "1514"},
        "ip": {"ip_ip_src": C, "ip_ip_dst": S, "ip_ip_id": "1"},
        "tcp": {
            "tcp_tcp_srcport": "5555",
            "tcp_tcp_dstport": "443",
            "tcp_tcp_seq_raw": "2000",
            "tcp_tcp_ack_raw": "1",
            "tcp_tcp_window_size_value": "8192",
            "tcp_tcp_flags_str": "\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            **tcp_fields,
        },
    }


def test_build_packet_lit_tcp_len():
    assert build_packet(0.0, _tcp_layers(tcp_tcp_len="1460")).tcp_len == 1460


def test_build_packet_tcp_len_nul_sur_un_segment_sans_donnees():
    assert build_packet(0.0, _tcp_layers(tcp_tcp_len="0")).tcp_len == 0


def test_build_packet_tcp_len_absent_reste_none():
    assert build_packet(0.0, _tcp_layers()).tcp_len is None


def test_tcp_len_est_propage_du_parseur_au_modele_pkt():
    raw = build_packet(0.0, _tcp_layers(tcp_tcp_len="1460"))
    assert _to_pkt("A", raw).tcp_len == 1460
