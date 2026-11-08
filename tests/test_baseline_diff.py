# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.baseline_diff -- compare deux Report deja calcules. On
construit ici directement des Report minimalistes (pas besoin de
rejouer analyse() en entier) pour isoler le comportement de diff_reports
lui-meme.
"""

import csv

from netcross_core.baseline_diff import DiffFinding, diff_reports, write_diff_csv
from netcross_core.expert_model import PacketEvidence
from netcross_core.models import Report


def test_point_absent_du_courant_signale_a_verifier():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A"])
    findings = diff_reports(baseline, current)
    perimetre = [f for f in findings if f.category == "Perimetre"]
    assert len(perimetre) == 1
    assert perimetre[0].segment == "B"
    assert perimetre[0].severity == "a_verifier"


def test_point_nouveau_dans_le_courant_signale_a_verifier():
    baseline = Report(points=["A"])
    current = Report(points=["A", "C"])
    findings = diff_reports(baseline, current)
    perimetre = [f for f in findings if f.category == "Perimetre"]
    assert perimetre[0].segment == "C"


def test_regression_taux_de_pertes():
    baseline = Report(points=["A", "B"])
    baseline.loss_count["B"] = 0
    baseline.seen_count["B"] = 100
    current = Report(points=["A", "B"])
    current.loss_count["B"] = 20  # 20% de pertes, avant 0%
    current.seen_count["B"] = 100
    findings = diff_reports(baseline, current)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert len(pertes) == 1
    assert pertes[0].severity == "regression"
    assert pertes[0].segment == "B"


def test_petit_ecart_de_pertes_sous_le_seuil_est_ignore():
    baseline = Report(points=["A", "B"])
    baseline.loss_count["B"] = 1
    baseline.seen_count["B"] = 1000
    current = Report(points=["A", "B"])
    current.loss_count["B"] = 2  # 0.1% -> 0.2%, sous le seuil par defaut (2pp)
    current.seen_count["B"] = 1000
    findings = diff_reports(baseline, current)
    assert not [f for f in findings if f.category == "Pertes"]


def test_amelioration_taux_de_pertes():
    baseline = Report(points=["A", "B"])
    baseline.loss_count["B"] = 20
    baseline.seen_count["B"] = 100
    current = Report(points=["A", "B"])
    current.loss_count["B"] = 0
    current.seen_count["B"] = 100
    findings = diff_reports(baseline, current)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert pertes[0].severity == "amelioration"


def test_compare_count_ignore_petit_delta_absolu():
    baseline = Report(points=["A"])
    baseline.rst_localized["A"] = 1
    current = Report(points=["A"])
    current.rst_localized["A"] = 3  # delta=2 < min_delta=3 par defaut
    findings = diff_reports(baseline, current)
    assert not [f for f in findings if "RST" in f.message]


def test_compare_count_ignore_petit_delta_relatif():
    baseline = Report(points=["A"])
    baseline.rst_localized["A"] = 400
    current = Report(points=["A"])
    current.rst_localized["A"] = 404  # delta=4 >= min_delta mais rel=1% < 50%
    findings = diff_reports(baseline, current)
    assert not [f for f in findings if "RST" in f.message]


def test_compare_count_regression_significative():
    baseline = Report(points=["A"])
    baseline.rst_localized["A"] = 1
    current = Report(points=["A"])
    current.rst_localized["A"] = 5  # delta=4 (>=3), rel=400% (>=50%)
    findings = diff_reports(baseline, current)
    matches = [f for f in findings if "RST injectes localement" in f.message]
    assert len(matches) == 1
    assert matches[0].severity == "regression"


def test_icmp_frag_needed_seuil_permissif_1_occurrence():
    # min_delta=1, rel_threshold=0.0 pour ICMP Frag Needed -- une seule
    # nouvelle occurrence doit deja etre signalee
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.icmp_frag_needed["A"] = 1
    findings = diff_reports(baseline, current)
    assert any("ICMP Fragmentation Needed" in f.message for f in findings)


def test_icmpv6_too_big_seuil_permissif_1_occurrence():
    # Equivalent IPv6 (Session 22) du test ci-dessus -- higher_is_worse
    # =False cote les deux : plus de signal ICMP(v6) observe = PMTUD qui
    # fonctionne mieux, donc "amelioration" et non "regression".
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.icmpv6_too_big["A"] = 1
    findings = diff_reports(baseline, current)
    matches = [f for f in findings if "ICMPv6 Packet Too Big" in f.message]
    assert len(matches) == 1
    assert matches[0].severity == "amelioration"


def test_pmtud_blackhole_nouvelle_occurrence_signalee():
    # min_delta=1, rel_threshold=0.0 -- comme ICMP Frag Needed, une seule
    # nouvelle occurrence de noir PMTUD doit deja etre signalee
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    findings = diff_reports(baseline, current)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    assert len(pmtud) == 1
    assert pmtud[0].severity == "regression"
    assert pmtud[0].segment == "A -> B"


def test_idle_timeout_dropped_nouvelle_occurrence_signalee():
    # min_delta=1, rel_threshold=0.0 -- meme regime de seuil que PMTUD :
    # une seule coupure NAT/FW silencieuse nouvelle doit deja etre
    # signalee (higher_is_worse=True, valeur par defaut -- plus de
    # coupures = regression, a la difference d'icmpv6_too_big).
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.idle_timeout_dropped[("A", "B")] = 1
    findings = diff_reports(baseline, current)
    idle = [f for f in findings if f.category == "NAT/Pare-feu"]
    assert len(idle) == 1
    assert idle[0].severity == "regression"
    assert idle[0].segment == "A -> B"


def test_arp_ip_conflict_nouvelle_occurrence_signalee():
    # min_delta=1, rel_threshold=0.0 -- meme regime de seuil que PMTUD/
    # idle_timeout : un seul conflit d'adresse IP nouveau doit deja etre
    # signale (higher_is_worse=True, valeur par defaut).
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.arp_ip_conflict["A"] = 1
    findings = diff_reports(baseline, current)
    arp = [f for f in findings if f.category == "ARP"]
    assert len(arp) == 1
    assert arp[0].severity == "regression"
    assert arp[0].segment == "A"


def test_stp_topology_change_nouvelle_occurrence_signalee():
    # min_delta=1, rel_threshold=0.0 -- meme regime de seuil que ARP.
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.stp_topology_change["A"] = 1
    findings = diff_reports(baseline, current)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) == 1
    assert stp[0].severity == "regression"
    assert stp[0].segment == "A"


def test_stp_root_change_nouvelle_occurrence_signalee():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.stp_root_change["A"] = 1
    findings = diff_reports(baseline, current)
    stp = [f for f in findings if f.category == "STP"]
    assert len(stp) == 1
    assert stp[0].severity == "regression"
    assert stp[0].segment == "A"


def test_tls_cert_invalid_dates_nouvelle_occurrence_signalee():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_invalid_dates["A"] = 1
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "regression"
    assert tls[0].segment == "A"


def test_tls_cert_mismatch_nouvelle_occurrence_signalee():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_mismatch[("A", "B")] = 1
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "regression"
    assert tls[0].segment == "A -> B"


def test_tls_handshake_no_reply_nouvelle_occurrence_signalee():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_no_reply["A"] = 1
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "regression"
    assert tls[0].segment == "A"


def test_tls_handshake_incomplete_nouvelle_occurrence_signalee():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_incomplete["A"] = 1
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS"]
    assert len(tls) == 1
    assert tls[0].severity == "regression"
    assert tls[0].segment == "A"


def test_retransmission_rto_regression_signalee():
    # seuils par defaut de _compare_count (min_delta=3, rel_threshold=0.5)
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.retrans_rto["A"] = 5
    findings = diff_reports(baseline, current)
    rto = [f for f in findings if f.category == "TCP" and "RTO" in f.message]
    assert len(rto) == 1
    assert rto[0].severity == "regression"
    assert rto[0].segment == "A"


def test_wscale_stripped_nouvelle_occurrence_signalee():
    # min_delta=1, rel_threshold=0.0 -- comme PMTUD, une seule nouvelle
    # occurrence de perte d'option doit deja etre signalee
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.wscale_stripped[("A", "B")] = 1
    findings = diff_reports(baseline, current)
    ws = [f for f in findings if f.category == "TCP" and "Window Scale" in f.message]
    assert len(ws) == 1
    assert ws[0].severity == "regression"
    assert ws[0].segment == "A -> B"


def test_mss_clamped_seuils_par_defaut():
    # mss_clamped utilise les seuils par defaut (min_delta=3,
    # rel_threshold=0.5) -- moins urgent que wscale/sack (severite "info"
    # cote synthesis), une seule occurrence ne doit PAS declencher
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.mss_clamped[("A", "B")] = 1
    findings = diff_reports(baseline, current)
    mss = [f for f in findings if f.category == "TCP" and "MSS" in f.message]
    assert mss == []


def test_latence_regression_avec_seuil_relatif():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0] * 5
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [50.0] * 5  # +40ms, +400%
    findings = diff_reports(baseline, current)
    latence = [f for f in findings if f.category == "Latence"]
    assert len(latence) == 1
    assert latence[0].severity == "regression"
    assert latence[0].segment == "A -> B"


def test_latence_stable_sous_les_deux_seuils():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [100.0] * 5
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [103.0] * 5  # +3ms, +3% : sous les deux seuils
    findings = diff_reports(baseline, current)
    assert not [f for f in findings if f.category == "Latence"]


def test_latence_disparait_completement_signale_a_verifier():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0]
    current = Report(points=["A", "B"])
    findings = diff_reports(baseline, current)
    latence = [f for f in findings if f.category == "Latence"]
    assert latence[0].severity == "a_verifier"


def test_saturation_verdict_regression():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0]  # necessaire pour que la paire soit
    current = Report(points=["A", "B"])  # consideree (voir all_pairs dans diff_reports)
    current.latency[("A", "B")] = [10.0]
    baseline.saturation_verdict[("A", "B")] = "fluide"
    current.saturation_verdict[("A", "B")] = "saturation probable"
    findings = diff_reports(baseline, current)
    sat = [f for f in findings if f.category == "Saturation"]
    assert sat[0].severity == "regression"


def test_rtp_mos_regression_appariement_par_label_sans_ssrc():
    baseline = Report(points=["A", "B"])
    baseline.rtp_streams = [{"label": "A -> B (SSRC=111)", "mos": 4.0}]
    current = Report(points=["A", "B"])
    current.rtp_streams = [{"label": "A -> B (SSRC=222)", "mos": 3.0}]
    findings = diff_reports(baseline, current)
    rtp = [f for f in findings if f.category == "RTP/Voix"]
    assert len(rtp) == 1
    assert rtp[0].severity == "regression"


def test_topologie_arc_disparu_signale():
    baseline = Report(points=["A", "B"])
    baseline.topology_edges = [("A", "B", {})]
    current = Report(points=["A", "B"])
    current.topology_edges = []
    findings = diff_reports(baseline, current)
    topo = [f for f in findings if f.category == "Topologie"]
    assert len(topo) == 1
    assert "plus detecte" in topo[0].message


def test_topologie_nouvel_arc_signale():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.topology_edges = [("A", "B", {})]
    findings = diff_reports(baseline, current)
    topo = [f for f in findings if f.category == "Topologie"]
    assert "Nouvel arc" in topo[0].message or "nouvel arc" in topo[0].message.lower()


def test_findings_tries_regressions_avant_ameliorations():
    baseline = Report(points=["A"])
    baseline.rst_localized["A"] = 1
    current = Report(points=["A"])
    current.rst_localized["A"] = 10  # regression forte
    baseline.dup_ack["A"] = 10
    current.dup_ack["A"] = 1  # amelioration forte
    findings = diff_reports(baseline, current)
    severities = [f.severity for f in findings]
    assert severities.index("regression") < severities.index("amelioration")


def test_dns_nouvelles_servfail_est_une_regression():
    baseline = Report(points=["A"])
    baseline.dns_servfail_count["A"] = 0
    current = Report(points=["A"])
    current.dns_servfail_count["A"] = 3
    findings = diff_reports(baseline, current)
    dns = [f for f in findings if f.category == "DNS"]
    assert len(dns) == 1
    assert dns[0].severity == "regression"
    assert dns[0].segment == "A"


def test_dns_resolution_plus_lente_est_une_regression():
    baseline = Report(points=["A"])
    baseline.dns_duration_ms = [20.0, 20.0]
    current = Report(points=["A"])
    current.dns_duration_ms = [300.0, 300.0]
    findings = diff_reports(baseline, current)
    dns = [f for f in findings if f.category == "DNS"]
    assert len(dns) == 1
    assert dns[0].severity == "regression"
    assert dns[0].segment == "global"


def test_dns_petit_ecart_de_duree_est_ignore():
    baseline = Report(points=["A"])
    baseline.dns_duration_ms = [20.0]
    current = Report(points=["A"])
    current.dns_duration_ms = [25.0]
    findings = diff_reports(baseline, current)
    assert [f for f in findings if f.category == "DNS"] == []


def test_http_nouvelles_erreurs_5xx_est_une_regression():
    # meme seuil agressif (min_delta=1, rel_threshold=0.0) que DNS SERVFAIL :
    # un 5xx qui apparait est un signal fort, pas une estimation fragile.
    baseline = Report(points=["A"])
    baseline.http_server_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_server_error_count["A"] = 3
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP"]
    assert len(http) == 1
    assert http[0].severity == "regression"
    assert http[0].segment == "A"


def test_http_petite_hausse_4xx_est_ignoree():
    # a la difference du 5xx, le 4xx garde les seuils par defaut
    # (min_delta=3, rel_threshold=0.5) : trop souvent legitime/cote client
    # (404 sur une ressource reellement absente, bruit de robots...) pour
    # remonter une regression des la premiere occurrence.
    baseline = Report(points=["A"])
    baseline.http_client_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_client_error_count["A"] = 2
    findings = diff_reports(baseline, current)
    assert [f for f in findings if f.category == "HTTP"] == []


def test_http_hausse_notable_4xx_est_une_regression():
    baseline = Report(points=["A"])
    baseline.http_client_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_client_error_count["A"] = 3
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP"]
    assert len(http) == 1
    assert http[0].severity == "regression"


def test_http_nouvelles_requetes_sans_reponse_est_une_regression():
    baseline = Report(points=["A"])
    baseline.http_timeout["A"] = []
    current = Report(points=["A"])
    current.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP"]
    assert len(http) == 1
    assert http[0].severity == "regression"


def test_http_reponse_plus_lente_est_une_regression():
    baseline = Report(points=["A"])
    baseline.http_response_time_ms = [50.0, 50.0]
    current = Report(points=["A"])
    current.http_response_time_ms = [700.0, 700.0]
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP"]
    assert len(http) == 1
    assert http[0].severity == "regression"
    assert http[0].segment == "global"


def test_http_petit_ecart_de_duree_est_ignore():
    baseline = Report(points=["A"])
    baseline.http_response_time_ms = [50.0]
    current = Report(points=["A"])
    current.http_response_time_ms = [60.0]
    findings = diff_reports(baseline, current)
    assert [f for f in findings if f.category == "HTTP"] == []


def test_write_diff_csv(tmp_path):
    findings = [
        DiffFinding("regression", "Pertes", "B", "taux de pertes 0% -> 20%", 0.0, 20.0),
        DiffFinding("amelioration", "TCP", "A", "RST : 5 -> 1 (-4)"),
    ]
    out = tmp_path / "diff.csv"
    write_diff_csv(findings, str(out))
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["severite", "categorie", "segment", "message", "avant", "apres"]
    assert rows[1][0] == "regression"
    assert rows[2][4] == ""  # 'avant' absent pour ce finding -> chaine vide


# -- score de confiance (sample_size) --


def test_regression_pertes_sample_size_est_le_denominateur_courant():
    baseline = Report(points=["A", "B"])
    baseline.loss_count["B"] = 0
    baseline.seen_count["B"] = 100
    current = Report(points=["A", "B"])
    current.loss_count["B"] = 20
    current.seen_count["B"] = 150
    findings = diff_reports(baseline, current)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert pertes[0].sample_size == 150


def test_latence_regression_sample_size_est_le_nombre_d_echantillons_courants():
    baseline = Report(points=["A", "B"])
    baseline.latency[("A", "B")] = [10.0] * 5
    current = Report(points=["A", "B"])
    current.latency[("A", "B")] = [50.0] * 7
    findings = diff_reports(baseline, current)
    latence = [f for f in findings if f.category == "Latence"]
    assert latence[0].sample_size == 7


def test_dns_resolution_plus_lente_sample_size():
    baseline = Report(points=["A"])
    baseline.dns_duration_ms = [20.0, 20.0]
    current = Report(points=["A"])
    current.dns_duration_ms = [300.0, 300.0, 300.0]
    findings = diff_reports(baseline, current)
    dns = [f for f in findings if f.category == "DNS"]
    assert dns[0].sample_size == 3


def test_http_reponse_plus_lente_sample_size():
    baseline = Report(points=["A"])
    baseline.http_response_time_ms = [50.0, 50.0]
    current = Report(points=["A"])
    current.http_response_time_ms = [700.0, 700.0, 700.0]
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP"]
    assert http[0].sample_size == 3


def test_rtp_mos_regression_sample_size_depuis_sample_count():
    baseline = Report(points=["A", "B"])
    baseline.rtp_streams = [{"label": "A -> B (SSRC=111)", "mos": 4.0, "sample_count": 200}]
    current = Report(points=["A", "B"])
    current.rtp_streams = [{"label": "A -> B (SSRC=222)", "mos": 3.0, "sample_count": 2}]
    findings = diff_reports(baseline, current)
    rtp = [f for f in findings if f.category == "RTP/Voix"]
    assert rtp[0].sample_size == 2


def test_compare_count_ne_porte_jamais_de_sample_size():
    """Les compteurs bruts (RST, NAK...) sont une preuve directe, pas une
    estimation -- pas de sample_size, meme quand l'ecart est significatif."""
    baseline = Report(points=["A"])
    baseline.rst_localized["A"] = 0
    current = Report(points=["A"])
    current.rst_localized["A"] = 10
    findings = diff_reports(baseline, current)
    tcp = [f for f in findings if f.category == "TCP"]
    assert tcp[0].sample_size is None


# -- preuves (evidence, Session 33 -- suite de l'EvidenceLink introduit en
# Session 32 pour Finding). Decision de conception : l'evidence vient
# toujours du rapport COURANT (jamais du baseline, jamais des deux), meme
# priorite "apres" que sample_size ci-dessus. --


def test_diff_finding_par_defaut_sans_evidence():
    """Un DiffFinding sur une categorie non cablee (Pertes) ne porte pas
    d'evidence -- valeur par defaut [], pas None, pour rester coherent avec
    le duck-typing de json_report/triage (`if evidence:`/`or ()`)."""
    baseline = Report(points=["A", "B"])
    baseline.loss_count["B"] = 0
    baseline.seen_count["B"] = 100
    current = Report(points=["A", "B"])
    current.loss_count["B"] = 20
    current.seen_count["B"] = 100
    findings = diff_reports(baseline, current)
    pertes = [f for f in findings if f.category == "Pertes"]
    assert pertes[0].evidence == []


def test_arp_ip_conflict_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.arp_ip_conflict["A"] = 1
    current.arp_ip_conflict_examples["A"] = ["10.0.0.9 revendiquee par aa:...:01 et aa:...:99"]
    findings = diff_reports(baseline, current)
    arp = [f for f in findings if f.category == "ARP"]
    assert len(arp[0].evidence) == 1
    assert arp[0].evidence[0].point == "A"
    assert arp[0].evidence[0].text == "10.0.0.9 revendiquee par aa:...:01 et aa:...:99"


def test_arp_ip_conflict_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.arp_ip_conflict["A"] = 1
    current.arp_ip_conflict_examples["A"] = ["10.0.0.9 revendiquee par aa:...:01 et aa:...:99"]
    current.arp_ip_conflict_frames["A"] = [31]
    findings = diff_reports(baseline, current)
    arp = [f for f in findings if f.category == "ARP"]
    assert arp[0].evidence[0].packet == PacketEvidence("A", 31)


def test_stp_root_change_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.stp_root_change["A"] = 1
    current.stp_root_change_examples["A"] = ["racine changee de 32768/aa:...:01 vers 32768/aa:...:02"]
    findings = diff_reports(baseline, current)
    stp = [f for f in findings if f.category == "STP"]
    assert stp[0].evidence[0].text == "racine changee de 32768/aa:...:01 vers 32768/aa:...:02"


def test_stp_root_change_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.stp_root_change["A"] = 1
    current.stp_root_change_examples["A"] = ["racine changee de 32768/aa:...:01 vers 32768/aa:...:02"]
    current.stp_root_change_frames["A"] = [32]
    findings = diff_reports(baseline, current)
    stp = [f for f in findings if f.category == "STP"]
    assert stp[0].evidence[0].packet == PacketEvidence("A", 32)


def test_stp_topology_change_reste_sans_evidence():
    """Report ne collecte pas d'exemples pour stp_topology_change (seulement
    stp_root_change) -- asymetrie deja presente cote synthesis.py (Session
    32), reproduite ici a l'identique plutot que comblee artificiellement."""
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.stp_topology_change["A"] = 1
    findings = diff_reports(baseline, current)
    stp = [f for f in findings if f.category == "STP" and "topologie" in f.message]
    assert stp[0].evidence == []


def test_tls_cert_invalid_dates_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_invalid_dates["A"] = 1
    current.tls_cert_invalid_dates_examples["A"] = ["serie 38:f5:... expire depuis le 2026-08-31"]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "validite" in f.message]
    assert tls[0].evidence[0].text == "serie 38:f5:... expire depuis le 2026-08-31"


def test_tls_cert_invalid_dates_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_invalid_dates["A"] = 1
    current.tls_cert_invalid_dates_examples["A"] = ["serie 38:f5:... expire depuis le 2026-08-31"]
    current.tls_cert_invalid_dates_frames["A"] = [33]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "validite" in f.message]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 33)


def test_pmtud_blackhole_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    current.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 3x, DF actif"]
    findings = diff_reports(baseline, current)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    assert pmtud[0].evidence[0].point == "A -> B"
    assert pmtud[0].evidence[0].text == "seq=123 retransmis 3x, DF actif"


def test_pmtud_blackhole_evidence_porte_le_numero_de_trame():
    # Session 37 : PacketEvidence sur DiffFinding, jusque-la reserve a
    # Finding (Session 35) -- meme pilote PMTUD, etendu ici a DiffFinding.
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    current.pmtud_blackhole_examples[("A", "B")] = ["seq=123 retransmis 3x, DF actif"]
    current.pmtud_blackhole_frames[("A", "B")] = [34]
    findings = diff_reports(baseline, current)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    assert pmtud[0].evidence[0].packet == PacketEvidence("A -> B", 34)


def test_idle_timeout_dropped_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.idle_timeout_dropped[("A", "B")] = 1
    current.idle_timeout_examples[("A", "B")] = ["10.0.0.1:1234 silence de 94.0s"]
    findings = diff_reports(baseline, current)
    idle = [f for f in findings if f.category == "NAT/Pare-feu"]
    assert idle[0].evidence[0].text == "10.0.0.1:1234 silence de 94.0s"


def test_idle_timeout_dropped_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.idle_timeout_dropped[("A", "B")] = 1
    current.idle_timeout_examples[("A", "B")] = ["10.0.0.1:1234 silence de 94.0s"]
    current.idle_timeout_frames[("A", "B")] = [35]
    findings = diff_reports(baseline, current)
    idle = [f for f in findings if f.category == "NAT/Pare-feu"]
    assert idle[0].evidence[0].packet == PacketEvidence("A -> B", 35)


def test_tls_cert_mismatch_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_mismatch[("A", "B")] = 1
    current.tls_cert_mismatch_examples[("A", "B")] = ["serie 11:.. en A vs serie 22:.. en B"]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "different" in f.message]
    assert tls[0].evidence[0].text == "serie 11:.. en A vs serie 22:.. en B"


def test_tls_cert_mismatch_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_cert_mismatch[("A", "B")] = 1
    current.tls_cert_mismatch_examples[("A", "B")] = ["serie 11:.. en A vs serie 22:.. en B"]
    current.tls_cert_mismatch_frames[("A", "B")] = [36]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "different" in f.message]
    assert tls[0].evidence[0].packet == PacketEvidence("A -> B", 36)


def test_tls_handshake_no_reply_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_no_reply["A"] = 1
    current.tls_handshake_no_reply_examples["A"] = ["10.0.0.1:1234 -> 10.0.0.2:443 : ClientHello envoye"]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "sans reponse" in f.message]
    assert tls[0].evidence[0].text == "10.0.0.1:1234 -> 10.0.0.2:443 : ClientHello envoye"


def test_tls_handshake_no_reply_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_no_reply["A"] = 1
    current.tls_handshake_no_reply_examples["A"] = ["ClientHello envoye"]
    current.tls_handshake_no_reply_frames["A"] = [37]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "sans reponse" in f.message]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 37)


def test_tls_handshake_incomplete_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_incomplete["A"] = 1
    current.tls_handshake_incomplete_examples["A"] = ["10.0.0.1:1234 -> 10.0.0.2:443 : ServerHello recu"]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "interrompue" in f.message]
    assert tls[0].evidence[0].text == "10.0.0.1:1234 -> 10.0.0.2:443 : ServerHello recu"


def test_tls_handshake_incomplete_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.tls_handshake_incomplete["A"] = 1
    current.tls_handshake_incomplete_examples["A"] = ["ServerHello recu"]
    current.tls_handshake_incomplete_frames["A"] = [38]
    findings = diff_reports(baseline, current)
    tls = [f for f in findings if f.category == "TLS" and "interrompue" in f.message]
    assert tls[0].evidence[0].packet == PacketEvidence("A", 38)


def test_mss_clamped_evidence_vient_du_courant():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.mss_clamped[("A", "B")] = 5
    current.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    findings = diff_reports(baseline, current)
    tcp = [f for f in findings if f.category == "TCP" and "MSS" in f.message]
    assert tcp[0].evidence[0].text == "MSS 1460 -> 1400"


def test_mss_clamped_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.mss_clamped[("A", "B")] = 5
    current.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    current.mss_clamped_frames[("A", "B")] = [37]
    findings = diff_reports(baseline, current)
    tcp = [f for f in findings if f.category == "TCP" and "MSS" in f.message]
    assert tcp[0].evidence[0].packet == PacketEvidence("A -> B", 37)


def test_dns_timeout_evidence_est_la_liste_elle_meme():
    """dns_timeout est deja une liste d'exemples formates (pas un compteur +
    un champ *_examples separe) -- l'evidence reutilise directement cette
    liste, meme principe que dns_timeout cote synthesis.py."""
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.dns_timeout["A"] = ["10.0.0.5 -> exemple.test (A) : aucune reponse"]
    findings = diff_reports(baseline, current)
    dns = [f for f in findings if f.category == "DNS" and "sans reponse" in f.message]
    assert dns[0].evidence[0].text == "10.0.0.5 -> exemple.test (A) : aucune reponse"


def test_dns_timeout_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.dns_timeout["A"] = ["10.0.0.5 -> exemple.test (A) : aucune reponse"]
    current.dns_timeout_frames["A"] = [38]
    findings = diff_reports(baseline, current)
    dns = [f for f in findings if f.category == "DNS" and "sans reponse" in f.message]
    assert dns[0].evidence[0].packet == PacketEvidence("A", 38)


def test_http_timeout_evidence_est_la_liste_elle_meme():
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.http_timeout["A"] = ["GET /slow -> aucune reponse"]
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP" and "sans reponse" in f.message]
    assert http[0].evidence[0].text == "GET /slow -> aucune reponse"


def test_http_timeout_evidence_porte_le_numero_de_trame():
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    current.http_timeout["A"] = ["GET /slow -> aucune reponse"]
    current.http_timeout_frames["A"] = [39]
    findings = diff_reports(baseline, current)
    http = [f for f in findings if f.category == "HTTP" and "sans reponse" in f.message]
    assert http[0].evidence[0].packet == PacketEvidence("A", 39)


def test_http_4xx_evidence_filtree_par_classe_de_statut():
    baseline = Report(points=["A"])
    baseline.http_client_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_client_error_count["A"] = 3
    current.http_error_examples["A"] = [
        "GET /notfound -> 404",
        "GET /error -> 500",
    ]
    findings = diff_reports(baseline, current)
    http4xx = [f for f in findings if f.category == "HTTP" and "4xx" in f.message]
    texts = [e.text for e in http4xx[0].evidence]
    assert texts == ["GET /notfound -> 404"]


def test_http_4xx_evidence_porte_le_numero_de_trame_correspondant():
    baseline = Report(points=["A"])
    baseline.http_client_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_client_error_count["A"] = 3
    current.http_error_examples["A"] = ["GET /notfound -> 404", "GET /error -> 500"]
    current.http_error_frames["A"] = [41, 42]
    findings = diff_reports(baseline, current)
    http4xx = [f for f in findings if f.category == "HTTP" and "4xx" in f.message]
    assert http4xx[0].evidence[0].packet == PacketEvidence("A", 41)


def test_http_5xx_evidence_filtree_par_classe_de_statut():
    baseline = Report(points=["A"])
    baseline.http_server_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_server_error_count["A"] = 3
    current.http_error_examples["A"] = [
        "GET /notfound -> 404",
        "GET /error -> 500",
    ]
    findings = diff_reports(baseline, current)
    http5xx = [f for f in findings if f.category == "HTTP" and "5xx" in f.message]
    texts = [e.text for e in http5xx[0].evidence]
    assert texts == ["GET /error -> 500"]


def test_http_5xx_evidence_porte_le_numero_de_trame_correspondant():
    baseline = Report(points=["A"])
    baseline.http_server_error_count["A"] = 0
    current = Report(points=["A"])
    current.http_server_error_count["A"] = 3
    current.http_error_examples["A"] = ["GET /notfound -> 404", "GET /error -> 500"]
    current.http_error_frames["A"] = [41, 42]
    findings = diff_reports(baseline, current)
    http5xx = [f for f in findings if f.category == "HTTP" and "5xx" in f.message]
    assert http5xx[0].evidence[0].packet == PacketEvidence("A", 42)


def test_evidence_vient_du_courant_pas_du_baseline():
    """Verification explicite de la decision de conception : meme si le
    baseline porte lui-meme un exemple pour la meme categorie/segment,
    seul celui du courant doit apparaitre dans l'evidence."""
    baseline = Report(points=["A", "B"])
    baseline.pmtud_blackhole[("A", "B")] = 1
    baseline.pmtud_blackhole_examples[("A", "B")] = ["exemple du baseline, ne doit jamais apparaitre"]
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 5  # ecart suffisant pour declencher un constat
    current.pmtud_blackhole_examples[("A", "B")] = ["exemple du courant"]
    findings = diff_reports(baseline, current)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    texts = [e.text for e in pmtud[0].evidence]
    assert texts == ["exemple du courant"]


def test_evidence_absente_si_aucun_exemple_collecte():
    """Un compteur declenche un constat mais Report n'a jamais peuple le
    champ *_examples correspondant (cas synthetique) -- evidence reste une
    liste vide, pas une exception."""
    baseline = Report(points=["A", "B"])
    current = Report(points=["A", "B"])
    current.pmtud_blackhole[("A", "B")] = 1
    # pmtud_blackhole_examples volontairement non renseigne
    findings = diff_reports(baseline, current)
    pmtud = [f for f in findings if f.category == "PMTUD"]
    assert pmtud[0].evidence == []
