# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.rule_engine -- premier pilote du moteur d'execution
(voir docstring de module, CLAUDE.md section "Prochaine feature").
Structure calquee sur tests/test_synthesis.py pour "pertes" : Report
minimalistes cible par cible, memes seuils testes (anomalie >= 5%,
a_surveiller < 5%, aucun Finding si loss_count == 0). Ajoute une
verification d'equivalence explicite avec build_findings() (les deux
chemins doivent produire des Finding identiques pour loss_per_segment).

Session 56 : quatre nouvelles regles (tcp_zero_window, dns_nxdomain,
dns_servfail, hop_delta_outliers -- voir docstring de module de
rule_engine.py pour le detail du lot). Meme structure de tests par
regle (declenche/silencieux/equivalence), mais le filtre d'equivalence
utilise `rule_id` et non `category` cette fois : contrairement a
"Pertes" (une seule regle dans toute cette categorie), "TCP"/"DNS"/
"Routage" portent chacune PLUSIEURS rule_id distincts dans
expert_rules.py -- filtrer par seule categorie melangerait des Finding
d'autres regles (ex: TCP porte aussi tcp_rst_localized/retrans_rto...,
DNS porte aussi dns_timeout/dns_slow_resolution...) et fausserait la
comparaison longueur-a-longueur entre les deux chemins.

Session 57 : deux nouvelles regles (dns_timeout, dns_missing -- voir
docstring de module de rule_engine.py). Meme structure de tests par
regle, avec en plus une verification explicite d'`evidence` (non vide,
memes `EvidenceLink`/`PacketEvidence` que cote procedural) : premieres
regles de ce pilote dont le Finding porte des preuves, jamais verifie
jusqu'ici (Session 55/56 n'ont teste aucune regle a evidence non vide).

Session 58 : six nouvelles regles, toutes issues du meme bloc
`-- TCP avance --` de synthesis.py (tcp_retransmission_rto,
tcp_retransmission_spurious, tcp_retransmission_fast,
tcp_rst_localized, tcp_syn_no_synack, syn_reply_missing -- voir
docstring de module de rule_engine.py). Meme structure de tests par
regle (declenche/silencieux/equivalence) ; la categorie "TCP" porte
desormais neuf rule_id distincts dans ce pilote (les trois deja
presentes -- tcp_zero_window -- plus les six ci-dessus), le filtre
d'equivalence par regle utilise donc `rule_id`, jamais `category`,
meme raison que documentee depuis la Session 56.

Session 59 : deux nouvelles regles, dernieres du meme bloc
`-- TCP avance --` -- `tcp_options_stripped` (fusionne DEUX compteurs
distincts, `wscale_stripped`/`sack_stripped`, sous un seul `rule_id` :
premiere fois pour ce pilote, tests dedies aux deux compteurs
separement en plus de l'equivalence habituelle) et `tcp_mss_clamped`
(clee par paire de points comme `tcp_options_stripped`, mais avec
`evidence` non vide comme `dns_timeout`/`dns_missing` -- Session 57 ;
voir docstring de module de rule_engine.py pour le detail complet).

Session 60 : trois nouvelles regles, trois des treize candidats "de
forme simple mais NON verifies bloc par bloc" nommes par CLAUDE.md/
"Prochaine feature" depuis la Session 59 -- `ttl_variation` (meme forme
que `tcp_zero_window`, PAR POINT), `pcp_change` (meme forme que
`hop_delta_outliers`, PAR PAIRE) et `icmp_fragmentation_needed`
(DEUXIEME regle de ce pilote a fusionner deux compteurs Report distincts
sous un seul `rule_id`, apres `tcp_options_stripped` -- voir docstring
de module de rule_engine.py pour le detail complet). Meme structure de
tests par regle (declenche/silencieux/equivalence) ; `icmp_fragmentation_needed`
recoit en plus un test dedie a chacun des deux compteurs sources
separement, meme discipline que `tcp_options_stripped` (Session 59).

Session 61 : six nouvelles regles, les SIX candidats confirmes de
forme directement reproductible nommes par CLAUDE.md/"Prochaine
feature" depuis la Session 60 -- `tls_cert_invalid_dates`,
`tls_handshake_no_reply`, `tls_handshake_incomplete` (PAR POINT, meme
forme que `tcp_mss_clamped`), `tls_cert_mismatch` (PAR PAIRE, meme
forme cote paire), `http_timeout` (PAR POINT, compteur en LISTE, meme
forme que `dns_timeout` -- Session 57) et `http_missing` (PAR PAIRE,
compteur en LISTE sans frames, meme forme que `dns_missing` -- Session
57 ; voir docstring de module de rule_engine.py pour le detail
complet). Meme structure de tests par regle (declenche/silencieux/
equivalence), plus un test d'`evidence` dedie pour les cinq regles qui
en portent une (toutes sauf aucune ici -- les six portent une
`evidence`, `http_missing` sans `packet` comme `dns_missing`).

Session 68 : deux nouvelles regles, `dns_slow_resolution` et
`http_slow_response` -- PREMIERES regles de ce pilote a lire une LISTE
BRUTE (`Report.dns_duration_ms`/`Report.http_response_time_ms`) plutot
qu'un dict PAR POINT/PAIRE, segment fixe `"global"`, aucune `evidence`
(voir docstring de module de rule_engine.py pour le detail complet).
Structure de tests adaptee en consequence : pas de test par point/paire
ni d'evidence, mais un test dedie au seuil (au-dessus/au-dessous) et a
`sample_size`, meme discipline que `test_pertes_anomalie_au_dessus_de_
5_pourcent`/`test_sample_size_est_le_nombre_de_paquets_vus` pour
`loss_per_segment` (Session 55), seule autre regle a seuil pilotee a
ce jour.

Session 69 : cinq nouvelles regles d'un coup, les CINQ a
`correlation_rule` non `None` du catalogue, toutes jamais auditees
avant cette session -- `qos_dscp_remarking`, `fragmentation_new`,
`saturation`, `bufferbloat`, `pmtud_blackhole` (voir docstring de
module de rule_engine.py pour le detail complet de chaque forme).
Structure de tests adaptee par regle : `qos_dscp_remarking` et
`pmtud_blackhole` suivent la structure habituelle compteur par
paire (declenche/absent/nul/equivalence, plus un test d'`evidence`
dedie pour `pmtud_blackhole` et un test dedie aux compteurs
compagnons pour `qos_dscp_remarking`) ; `bufferbloat` n'a pas de test
"nul" (aucune garde dans la boucle source, verifie dans la docstring
de l'evaluateur) ; `fragmentation_new` et `saturation` recoivent
chacune DEUX tests "declenche" distincts (un par branche de severite,
meme discipline que `test_pertes_anomalie_au_dessus_de_5_pourcent`/
`test_pertes_a_surveiller_en_dessous_de_5_pourcent` pour
`loss_per_segment`), plus pour `saturation` un test dedie a la garde
"NON correlees". Le role de "regle connue sans evaluateur" disparait avec la Session 70
(jobs 1 et 2) : `rtp_quality_mos` puis `server_processing_dominant`
recoivent leur evaluateur, les 41 regles du catalogue sont donc TOUTES
pilotees et `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
est retire (il ne restait aucune regle pour tenir ce role).
"""

import pytest

from netcross_core.models import Report
from netcross_report.rule_engine import available_rule_ids, evaluate
from netcross_report.synthesis import build_findings


def test_pertes_anomalie_au_dessus_de_5_pourcent():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10%
    findings = evaluate("loss_per_segment", r)
    assert findings[0].severity == "anomalie"


def test_pertes_a_surveiller_en_dessous_de_5_pourcent():
    r = Report(points=["A"])
    r.loss_count["A"] = 2
    r.seen_count["A"] = 100  # 2%
    findings = evaluate("loss_per_segment", r)
    assert findings[0].severity == "a_surveiller"


def test_pertes_nulles_pas_de_finding():
    r = Report(points=["A"])
    r.loss_count["A"] = 0
    assert evaluate("loss_per_segment", r) == []


def test_rule_id_et_domain_repris_de_la_regle_du_catalogue():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    findings = evaluate("loss_per_segment", r)
    assert findings[0].rule_id == "loss_per_segment"
    assert findings[0].category == "Pertes"


def test_sample_size_est_le_nombre_de_paquets_vus():
    r = Report(points=["A"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    findings = evaluate("loss_per_segment", r)
    assert findings[0].sample_size == 100


def test_equivalent_a_build_findings_sur_plusieurs_points():
    r = Report(points=["A", "B", "C"])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # anomalie, 10%
    r.loss_count["B"] = 1
    r.seen_count["B"] = 100  # a_surveiller, 1%
    # C : aucune perte, ne doit produire de Finding ni cote procedural
    # ni cote moteur.

    procedural = [f for f in build_findings(r) if f.category == "Pertes"]
    via_moteur = evaluate("loss_per_segment", r)

    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.sample_size, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.sample_size,
            m.rule_id,
        )


def test_regle_inconnue_leve_key_error():
    r = Report(points=["A"])
    with pytest.raises(KeyError):
        evaluate("regle_qui_nexiste_pas", r)


def test_available_rule_ids_ne_contient_que_les_regles_pilotees():
    assert available_rule_ids() == [
        "loss_per_segment",
        "tcp_zero_window",
        "hop_delta_outliers",
        "dns_nxdomain",
        "dns_servfail",
        "nat_fw_silent_drop",
        "dns_timeout",
        "dns_missing",
        "tcp_retransmission_rto",
        "tcp_retransmission_spurious",
        "tcp_retransmission_fast",
        "tcp_rst_localized",
        "tcp_syn_no_synack",
        "syn_reply_missing",
        "tcp_options_stripped",
        "tcp_mss_clamped",
        "ttl_variation",
        "pcp_change",
        "icmp_fragmentation_needed",
        "tls_cert_invalid_dates",
        "tls_cert_mismatch",
        "tls_handshake_no_reply",
        "tls_handshake_incomplete",
        "http_timeout",
        "http_missing",
        "http_client_error",
        "http_server_error",
        "dhcp_issues",
        "sip_issues",
        "vlan_change",
        "arp_ip_conflict",
        "stp_instability",
        "dns_slow_resolution",
        "http_slow_response",
        "qos_dscp_remarking",
        "fragmentation_new",
        "saturation",
        "bufferbloat",
        "pmtud_blackhole",
        "rtp_quality_mos",
        "server_processing_dominant",
    ]


# -- tcp_zero_window (Session 56) -------------------------------------


def test_tcp_zero_window_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.zero_window["A"] = 3
    findings = evaluate("tcp_zero_window", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_zero_window"
    assert "fenetre TCP=0" in f.message


def test_tcp_zero_window_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_zero_window", r) == []


def test_tcp_zero_window_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.zero_window["A"] = 3
    r.zero_window["B"] = 0  # present mais nul : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_zero_window"]
    via_moteur = evaluate("tcp_zero_window", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- dns_nxdomain (Session 56) ------------------------------------------


def test_dns_nxdomain_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.dns_nxdomain_count["A"] = 4
    findings = evaluate("dns_nxdomain", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "DNS"
    assert f.segment == "A"
    assert f.rule_id == "dns_nxdomain"
    assert "NXDOMAIN" in f.message


def test_dns_nxdomain_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("dns_nxdomain", r) == []


def test_dns_nxdomain_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.dns_nxdomain_count["A"] = 4
    r.dns_nxdomain_count["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "dns_nxdomain"]
    via_moteur = evaluate("dns_nxdomain", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- dns_servfail (Session 56) -------------------------------------------


def test_dns_servfail_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.dns_servfail_count["A"] = 2
    findings = evaluate("dns_servfail", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "DNS"
    assert f.segment == "A"
    assert f.rule_id == "dns_servfail"
    assert "SERVFAIL" in f.message


def test_dns_servfail_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("dns_servfail", r) == []


def test_dns_servfail_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.dns_servfail_count["A"] = 2
    r.dns_servfail_count["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "dns_servfail"]
    via_moteur = evaluate("dns_servfail", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- hop_delta_outliers (Session 56) -- seule regle de ce lot clee par une
# PAIRE de points adjacents plutot qu'un point seul.


def test_hop_delta_outliers_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.hop_delta_outliers[("A", "B")] = 2
    findings = evaluate("hop_delta_outliers", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "Routage"
    assert f.segment == "A -> B"
    assert f.rule_id == "hop_delta_outliers"


def test_hop_delta_outliers_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("hop_delta_outliers", r) == []


def test_hop_delta_outliers_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.hop_delta_outliers[("A", "B")] = 2
    r.hop_delta_outliers[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "hop_delta_outliers"]
    via_moteur = evaluate("hop_delta_outliers", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- dns_timeout (Session 57) -- premiere regle de ce pilote dont le
# compteur source (Report.dns_timeout) porte des LISTES, pas des
# entiers, et dont le Finding porte des `evidence` non vides.


def test_dns_timeout_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["requete vers example.invalid"]
    findings = evaluate("dns_timeout", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "DNS"
    assert f.segment == "A"
    assert f.rule_id == "dns_timeout"
    assert "sans aucune reponse" in f.message


def test_dns_timeout_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("dns_timeout", r) == []


def test_dns_timeout_liste_vide_pas_de_finding():
    # Cle presente (defaultdict) mais liste vide : ne doit pas declencher,
    # meme discipline que zero_window["A"] = 0 pour les compteurs entiers.
    r = Report(points=["A"])
    r.dns_timeout["A"]  # touche la cle sans y ajouter d'element (defaultdict)
    assert evaluate("dns_timeout", r) == []


def test_dns_timeout_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["requete vers example.invalid"]
    r.dns_timeout_frames["A"] = [42]
    findings = evaluate("dns_timeout", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "requete vers example.invalid"
    assert ev.packet is not None
    assert ev.packet.frame_number == 42


def test_dns_timeout_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.dns_timeout["A"] = ["requete vers example.invalid"]
    r.dns_timeout_frames["A"] = [42]
    r.dns_timeout["B"]  # presente mais vide : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "dns_timeout"]
    via_moteur = evaluate("dns_timeout", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- dns_missing (Session 57) -- comme hop_delta_outliers, clee par une
# PAIRE de points adjacents ; comme dns_timeout ci-dessus, compteur en
# LISTE et Finding a evidence non vide, mais SANS frames (absent de
# Report pour ce compteur, verifie dans models.py).


def test_dns_missing_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.dns_missing[("A", "B")] = ["requete vue en A, absente en B"]
    findings = evaluate("dns_missing", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "DNS"
    assert f.segment == "A -> B"
    assert f.rule_id == "dns_missing"
    assert "manquant" in f.message


def test_dns_missing_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("dns_missing", r) == []


def test_dns_missing_evidence_reprend_les_textes_sans_packet():
    r = Report(points=["A", "B"])
    r.dns_missing[("A", "B")] = ["requete vue en A, absente en B"]
    findings = evaluate("dns_missing", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "requete vue en A, absente en B"
    assert ev.packet is None


def test_dns_missing_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.dns_missing[("A", "B")] = ["requete vue en A, absente en B"]
    r.dns_missing[("B", "C")]  # presente mais vide : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "dns_missing"]
    via_moteur = evaluate("dns_missing", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- tcp_retransmission_rto (Session 58) -- meme forme que
# tcp_zero_window (Session 56) : compteur dict[str, int], severite
# unique 'a_surveiller' lue depuis rule.severity.


def test_tcp_retransmission_rto_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.retrans_rto["A"] = 3
    findings = evaluate("tcp_retransmission_rto", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_retransmission_rto"
    assert "expiration de minuteur" in f.message


def test_tcp_retransmission_rto_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_retransmission_rto", r) == []


def test_tcp_retransmission_rto_nul_pas_de_finding():
    r = Report(points=["A"])
    r.retrans_rto["A"] = 0
    assert evaluate("tcp_retransmission_rto", r) == []


def test_tcp_retransmission_rto_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.retrans_rto["A"] = 3
    r.retrans_rto["B"] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_retransmission_rto"]
    via_moteur = evaluate("tcp_retransmission_rto", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- tcp_retransmission_spurious (Session 58) -- meme forme,
# report.retrans_spurious, severite unique 'a_surveiller'.


def test_tcp_retransmission_spurious_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.retrans_spurious["A"] = 4
    findings = evaluate("tcp_retransmission_spurious", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_retransmission_spurious"
    assert "inutile" in f.message


def test_tcp_retransmission_spurious_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_retransmission_spurious", r) == []


def test_tcp_retransmission_spurious_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.retrans_spurious["A"] = 4
    r.retrans_spurious["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_retransmission_spurious"]
    via_moteur = evaluate("tcp_retransmission_spurious", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- tcp_retransmission_fast (Session 58) -- meme forme,
# report.retrans_fast, severite unique 'info' (seule 'info' de ce lot).


def test_tcp_retransmission_fast_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.retrans_fast["A"] = 7
    findings = evaluate("tcp_retransmission_fast", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_retransmission_fast"
    assert "3 ACK dupliques" in f.message


def test_tcp_retransmission_fast_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_retransmission_fast", r) == []


def test_tcp_retransmission_fast_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.retrans_fast["A"] = 7
    r.retrans_fast["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_retransmission_fast"]
    via_moteur = evaluate("tcp_retransmission_fast", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- tcp_rst_localized (Session 58) -- meme forme, report.rst_localized,
# severite unique 'anomalie'.


def test_tcp_rst_localized_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.rst_localized["A"] = 5
    findings = evaluate("tcp_rst_localized", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_rst_localized"
    assert "injection locale probable" in f.message


def test_tcp_rst_localized_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_rst_localized", r) == []


def test_tcp_rst_localized_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.rst_localized["A"] = 5
    r.rst_localized["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_rst_localized"]
    via_moteur = evaluate("tcp_rst_localized", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- tcp_syn_no_synack (Session 58) -- meme forme, report.syn_no_synack,
# severite unique 'anomalie'.


def test_tcp_syn_no_synack_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.syn_no_synack["A"] = 2
    findings = evaluate("tcp_syn_no_synack", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_syn_no_synack"
    assert "bloquees" in f.message


def test_tcp_syn_no_synack_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tcp_syn_no_synack", r) == []


def test_tcp_syn_no_synack_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.syn_no_synack["A"] = 2
    r.syn_no_synack["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_syn_no_synack"]
    via_moteur = evaluate("tcp_syn_no_synack", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- syn_reply_missing (Session 58) -- meme forme,
# report.syn_reply_missing, severite unique 'anomalie'.


def test_syn_reply_missing_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.syn_reply_missing["A"] = 1
    findings = evaluate("syn_reply_missing", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "syn_reply_missing"
    assert "ne remonte pas" in f.message


def test_syn_reply_missing_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("syn_reply_missing", r) == []


def test_syn_reply_missing_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.syn_reply_missing["A"] = 1
    r.syn_reply_missing["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "syn_reply_missing"]
    via_moteur = evaluate("syn_reply_missing", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- tcp_options_stripped (Session 59) -- PREMIERE regle de ce pilote a
# fusionner DEUX compteurs Report distincts (wscale_stripped,
# sack_stripped) sous un seul rule_id, meme severite 'a_surveiller'
# pour les deux.


def test_tcp_options_stripped_wscale_seul_declenche():
    r = Report(points=["A", "B"])
    r.wscale_stripped[("A", "B")] = 3
    findings = evaluate("tcp_options_stripped", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "TCP"
    assert f.segment == "A -> B"
    assert f.rule_id == "tcp_options_stripped"
    assert "Window Scale" in f.message


def test_tcp_options_stripped_sack_seul_declenche():
    r = Report(points=["A", "B"])
    r.sack_stripped[("A", "B")] = 2
    findings = evaluate("tcp_options_stripped", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "TCP"
    assert f.segment == "A -> B"
    assert f.rule_id == "tcp_options_stripped"
    assert "SACK Permitted" in f.message


def test_tcp_options_stripped_wscale_et_sack_deux_findings():
    r = Report(points=["A", "B"])
    r.wscale_stripped[("A", "B")] = 3
    r.sack_stripped[("A", "B")] = 2
    findings = evaluate("tcp_options_stripped", r)
    assert len(findings) == 2
    assert all(f.rule_id == "tcp_options_stripped" for f in findings)
    assert all(f.severity == "a_surveiller" for f in findings)
    assert "Window Scale" in findings[0].message
    assert "SACK Permitted" in findings[1].message


def test_tcp_options_stripped_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("tcp_options_stripped", r) == []


def test_tcp_options_stripped_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.wscale_stripped[("A", "B")] = 3
    r.sack_stripped[("A", "B")] = 2

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_options_stripped"]
    via_moteur = evaluate("tcp_options_stripped", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )


# -- tcp_mss_clamped (Session 59) -- clee par paire de points comme
# tcp_options_stripped, mais evidence non vide (comme dns_timeout/
# dns_missing, Session 57), severite unique 'info'.


def test_tcp_mss_clamped_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 4
    findings = evaluate("tcp_mss_clamped", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "TCP"
    assert f.segment == "A -> B"
    assert f.rule_id == "tcp_mss_clamped"
    assert "MSS reduit" in f.message


def test_tcp_mss_clamped_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("tcp_mss_clamped", r) == []


def test_tcp_mss_clamped_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 0
    assert evaluate("tcp_mss_clamped", r) == []


def test_tcp_mss_clamped_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A", "B"])
    r.mss_clamped[("A", "B")] = 4
    r.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    r.mss_clamped_frames[("A", "B")] = [17]
    findings = evaluate("tcp_mss_clamped", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "MSS 1460 -> 1400"
    assert ev.packet is not None
    assert ev.packet.frame_number == 17


def test_tcp_mss_clamped_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.mss_clamped[("A", "B")] = 4
    r.mss_clamped_examples[("A", "B")] = ["MSS 1460 -> 1400"]
    r.mss_clamped_frames[("A", "B")] = [17]
    r.mss_clamped[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tcp_mss_clamped"]
    via_moteur = evaluate("tcp_mss_clamped", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- nat_fw_silent_drop (Session 67) -- meme forme que tcp_mss_clamped,
# report.idle_timeout_dropped, PAR PAIRE de points, evidence non vide,
# severite unique 'anomalie'.


def test_nat_fw_silent_drop_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 2
    findings = evaluate("nat_fw_silent_drop", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "NAT/Pare-feu"
    assert f.segment == "A -> B"
    assert f.rule_id == "nat_fw_silent_drop"
    assert "coupure NAT/pare-feu silencieuse probable" in f.message


def test_nat_fw_silent_drop_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("nat_fw_silent_drop", r) == []


def test_nat_fw_silent_drop_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 0
    assert evaluate("nat_fw_silent_drop", r) == []


def test_nat_fw_silent_drop_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A", "B"])
    r.idle_timeout_dropped[("A", "B")] = 2
    r.idle_timeout_examples[("A", "B")] = ["10.0.0.5:51000 -> 10.0.0.9:443 (silence 90.0s)"]
    r.idle_timeout_frames[("A", "B")] = [42]
    findings = evaluate("nat_fw_silent_drop", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "10.0.0.5:51000 -> 10.0.0.9:443 (silence 90.0s)"
    assert ev.packet is not None
    assert ev.packet.frame_number == 42


def test_nat_fw_silent_drop_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.idle_timeout_dropped[("A", "B")] = 2
    r.idle_timeout_examples[("A", "B")] = ["10.0.0.5:51000 -> 10.0.0.9:443 (silence 90.0s)"]
    r.idle_timeout_frames[("A", "B")] = [42]
    r.idle_timeout_dropped[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "nat_fw_silent_drop"]
    via_moteur = evaluate("nat_fw_silent_drop", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- ttl_variation (Session 60) -- meme forme que tcp_zero_window,
# report.ttl_unstable, severite unique 'a_surveiller'.


def test_ttl_variation_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.ttl_unstable["A"] = 3
    findings = evaluate("ttl_variation", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "Routage"
    assert f.segment == "A"
    assert f.rule_id == "ttl_variation"
    assert "TTL variable" in f.message


def test_ttl_variation_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("ttl_variation", r) == []


def test_ttl_variation_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.ttl_unstable["A"] = 3
    r.ttl_unstable["B"] = 0  # present mais nul : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "ttl_variation"]
    via_moteur = evaluate("ttl_variation", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- pcp_change (Session 60) -- meme forme que hop_delta_outliers,
# report.pcp_change, cle par paire de points, severite unique
# 'a_surveiller'.


def test_pcp_change_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.pcp_change[("A", "B")] = 2
    findings = evaluate("pcp_change", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "QoS"
    assert f.segment == "A -> B"
    assert f.rule_id == "pcp_change"
    assert "802.1p" in f.message


def test_pcp_change_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("pcp_change", r) == []


def test_pcp_change_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.pcp_change[("A", "B")] = 2
    r.pcp_change[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "pcp_change"]
    via_moteur = evaluate("pcp_change", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- icmp_fragmentation_needed (Session 60) -- DEUXIEME regle de ce
# pilote a fusionner deux compteurs Report distincts sous un seul
# rule_id (apres tcp_options_stripped, Session 59), mais par POINT
# (pas par paire) et sans evidence -- report.icmp_frag_needed (IPv4)
# et report.icmpv6_too_big (IPv6), severite unique 'info' pour les
# deux.


def test_icmp_fragmentation_needed_ipv4_seul_declenche():
    r = Report(points=["A"])
    r.icmp_frag_needed["A"] = 3
    findings = evaluate("icmp_fragmentation_needed", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "Fragmentation"
    assert f.segment == "A"
    assert f.rule_id == "icmp_fragmentation_needed"
    assert "ICMP Fragmentation Needed" in f.message


def test_icmp_fragmentation_needed_ipv6_seul_declenche():
    r = Report(points=["A"])
    r.icmpv6_too_big["A"] = 2
    findings = evaluate("icmp_fragmentation_needed", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "Fragmentation"
    assert f.segment == "A"
    assert f.rule_id == "icmp_fragmentation_needed"
    assert "ICMPv6 Packet Too Big" in f.message


def test_icmp_fragmentation_needed_ipv4_et_ipv6_deux_findings():
    r = Report(points=["A"])
    r.icmp_frag_needed["A"] = 3
    r.icmpv6_too_big["A"] = 2
    findings = evaluate("icmp_fragmentation_needed", r)
    assert len(findings) == 2
    assert all(f.rule_id == "icmp_fragmentation_needed" for f in findings)
    assert all(f.severity == "info" for f in findings)
    assert "ICMP Fragmentation Needed" in findings[0].message
    assert "ICMPv6 Packet Too Big" in findings[1].message


def test_icmp_fragmentation_needed_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("icmp_fragmentation_needed", r) == []


def test_icmp_fragmentation_needed_equivalent_a_build_findings():
    r = Report(points=["A"])
    r.icmp_frag_needed["A"] = 3
    r.icmpv6_too_big["A"] = 2

    procedural = [f for f in build_findings(r) if f.rule_id == "icmp_fragmentation_needed"]
    via_moteur = evaluate("icmp_fragmentation_needed", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )


# -- tls_cert_invalid_dates (Session 61) -- meme forme que
# tcp_mss_clamped, report.tls_cert_invalid_dates, PAR POINT, compteur
# entier + evidence a trois arguments, severite unique 'anomalie'.


def test_tls_cert_invalid_dates_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.tls_cert_invalid_dates["A"] = 2
    findings = evaluate("tls_cert_invalid_dates", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TLS"
    assert f.segment == "A"
    assert f.rule_id == "tls_cert_invalid_dates"
    assert "hors de leur fenetre de validite" in f.message


def test_tls_cert_invalid_dates_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tls_cert_invalid_dates", r) == []


def test_tls_cert_invalid_dates_nul_pas_de_finding():
    r = Report(points=["A"])
    r.tls_cert_invalid_dates["A"] = 0
    assert evaluate("tls_cert_invalid_dates", r) == []


def test_tls_cert_invalid_dates_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.tls_cert_invalid_dates["A"] = 2
    r.tls_cert_invalid_dates_examples["A"] = ["certificat expire le 2024-01-01"]
    r.tls_cert_invalid_dates_frames["A"] = [11]
    findings = evaluate("tls_cert_invalid_dates", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "certificat expire le 2024-01-01"
    assert ev.packet is not None
    assert ev.packet.frame_number == 11


def test_tls_cert_invalid_dates_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.tls_cert_invalid_dates["A"] = 2
    r.tls_cert_invalid_dates_examples["A"] = ["certificat expire le 2024-01-01"]
    r.tls_cert_invalid_dates_frames["A"] = [11]
    r.tls_cert_invalid_dates["B"] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tls_cert_invalid_dates"]
    via_moteur = evaluate("tls_cert_invalid_dates", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- tls_cert_mismatch (Session 61) -- meme forme que tcp_mss_clamped,
# report.tls_cert_mismatch, PAR PAIRE de points adjacents, compteur
# entier + evidence a trois arguments, severite unique 'anomalie'.


def test_tls_cert_mismatch_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    findings = evaluate("tls_cert_mismatch", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TLS"
    assert f.segment == "A -> B"
    assert f.rule_id == "tls_cert_mismatch"
    assert "certificat different" in f.message


def test_tls_cert_mismatch_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("tls_cert_mismatch", r) == []


def test_tls_cert_mismatch_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 0
    assert evaluate("tls_cert_mismatch", r) == []


def test_tls_cert_mismatch_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A", "B"])
    r.tls_cert_mismatch[("A", "B")] = 1
    r.tls_cert_mismatch_examples[("A", "B")] = ["serie 0x1 en A, 0x2 en B"]
    r.tls_cert_mismatch_frames[("A", "B")] = [23]
    findings = evaluate("tls_cert_mismatch", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "serie 0x1 en A, 0x2 en B"
    assert ev.packet is not None
    assert ev.packet.frame_number == 23


def test_tls_cert_mismatch_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.tls_cert_mismatch[("A", "B")] = 1
    r.tls_cert_mismatch_examples[("A", "B")] = ["serie 0x1 en A, 0x2 en B"]
    r.tls_cert_mismatch_frames[("A", "B")] = [23]
    r.tls_cert_mismatch[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tls_cert_mismatch"]
    via_moteur = evaluate("tls_cert_mismatch", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- tls_handshake_no_reply (Session 61) -- meme forme que
# tls_cert_invalid_dates, report.tls_handshake_no_reply, PAR POINT,
# severite unique 'anomalie'.


def test_tls_handshake_no_reply_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.tls_handshake_no_reply["A"] = 3
    findings = evaluate("tls_handshake_no_reply", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TLS"
    assert f.segment == "A"
    assert f.rule_id == "tls_handshake_no_reply"
    assert "sans reponse" in f.message


def test_tls_handshake_no_reply_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tls_handshake_no_reply", r) == []


def test_tls_handshake_no_reply_nul_pas_de_finding():
    r = Report(points=["A"])
    r.tls_handshake_no_reply["A"] = 0
    assert evaluate("tls_handshake_no_reply", r) == []


def test_tls_handshake_no_reply_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.tls_handshake_no_reply["A"] = 3
    r.tls_handshake_no_reply_examples["A"] = ["ClientHello vers 10.0.0.1:443"]
    r.tls_handshake_no_reply_frames["A"] = [5]
    findings = evaluate("tls_handshake_no_reply", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "ClientHello vers 10.0.0.1:443"
    assert ev.packet is not None
    assert ev.packet.frame_number == 5


def test_tls_handshake_no_reply_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.tls_handshake_no_reply["A"] = 3
    r.tls_handshake_no_reply_examples["A"] = ["ClientHello vers 10.0.0.1:443"]
    r.tls_handshake_no_reply_frames["A"] = [5]
    r.tls_handshake_no_reply["B"] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tls_handshake_no_reply"]
    via_moteur = evaluate("tls_handshake_no_reply", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- tls_handshake_incomplete (Session 61) -- meme forme que
# tls_handshake_no_reply, report.tls_handshake_incomplete, PAR POINT,
# severite unique 'anomalie'.


def test_tls_handshake_incomplete_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.tls_handshake_incomplete["A"] = 1
    findings = evaluate("tls_handshake_incomplete", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TLS"
    assert f.segment == "A"
    assert f.rule_id == "tls_handshake_incomplete"
    assert "interrompue" in f.message


def test_tls_handshake_incomplete_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("tls_handshake_incomplete", r) == []


def test_tls_handshake_incomplete_nul_pas_de_finding():
    r = Report(points=["A"])
    r.tls_handshake_incomplete["A"] = 0
    assert evaluate("tls_handshake_incomplete", r) == []


def test_tls_handshake_incomplete_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.tls_handshake_incomplete["A"] = 1
    r.tls_handshake_incomplete_examples["A"] = ["ServerHello recu, rien ensuite"]
    r.tls_handshake_incomplete_frames["A"] = [9]
    findings = evaluate("tls_handshake_incomplete", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "ServerHello recu, rien ensuite"
    assert ev.packet is not None
    assert ev.packet.frame_number == 9


def test_tls_handshake_incomplete_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.tls_handshake_incomplete["A"] = 1
    r.tls_handshake_incomplete_examples["A"] = ["ServerHello recu, rien ensuite"]
    r.tls_handshake_incomplete_frames["A"] = [9]
    r.tls_handshake_incomplete["B"] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "tls_handshake_incomplete"]
    via_moteur = evaluate("tls_handshake_incomplete", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- http_timeout (Session 61) -- meme forme que dns_timeout,
# report.http_timeout, PAR POINT, compteur en LISTE (condition
# `if timeouts:`, pas `n > 0`), severite unique 'anomalie'.


def test_http_timeout_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["GET /index.html vu, jamais de reponse"]
    findings = evaluate("http_timeout", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "HTTP"
    assert f.segment == "A"
    assert f.rule_id == "http_timeout"
    assert "sans aucune reponse" in f.message


def test_http_timeout_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("http_timeout", r) == []


def test_http_timeout_liste_vide_pas_de_finding():
    # Cle presente (defaultdict) mais liste vide : ne doit pas declencher,
    # meme discipline que dns_timeout["A"] = [] (Session 57).
    r = Report(points=["A"])
    r.http_timeout["A"]  # touche la cle sans y ajouter d'element (defaultdict)
    assert evaluate("http_timeout", r) == []


def test_http_timeout_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.http_timeout["A"] = ["GET /index.html vu, jamais de reponse"]
    r.http_timeout_frames["A"] = [31]
    findings = evaluate("http_timeout", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "GET /index.html vu, jamais de reponse"
    assert ev.packet is not None
    assert ev.packet.frame_number == 31


def test_http_timeout_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.http_timeout["A"] = ["GET /index.html vu, jamais de reponse"]
    r.http_timeout_frames["A"] = [31]
    r.http_timeout["B"]  # presente mais vide : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "http_timeout"]
    via_moteur = evaluate("http_timeout", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- http_missing (Session 61) -- meme forme que dns_missing,
# report.http_missing, PAR PAIRE de points adjacents, compteur en
# LISTE, evidence SANS frames (absent de Report pour ce compteur,
# verifie dans models.py), severite unique 'a_surveiller'.


def test_http_missing_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.http_missing[("A", "B")] = ["GET /index.html vu en A, absent en B"]
    findings = evaluate("http_missing", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "HTTP"
    assert f.segment == "A -> B"
    assert f.rule_id == "http_missing"
    assert "manquant" in f.message


def test_http_missing_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("http_missing", r) == []


def test_http_missing_evidence_reprend_les_textes_sans_packet():
    r = Report(points=["A", "B"])
    r.http_missing[("A", "B")] = ["GET /index.html vu en A, absent en B"]
    findings = evaluate("http_missing", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "GET /index.html vu en A, absent en B"
    assert ev.packet is None


def test_http_missing_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.http_missing[("A", "B")] = ["GET /index.html vu en A, absent en B"]
    r.http_missing[("B", "C")]  # presente mais vide : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "http_missing"]
    via_moteur = evaluate("http_missing", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- http_client_error (Session 62) -- report.http_client_error_count,
# PAR POINT, compteur ENTIER (condition `n > 0`, pas une liste comme
# http_timeout/http_missing), evidence filtree par
# _http_error_evidence() (DEUXIEME fonction privee copiee par ce
# pilote) depuis le champ PARTAGE report.http_error_examples (melange
# 4xx/5xx a la collecte), severite unique 'info'.


def test_http_client_error_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /login -> 404"]
    findings = evaluate("http_client_error", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.category == "HTTP"
    assert f.segment == "A"
    assert f.rule_id == "http_client_error"
    assert "4xx" in f.message


def test_http_client_error_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("http_client_error", r) == []


def test_http_client_error_compteur_nul_pas_de_finding():
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 0  # touche la cle sans la depasser (defaultdict)
    assert evaluate("http_client_error", r) == []


def test_http_client_error_evidence_filtre_les_5xx_du_champ_partage():
    # http_error_examples melange volontairement 4xx et 5xx a la
    # collecte (Report.http_error_examples, un seul champ) : seul le
    # 4xx doit apparaitre dans l'evidence de http_client_error.
    r = Report(points=["A"])
    r.http_client_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /login -> 404", "GET /api -> 500"]
    r.http_error_frames["A"] = [12, 13]
    findings = evaluate("http_client_error", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "GET /login -> 404"
    assert ev.packet is not None
    assert ev.packet.frame_number == 12


def test_http_client_error_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.http_client_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /login -> 404", "GET /api -> 500"]
    r.http_error_frames["A"] = [12, 13]
    r.http_client_error_count["B"] = 0  # presente mais nul : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "http_client_error"]
    via_moteur = evaluate("http_client_error", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- http_server_error (Session 62) -- meme forme que http_client_error
# ci-dessus (report.http_server_error_count, PAR POINT, compteur
# ENTIER), evidence filtree par _http_error_evidence() sur classe de
# statut 5 cette fois, severite unique 'anomalie'.


def test_http_server_error_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /api -> 500"]
    findings = evaluate("http_server_error", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "HTTP"
    assert f.segment == "A"
    assert f.rule_id == "http_server_error"
    assert "5xx" in f.message


def test_http_server_error_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("http_server_error", r) == []


def test_http_server_error_compteur_nul_pas_de_finding():
    r = Report(points=["A"])
    r.http_server_error_count["A"] = 0
    assert evaluate("http_server_error", r) == []


def test_http_server_error_evidence_filtre_les_4xx_du_champ_partage():
    r = Report(points=["A"])
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /login -> 404", "GET /api -> 500"]
    r.http_error_frames["A"] = [12, 13]
    findings = evaluate("http_server_error", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "GET /api -> 500"
    assert ev.packet is not None
    assert ev.packet.frame_number == 13


def test_http_server_error_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.http_server_error_count["A"] = 1
    r.http_error_examples["A"] = ["GET /login -> 404", "GET /api -> 500"]
    r.http_error_frames["A"] = [12, 13]
    r.http_server_error_count["B"] = 0

    procedural = [f for f in build_findings(r) if f.rule_id == "http_server_error"]
    via_moteur = evaluate("http_server_error", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- dhcp_issues (Session 63) -- TROISIEME regle de ce pilote a fusionner
# deux compteurs Report distincts sous un seul rule_id (apres
# tcp_options_stripped -- Session 59 -- et icmp_fragmentation_needed --
# Session 60), mais PREMIERE dont les deux compteurs n'ont pas la meme
# forme entre eux : dhcp_nak_count (PAR POINT, entier, sans evidence,
# forme de tcp_zero_window) et dhcp_missing (PAR PAIRE, LISTE, avec
# evidence a deux arguments, forme de dns_missing). Tests dedies a
# chacun des deux compteurs separement, meme discipline que les deux
# regles fusionnees precedentes.


def test_dhcp_issues_nak_seul_declenche():
    r = Report(points=["A"])
    r.dhcp_nak_count["A"] = 2
    findings = evaluate("dhcp_issues", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "DHCP"
    assert f.segment == "A"
    assert f.rule_id == "dhcp_issues"
    assert "DHCPNAK" in f.message
    assert f.evidence == []  # ce compteur ne porte aucune preuve, cote procedural comme ici


def test_dhcp_issues_missing_seul_declenche():
    r = Report(points=["A", "B"])
    r.dhcp_missing[("A", "B")] = ["DHCPOFFER", "DHCPACK"]
    findings = evaluate("dhcp_issues", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "DHCP"
    assert f.segment == "A -> B"
    assert f.rule_id == "dhcp_issues"
    assert "2 message(s) DHCP manquant(s)" in f.message


def test_dhcp_issues_nak_et_missing_deux_findings():
    r = Report(points=["A", "B"])
    r.dhcp_nak_count["A"] = 1
    r.dhcp_missing[("A", "B")] = ["DHCPACK"]
    findings = evaluate("dhcp_issues", r)
    assert len(findings) == 2
    assert all(f.rule_id == "dhcp_issues" for f in findings)
    assert all(f.severity == "anomalie" for f in findings)
    # meme ordre que les deux boucles consecutives du bloc source
    assert "DHCPNAK" in findings[0].message
    assert "manquant(s)" in findings[1].message


def test_dhcp_issues_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("dhcp_issues", r) == []


def test_dhcp_issues_compteur_nul_et_liste_vide_pas_de_finding():
    # les deux conditions de garde different entre les deux compteurs
    # (n > 0 pour l'entier, liste non vide pour la liste) : les deux
    # verifiees ici sur des cles touchees mais sans contenu.
    r = Report(points=["A", "B"])
    r.dhcp_nak_count["A"] = 0
    r.dhcp_missing[("A", "B")] = []
    assert evaluate("dhcp_issues", r) == []


def test_dhcp_issues_evidence_du_compteur_missing():
    # aucun champ dhcp_missing_frames sur Report (verifie dans
    # models.py) : _evidence() est appele a DEUX arguments cote
    # procedural, donc aucun PacketEvidence attache -- comme
    # dns_missing/http_missing, contrairement a dns_timeout.
    r = Report(points=["A", "B"])
    r.dhcp_missing[("A", "B")] = ["DHCPOFFER", "DHCPACK"]
    findings = evaluate("dhcp_issues", r)
    evidence = findings[0].evidence
    assert len(evidence) == 2
    assert [e.point for e in evidence] == ["A -> B", "A -> B"]
    assert [e.text for e in evidence] == ["DHCPOFFER", "DHCPACK"]
    assert all(e.packet is None for e in evidence)


def test_dhcp_issues_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.dhcp_nak_count["A"] = 1
    r.dhcp_nak_count["B"] = 0  # presente mais nulle : ne doit declencher ni d'un cote ni de l'autre
    r.dhcp_missing[("A", "B")] = ["DHCPOFFER", "DHCPACK"]

    # comparaison positionnelle possible ici, mais par COINCIDENCE :
    # build_findings trie sa liste avant de la renvoyer (voir
    # test_sip_issues_ordre_procedural_differe_de_l_ordre_de_construction)
    # et les segments de cette regle ("A" puis "A -> B") sont deja dans
    # l'ordre du tri. L'ordre de construction est verifie separement par
    # test_dhcp_issues_nak_et_missing_deux_findings ci-dessus.
    procedural = [f for f in build_findings(r) if f.rule_id == "dhcp_issues"]
    via_moteur = evaluate("dhcp_issues", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )
        assert len(p.evidence) == len(m.evidence)
        for pe, me in zip(p.evidence, m.evidence, strict=True):
            assert (pe.point, pe.text, pe.packet) == (me.point, me.text, me.packet)


# -- sip_issues (Session 63) -- derniere regle a compteurs fusionnes
# heterogenes, et seule de tout ce pilote a lire une source qui n'est
# pas un dict compteur : Report.sip_failed_calls est une list[str] de
# messages deja formates, un Finding par entree sur le segment litteral
# "global", sans condition de garde ni evidence. sip_missing reprend
# exactement la forme de dhcp_missing ci-dessus.


def test_sip_issues_failed_calls_un_finding_par_entree():
    r = Report(points=["A"])
    r.sip_failed_calls = ["appel 1234@pbx echoue (486 Busy Here)", "appel 5678@pbx echoue (503)"]
    findings = evaluate("sip_issues", r)
    assert len(findings) == 2
    assert all(f.severity == "anomalie" for f in findings)
    assert all(f.category == "SIP" for f in findings)
    assert all(f.segment == "global" for f in findings)
    assert all(f.rule_id == "sip_issues" for f in findings)
    # le message EST recopie tel quel depuis la liste deja formatee
    assert [f.message for f in findings] == r.sip_failed_calls
    # pas d'evidence : le message est deja la preuve (choix du bloc source)
    assert all(f.evidence == [] for f in findings)


def test_sip_issues_missing_seul_declenche():
    r = Report(points=["A", "B"])
    r.sip_missing[("A", "B")] = ["INVITE"]
    findings = evaluate("sip_issues", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "SIP"
    assert f.segment == "A -> B"
    assert f.rule_id == "sip_issues"
    assert "1 message(s) de signalisation manquant(s)" in f.message


def test_sip_issues_failed_calls_et_missing_deux_findings():
    r = Report(points=["A", "B"])
    r.sip_failed_calls = ["appel 1234@pbx echoue (486 Busy Here)"]
    r.sip_missing[("A", "B")] = ["INVITE"]
    findings = evaluate("sip_issues", r)
    assert len(findings) == 2
    assert all(f.rule_id == "sip_issues" for f in findings)
    # meme ordre que le bloc source : la comprehension sur
    # sip_failed_calls precede la boucle sur sip_missing
    assert findings[0].segment == "global"
    assert findings[1].segment == "A -> B"


def test_sip_issues_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("sip_issues", r) == []


def test_sip_issues_liste_vide_pas_de_finding():
    # sip_failed_calls vide ne produit rien PAR CONSTRUCTION (aucune
    # condition de garde dans la comprehension source, contrairement
    # aux autres formes) ; sip_missing garde bien `if missing:`.
    r = Report(points=["A", "B"])
    r.sip_failed_calls = []
    r.sip_missing[("A", "B")] = []
    assert evaluate("sip_issues", r) == []


def test_sip_issues_evidence_du_compteur_missing():
    r = Report(points=["A", "B"])
    r.sip_missing[("A", "B")] = ["INVITE", "BYE"]
    findings = evaluate("sip_issues", r)
    evidence = findings[0].evidence
    assert len(evidence) == 2
    assert [e.text for e in evidence] == ["INVITE", "BYE"]
    assert all(e.point == "A -> B" for e in evidence)
    assert all(e.packet is None for e in evidence)


def test_sip_issues_ordre_procedural_differe_de_l_ordre_de_construction():
    """Decouverte de la Session 63, jamais rencontree par les 26 regles
    pilotees avant : `build_findings()` TRIE sa liste complete avant de
    la renvoyer (`findings.sort(key=(SEVERITY_ORDER, category,
    segment))`, derniere ligne de la fonction), alors qu'`evaluate()`
    renvoie ses Finding dans l'ordre de CONSTRUCTION du bloc source.

    Pour les 26 regles precedentes les deux ordres coincidaient par
    hasard (segments deja tries, ou tous identiques -- cas de
    `tcp_options_stripped`, deux Finding sur le meme segment, tri stable
    donc ordre preserve). `sip_issues` est la premiere a les separer :
    ses deux sites de construction produisent respectivement le segment
    litteral "global" (d'abord) puis "A -> B", que le tri final remet
    dans l'ordre inverse ("A" majuscule < "g" minuscule).

    `evaluate()` ne reproduit deliberement PAS ce tri : c'est une etape
    de PRESENTATION appliquee par `build_findings()` a l'ensemble des
    41 regles a la fois, pas une propriete d'une regle donnee -- un
    evaluateur qui trierait ses propres Finding donnerait d'ailleurs un
    ordre different du tri global des que deux regles se melangent.
    Consequence directe : le test d'equivalence de cette regle compare
    les deux chemins par CONTENU (meme cle de tri appliquee aux deux
    cotes), pas positionnellement -- voir ci-dessous.
    """
    r = Report(points=["A", "B"])
    r.sip_failed_calls = ["appel 1234@pbx echoue (486 Busy Here)"]
    r.sip_missing[("A", "B")] = ["INVITE"]

    procedural = [f for f in build_findings(r) if f.rule_id == "sip_issues"]
    via_moteur = evaluate("sip_issues", r)
    assert [f.segment for f in procedural] == ["A -> B", "global"]  # ordre TRIE
    assert [f.segment for f in via_moteur] == ["global", "A -> B"]  # ordre de CONSTRUCTION


def test_sip_issues_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.sip_failed_calls = ["appel 1234@pbx echoue (486 Busy Here)"]
    r.sip_missing[("A", "B")] = ["INVITE", "BYE"]

    # comparaison par CONTENU et non positionnelle : les deux chemins
    # produisent les memes Finding mais pas dans le meme ordre (tri
    # final de build_findings -- voir le test ci-dessus). Meme cle de
    # tri appliquee aux deux cotes pour les rendre comparables.
    def _cle(f):
        return (f.severity, f.category, f.segment, f.message)

    procedural = sorted((f for f in build_findings(r) if f.rule_id == "sip_issues"), key=_cle)
    via_moteur = sorted(evaluate("sip_issues", r), key=_cle)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )
        assert len(p.evidence) == len(m.evidence)
        for pe, me in zip(p.evidence, m.evidence, strict=True):
            assert (pe.point, pe.text, pe.packet) == (me.point, me.text, me.packet)


# -- vlan_change (Session 64) -- premiere regle PILOTEE parmi les treize
# jamais auditees identifiees par la Session 63. Meme forme que
# hop_delta_outliers/pcp_change, report.vlan_change, cle par paire de
# points, severite unique 'a_surveiller'.


def test_vlan_change_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.vlan_change[("A", "B")] = 3
    findings = evaluate("vlan_change", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "VLAN"
    assert f.segment == "A -> B"
    assert f.rule_id == "vlan_change"
    assert "VLAN" in f.message


def test_vlan_change_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("vlan_change", r) == []


def test_vlan_change_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.vlan_change[("A", "B")] = 3
    r.vlan_change[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "vlan_change"]
    via_moteur = evaluate("vlan_change", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- arp_ip_conflict (Session 65) -- deuxieme regle PILOTEE parmi les
# douze restees jamais auditees apres la Session 64. Meme forme que
# tls_cert_invalid_dates, report.arp_ip_conflict, PAR POINT, compteur
# entier + evidence a trois arguments, severite unique 'anomalie'.
# Threshold catalogue (min_distinct_macs) non consomme par ce bloc --
# voir docstring de _evaluate_arp_ip_conflict, rule_engine.py.


def test_arp_ip_conflict_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.arp_ip_conflict["A"] = 1
    findings = evaluate("arp_ip_conflict", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "ARP"
    assert f.segment == "A"
    assert f.rule_id == "arp_ip_conflict"
    assert "conflit d'adresse IP probable" in f.message


def test_arp_ip_conflict_absent_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("arp_ip_conflict", r) == []


def test_arp_ip_conflict_nul_pas_de_finding():
    r = Report(points=["A"])
    r.arp_ip_conflict["A"] = 0
    assert evaluate("arp_ip_conflict", r) == []


def test_arp_ip_conflict_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.arp_ip_conflict["A"] = 1
    r.arp_ip_conflict_examples["A"] = ["10.0.0.5 revendique par 2 adresses MAC differentes : aa:aa, bb:bb"]
    r.arp_ip_conflict_frames["A"] = [42]
    findings = evaluate("arp_ip_conflict", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "10.0.0.5 revendique par 2 adresses MAC differentes : aa:aa, bb:bb"
    assert ev.packet is not None
    assert ev.packet.frame_number == 42


def test_arp_ip_conflict_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.arp_ip_conflict["A"] = 1
    r.arp_ip_conflict_examples["A"] = ["10.0.0.5 revendique par 2 adresses MAC differentes : aa:aa, bb:bb"]
    r.arp_ip_conflict_frames["A"] = [42]
    r.arp_ip_conflict["B"] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "arp_ip_conflict"]
    via_moteur = evaluate("arp_ip_conflict", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- stp_instability (Session 66) -- QUATRIEME regle de ce pilote a
# fusionner deux compteurs Report distincts sous un seul rule_id (apres
# tcp_options_stripped -- Session 59 --, icmp_fragmentation_needed --
# Session 60 -- et dhcp_issues -- Session 63). Candidat le mieux connu
# des six regles jamais auditees identifiees par la Session 63.
# Contrairement a dhcp_issues, les deux compteurs fusionnes ici
# partagent la MEME granularite (par point) et la MEME condition de
# garde -- seule la presence d'evidence differe entre les deux boucles.


def test_stp_instability_topology_change_seul_declenche():
    r = Report(points=["A"])
    r.stp_topology_change["A"] = 3
    findings = evaluate("stp_instability", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "STP"
    assert f.segment == "A"
    assert f.rule_id == "stp_instability"
    assert "changement de topologie STP" in f.message
    assert f.evidence == []  # ce compteur ne porte aucune preuve, cote procedural comme ici


def test_stp_instability_root_change_seul_declenche():
    r = Report(points=["A"])
    r.stp_root_change["A"] = 2
    findings = evaluate("stp_instability", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "STP"
    assert f.segment == "A"
    assert f.rule_id == "stp_instability"
    assert "reelection(s) du pont racine" in f.message


def test_stp_instability_topology_et_root_deux_findings():
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 1
    r.stp_root_change["B"] = 1
    findings = evaluate("stp_instability", r)
    assert len(findings) == 2
    assert all(f.rule_id == "stp_instability" for f in findings)
    assert all(f.severity == "anomalie" for f in findings)
    # meme ordre que les deux boucles consecutives du bloc source
    assert "topologie" in findings[0].message
    assert "reelection" in findings[1].message


def test_stp_instability_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("stp_instability", r) == []


def test_stp_instability_compteurs_nuls_pas_de_finding():
    # les deux compteurs partagent ici la meme condition de garde
    # (n <= 0 : continue), contrairement a dhcp_issues ou les deux
    # gardes different (entier vs liste non vide).
    r = Report(points=["A"])
    r.stp_topology_change["A"] = 0
    r.stp_root_change["A"] = 0
    assert evaluate("stp_instability", r) == []


def test_stp_instability_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.stp_root_change["A"] = 1
    r.stp_root_change_examples["A"] = ["pont racine change de 32768/aa:aa:aa:aa:aa:aa a 28672/bb:bb:bb:bb:bb:bb"]
    r.stp_root_change_frames["A"] = [17]
    findings = evaluate("stp_instability", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "pont racine change de 32768/aa:aa:aa:aa:aa:aa a 28672/bb:bb:bb:bb:bb:bb"
    assert ev.packet is not None
    assert ev.packet.frame_number == 17


def test_stp_instability_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.stp_topology_change["A"] = 2
    r.stp_topology_change["B"] = 0  # presente mais nulle : ne doit declencher ni cote
    r.stp_root_change["A"] = 1
    r.stp_root_change_examples["A"] = ["pont racine change de 32768/aa:aa:aa:aa:aa:aa a 28672/bb:bb:bb:bb:bb:bb"]
    r.stp_root_change_frames["A"] = [17]

    # comparaison positionnelle possible ici, mais par COINCIDENCE (meme
    # remarque que dhcp_issues) : build_findings trie sa liste avant de
    # la renvoyer, et les deux segments de cette regle sont identiques
    # ("A" puis "A") -- le tri final est stable et preserve donc l'ordre
    # de construction.
    procedural = [f for f in build_findings(r) if f.rule_id == "stp_instability"]
    via_moteur = evaluate("stp_instability", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )
        assert len(p.evidence) == len(m.evidence)
        for pe, me in zip(p.evidence, m.evidence, strict=True):
            assert (pe.point, pe.text, pe.packet) == (me.point, me.text, me.packet)


# -- dns_slow_resolution (Session 68) -----------------------------------


def test_dns_slow_resolution_au_dessus_du_seuil_declenche():
    r = Report(points=["A"])
    r.dns_duration_ms = [100.0, 300.0, 250.0]  # moyenne 216.67ms > 200ms
    findings = evaluate("dns_slow_resolution", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "DNS"
    assert f.segment == "global"
    assert f.rule_id == "dns_slow_resolution"
    assert "duree moyenne de resolution DNS" in f.message
    assert f.evidence == []  # segment "global", aucun point/paire associe


def test_dns_slow_resolution_au_ou_sous_le_seuil_pas_de_finding():
    r = Report(points=["A"])
    r.dns_duration_ms = [50.0, 150.0, 200.0]  # moyenne 133.33ms <= 200ms
    assert evaluate("dns_slow_resolution", r) == []


def test_dns_slow_resolution_liste_vide_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("dns_slow_resolution", r) == []


def test_dns_slow_resolution_sample_size_est_la_taille_de_la_liste():
    r = Report(points=["A"])
    r.dns_duration_ms = [400.0, 500.0, 600.0]
    findings = evaluate("dns_slow_resolution", r)
    assert findings[0].sample_size == 3


def test_dns_slow_resolution_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.dns_duration_ms = [220.0, 240.0, 260.0]

    procedural = [f for f in build_findings(r) if f.rule_id == "dns_slow_resolution"]
    via_moteur = evaluate("dns_slow_resolution", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id, p.sample_size) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
        m.sample_size,
    )


# -- http_slow_response (Session 68) -------------------------------------


def test_http_slow_response_au_dessus_du_seuil_declenche():
    r = Report(points=["A"])
    r.http_response_time_ms = [400.0, 600.0, 550.0]  # moyenne 516.67ms > 500ms
    findings = evaluate("http_slow_response", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "HTTP"
    assert f.segment == "global"
    assert f.rule_id == "http_slow_response"
    assert "duree moyenne de reponse HTTP" in f.message
    assert f.evidence == []  # segment "global", aucun point/paire associe


def test_http_slow_response_au_ou_sous_le_seuil_pas_de_finding():
    r = Report(points=["A"])
    r.http_response_time_ms = [100.0, 300.0, 500.0]  # moyenne 300ms <= 500ms
    assert evaluate("http_slow_response", r) == []


def test_http_slow_response_liste_vide_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("http_slow_response", r) == []


def test_http_slow_response_sample_size_est_la_taille_de_la_liste():
    r = Report(points=["A"])
    r.http_response_time_ms = [700.0, 800.0, 900.0, 1000.0]
    findings = evaluate("http_slow_response", r)
    assert findings[0].sample_size == 4


def test_http_slow_response_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.http_response_time_ms = [520.0, 540.0, 560.0]

    procedural = [f for f in build_findings(r) if f.rule_id == "http_slow_response"]
    via_moteur = evaluate("http_slow_response", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id, p.sample_size) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
        m.sample_size,
    )


# -- qos_dscp_remarking (Session 69) ---------------------------------


def test_qos_dscp_remarking_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.qos_change[("A", "B")] = 5
    r.qos_l2_remark[("A", "B")] = 3
    r.qos_l3_remark[("A", "B")] = 2
    findings = evaluate("qos_dscp_remarking", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "QoS"
    assert f.segment == "A -> B"
    assert f.rule_id == "qos_dscp_remarking"
    assert "5 paquets avec DSCP modifie" in f.message
    assert "3 sans saut de routeur -> equipement L2" in f.message
    assert "2 avec saut -> routeur" in f.message


def test_qos_dscp_remarking_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("qos_dscp_remarking", r) == []


def test_qos_dscp_remarking_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.qos_change[("A", "B")] = 0
    assert evaluate("qos_dscp_remarking", r) == []


def test_qos_dscp_remarking_compteurs_l2_l3_absents_par_defaut_a_zero():
    # qos_change peut se declencher sans que qos_l2_remark/qos_l3_remark
    # soient renseignes (delta de TTL non disponible des deux cotes,
    # voir analysis.py) -- .get(..., 0) reprend le meme comportement
    # que le bloc source.
    r = Report(points=["A", "B"])
    r.qos_change[("A", "B")] = 4
    findings = evaluate("qos_dscp_remarking", r)
    assert "0 sans saut de routeur -> equipement L2, 0 avec saut -> routeur" in findings[0].message


def test_qos_dscp_remarking_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.qos_change[("A", "B")] = 5
    r.qos_l2_remark[("A", "B")] = 3
    r.qos_l3_remark[("A", "B")] = 2
    r.qos_change[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "qos_dscp_remarking"]
    via_moteur = evaluate("qos_dscp_remarking", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- fragmentation_new (Session 69) ------------------------------------


def test_fragmentation_new_correlee_declenche_anomalie():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 4
    r.encap_frag_correlated[("A", "B")] = 2
    findings = evaluate("fragmentation_new", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "Fragmentation"
    assert f.segment == "A -> B"
    assert f.rule_id == "fragmentation_new"
    assert "4 datagrammes fragmentes, 2 coincident" in f.message
    assert "le tunnel reduit le MTU disponible" in f.message


def test_fragmentation_new_non_correlee_declenche_a_surveiller():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 4
    # encap_frag_correlated absent (0 par defaut) : sous le seuil (1.0)
    findings = evaluate("fragmentation_new", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.message == "4 datagrammes non fragmentes en amont deviennent fragmentes ici"


def test_fragmentation_new_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("fragmentation_new", r) == []


def test_fragmentation_new_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 0
    r.encap_frag_correlated[("A", "B")] = 3  # ne doit rien declencher : frag_new prime
    assert evaluate("fragmentation_new", r) == []


def test_fragmentation_new_seuil_pilote_depuis_le_catalogue():
    # correlated_encap_change_min_count = 1.0 dans le catalogue : un
    # seul evenement correle (correlated == 1, pile au seuil, pas
    # seulement au-dessus comme test_fragmentation_new_correlee_
    # declenche_anomalie ou correlated=2) suffit deja a declencher
    # 'anomalie' -- meme discipline que loss_per_segment pour son
    # propre seuil (Session 55).
    r = Report(points=["A", "B"])
    r.frag_new[("A", "B")] = 1
    r.encap_frag_correlated[("A", "B")] = 1
    findings = evaluate("fragmentation_new", r)
    assert findings[0].severity == "anomalie"


def test_fragmentation_new_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.frag_new[("A", "B")] = 4
    r.encap_frag_correlated[("A", "B")] = 2  # anomalie
    r.frag_new[("B", "C")] = 3  # a_surveiller (pas de correlation)

    procedural = [f for f in build_findings(r) if f.rule_id == "fragmentation_new"]
    via_moteur = evaluate("fragmentation_new", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )


# -- saturation (Session 69) ---------------------------------------------


def test_saturation_verdict_policing_declenche_anomalie():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = (
        "pertes concentrees sur un palier de debit tres stable, proche du "
        "maximum observe -> limitation/policing probable (seuil configure) "
        "plutot qu'une saturation progressive"
    )
    findings = evaluate("saturation", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "Saturation"
    assert f.segment == "A -> B"
    assert f.rule_id == "saturation"
    assert f.message == r.saturation_verdict[("A", "B")]


def test_saturation_verdict_saturation_declenche_anomalie():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = (
        "pertes fortement correlees aux pics de debit -> saturation de lien ou de buffer sur ce segment"
    )
    findings = evaluate("saturation", r)
    assert findings[0].severity == "anomalie"


def test_saturation_verdict_correlation_partielle_declenche_a_surveiller():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = (
        "correlation debit/pertes partielle, pas de signature nette -> a confirmer avec plus de donnees"
    )
    findings = evaluate("saturation", r)
    assert len(findings) == 1
    assert findings[0].severity == "a_surveiller"


def test_saturation_verdict_non_correlee_pas_de_finding():
    r = Report(points=["A", "B"])
    r.saturation_verdict[("A", "B")] = (
        "pertes NON correlees a un debit eleve -> cause probablement physique, filtrage actif ou congestion "
        "ailleurs, pas une saturation de ce segment"
    )
    assert evaluate("saturation", r) == []


def test_saturation_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("saturation", r) == []


def test_saturation_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.saturation_verdict[("A", "B")] = (
        "pertes fortement correlees aux pics de debit -> saturation de lien ou de buffer sur ce segment"
    )
    r.saturation_verdict[("B", "C")] = (
        "pertes NON correlees a un debit eleve -> cause probablement physique, filtrage actif ou congestion "
        "ailleurs, pas une saturation de ce segment"
    )

    procedural = [f for f in build_findings(r) if f.rule_id == "saturation"]
    via_moteur = evaluate("saturation", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )


# -- bufferbloat (Session 69) --------------------------------------------


def test_bufferbloat_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.bufferbloat_hint[("A", "B")] = (12.0, 90.0)
    findings = evaluate("bufferbloat", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "Bufferbloat"
    assert f.segment == "A -> B"
    assert f.rule_id == "bufferbloat"
    assert f.message == "latence 12.0ms a faible charge vs 90.0ms a forte charge"


def test_bufferbloat_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("bufferbloat", r) == []


def test_bufferbloat_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.bufferbloat_hint[("A", "B")] = (12.0, 90.0)
    r.bufferbloat_hint[("B", "C")] = (8.0, 40.0)

    procedural = [f for f in build_findings(r) if f.rule_id == "bufferbloat"]
    via_moteur = evaluate("bufferbloat", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur, strict=True):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
        )


# -- pmtud_blackhole (Session 69) -----------------------------------------


def test_pmtud_blackhole_declenche_severite_du_catalogue():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 3
    findings = evaluate("pmtud_blackhole", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "PMTUD"
    assert f.segment == "A -> B"
    assert f.rule_id == "pmtud_blackhole"
    assert "3 segment(s) TCP retransmis plusieurs fois en A" in f.message
    assert "noir PMTUD probable" in f.message


def test_pmtud_blackhole_absent_pas_de_finding():
    r = Report(points=["A", "B"])
    assert evaluate("pmtud_blackhole", r) == []


def test_pmtud_blackhole_nul_pas_de_finding():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 0
    assert evaluate("pmtud_blackhole", r) == []


def test_pmtud_blackhole_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A", "B"])
    r.pmtud_blackhole[("A", "B")] = 3
    r.pmtud_blackhole_examples[("A", "B")] = ["seg 1200o, 4e tentative sans reponse"]
    r.pmtud_blackhole_frames[("A", "B")] = [77]
    findings = evaluate("pmtud_blackhole", r)
    assert len(findings[0].evidence) == 1
    ev = findings[0].evidence[0]
    assert ev.point == "A -> B"
    assert ev.text == "seg 1200o, 4e tentative sans reponse"
    assert ev.packet is not None
    assert ev.packet.frame_number == 77


def test_pmtud_blackhole_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.pmtud_blackhole[("A", "B")] = 3
    r.pmtud_blackhole_examples[("A", "B")] = ["seg 1200o, 4e tentative sans reponse"]
    r.pmtud_blackhole_frames[("A", "B")] = [77]
    r.pmtud_blackhole[("B", "C")] = 0  # presente mais nulle : ne doit declencher ni cote

    procedural = [f for f in build_findings(r) if f.rule_id == "pmtud_blackhole"]
    via_moteur = evaluate("pmtud_blackhole", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
    )
    assert len(p.evidence) == len(m.evidence) == 1
    assert (p.evidence[0].point, p.evidence[0].text, p.evidence[0].packet) == (
        m.evidence[0].point,
        m.evidence[0].text,
        m.evidence[0].packet,
    )


# -- rtp_quality_mos (Session 70, job1) -------------------------------------


def _rtp_stream(label: str, mos: float | None, r_factor: float = 80.0, sample_count: int | None = 100) -> dict:
    """Construit un dict de flux RTP dans le meme format que
    `analysis.py::_analyse_rtp()` (label, ssrc, r_factor, mos,
    sample_count) pour les tests ci-dessous."""
    return {
        "label": label,
        "ssrc": 0x12345678,
        "r_factor": r_factor,
        "mos": mos,
        "sample_count": sample_count,
    }


def test_rtp_quality_mos_declenche_anomalie():
    r = Report(points=["A"])
    r.rtp_streams = [_rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x12345678)", 2.5)]
    findings = evaluate("rtp_quality_mos", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "RTP/Voix"
    assert f.segment == "10.0.0.1:5004 -> 10.0.0.2:5006"
    assert f.rule_id == "rtp_quality_mos"
    assert "MOS estime 2.50" in f.message
    assert "R-factor 80" in f.message
    assert f.sample_size == 100
    assert f.evidence == []  # liste de dicts, aucun champ *_examples/frames


def test_rtp_quality_mos_declenche_a_surveiller():
    r = Report(points=["A"])
    r.rtp_streams = [_rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x12345678)", 3.4)]
    findings = evaluate("rtp_quality_mos", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert "MOS estime 3.40" in f.message


def test_rtp_quality_mos_mos_acceptable_pas_de_finding():
    r = Report(points=["A"])
    r.rtp_streams = [_rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x12345678)", 4.2)]
    assert evaluate("rtp_quality_mos", r) == []


def test_rtp_quality_mos_mos_none_ignore():
    r = Report(points=["A"])
    r.rtp_streams = [_rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x12345678)", None)]
    assert evaluate("rtp_quality_mos", r) == []


def test_rtp_quality_mos_liste_vide_pas_de_finding():
    r = Report(points=["A"])
    assert evaluate("rtp_quality_mos", r) == []


def test_rtp_quality_mos_plusieurs_flux_melange():
    r = Report(points=["A"])
    r.rtp_streams = [
        _rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x11111111)", 2.0),  # anomalie
        _rtp_stream("10.0.0.3:5004 -> 10.0.0.4:5006 (SSRC=0x22222222)", 3.5),  # a_surveiller
        _rtp_stream("10.0.0.5:5004 -> 10.0.0.6:5006 (SSRC=0x33333333)", 4.0),  # acceptable
        _rtp_stream("10.0.0.7:5004 -> 10.0.0.8:5006 (SSRC=0x44444444)", None),  # ignore
    ]
    findings = evaluate("rtp_quality_mos", r)
    assert len(findings) == 2
    assert findings[0].severity == "anomalie"
    assert findings[0].segment == "10.0.0.1:5004 -> 10.0.0.2:5006"
    assert findings[1].severity == "a_surveiller"
    assert findings[1].segment == "10.0.0.3:5004 -> 10.0.0.4:5006"


def test_rtp_quality_mos_equivalent_a_build_findings():
    r = Report(points=["A", "B"])
    r.rtp_streams = [
        _rtp_stream("10.0.0.1:5004 -> 10.0.0.2:5006 (SSRC=0x12345678)", 2.5),
        _rtp_stream("10.0.0.3:5004 -> 10.0.0.4:5006 (SSRC=0x87654321)", 3.4),
    ]

    procedural = [f for f in build_findings(r) if f.rule_id == "rtp_quality_mos"]
    via_moteur = evaluate("rtp_quality_mos", r)
    assert len(procedural) == len(via_moteur) == 2
    for p, m in zip(procedural, via_moteur):
        assert (p.severity, p.category, p.segment, p.message, p.rule_id, p.sample_size) == (
            m.severity,
            m.category,
            m.segment,
            m.message,
            m.rule_id,
            m.sample_size,
        )


# -- server_processing_dominant (Session 70, job2) ---------------------------


def test_server_processing_dominant_declenche():
    r = Report(points=["A", "B"])
    r.server_think_time = {"A": [100.0, 120.0, 80.0]}  # moy 100ms
    r.latency[("A", "B")] = [10.0, 12.0, 8.0]  # moy 10ms, 100 > 3*10 and > 20
    findings = evaluate("server_processing_dominant", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "a_surveiller"
    assert f.category == "Reseau/Serveur"
    assert f.segment == "global"
    assert f.rule_id == "server_processing_dominant"
    assert "temps de traitement serveur moyen 100ms" in f.message
    assert "reseau 10.0ms" in f.message
    assert f.sample_size == 3
    assert f.evidence == []


def test_server_processing_dominant_ratio_insuffisant_pas_de_finding():
    r = Report(points=["A", "B"])
    r.server_think_time = {"A": [30.0]}  # moy 30ms
    r.latency[("A", "B")] = [15.0]  # moy 15ms, 30 < 3*15=45
    assert evaluate("server_processing_dominant", r) == []


def test_server_processing_dominant_seuil_absolu_non_atteint_pas_de_finding():
    r = Report(points=["A", "B"])
    r.server_think_time = {"A": [15.0]}  # moy 15ms, < 20ms seuil absolu
    r.latency[("A", "B")] = [1.0]  # moy 1ms, 15 > 3*1=3 mais 15 <= 20
    assert evaluate("server_processing_dominant", r) == []


def test_server_processing_dominant_server_think_time_vide_pas_de_finding():
    r = Report(points=["A", "B"])
    r.latency[("A", "B")] = [10.0]
    assert evaluate("server_processing_dominant", r) == []


def test_server_processing_dominant_latence_absente_pas_de_finding():
    r = Report(points=["A", "B"])
    r.server_think_time = {"A": [100.0, 120.0]}
    # pas de r.latency[("A", "B")]
    assert evaluate("server_processing_dominant", r) == []


def test_server_processing_dominant_un_seul_point_pas_de_finding():
    r = Report(points=["A"])
    r.server_think_time = {"A": [100.0]}
    # un seul point -> pas de paire -> pas de latence reseau
    assert evaluate("server_processing_dominant", r) == []


def test_server_processing_dominant_equivalent_a_build_findings():
    r = Report(points=["A", "B", "C"])
    r.server_think_time = {"A": [100.0, 120.0, 80.0], "B": [90.0]}
    r.latency[("A", "C")] = [10.0, 12.0, 8.0]

    procedural = [f for f in build_findings(r) if f.rule_id == "server_processing_dominant"]
    via_moteur = evaluate("server_processing_dominant", r)
    assert len(procedural) == len(via_moteur) == 1
    p, m = procedural[0], via_moteur[0]
    assert (p.severity, p.category, p.segment, p.message, p.rule_id, p.sample_size) == (
        m.severity,
        m.category,
        m.segment,
        m.message,
        m.rule_id,
        m.sample_size,
    )
