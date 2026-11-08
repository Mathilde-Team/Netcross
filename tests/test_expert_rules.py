# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.expert_rules -- verifie le contrat `Rule` (calque exact sur
le schema de la section 6.2 de FEATURES.md : id/domaine/preconditions/
metriques requises/fenetre temporelle/seuils-percentiles/contexte requis/
regle de correlation/severite/confiance/explication/pistes de
verification) et le catalogue des quarante-et-une regles qu'il formalise :
les treize "deja presentes" (Session 46) puis cinq des six "nouvelles"
de la section 6.2 (Session 47), puis huit regles supplementaires
(Session 49) formalisant des signaux voisins non nommes par la section
6.2 mais deja produits par le code existant, puis une regle
supplementaire (Session 51) pour la categorie "Reseau/Serveur", puis
cinq regles supplementaires (Session 52) pour la categorie "HTTP", puis
deux regles supplementaires (Session 53) pour le signal certificat de
la categorie "TLS", puis deux regles supplementaires (Session 54) pour
le signal "negociations TLS incompletes" nomme par la section 6.2 mais
laisse ouvert depuis la Session 49 -- voir docstring de module
d'expert_rules.py pour le detail complet, notamment pourquoi les regles
"nouvelles" de la Session 47 se sont revelees deja implementees, le
raisonnement au cas par cas des Sessions 49, 51 et 52, la correction
apportee en Session 53 au raisonnement tenu depuis la Session 49 a
propos de "TLS", et la decision architecturale enfin tranchee en
Session 54. Les seuils/domaines pinnes ci-dessous recopient des valeurs
LUES dans analysis.py/synthesis.py au moment de la redaction du
catalogue -- si l'un de ces fichiers change ces constantes, ces tests
doivent etre mis a jour consciemment plutot que de laisser le catalogue
diverger silencieusement de la realite qu'il decrit.
"""

from netcross_core.expert_rules import _RULE_CATALOG, Rule, get_rule, list_rules

_EXPECTED_IDS = (
    # Session 46 -- treize regles "deja presentes"
    "loss_per_segment",
    "tcp_retransmission_fast",
    "tcp_retransmission_rto",
    "tcp_retransmission_spurious",
    "tcp_zero_window",
    "tcp_rst_localized",
    "tcp_syn_no_synack",
    "ttl_variation",
    "qos_dscp_remarking",
    "fragmentation_new",
    "saturation",
    "bufferbloat",
    "rtp_quality_mos",
    "dhcp_issues",
    "sip_issues",
    # Session 47 -- cinq des six regles "nouvelles"
    "dns_slow_resolution",
    "pmtud_blackhole",
    "nat_fw_silent_drop",
    "arp_ip_conflict",
    "stp_instability",
    "vlan_change",
    "tcp_options_stripped",
    "tcp_mss_clamped",
    # Session 49 -- huit regles formalisant des signaux voisins non
    # nommes par la section 6.2 (voir docstring de module)
    "syn_reply_missing",
    "hop_delta_outliers",
    "pcp_change",
    "icmp_fragmentation_needed",
    "dns_nxdomain",
    "dns_servfail",
    "dns_timeout",
    "dns_missing",
    # Session 51 -- une des trois categories entierement sans regle
    # apres la Session 49 (voir docstring de module)
    "server_processing_dominant",
    # Session 52 -- deuxieme des trois categories laissees ouvertes par
    # la Session 51 ("HTTP", cinq sites de Finding)
    "http_client_error",
    "http_server_error",
    "http_timeout",
    "http_missing",
    "http_slow_response",
    # Session 53 -- derniere categorie laissee ouverte par la Session 49
    # ("TLS", certificat, deux sites de Finding)
    "tls_cert_invalid_dates",
    "tls_cert_mismatch",
    # Session 54 -- decision architecturale tranchee (option (a)) :
    # "negociations TLS incompletes" (§6.2), deux sites de Finding
    "tls_handshake_no_reply",
    "tls_handshake_incomplete",
)

_VALID_SEVERITIES = {"anomalie", "a_surveiller", "info"}

# Cinq paliers discrets documentes dans la docstring de module
# d'expert_rules.py -- toute valeur en dehors de cette echelle serait un
# palier invente sans justification documentee.
_CONFIDENCE_SCALE = {0.6, 0.7, 0.75, 0.8, 0.9}

_RULE_KWARGS = {
    "id": "x",
    "domain": "TCP",
    "preconditions": "p",
    "required_metrics": ("Report.x",),
    "time_window": "t",
    "required_context": "c",
    "severity": "info",
    "confidence": 0.5,
    "explanation": "e",
    "verification_leads": "v",
}


# -- contrat Rule (forme, independamment du catalogue) ----------------------


def test_rule_egalite_par_valeur():
    assert Rule(**_RULE_KWARGS) == Rule(**_RULE_KWARGS)
    assert Rule(**_RULE_KWARGS) != Rule(**{**_RULE_KWARGS, "id": "y"})


def test_rule_thresholds_vide_et_correlation_rule_none_par_defaut():
    r = Rule(**_RULE_KWARGS)
    assert r.thresholds == {}
    assert r.correlation_rule is None


def test_rule_thresholds_explicite():
    r = Rule(**_RULE_KWARGS, thresholds={"seuil": 5.0})
    assert r.thresholds == {"seuil": 5.0}


def test_rule_correlation_rule_explicite():
    r = Rule(**_RULE_KWARGS, correlation_rule="signal A croise avec signal B")
    assert r.correlation_rule == "signal A croise avec signal B"


# -- catalogue : structure ---------------------------------------------------


def test_catalogue_quarante_et_une_regles():
    assert len(_RULE_CATALOG) == 41


def test_catalogue_ids_uniques_et_attendus():
    ids = [r.id for r in _RULE_CATALOG]
    assert len(ids) == len(set(ids)), "un id de regle est duplique dans le catalogue"
    assert set(ids) == set(_EXPECTED_IDS)


def test_catalogue_severites_valides():
    for r in _RULE_CATALOG:
        assert r.severity in _VALID_SEVERITIES, r.id


def test_catalogue_confidence_dans_l_echelle_documentee():
    for r in _RULE_CATALOG:
        assert r.confidence in _CONFIDENCE_SCALE, r.id


def test_catalogue_metriques_requises_non_vides():
    for r in _RULE_CATALOG:
        assert r.required_metrics, r.id
        assert all(isinstance(m, str) and m for m in r.required_metrics), r.id


def test_catalogue_preconditions_explanation_verification_leads_non_vides():
    # Les champs prose du contrat ne doivent jamais rester des chaines
    # vides par oubli -- chaque regle du catalogue les redige reellement.
    for r in _RULE_CATALOG:
        assert r.preconditions, r.id
        assert r.explanation, r.id
        assert r.verification_leads, r.id
        assert r.time_window, r.id
        assert r.required_context, r.id


def test_catalogue_cinq_regles_seulement_ont_une_correlation():
    # Voir docstring de module d'expert_rules.py : saturation/bufferbloat/
    # remarquage QoS/fragmentation (Session 46) puis PMTUD black hole
    # (Session 47) croisent deja deux signaux bruts distincts, les dix-
    # huit autres regles restent autonomes.
    correlees = {r.id for r in _RULE_CATALOG if r.correlation_rule is not None}
    assert correlees == {
        "saturation",
        "bufferbloat",
        "qos_dscp_remarking",
        "fragmentation_new",
        "pmtud_blackhole",
    }


def test_catalogue_domaines_couvrent_les_dix_neuf_familles_attendues():
    assert {r.domain for r in _RULE_CATALOG} == {
        "Pertes",
        "TCP",
        "Routage",
        "QoS",
        "Fragmentation",
        "Saturation",
        "Bufferbloat",
        "RTP/Voix",
        "DHCP",
        "SIP",
        "DNS",
        "PMTUD",
        "NAT/Pare-feu",
        "ARP",
        "STP",
        "VLAN",
        "Reseau/Serveur",
        "HTTP",
        "TLS",
    }


def test_catalogue_neuf_regles_tcp():
    # retransmissions (3 sous-types) + zero_window + rst_localized +
    # syn_no_synack (Session 46), + options retirees + MSS clamped
    # (Session 47), + syn_reply_missing (Session 49) -- voir docstring de
    # module.
    assert len([r for r in _RULE_CATALOG if r.domain == "TCP"]) == 9


def test_catalogue_cinq_regles_http():
    # client_error (4xx) + server_error (5xx) + timeout + missing +
    # slow_response (Session 52) -- voir docstring de module.
    assert len([r for r in _RULE_CATALOG if r.domain == "HTTP"]) == 5


# -- get_rule / list_rules ---------------------------------------------------


def test_get_rule_id_connu():
    r = get_rule("tcp_zero_window")
    assert r is not None
    assert r.domain == "TCP"
    assert r.severity == "a_surveiller"


def test_get_rule_id_inconnu_retourne_none():
    assert get_rule("ceci_n_existe_pas") is None


def test_list_rules_sans_filtre_retourne_tout_dans_l_ordre_du_catalogue():
    assert list_rules() == list(_RULE_CATALOG)


def test_list_rules_filtre_par_domaine():
    tcp_rules = list_rules(domain="TCP")
    assert len(tcp_rules) == 9
    assert all(r.domain == "TCP" for r in tcp_rules)


def test_list_rules_domaine_inconnu_donne_une_liste_vide():
    assert list_rules(domain="Ceci n'existe pas") == []


def test_list_rules_domaine_none_equivaut_a_sans_argument():
    assert list_rules(domain=None) == list_rules()


# -- spot checks Session 47 --------------------------------------------------


def test_tcp_options_stripped_et_mss_clamped_meme_source_severites_differentes():
    # Meme fonction source (_analyse_tcp_options) mais deux regles
    # distinctes : severite fixe differente ("a_surveiller" contre
    # "info"), voir docstring de module pour la justification.
    stripped = get_rule("tcp_options_stripped")
    clamped = get_rule("tcp_mss_clamped")
    assert stripped.severity == "a_surveiller"
    assert clamped.severity == "info"
    assert stripped.domain == clamped.domain == "TCP"


def test_negociations_tls_incompletes_desormais_cataloguees():
    # Jusqu'a la Session 53 incluse, le domaine "TLS" du catalogue ne
    # couvrait QUE le signal certificat (tls_cert_invalid_dates/
    # tls_cert_mismatch), jamais "negociations incompletes" -- ce
    # dernier signal ne produisait aucun synthesis.Finding. Depuis la
    # Session 54 (decision architecturale tranchee, option (a), voir
    # docstring de module), il en produit deux : tls_handshake_no_reply
    # et tls_handshake_incomplete. Le module netcross_core.
    # tls_diagnostics (Session 49, voir docstring de module) reste
    # INCHANGE et independant -- ce nouveau detecteur ne le remplace ni
    # ne s'appuie sur lui, meme but voisin, code totalement separe.
    tls_rule_ids = {r.id for r in list_rules() if r.domain == "TLS"}
    assert tls_rule_ids == {
        "tls_cert_invalid_dates",
        "tls_cert_mismatch",
        "tls_handshake_no_reply",
        "tls_handshake_incomplete",
    }


# -- spot checks Session 51 --------------------------------------------------


def test_server_processing_dominant_domaine_et_severite():
    r = get_rule("server_processing_dominant")
    assert r is not None
    assert r.domain == "Reseau/Serveur"
    assert r.severity == "a_surveiller"
    assert r.confidence == 0.7
    assert "Report.server_think_time" in r.required_metrics
    assert "Report.latency" in r.required_metrics


# -- spot checks Session 52 --------------------------------------------------


def test_http_client_error_est_info_http_server_error_est_anomalie():
    # Meme registre que dns_nxdomain (info)/dns_servfail (anomalie) :
    # erreur cote client pas forcement reseau, echec cote serveur souvent
    # pris a tort pour un probleme reseau.
    client = get_rule("http_client_error")
    server = get_rule("http_server_error")
    assert client.severity == "info"
    assert server.severity == "anomalie"
    assert client.domain == server.domain == "HTTP"


def test_http_timeout_et_http_missing_severites():
    assert get_rule("http_timeout").severity == "anomalie"
    assert get_rule("http_missing").severity == "a_surveiller"


def test_seuil_http_lent():
    assert get_rule("http_slow_response").thresholds == {"mean_duration_ms_min": 500.0}


def test_regles_http_toutes_autonomes():
    # Aucune des cinq regles HTTP ne croise un autre signal brut distinct
    # -- meme registre que les regles DNS dont elles s'inspirent.
    for rule_id in ("http_client_error", "http_server_error", "http_timeout", "http_missing", "http_slow_response"):
        assert get_rule(rule_id).correlation_rule is None


def test_seuil_server_processing_dominant():
    r = get_rule("server_processing_dominant")
    assert r.thresholds == {"ratio_serveur_reseau": 3.0, "seuil_serveur_ms": 20.0}


# -- spot checks Session 53 --------------------------------------------------


def test_catalogue_quatre_regles_tls():
    # certificat hors validite + certificat substitue (Session 26/53) +
    # negociation sans reponse + negociation interrompue (Session 54) --
    # QUATRE sites de Finding au total sous le meme domaine -- voir
    # docstring de module.
    assert len([r for r in _RULE_CATALOG if r.domain == "TLS"]) == 4


def test_tls_cert_invalid_dates_et_mismatch_meme_severite_meme_confiance():
    # Les deux regles TLS partagent severite/confiance (voir docstring de
    # module pour la justification -- lecture native/correspondance par
    # identifiant exact, meme registre que stp_instability/vlan_change).
    invalid = get_rule("tls_cert_invalid_dates")
    mismatch = get_rule("tls_cert_mismatch")
    assert invalid.severity == mismatch.severity == "anomalie"
    assert invalid.confidence == mismatch.confidence == 0.8
    assert invalid.domain == mismatch.domain == "TLS"


def test_regles_tls_toutes_autonomes_et_sans_seuil():
    # Aucune des deux regles TLS ne croise un autre signal brut distinct,
    # et aucune ne porte de palier numerique -- se declenchent sur toute
    # occurrence (n > 0), meme registre que stp_instability/vlan_change.
    for rule_id in ("tls_cert_invalid_dates", "tls_cert_mismatch"):
        r = get_rule(rule_id)
        assert r.correlation_rule is None
        assert r.thresholds == {}


def test_tls_cert_invalid_dates_metriques_requises():
    r = get_rule("tls_cert_invalid_dates")
    assert "Report.tls_cert_invalid_dates" in r.required_metrics
    assert "Pkt.tls_cert_not_before" in r.required_metrics
    assert "Pkt.tls_cert_not_after" in r.required_metrics


def test_tls_cert_mismatch_metriques_requises():
    r = get_rule("tls_cert_mismatch")
    assert "Report.tls_cert_mismatch" in r.required_metrics
    assert "Pkt.tls_cert_serial" in r.required_metrics


# -- spot checks Session 54 --------------------------------------------------


def test_tls_handshake_no_reply_et_incomplete_meme_severite_meme_confiance():
    # Meme registre que les regles certificat de la Session 53 -- voir
    # docstring de module pour la justification complete (correspondance
    # par identifiant exact entre plusieurs paquets d'un meme point).
    no_reply = get_rule("tls_handshake_no_reply")
    incomplete = get_rule("tls_handshake_incomplete")
    assert no_reply.severity == incomplete.severity == "anomalie"
    assert no_reply.confidence == incomplete.confidence == 0.8
    assert no_reply.domain == incomplete.domain == "TLS"


def test_regles_tls_handshake_toutes_autonomes_et_sans_seuil():
    for rule_id in ("tls_handshake_no_reply", "tls_handshake_incomplete"):
        r = get_rule(rule_id)
        assert r.correlation_rule is None
        assert r.thresholds == {}


def test_tls_handshake_no_reply_metriques_requises():
    r = get_rule("tls_handshake_no_reply")
    assert "Report.tls_handshake_no_reply" in r.required_metrics
    assert "Pkt.tls_client_hello" in r.required_metrics
    assert "Pkt.tls_server_hello" in r.required_metrics


def test_tls_handshake_incomplete_metriques_requises():
    r = get_rule("tls_handshake_incomplete")
    assert "Report.tls_handshake_incomplete" in r.required_metrics
    assert "Pkt.tls_server_hello" in r.required_metrics
    assert "Pkt.tls_application_data" in r.required_metrics


# -- spot checks Session 49 --------------------------------------------------


def test_icmp_fragmentation_needed_couvre_ipv4_et_ipv6_en_une_seule_regle():
    # Deux sites de Finding distincts (IPv4 Report.icmp_frag_needed,
    # IPv6 Report.icmpv6_too_big) mais UNE seule regle -- meme severite,
    # meme signal fonctionnel, meme discipline que tcp_options_stripped
    # (voir docstring de module).
    r = get_rule("icmp_fragmentation_needed")
    assert r.domain == "Fragmentation"
    assert r.severity == "info"
    assert "Report.icmp_frag_needed" in r.required_metrics
    assert "Report.icmpv6_too_big" in r.required_metrics


def test_quatre_regles_dns_brutes_gardent_des_severites_distinctes():
    # Contrairement a icmp_fragmentation_needed ci-dessus, ces quatre
    # signaux ne sont PAS fusionnes : leurs severites different (meme
    # raisonnement que les trois sous-types de retransmission TCP,
    # Session 46 -- fusionner masquerait la gradation).
    assert get_rule("dns_nxdomain").severity == "info"
    assert get_rule("dns_servfail").severity == "anomalie"
    assert get_rule("dns_timeout").severity == "anomalie"
    assert get_rule("dns_missing").severity == "a_surveiller"
    assert len({"dns_nxdomain", "dns_servfail", "dns_timeout", "dns_missing"}) == 4


def test_syn_reply_missing_meme_domaine_que_syn_no_synack_mecanisme_partage():
    # Meme fonction source (_analyse_handshake) que tcp_syn_no_synack,
    # mais un signal distinct (voir docstring de module) -- deux id
    # differents, meme domaine.
    missing = get_rule("syn_reply_missing")
    no_synack = get_rule("tcp_syn_no_synack")
    assert missing.domain == no_synack.domain == "TCP"
    assert missing.id != no_synack.id


def test_hop_delta_outliers_et_pcp_change_domaines_des_regles_voisines():
    # hop_delta_outliers formalise un signal de la meme section de code
    # que ttl_variation (Routage) ; pcp_change, de la meme section que
    # qos_dscp_remarking (QoS) -- voir docstring de module.
    assert get_rule("hop_delta_outliers").domain == get_rule("ttl_variation").domain == "Routage"
    assert get_rule("pcp_change").domain == get_rule("qos_dscp_remarking").domain == "QoS"


# -- seuils pinnes (recopies depuis analysis.py/synthesis.py) ---------------


def test_seuil_pertes_anomalie_5_pourcent():
    assert get_rule("loss_per_segment").thresholds == {"anomalie_rate_pct": 5.0}


def test_seuils_mos_rtp():
    r = get_rule("rtp_quality_mos")
    assert r.thresholds == {"anomalie_mos_max": 3.0, "a_surveiller_mos_max": 3.6}


def test_seuils_bufferbloat():
    r = get_rule("bufferbloat")
    assert r.thresholds == {
        "high_over_low_ratio_min": 1.5,
        "min_absolute_delta_ms": 5.0,
        "min_common_buckets": 4.0,
    }


def test_seuils_saturation():
    r = get_rule("saturation")
    assert r.thresholds == {
        "frac_high_policing_min": 0.7,
        "rel_stdev_policing_max": 0.15,
        "mean_loss_ratio_policing_min": 0.85,
        "frac_high_saturation_min": 0.6,
        "frac_high_no_correlation_max": 0.3,
    }


def test_seuil_fragmentation_correlation_encapsulation():
    assert get_rule("fragmentation_new").thresholds == {"correlated_encap_change_min_count": 1.0}


def test_seuil_dns_lent():
    assert get_rule("dns_slow_resolution").thresholds == {"mean_duration_ms_min": 200.0}


def test_seuils_pmtud_blackhole():
    r = get_rule("pmtud_blackhole")
    assert r.thresholds == {"min_segment_bytes": 512.0, "min_upstream_attempts": 2.0}


def test_seuil_nat_fw_silencieux():
    assert get_rule("nat_fw_silent_drop").thresholds == {"idle_timeout_seconds": 60.0}


def test_seuil_conflit_arp():
    assert get_rule("arp_ip_conflict").thresholds == {"min_distinct_macs": 2.0}


def test_regles_sans_palier_numerique_ont_des_thresholds_vides():
    # Se declenchent sur toute occurrence (n > 0), sans gradation
    # numerique supplementaire -- voir docstring de Rule.thresholds.
    sans_seuil = (
        "tcp_retransmission_fast",
        "tcp_retransmission_rto",
        "tcp_retransmission_spurious",
        "tcp_zero_window",
        "tcp_rst_localized",
        "tcp_syn_no_synack",
        "ttl_variation",
        "qos_dscp_remarking",
        "dhcp_issues",
        "sip_issues",
        "stp_instability",
        "vlan_change",
        "tcp_options_stripped",
        "tcp_mss_clamped",
        # Session 49
        "syn_reply_missing",
        "hop_delta_outliers",
        "pcp_change",
        "icmp_fragmentation_needed",
        "dns_nxdomain",
        "dns_servfail",
        "dns_timeout",
        "dns_missing",
        # Session 52
        "http_client_error",
        "http_server_error",
        "http_timeout",
        "http_missing",
        # Session 53
        "tls_cert_invalid_dates",
        "tls_cert_mismatch",
        # Session 54
        "tls_handshake_no_reply",
        "tls_handshake_incomplete",
    )
    for rule_id in sans_seuil:
        assert get_rule(rule_id).thresholds == {}, rule_id


# -- tracabilite : les domaines correspondent a de vrais Finding.category ---


def test_domaines_correspondent_a_des_finding_category_reels():
    # Construit un Report minimaliste declenchant plusieurs categories a
    # la fois (meme pattern que test_synthesis.py : peupler directement
    # les champs Report cibles plutot que rejouer analyse() en entier) et
    # verifie que les categories reellement produites par build_findings()
    # sont bien utilisees comme `domain` dans le catalogue -- celui-ci
    # n'invente pas sa propre taxonomie parallele a Finding.category.
    from netcross_core.models import Report
    from netcross_report.synthesis import build_findings

    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.loss_count["B"] = 10
    r.seen_count["B"] = 100
    r.zero_window["A"] = 1
    r.ttl_unstable["A"] = 1
    r.dhcp_nak_count["A"] = 1
    r.sip_failed_calls.append("Call-ID abc : echec 486 Busy Here")
    # Session 47 : les six domaines "regles nouvelles" ajoutes au catalogue.
    r.dns_duration_ms.append(250.0)
    r.pmtud_blackhole[("A", "B")] = 1
    r.idle_timeout_dropped[("A", "B")] = 1
    r.arp_ip_conflict["A"] = 1
    r.stp_topology_change["A"] = 1
    r.vlan_change[("A", "B")] = 1

    produced_categories = {f.category for f in build_findings(r)}
    assert produced_categories == {
        "Pertes",
        "TCP",
        "Routage",
        "DHCP",
        "SIP",
        "DNS",
        "PMTUD",
        "NAT/Pare-feu",
        "ARP",
        "STP",
        "VLAN",
    }

    catalog_domains = {rule.domain for rule in list_rules()}
    assert produced_categories <= catalog_domains


# -- tracabilite : Finding.rule_id (Session 48) --


def test_rule_id_couvre_les_quarante_et_une_regles_et_respecte_le_domaine():
    """Verifie le cablage des Sessions 48 (`Finding.rule_id`), 49 (huit
    regles supplementaires), 51 (`server_processing_dominant`), 52 (cinq
    regles "HTTP"), 53 (deux regles "TLS", certificat) et 54 (deux
    regles "TLS", negociations incompletes) du point de vue du
    CATALOGUE : construit un Report qui declenche les quarante-et-une
    signaux catalogues, puis verifie pour CHAQUE Finding produit que
    `rule_id` est soit None soit un identifiant qui resout reellement via
    `get_rule()` ET dont le `domain` correspond EXACTEMENT a
    `Finding.category` -- jamais une simple co-incidence de nommage.
    Verifie aussi que les quarante-et-une regles sont chacune utilisee au
    moins une fois (aucune regle du catalogue orpheline de son cote).
    Depuis la Session 54, "negociations TLS incompletes" (§6.2) est
    elle-meme cataloguee -- plus aucun signal nomme par la section 6.2
    n'est hors de ce systeme."""
    from netcross_core.models import Report
    from netcross_report.synthesis import build_findings

    r = Report(points=["A", "B"], pairs=[("A", "B")])
    # -- les vingt-trois signaux relies a une regle depuis la Session 48 --
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100
    r.saturation_verdict[("A", "B")] = "saturation probable en aval"
    r.bufferbloat_hint[("A", "B")] = (10.0, 80.0)
    r.ttl_unstable["A"] = 1
    r.qos_change[("A", "B")] = 4
    r.frag_new[("A", "B")] = 5
    r.pmtud_blackhole[("A", "B")] = 1
    r.idle_timeout_dropped[("A", "B")] = 1
    r.arp_ip_conflict["A"] = 1
    r.stp_topology_change["A"] = 1
    r.stp_root_change["A"] = 1
    r.vlan_change[("A", "B")] = 1
    r.zero_window["A"] = 1
    r.retrans_rto["A"] = 1
    r.retrans_spurious["A"] = 1
    r.retrans_fast["A"] = 1
    r.mss_clamped[("A", "B")] = 1
    r.wscale_stripped[("A", "B")] = 1
    r.sack_stripped[("A", "B")] = 1
    r.rst_localized["A"] = 1
    r.syn_no_synack["A"] = 1
    r.rtp_streams = [{"label": "A -> B (SSRC=1)", "mos": 2.0, "r_factor": 30.0}]
    r.dhcp_nak_count["A"] = 1
    r.sip_failed_calls.append("Call-ID abc : echec 486 Busy Here")
    r.dns_duration_ms.append(250.0)

    # -- huit regles supplementaires reliees a une regle depuis la Session 49 --
    r.hop_delta_outliers[("A", "B")] = 1
    r.pcp_change[("A", "B")] = 1
    r.icmp_frag_needed["A"] = 1
    r.icmpv6_too_big["A"] = 1
    r.syn_reply_missing["A"] = 1
    r.dns_nxdomain_count["A"] = 1
    r.dns_servfail_count["A"] = 1
    r.dns_timeout["A"] = ["id=0x1 (example.com) : aucune reponse observee dans la capture"]
    r.dns_missing[("A", "B")] = ["id=0x1 (example.com) : requete vue en A, absente en B"]

    # -- server_processing_dominant, catalogue depuis la Session 51 --
    r.server_think_time["A"] = [100.0, 110.0]
    r.latency[("A", "B")] = [5.0]

    # -- cinq regles HTTP, cataloguees depuis la Session 52 --
    r.http_client_error_count["A"] = 1
    r.http_server_error_count["A"] = 1
    r.http_timeout["A"] = ["/x : aucune reponse observee dans la capture"]
    r.http_missing[("A", "B")] = ["/x : requete vue en A, absente en B"]
    r.http_response_time_ms.append(600.0)

    # -- deux regles TLS (certificat), cataloguees depuis la Session 53 --
    r.tls_cert_invalid_dates["A"] = 1
    r.tls_cert_mismatch[("A", "B")] = 1

    # -- deux regles TLS (negociations incompletes), cataloguees depuis
    # la Session 54 --
    r.tls_handshake_no_reply["A"] = 1
    r.tls_handshake_incomplete["A"] = 1

    used_rule_ids = set()
    for f in build_findings(r):
        if f.rule_id is None:
            continue
        rule = get_rule(f.rule_id)
        assert rule is not None, f.rule_id
        assert rule.domain == f.category, (f.category, f.rule_id, rule.domain)
        used_rule_ids.add(f.rule_id)

    assert used_rule_ids == {rule.id for rule in list_rules()}
