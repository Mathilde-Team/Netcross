# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.security_report -- tests du rapport de securite
consolide et du tableau de bord (CVE-5, issue #139).

Le module ne detecte rien : il regroupe, classe et met en forme les
`Report.service_fingerprints`/`Report.security_findings` produits en
amont. Les tests portent donc sur (1) la classification par severite,
(2) le rattachement CVE -> service, strict pour eviter tout faux positif,
(3) le tableau de bord, (4) le rendu texte, et (5) l'absence de constat
invente sur un Report sans signal de securite (dont un Report issu de
`analyse()` sur trafic normal).

Tous les objets sont synthetiques (aucune capture, aucun tshark), comme
le reste de la suite.
"""

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.models import Report
from netcross_report.security_report import (
    MAX_ROWS_PER_SECTION,
    build_security_report,
    format_security_report,
    print_security_report,
    severity_from_cvss,
)


def _fp(service="Apache", version="2.4.41", host="10.0.0.5", port=80, point="A"):
    return {"service": service, "version": version, "host": host, "port": port, "point": point}


def _cve(cve_id="CVE-2021-41773", cvss=7.5, service="Apache", version="2.4.41", **extra):
    return {
        "category": "cve",
        "cve_id": cve_id,
        "cvss": cvss,
        "service": service,
        "version": version,
        "detail": "path traversal",
        **extra,
    }


def _report(fingerprints=(), findings=()):
    r = Report()
    r.service_fingerprints = list(fingerprints)
    r.security_findings = list(findings)
    return r


# -- Report vide / aucun faux positif ----------------------------------------


def test_report_vide_donne_un_rapport_vide():
    sr = build_security_report(Report())
    assert sr.services == [] and sr.exploits == [] and sr.anomalies == [] and sr.cves == []
    assert sr.dashboard.score == 0
    assert sr.dashboard.level is None
    assert all(n == 0 for n in sr.dashboard.by_severity.values())


def test_report_vide_texte_indique_aucun_constat():
    text = "\n".join(format_security_report(build_security_report(Report())))
    assert "aucun constat" in text
    assert "aucune tentative d'exploitation detectee" in text
    assert "aucune CVE confirmee" in text


def test_trafic_normal_ne_produit_aucun_constat_de_securite():
    """Un Report issu d'analyse() sur un trafic HTTP banal, sans signal
    amont, ne doit faire apparaitre AUCUN constat."""
    pkts = [
        make_pkt(point="A", sport=40000, dport=80, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=40000, dport=80, ts=0.01, flags="S", seq=1),
        make_pkt(point="A", sport=40000, dport=80, ts=0.1, http_is_request=True, http_method="GET", http_uri="/"),
        make_pkt(point="B", sport=40000, dport=80, ts=0.11, http_is_request=True, http_method="GET", http_uri="/"),
    ]
    r = analyse(correlate(pkts), points_order=["A", "B"], all_packets=pkts)
    sr = build_security_report(r)
    assert sr.dashboard.score == 0
    assert sr.dashboard.level is None
    assert sr.exploits == sr.anomalies == sr.cves == []


# -- classification par severite ---------------------------------------------


def test_severity_from_cvss_tranches_nvd():
    assert severity_from_cvss(10.0) == "critique"
    assert severity_from_cvss(9.0) == "critique"
    assert severity_from_cvss(8.9) == "elevee"
    assert severity_from_cvss(7.0) == "elevee"
    assert severity_from_cvss(6.9) == "moyenne"
    assert severity_from_cvss(4.0) == "moyenne"
    assert severity_from_cvss(3.9) == "faible"
    assert severity_from_cvss(0.0) == "faible"


def test_severite_explicite_prime_sur_le_cvss():
    sr = build_security_report(_report(findings=[_cve(cvss=9.8, severity="moyenne")]))
    assert sr.cves[0].severity == "moyenne"


def test_severite_deduite_du_cvss_quand_absente():
    sr = build_security_report(_report(findings=[_cve(cvss=9.8)]))
    assert sr.cves[0].severity == "critique"


def test_alias_de_severite_et_casse():
    findings = [
        {"category": "exploit", "severity": "Critical", "detail": "a"},
        {"category": "exploit", "severity": "ÉLEVÉE", "detail": "b"},
        {"category": "exploit", "severity": "medium", "detail": "c"},
        {"category": "exploit", "severity": "Low", "detail": "d"},
    ]
    sr = build_security_report(_report(findings=findings))
    assert [i.severity for i in sr.exploits] == ["critique", "elevee", "moyenne", "faible"]


def test_severite_inconnue_sans_cvss_tombe_sur_faible():
    sr = build_security_report(_report(findings=[{"category": "exploit", "severity": "???", "detail": "x"}]))
    assert sr.exploits[0].severity == "faible"


def test_categorie_inconnue_ou_absente_classee_en_anomalie():
    findings = [{"severity": "moyenne", "detail": "x"}, {"category": "bizarre", "severity": "faible", "detail": "y"}]
    sr = build_security_report(_report(findings=findings))
    assert len(sr.anomalies) == 2
    assert sr.exploits == [] and sr.cves == []


def test_sections_triees_par_severite_puis_cvss_decroissants():
    findings = [
        _cve("CVE-A", cvss=5.0),
        _cve("CVE-B", cvss=9.8),
        _cve("CVE-C", cvss=7.5),
        _cve("CVE-D", cvss=7.9),
    ]
    sr = build_security_report(_report(findings=findings))
    assert [c.cve_id for c in sr.cves] == ["CVE-B", "CVE-D", "CVE-C", "CVE-A"]


def test_entrees_malformees_ignorees_sans_lever():
    r = _report(
        fingerprints=["pas un dict", None, {"version": "1.0"}, _fp()],
        findings=[42, None, "x", {"category": "exploit", "severity": "elevee", "detail": "ok"}],
    )
    sr = build_security_report(r)
    assert len(sr.services) == 1  # le seul fingerprint valide
    assert len(sr.exploits) == 1


# -- rattachement CVE -> service (pas de faux positif) ------------------------


def test_service_marque_vulnerable_par_une_cve_de_meme_version():
    sr = build_security_report(_report([_fp()], [_cve("CVE-2021-41773", 7.5), _cve("CVE-2021-42013", 9.8)]))
    (svc,) = sr.services
    assert svc.vulnerable
    assert svc.severity == "critique"
    assert svc.cve_ids == ["CVE-2021-41773", "CVE-2021-42013"]
    assert sr.dashboard.services_vulnerable == 1


def test_autre_version_du_meme_service_non_marquee():
    sr = build_security_report(_report([_fp(version="2.4.58")], [_cve(version="2.4.41")]))
    assert not sr.services[0].vulnerable
    assert sr.dashboard.services_vulnerable == 0


def test_autre_service_non_marque():
    sr = build_security_report(_report([_fp(service="nginx", version="1.24.0")], [_cve()]))
    assert not sr.services[0].vulnerable


def test_cve_sans_version_ne_rattache_pas_un_service_versionne():
    sr = build_security_report(_report([_fp()], [_cve(version=None)]))
    assert not sr.services[0].vulnerable


def test_nom_de_service_insensible_a_la_casse():
    sr = build_security_report(_report([_fp(service="apache")], [_cve(service="APACHE")]))
    assert sr.services[0].vulnerable


def test_hote_et_port_de_la_cve_restreignent_le_rattachement():
    fps = [_fp(host="10.0.0.5", port=80), _fp(host="10.0.0.6", port=80), _fp(host="10.0.0.5", port=8080)]
    sr = build_security_report(_report(fps, [_cve(host="10.0.0.5", port=80)]))
    vulnerable = [(s.host, s.port) for s in sr.services if s.vulnerable]
    assert vulnerable == [("10.0.0.5", 80)]


def test_cve_sans_hote_rattache_toutes_les_instances():
    fps = [_fp(host="10.0.0.5"), _fp(host="10.0.0.6")]
    sr = build_security_report(_report(fps, [_cve()]))
    assert sr.dashboard.services_vulnerable == 2


def test_meme_service_vu_a_plusieurs_points_fusionne():
    fps = [_fp(point="B"), _fp(point="A"), _fp(point="A")]
    sr = build_security_report(_report(fps))
    (svc,) = sr.services
    assert svc.points == ["A", "B"]
    assert sr.dashboard.services_total == 1


def test_services_classes_par_criticite_puis_sains_en_dernier():
    fps = [
        _fp(service="OpenSSH", version="8.9", port=22),
        _fp(service="Apache", version="2.4.41", port=80),
        _fp(service="Exim", version="4.94", port=25),
    ]
    findings = [
        _cve("CVE-1", cvss=5.0, service="Exim", version="4.94"),
        _cve("CVE-2", cvss=9.8, service="Apache", version="2.4.41"),
    ]
    sr = build_security_report(_report(fps, findings))
    assert [s.service for s in sr.services] == ["Apache", "Exim", "OpenSSH"]
    assert [s.severity for s in sr.services] == ["critique", "moyenne", None]


def test_les_cve_sans_service_detecte_restent_listees():
    """Une CVE sans fingerprint correspondant reste visible dans sa section."""
    sr = build_security_report(_report([], [_cve()]))
    assert sr.services == []
    assert len(sr.cves) == 1


# -- tableau de bord -----------------------------------------------------------


def test_dashboard_compteurs_et_score():
    fps = [_fp(), _fp(service="OpenSSH", version="8.9", port=22)]
    findings = [
        _cve(cvss=9.8),  # critique -> 40
        {"category": "exploit", "severity": "elevee", "detail": "Log4Shell"},  # 20
        {"category": "anomalie", "severity": "moyenne", "detail": "fuzzing"},  # 8
        {"category": "anomalie", "severity": "faible", "detail": "overflow"},  # 2
    ]
    d = build_security_report(_report(fps, findings)).dashboard
    assert (d.services_total, d.services_vulnerable) == (2, 1)
    assert (d.exploits, d.anomalies, d.cves) == (1, 2, 1)
    assert d.by_severity == {"critique": 1, "elevee": 1, "moyenne": 1, "faible": 1}
    assert d.score == 70
    assert d.level == "critique"


def test_score_plafonne_a_100():
    findings = [{"category": "exploit", "severity": "critique", "detail": str(i)} for i in range(5)]
    d = build_security_report(_report(findings=findings)).dashboard
    assert d.score == 100


def test_anomalies_netcross_et_expert_info_dans_des_sections_distinctes():
    """Issue #348 : un detecteur Netcross (ex. DGA) n'est pas une alerte
    Expert Info correlee (ex. fuzzing CVE-3) -- deux sections distinctes,
    jamais melangees."""
    findings = [
        {"category": "anomalie", "severity": "moyenne", "detail": "domaine DGA suspect : x.example"},
        {"category": "anomalie", "severity": "moyenne", "detail": "suspicion de fuzzing", "source": "expert_info"},
    ]
    sr = build_security_report(_report(findings=findings))
    assert sr.anomalies[0].source == "netcross"
    assert sr.anomalies[1].source == "expert_info"
    text = "\n".join(format_security_report(sr))
    idx_netcross = text.index("Anomalies (detecteurs Netcross)")
    idx_expert = text.index("Anomalies (alertes Expert Info correlees)")
    idx_dga = text.index("domaine DGA suspect")
    idx_fuzzing = text.index("suspicion de fuzzing")
    assert idx_netcross < idx_dga < idx_expert < idx_fuzzing


def test_niveau_global_est_la_pire_severite():
    findings = [
        {"category": "anomalie", "severity": "moyenne", "detail": "a"},
        {"category": "anomalie", "severity": "faible", "detail": "b"},
    ]
    assert build_security_report(_report(findings=findings)).dashboard.level == "moyenne"


# -- rendu texte ----------------------------------------------------------------


def test_rendu_texte_contient_les_quatre_sections_et_le_tableau_de_bord():
    fps = [_fp()]
    findings = [
        _cve("CVE-2021-41773", 7.5),
        {"category": "exploit", "severity": "critique", "detail": "Log4Shell (${jndi:...})", "host": "10.0.0.5"},
        {"category": "anomalie", "severity": "moyenne", "detail": "fuzzing HTTP"},
    ]
    text = "\n".join(format_security_report(build_security_report(_report(fps, findings))))
    assert "Tableau de bord securite" in text
    assert "Services detectes (classes par criticite)" in text
    assert "Tentatives d'exploitation detectees" in text
    assert "Anomalies (detecteurs Netcross)" in text
    assert "Anomalies (alertes Expert Info correlees)" in text
    assert "CVE confirmees" in text
    assert "Apache/2.4.41 @ 10.0.0.5:80" in text
    assert "CVE-2021-41773 (CVSS 7.5)" in text
    assert "Log4Shell" in text
    assert "score de risque global : 68/100" in text  # 20 (cve) + 40 (exploit) + 8 (anomalie)


def test_rendu_texte_service_sain_indique_aucune_vulnerabilite():
    text = "\n".join(format_security_report(build_security_report(_report([_fp()]))))
    assert "[ok] Apache/2.4.41 @ 10.0.0.5:80 -- aucune vulnerabilite connue" in text


def test_rendu_texte_plafonne_les_lignes_par_section():
    n = MAX_ROWS_PER_SECTION + 7
    findings = [{"category": "exploit", "severity": "faible", "detail": f"e{i}"} for i in range(n)]
    lines = format_security_report(build_security_report(_report(findings=findings)))
    assert sum(1 for line in lines if line.startswith("  [faible]")) == MAX_ROWS_PER_SECTION
    assert any("7 ligne(s) supplementaire(s)" in line for line in lines)


def test_print_security_report_ecrit_sur_stdout(capsys):
    print_security_report(build_security_report(_report(findings=[_cve()])))
    out = capsys.readouterr().out
    assert "RAPPORT DE SECURITE" in out
    assert "CVE-2021-41773" in out
