# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.security.dns_tunnel -- issue #144 (FLOW-3) : detection de
tunneling DNS. Paquets synthetiques (make_pkt) ; le trafic « legitime »
imite un poste de travail ordinaire (navigation, messagerie, mises a jour,
DNS inverse, DNSSEC) pour verifier le critere « aucun faux positif ».
"""

import base64
import random

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_core.security.dns_tunnel import (
    SIGNAL_DOMINANT_DOMAIN,
    SIGNAL_HIGH_ENTROPY,
    SIGNAL_LARGE_RESPONSE,
    SIGNAL_LONG_LABEL,
    SIGNAL_LONG_NAME,
    SIGNAL_REGULAR_TIMING,
    DnsTunnelThresholds,
    detect_dns_tunneling,
    shannon_entropy,
    split_domain,
)
from netcross_core.security.findings import apply_security_findings, dns_tunnel_findings


def _q(name, ts=0.0, *, txn=1, point="A", frame=None, length=90):
    return make_pkt(
        point=point,
        ts=ts,
        proto="UDP",
        sport=40000,
        dport=53,
        dns_txn_id=txn,
        dns_is_response=False,
        dns_qry_name=name,
        frame_number=frame,
        length=length,
    )


def _r(name, ts=0.0, *, txn=1, point="A", length=120, frame=None):
    return make_pkt(
        point=point,
        ts=ts,
        proto="UDP",
        sport=53,
        dport=40000,
        dns_txn_id=txn,
        dns_is_response=True,
        dns_qry_name=name,
        length=length,
        frame_number=frame,
    )


def _random_label(rng, n=32):
    return base64.b32encode(bytes(rng.randrange(256) for _ in range(n))).decode().lower().rstrip("=")[:n]


def _tunnel_queries(domain="t.evil.example", count=20, *, point="A", start=0.0, step=0.37, seed=1):
    rng = random.Random(seed)
    return [
        _q(f"{_random_label(rng)}.{domain}", start + i * step, txn=i, point=point, frame=i + 1) for i in range(count)
    ]


def _legit_workstation(point="A"):
    """Trafic DNS ordinaire : noms varies, courts, requetes irregulieres."""
    names = [
        "www.google.com",
        "mail.google.com",
        "accounts.google.com",
        "fonts.gstatic.com",
        "www.wikipedia.org",
        "fr.wikipedia.org",
        "upload.wikimedia.org",
        "github.com",
        "api.github.com",
        "avatars.githubusercontent.com",
        "www.lemonde.fr",
        "static.lemde.fr",
        "outlook.office365.com",
        "login.microsoftonline.com",
        "update.microsoft.com",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "www.bbc.co.uk",
        "news.bbc.co.uk",
        "ocsp.digicert.com",
        "1.0.0.10.in-addr.arpa",
        "b.a.9.8.7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.f.e.d.c.ip6.arpa",
        "printer.local",
    ]
    rng = random.Random(7)
    pkts, ts = [], 0.0
    for i in range(80):
        ts += rng.uniform(0.2, 9.0)
        name = names[i % len(names)]
        pkts.append(_q(name, ts, txn=i, point=point))
        pkts.append(_r(name, ts + 0.02, txn=i, point=point))
        # beaucoup de trafic non DNS autour
        pkts.extend(make_pkt(point=point, ts=ts + 0.05) for _ in range(12))
    return pkts


# --- primitives -------------------------------------------------------------


def test_shannon_entropy_valeurs_connues():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_split_domain_deux_labels_et_sld_generique():
    assert split_domain("www.example.com") == ("example.com", "www")
    assert split_domain("a.b.c.example.com.") == ("example.com", "a.b.c")
    assert split_domain("example.com") == ("example.com", "")
    assert split_domain("www.bbc.co.uk") == ("bbc.co.uk", "www")
    assert split_domain("bbc.co.uk") == ("co.uk", "bbc")  # limite assumee : pas de liste des suffixes publics
    assert split_domain("WWW.Example.COM") == ("example.com", "www")


# --- signaux forts ----------------------------------------------------------


def test_label_de_plus_de_63_caracteres_leve_une_suspicion():
    long_label = "a" * 64
    result = detect_dns_tunneling([_q(f"{long_label}.evil.example", frame=5)])
    (s,) = result.suspicions
    assert s["kind"] == "domain" and s["domain"] == "evil.example"
    assert s["signals"] == [SIGNAL_LONG_LABEL]
    assert s["severity"] == "moyenne"
    assert s["max_label_len"] == 64
    assert s["frames"] == [5]


def test_label_de_63_caracteres_exactement_est_valide():
    assert detect_dns_tunneling([_q(f"{'a' * 63}.evil.example")]).suspicions == []


def test_noms_de_plus_de_100_caracteres_exigent_trois_requetes():
    name = ".".join(["abcdefghij"] * 11) + ".evil.example"  # labels <= 63, total > 100
    assert len(name) > 100
    two = detect_dns_tunneling([_q(name, i, txn=i) for i in range(2)])
    assert two.suspicions == []
    three = detect_dns_tunneling([_q(name, i, txn=i) for i in range(3)])
    (s,) = three.suspicions
    assert SIGNAL_LONG_NAME in s["signals"]
    assert s["max_name_len"] == len(name)


def test_tunnel_haute_entropie_detecte_avec_score_par_domaine():
    result = detect_dns_tunneling(_tunnel_queries(count=20))
    (s,) = result.suspicions
    assert s["domain"] == "evil.example"
    assert SIGNAL_HIGH_ENTROPY in s["signals"]
    assert s["unique_subdomains"] == 20
    assert s["mean_entropy"] >= 3.6
    (score,) = result.domain_entropy
    assert score["domain"] == "evil.example" and score["mean_entropy"] == s["mean_entropy"]


def test_entropie_isolee_ne_leve_rien():
    """Un seul nom aleatoire (CDN, hash) n'est pas un tunnel."""
    rng = random.Random(3)
    assert detect_dns_tunneling([_q(f"{_random_label(rng)}.cdn.example")]).suspicions == []
    assert detect_dns_tunneling(_tunnel_queries(count=9)).suspicions == []


def test_sous_domaines_courts_a_haute_entropie_ne_levent_rien():
    pkts = [_q(f"{c}{d}.example.com", i, txn=i) for i, (c, d) in enumerate(zip("abcdefghijkl", "mnopqrstuvwx"))]
    assert detect_dns_tunneling(pkts).suspicions == []


# --- signaux faibles --------------------------------------------------------


def test_signaux_faibles_seuls_ne_levent_rien():
    """Domaine dominant + requetes regulieres + grosses reponses, mais noms lisibles."""
    pkts = []
    for i in range(40):
        pkts.append(_q("api.example.com", i * 30.0, txn=i))
        pkts.append(_r("api.example.com", i * 30.0 + 0.05, txn=i, length=900))
        pkts.extend(make_pkt(ts=i * 30.0) for _ in range(10))  # trafic non DNS : pas de constat de volume
    assert detect_dns_tunneling(pkts).suspicions == []


def test_signaux_faibles_aggravent_une_suspicion_deja_levee():
    pkts = _tunnel_queries(count=40, step=1.0)  # regulier, domaine dominant
    pkts += [_r("x.t.evil.example", 50 + i, txn=100 + i, length=900) for i in range(6)]
    (s,) = detect_dns_tunneling(pkts).suspicions
    assert s["severity"] == "elevee"
    for sig in (SIGNAL_HIGH_ENTROPY, SIGNAL_LARGE_RESPONSE, SIGNAL_DOMINANT_DOMAIN, SIGNAL_REGULAR_TIMING):
        assert sig in s["signals"]


def test_intervalles_irreguliers_pas_de_signal_regulier():
    rng = random.Random(5)
    t, pkts = 0.0, []
    for q in _tunnel_queries(count=30):
        t += rng.uniform(0.1, 6.0)
        q.ts = t
        pkts.append(q)
    (s,) = detect_dns_tunneling(pkts).suspicions
    assert SIGNAL_REGULAR_TIMING not in s["signals"]


def test_dominance_exige_un_minimum_de_requetes():
    (s,) = detect_dns_tunneling(_tunnel_queries(count=12)).suspicions
    assert SIGNAL_DOMINANT_DOMAIN not in s["signals"]


# --- volume -----------------------------------------------------------------


def test_volume_dns_superieur_au_seuil_leve_un_constat_faible():
    pkts = [_q("www.example.com", i, txn=i) for i in range(60)] + [make_pkt() for _ in range(20)]
    (s,) = detect_dns_tunneling(pkts).suspicions
    assert s["kind"] == "volume" and s["severity"] == "faible"
    assert s["dns_packets"] == 60 and s["total_packets"] == 80 and s["ratio"] == 0.75


def test_volume_seuil_configurable_et_minimum_de_paquets():
    pkts = [_q("www.example.com", i, txn=i) for i in range(10)] + [make_pkt() for _ in range(10)]
    assert detect_dns_tunneling(pkts).suspicions == []
    strict = DnsTunnelThresholds(volume_ratio=0.3, volume_min_packets=5)
    assert [s["kind"] for s in detect_dns_tunneling(pkts, strict).suspicions] == ["volume"]


# --- aucun faux positif -----------------------------------------------------


def test_trafic_dns_legitime_ne_leve_aucune_suspicion():
    result = detect_dns_tunneling(_legit_workstation())
    assert result.suspicions == []
    assert result.domain_entropy  # les scores sont calcules meme sans suspicion


def test_dns_inverse_et_mdns_ignores_meme_avec_noms_longs():
    long_ptr = ".".join("0123456789abcdef"[i % 16] for i in range(64)) + ".ip6.arpa"
    pkts = [_q(long_ptr, i, txn=i) for i in range(5)] + [_q("printer.local", i, txn=10 + i) for i in range(5)]
    result = detect_dns_tunneling(pkts)
    assert result.suspicions == [] and result.domain_entropy == []


def test_paquets_sans_nom_dns_ignores():
    assert detect_dns_tunneling([make_pkt(), _q(None)]).suspicions == []


# --- points de capture ------------------------------------------------------


def test_suspicion_par_point_sans_double_comptage():
    pkts = _tunnel_queries(count=12, point="A") + _tunnel_queries(count=6, point="B")
    result = detect_dns_tunneling(pkts)
    assert [(s["point"], s["domain"]) for s in result.suspicions] == [("A", "evil.example")]
    assert {(d["point"], d["queries"]) for d in result.domain_entropy} == {("A", 12), ("B", 6)}


def test_seuils_configurables():
    pkts = _tunnel_queries(count=5)
    assert detect_dns_tunneling(pkts).suspicions == []
    loose = DnsTunnelThresholds(entropy_min_unique=5)
    assert len(detect_dns_tunneling(pkts, loose).suspicions) == 1


# --- integration Report / findings de securite -----------------------------


def test_dns_tunnel_findings_format_anomalie():
    result = detect_dns_tunneling(_tunnel_queries(count=20))
    (f,) = dns_tunnel_findings(result.suspicions)
    # regulier + domaine dominant : signaux faibles corroborants -> elevee
    assert f["category"] == "anomalie" and f["severity"] == "elevee" and f["point"] == "A"
    assert "evil.example" in f["detail"] and "tunneling DNS" in f["detail"]
    assert "trames" in f["detail"]


def test_dns_tunnel_findings_volume():
    pkts = [_q("www.example.com", i, txn=i) for i in range(60)]
    (f,) = dns_tunnel_findings(detect_dns_tunneling(pkts).suspicions)
    assert f["severity"] == "faible" and "volume DNS anormal" in f["detail"] and "100 %" in f["detail"]


def test_apply_security_findings_inclut_le_tunneling_dns():
    report = Report()
    pkts = _tunnel_queries(count=20)
    apply_security_findings(report, iter(pkts))  # un iterateur : le module materialise la liste
    cats = [f["category"] for f in report.security_findings]
    assert "anomalie" in cats  # au moins le tunneling DNS
    apply_security_findings(report, pkts)  # remplacement, pas ajout
    assert len(report.security_findings) == len(cats)  # pas d'ajout


def test_apply_security_findings_trafic_dns_legitime_reste_vide():
    report = Report()
    apply_security_findings(report, _legit_workstation())
    assert report.security_findings == []
