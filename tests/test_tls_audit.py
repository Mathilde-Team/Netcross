# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.security.tls_audit -- issue #153 (SCENARIO-7) : audit des
certificats TLS. Paquets synthetiques (make_pkt) portant les champs
`tls_cert_*` ; l'extraction depuis tshark est testee dans
test_tls_cert_extraction.py. Le certificat « sain » sert de reference pour
le critere « aucun faux positif sur un certificat legitime ».
"""

from datetime import datetime, timezone

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_core.security.findings import apply_security_findings, tls_audit_findings
from netcross_core.security.tls_audit import (
    CODE_BROKEN_SIGNATURE,
    CODE_DEPRECATED_SIGNATURE,
    CODE_EXPIRED,
    CODE_INCOMPLETE_CHAIN,
    CODE_IP_IN_SAN,
    CODE_LONG_NAME,
    CODE_LONG_VALIDITY,
    CODE_NOT_YET_VALID,
    CODE_RANDOM_NAME,
    CODE_SELF_SIGNED,
    CODE_WEAK_KEY,
    CODE_WILDCARD,
    CODE_WILDCARD_BROAD,
    TlsAuditPolicy,
    audit_certificate,
    audit_tls_certificates,
    parse_cert_date,
)
from netcross_report.security_report import build_security_report

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc).timestamp()


def _cert(**overrides):
    """Certificat feuille sain : 90 jours, RSA 2048/SHA-256, emis par un
    intermediaire, chaine complete, un seul nom DNS ordinaire."""
    fields = {
        "point": "A",
        "ts": NOW,
        "src": "10.0.0.5",
        "sport": 443,
        "dst": "203.0.113.9",
        "dport": 51000,
        "frame_number": 7,
        "tls_cert_serial": "10:01",
        "tls_cert_not_before": "2026-09-01 00:00:00 (UTC)",
        "tls_cert_not_after": "2026-11-30 00:00:00 (UTC)",
        "tls_cert_san": ("www.example.com",),
        "tls_cert_issuer": "CN=Lab Intermediate CA,O=Lab",
        "tls_cert_subject": "CN=www.example.com,O=Lab",
        "tls_cert_sig_hash": "sha256",
        "tls_cert_key_type": "RSA",
        "tls_cert_key_bits": 2048,
        "tls_cert_san_ip": (),
        "tls_cert_chain_len": 2,
    }
    fields.update(overrides)
    return make_pkt(**fields)


def _codes(pk, policy=None):
    issues = audit_certificate(pk, policy) if policy else audit_certificate(pk)
    return {i.code for i in issues}


# -- certificat sain -------------------------------------------------------


def test_certificat_sain_ne_leve_rien():
    assert audit_certificate(_cert()) == []


def test_paquet_sans_certificat_ignore():
    assert audit_certificate(make_pkt()) == []
    result = audit_tls_certificates([make_pkt(), make_pkt(point="B")])
    assert result.certificates == [] and result.servers == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"tls_cert_key_type": "EC", "tls_cert_key_bits": 256, "tls_cert_sig_hash": "sha384"},
        {"tls_cert_key_type": "EC", "tls_cert_key_bits": 384},
        {"tls_cert_key_type": "Ed25519", "tls_cert_key_bits": None, "tls_cert_sig_hash": None},
        {"tls_cert_key_type": "RSA", "tls_cert_key_bits": 4096},
        {"tls_cert_san": ("cdn.example.com", "img.example.com", "api.example.com", "a1b2c3.example.com")},
    ],
)
def test_variantes_saines_ne_levent_rien(overrides):
    assert audit_certificate(_cert(**overrides)) == []


# -- dates -----------------------------------------------------------------


def test_certificat_expire():
    pk = _cert(tls_cert_not_before="2025-12-01 00:00:00 (UTC)", tls_cert_not_after="2026-03-01 00:00:00 (UTC)")
    (issue,) = audit_certificate(pk)
    assert issue.code == CODE_EXPIRED and issue.severity == "elevee"
    assert "2026-03-01" in issue.detail and "2026-09-21" in issue.detail


def test_certificat_pas_encore_valide():
    pk = _cert(tls_cert_not_before="2026-12-01 00:00:00 (UTC)", tls_cert_not_after="2027-02-01 00:00:00 (UTC)")
    assert _codes(pk) == {CODE_NOT_YET_VALID}


def test_expiration_evaluee_a_l_horodatage_du_paquet_pas_a_aujourd_hui():
    # capture de 2024 : le certificat etait valide alors, il est expire depuis -> aucun constat
    ts_2024 = datetime(2024, 6, 1, tzinfo=timezone.utc).timestamp()
    pk = _cert(
        ts=ts_2024, tls_cert_not_before="2024-05-01 00:00:00 (UTC)", tls_cert_not_after="2024-08-01 00:00:00 (UTC)"
    )
    assert audit_certificate(pk) == []


def test_date_illisible_ne_leve_pas_de_constat_de_dates():
    pk = _cert(tls_cert_not_before="pas une date", tls_cert_not_after=None)
    assert audit_certificate(pk) == []
    assert parse_cert_date("2026-09-21 18:40:12 (UTC)") == datetime(2026, 9, 21, 18, 40, 12, tzinfo=timezone.utc)
    assert parse_cert_date("n'importe quoi") is None and parse_cert_date(None) is None


def test_validite_trop_longue():
    pk = _cert(tls_cert_not_after="2028-12-24 00:00:00 (UTC)")
    (issue,) = audit_certificate(pk)
    assert issue.code == CODE_LONG_VALIDITY and issue.severity == "faible" and "398" in issue.detail


def test_validite_de_398_jours_exactement_est_tolere():
    pk = _cert(tls_cert_not_before="2026-09-01 00:00:00 (UTC)", tls_cert_not_after="2027-10-04 00:00:00 (UTC)")
    assert audit_certificate(pk) == []  # 398 jours pile


def test_seuil_de_validite_configurable_ou_desactivable():
    pk = _cert(tls_cert_not_after="2027-03-30 00:00:00 (UTC)")  # 210 jours
    assert audit_certificate(pk) == []
    assert _codes(pk, TlsAuditPolicy(max_validity_days=200)) == {CODE_LONG_VALIDITY}
    long_pk = _cert(tls_cert_not_after="2030-01-01 00:00:00 (UTC)")
    assert _codes(long_pk, TlsAuditPolicy(max_validity_days=None)) == set()


# -- auto-signe ------------------------------------------------------------


def test_auto_signe():
    pk = _cert(
        tls_cert_issuer="CN=self.lab.test,O=Lab", tls_cert_subject="CN=self.lab.test,O=Lab", tls_cert_chain_len=1
    )
    (issue,) = audit_certificate(pk)
    assert issue.code == CODE_SELF_SIGNED and issue.severity == "moyenne"


def test_emetteur_inconnu_n_est_jamais_declare_auto_signe():
    pk = _cert(tls_cert_issuer=None, tls_cert_subject=None, tls_cert_chain_len=None)
    assert audit_certificate(pk) == []


# -- algorithmes faibles ---------------------------------------------------


@pytest.mark.parametrize("digest", ["md5", "MD5", "md2", "md4"])
def test_signature_cassee(digest):
    (issue,) = audit_certificate(_cert(tls_cert_sig_hash=digest))
    assert issue.code == CODE_BROKEN_SIGNATURE and issue.severity == "elevee"


def test_signature_sha1_obsolete():
    (issue,) = audit_certificate(_cert(tls_cert_sig_hash="sha1"))
    assert issue.code == CODE_DEPRECATED_SIGNATURE and issue.severity == "moyenne"
    assert "SHA1" in issue.detail


@pytest.mark.parametrize(
    ("key_type", "bits", "flagged"),
    [
        ("RSA", 1024, True),
        ("RSA", 2047, True),
        ("RSA", 2048, False),
        ("DSA", 1024, True),
        ("EC", 224, True),
        ("EC", 256, False),
        ("Ed25519", None, False),
        ("RSA", None, False),
    ],
)
def test_taille_de_cle(key_type, bits, flagged):
    codes = _codes(_cert(tls_cert_key_type=key_type, tls_cert_key_bits=bits))
    assert (CODE_WEAK_KEY in codes) is flagged


def test_seuils_de_cle_configurables():
    pk = _cert(tls_cert_key_type="RSA", tls_cert_key_bits=2048)
    assert _codes(pk, TlsAuditPolicy(min_rsa_bits=3072)) == {CODE_WEAK_KEY}


# -- chaine incomplete -----------------------------------------------------


def test_chaine_incomplete():
    (issue,) = audit_certificate(_cert(tls_cert_chain_len=1))
    assert issue.code == CODE_INCOMPLETE_CHAIN and issue.severity == "faible"


def test_chaine_complete_ou_inconnue_ne_leve_rien():
    assert audit_certificate(_cert(tls_cert_chain_len=3)) == []
    assert audit_certificate(_cert(tls_cert_chain_len=None)) == []


# -- noms ------------------------------------------------------------------


def test_wildcard_ordinaire_severite_faible():
    (issue,) = audit_certificate(_cert(tls_cert_san=("*.example.com", "example.com")))
    assert issue.code == CODE_WILDCARD and issue.severity == "faible" and "*.example.com" in issue.detail


@pytest.mark.parametrize("name", ["*", "*.com", "*.fr"])
def test_wildcard_trop_large(name):
    (issue,) = audit_certificate(_cert(tls_cert_san=(name,)))
    assert issue.code == CODE_WILDCARD_BROAD and issue.severity == "moyenne"


def test_ip_dans_le_san():
    (issue,) = audit_certificate(_cert(tls_cert_san_ip=("192.0.2.7", "2001:db8::1")))
    assert issue.code == CODE_IP_IN_SAN and "192.0.2.7" in issue.detail


def test_nom_tres_long():
    long_name = "a" * 60 + "." + "b" * 60 + ".example.com"
    assert CODE_LONG_NAME in _codes(_cert(tls_cert_san=(long_name,)))


def test_nom_aleatoire():
    assert CODE_RANDOM_NAME in _codes(_cert(tls_cert_san=("x9k2q8v7m4z1w6p3r5t0.example.com",)))
    # nom long mais lisible : pas aleatoire
    assert CODE_RANDOM_NAME not in _codes(_cert(tls_cert_san=("internal-billing-service.example.com",)))


def test_detail_des_noms_est_borne():
    names = tuple(f"*.z{i}.example.com" for i in range(9))
    (issue,) = audit_certificate(_cert(tls_cert_san=names))
    assert "(+6)" in issue.detail


# -- politique -------------------------------------------------------------


def test_politique_desactive_un_controle_et_remplace_une_severite():
    pk = _cert(tls_cert_issuer="CN=x", tls_cert_subject="CN=x", tls_cert_chain_len=1, tls_cert_sig_hash="sha1")
    assert _codes(pk) == {CODE_SELF_SIGNED, CODE_DEPRECATED_SIGNATURE}
    assert _codes(pk, TlsAuditPolicy(disabled=frozenset({CODE_SELF_SIGNED}))) == {CODE_DEPRECATED_SIGNATURE}
    policy = TlsAuditPolicy(severities={CODE_DEPRECATED_SIGNATURE: "elevee"})
    sha1 = next(i for i in audit_certificate(pk, policy) if i.code == CODE_DEPRECATED_SIGNATURE)
    assert sha1.severity == "elevee"


# -- agregation et score par serveur -----------------------------------------


def _bad(**overrides):
    """Expire + auto-signe + MD5 : 30 + 15 + 30 points."""
    fields = {
        "tls_cert_not_before": "2024-01-01 00:00:00 (UTC)",
        "tls_cert_not_after": "2024-03-01 00:00:00 (UTC)",
        "tls_cert_issuer": "CN=old",
        "tls_cert_subject": "CN=old",
        "tls_cert_sig_hash": "md5",
        "tls_cert_chain_len": 1,
        "tls_cert_serial": "AA",
    }
    fields.update(overrides)
    return _cert(**fields)


def test_score_de_risque_par_serveur():
    result = audit_tls_certificates([_bad(), _cert(src="10.0.0.6", tls_cert_serial="BB")])
    bad, healthy = result.servers
    assert (bad["host"], bad["port"], bad["score"], bad["severity"]) == ("10.0.0.5", 443, 75, "elevee")
    assert bad["issues"] == sorted([CODE_EXPIRED, CODE_SELF_SIGNED, CODE_BROKEN_SIGNATURE])
    assert (healthy["host"], healthy["score"], healthy["severity"], healthy["issues"]) == ("10.0.0.6", 0, None, [])


def test_score_plafonne_a_100():
    pkts = [_bad(tls_cert_serial=f"{i:02X}", tls_cert_subject=f"CN=c{i}") for i in range(5)]
    (server,) = audit_tls_certificates(pkts).servers
    assert server["score"] == 100 and server["certificates"] == 5


def test_meme_certificat_repete_compte_une_fois():
    pkts = [_bad(ts=NOW + i, frame_number=i + 1) for i in range(3)]
    result = audit_tls_certificates(pkts)
    (cert,) = result.certificates
    assert cert["occurrences"] == 3 and cert["frame"] == 1  # premiere occurrence = preuve
    assert result.servers[0]["score"] == 75


def test_meme_certificat_vu_a_deux_points_n_augmente_pas_le_score():
    result = audit_tls_certificates([_bad(point="A"), _bad(point="B")])
    assert len(result.certificates) == 2
    (server,) = result.servers
    assert server["score"] == 75 and server["points"] == ["A", "B"] and server["certificates"] == 1


def test_serveurs_tries_par_score_decroissant():
    result = audit_tls_certificates([_cert(src="10.0.0.9"), _bad(src="10.0.0.8", tls_cert_serial="C")])
    assert [s["host"] for s in result.servers] == ["10.0.0.8", "10.0.0.9"]


# -- integration au rapport de securite ----------------------------------------


def test_constats_du_rapport_de_securite():
    result = audit_tls_certificates([_bad()])
    findings = tls_audit_findings(result)
    assert {f["severity"] for f in findings} == {"elevee", "moyenne"}
    assert {f["category"] for f in findings} == {"anomalie"}
    expired = next(f for f in findings if "expire" in f["detail"])
    assert expired["host"] == "10.0.0.5" and expired["port"] == 443 and expired["point"] == "A"
    assert "score TLS du serveur 75/100" in expired["detail"] and "trame 7" in expired["detail"]
    assert "CN=old" in expired["detail"]


def test_constat_mentionne_l_emetteur_quand_il_differe_du_sujet():
    (finding,) = tls_audit_findings(audit_tls_certificates([_cert(tls_cert_chain_len=1)]))
    assert "emetteur CN=Lab Intermediate CA,O=Lab" in finding["detail"]


def test_certificat_sain_aucun_constat():
    assert tls_audit_findings(audit_tls_certificates([_cert(), _cert(point="B", ts=NOW + 1)])) == []


def test_apply_security_findings_inclut_l_audit_tls_et_remplace():
    report = Report()
    pkts = [_bad()]
    apply_security_findings(report, iter(pkts))
    first = list(report.security_findings)
    assert len(first) == 3 and {f["category"] for f in first} == {"anomalie"}
    apply_security_findings(report, pkts)
    assert report.security_findings == first


def test_apply_security_findings_applique_la_politique_fournie():
    report = Report()
    policy = TlsAuditPolicy(disabled=frozenset({CODE_EXPIRED, CODE_SELF_SIGNED, CODE_BROKEN_SIGNATURE}))
    apply_security_findings(report, [_bad()], tls_policy=policy)
    assert report.security_findings == []


def test_apply_security_findings_certificat_legitime_reste_vide():
    report = Report()
    apply_security_findings(report, [_cert(), _cert(point="B", ts=NOW + 5)])
    assert report.security_findings == []


def test_le_rapport_de_securite_compte_les_anomalies_tls():
    report = Report()
    apply_security_findings(report, [_bad()])
    sr = build_security_report(report)
    assert len(sr.anomalies) == 3 and sr.dashboard.score > 0
