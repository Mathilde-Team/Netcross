# SPDX-License-Identifier: GPL-3.0-or-later
"""
Extraction des details du certificat TLS feuille (issue #153) : emetteur,
sujet, algorithme de signature, cle publique, IP du SAN, longueur de chaine,
lus dans le DER brut que tshark expose en EK (`tls.handshake.certificate`).

Deux niveaux :
- `extract_tls_certificate` sur des couches EK synthetiques dont le DER est
  fabrique par `cryptography` (SHA-1/MD5 : DER openssl embarques, voir
  tls_cert_fixtures.py, car cryptography refuse de les signer) ;
- de bout en bout avec de VRAIS tshark sur des trames Ethernet/IPv4/TCP
  synthetisees octet par octet portant un message TLS Certificate : verifie
  la chaine tshark -> Pkt -> audit, dont le critere « aucun faux positif sur
  un certificat legitime ». Saute si tshark est absent du PATH.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import shutil
import socket
import struct

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from pcap_builders import write_pcap
from tls_cert_fixtures import MD5_RSA1024_DER_B64, SHA1_RSA1024_DER_B64

from netcross_core.models import Report
from netcross_core.parsing import parse_capture
from netcross_core.security.findings import apply_security_findings
from pcap_parser.protocols import _signature_hash, extract_tls_certificate

UTC = dt.timezone.utc
DATES = ["2026-09-01 00:00:00 (UTC)", "2026-11-30 00:00:00 (UTC)"]


# -- fabrication de certificats ------------------------------------------------


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make(cn, key, *, issuer_cn=None, issuer_key=None, start=None, days=90, san=(), ips=(), sign_hash=None):
    start = start or dt.datetime(2026, 9, 1, tzinfo=UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=days))
    )
    names = [x509.DNSName(n) for n in san] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    signer = issuer_key or key
    if sign_hash is None:
        sign_hash = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, sign_hash)


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _colon_hex(der: bytes) -> str:
    return ":".join(f"{b:02x}" for b in der)


def _layers(*ders: bytes) -> dict:
    blobs = [_colon_hex(d) for d in ders]
    return {
        "tls": {
            "x509af_x509af_utcTime": DATES * len(ders),
            "x509af_x509af_serialNumber": "01:02",
            "tls_tls_handshake_certificate": blobs if len(blobs) > 1 else blobs[0],
        }
    }


_RSA = rsa.generate_private_key(65537, 2048)
_EC = ec.generate_private_key(ec.SECP256R1())


# -- extract_tls_certificate : details du DER ------------------------------------


def test_auto_signe_rsa_2048_sha256():
    result = extract_tls_certificate(_layers(_der(_make("self.lab.test", _RSA, san=["self.lab.test"]))))
    assert result["issuer"] == result["subject"] == "CN=self.lab.test"
    assert (result["sig_hash"], result["key_type"]) == ("sha256", "RSA")
    assert (result["key_bits"], result["chain_len"]) == (2048, 1)
    assert result["san_ip"] == ()
    # les champs historiques sont conserves a l'identique
    assert result["not_before"] == DATES[0] and result["not_after"] == DATES[1] and result["serial"] == "01:02"


def test_chaine_de_deux_certificats_emetteur_different_et_longueur():
    root = _make("Lab Intermediate CA", _EC, issuer_cn="Lab Root")
    leaf = _make("www.lab.test", _RSA, issuer_cn="Lab Intermediate CA", issuer_key=_EC, san=["www.lab.test"])
    result = extract_tls_certificate(_layers(_der(leaf), _der(root)))
    assert result["subject"] == "CN=www.lab.test" and result["issuer"] == "CN=Lab Intermediate CA"
    assert result["chain_len"] == 2 and result["key_type"] == "RSA"
    assert result["sig_hash"] == "sha256"  # signature ECDSA-SHA256 de l'intermediaire


def test_cle_ec_224_et_cle_rsa_1024():
    ec224 = _make("ec.lab.test", ec.generate_private_key(ec.SECP224R1()))
    weak_rsa = _make("rsa.lab.test", rsa.generate_private_key(65537, 1024))
    assert extract_tls_certificate(_layers(_der(ec224)))["key_type"] == "EC"
    assert extract_tls_certificate(_layers(_der(ec224)))["key_bits"] == 224
    result = extract_tls_certificate(_layers(_der(weak_rsa)))
    assert (result["key_type"], result["key_bits"]) == ("RSA", 1024)


def test_ed25519_pas_de_hash_ni_de_taille():
    cert = _make("ed.lab.test", ed25519.Ed25519PrivateKey.generate())
    result = extract_tls_certificate(_layers(_der(cert)))
    assert (result["key_type"], result["key_bits"], result["sig_hash"]) == ("Ed25519", None, None)


def test_adresses_ip_du_san():
    cert = _make("ip.lab.test", _RSA, san=["ip.lab.test"], ips=["192.0.2.7", "2001:db8::1"])
    assert extract_tls_certificate(_layers(_der(cert)))["san_ip"] == ("192.0.2.7", "2001:db8::1")


@pytest.mark.parametrize(("b64", "digest"), [(SHA1_RSA1024_DER_B64, "sha1"), (MD5_RSA1024_DER_B64, "md5")])
def test_signatures_faibles_reconnues(b64, digest):
    result = extract_tls_certificate(_layers(base64.b64decode(b64)))
    assert result["sig_hash"] == digest and result["key_bits"] == 1024
    assert result["issuer"] == result["subject"]


def test_oid_de_signature_non_mappe_par_cryptography_reste_reconnu():
    class _Oid:
        dotted_string = "1.2.840.113549.1.1.2"  # md2WithRSAEncryption

    class _Cert:
        signature_algorithm_oid = _Oid()

        @property
        def signature_hash_algorithm(self):
            raise UnsupportedAlgorithm("md2")

    assert _signature_hash(_Cert()) == "md2"
    _Oid.dotted_string = "1.2.3.4"
    assert _signature_hash(_Cert()) is None


def test_sans_der_les_cles_de_details_sont_absentes():
    layers = {"tls": {"x509af_x509af_utcTime": DATES, "x509af_x509af_serialNumber": "01"}}
    assert set(extract_tls_certificate(layers)) == {"not_before", "not_after", "san", "serial"}


def test_der_illisible_ne_leve_pas_et_garde_les_champs_historiques():
    layers = _layers(b"\x30\x03\x02\x01\x00")
    assert set(extract_tls_certificate(layers)) == {"not_before", "not_after", "san", "serial"}
    layers["tls"]["tls_tls_handshake_certificate"] = "zz:not:hex"
    assert "issuer" not in extract_tls_certificate(layers)


# -- de bout en bout avec tshark -------------------------------------------------

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")

SERVER, CLIENT = "10.0.0.5", "203.0.113.9"
CAPTURE_TS = dt.datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _frame(src, dst, sport, dport, data):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + data
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst)
    )
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + tcp


def _certificate_record(*ders: bytes) -> bytes:
    body = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    handshake = b"\x0b" + (len(body) + 3).to_bytes(3, "big") + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", 0x0303, len(handshake)) + handshake


def _capture(tmp_path, *ders: bytes):
    path = tmp_path / "tls.pcap"
    ts_us = int(CAPTURE_TS.timestamp() * 1_000_000)
    write_pcap(path, [(ts_us, _frame(SERVER, CLIENT, 443, 51000, _certificate_record(*ders)))])
    return str(path)


def _legit_chain():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    inter = _make("Lab Intermediate CA", ca_key, issuer_cn="Lab Root", days=1800)
    leaf = _make(
        "www.lab.test", _RSA, issuer_cn="Lab Intermediate CA", issuer_key=ca_key, san=["www.lab.test"], days=90
    )
    return _der(leaf), _der(inter)


@needs_tshark
def test_tshark_certificat_legitime_aucun_faux_positif(tmp_path):
    (pk,) = [p for p in parse_capture("A", _capture(tmp_path, *_legit_chain())) if p.tls_cert_serial]
    assert pk.tls_cert_subject == "CN=www.lab.test" and pk.tls_cert_issuer == "CN=Lab Intermediate CA"
    assert (pk.tls_cert_sig_hash, pk.tls_cert_key_type, pk.tls_cert_key_bits) == ("sha256", "RSA", 2048)
    assert pk.tls_cert_chain_len == 2 and pk.tls_cert_san == ("www.lab.test",) and pk.tls_cert_san_ip == ()
    report = Report()
    apply_security_findings(report, [pk])
    # flow_stats ajoute des constats d'anomalie de flux (issue #145) :
    # on verifie juste l'absence de constats TLS/cert sur un certificat legitime.
    non_flow = [f for f in report.security_findings if "flux " not in f.get("detail", "")]
    assert non_flow == []


@needs_tshark
def test_tshark_feuille_seule_signalee_comme_chaine_incomplete(tmp_path):
    leaf, _inter = _legit_chain()
    pkts = parse_capture("A", _capture(tmp_path, leaf))
    report = Report()
    apply_security_findings(report, pkts)
    non_flow = [f for f in report.security_findings if "flux " not in f.get("detail", "")]
    (finding,) = non_flow
    assert finding["severity"] == "faible" and "chaine incomplete" in finding["detail"]
    assert (finding["host"], finding["port"]) == (SERVER, 443)


@needs_tshark
def test_tshark_certificat_faible_auto_signe_sha1(tmp_path):
    pkts = parse_capture("A", _capture(tmp_path, base64.b64decode(SHA1_RSA1024_DER_B64)))
    report = Report()
    apply_security_findings(report, pkts)
    non_flow = [f for f in report.security_findings if "flux " not in f.get("detail", "")]
    details = " | ".join(f["detail"] for f in non_flow)
    assert "auto-signe" in details and "SHA1" in details and "cle RSA de 1024 bits" in details
    assert "wildcard" not in details and "expire" not in details
    assert len(non_flow) == 3
    assert {f["severity"] for f in non_flow} == {"elevee", "moyenne"}


@needs_tshark
def test_tshark_certificat_expire_et_ip_dans_le_san(tmp_path):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    inter = _make("Lab Intermediate CA", ca_key, issuer_cn="Lab Root", days=1800)
    old = _make(
        "old.lab.test",
        _RSA,
        issuer_cn="Lab Intermediate CA",
        issuer_key=ca_key,
        start=dt.datetime(2024, 1, 1, tzinfo=UTC),
        days=60,
        san=["old.lab.test"],
        ips=["192.0.2.7"],
    )
    report = Report()
    apply_security_findings(report, parse_capture("A", _capture(tmp_path, _der(old), _der(inter))))
    non_flow = [f for f in report.security_findings if "flux " not in f.get("detail", "")]
    by_kind = {("expire" in f["detail"], "adresse IP" in f["detail"]): f for f in non_flow}
    assert by_kind[(True, False)]["severity"] == "elevee" and "2024-03-01" in by_kind[(True, False)]["detail"]
    assert by_kind[(False, True)]["severity"] == "faible" and "192.0.2.7" in by_kind[(False, True)]["detail"]
    assert len(non_flow) == 2
