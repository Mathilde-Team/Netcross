# SPDX-License-Identifier: GPL-3.0-or-later
"""mTLS, enrôlement et révocation des sondes (#1101).

Quatre niveaux :

- ``netcross_probe.securite`` : autorité de confiance, CSR, signature,
  contextes TLS mutuels, jetons à usage unique, révocation ;
- ``netcross_api.probe_routes`` : la route d'enrôlement du collecteur
  (contrat v1), seule route sans certificat client ;
- ``netcross_probe.enrolement`` : le client de la sonde (la clé privée
  ne quitte jamais la sonde) ;
- une vraie poignée de main TLS mutuelle (client sans certificat
  refusé pendant la poignée de main, pas par une route).

Les tests d'API sautent si l'extra [api] n'est pas installé, comme le
reste du dépôt.
"""

from __future__ import annotations

import json
import re
import secrets
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netcross_probe.enrolement import (
    FICHIER_CA,
    FICHIER_CERTIFICAT,
    FICHIER_CLE,
    EnrolementError,
    demander_enrolement,
)
from netcross_probe.securite import (
    EnrolementRefuseError,
    contexte_mtls_client,
    contexte_mtls_serveur,
    creer_autorite,
    expiration_certificat,
    generer_cle_privee,
    generer_csr_sonde,
    generer_jeton_enrolement,
    hacher_jeton,
    identifiant_sonde,
    signer_csr_sonde,
    verifier_certificat_sonde,
)

PROBE_ID = "prb_a1b2c3d4e5f60718293a4b5c"


# -- autorité, CSR, signature ----------------------------------------------------------------


@pytest.fixture()
def autorite():
    return creer_autorite()


@pytest.fixture()
def cle_sonde():
    return generer_cle_privee()


@pytest.fixture()
def certificat_sonde(autorite, cle_sonde):
    csr = generer_csr_sonde("ROUTEUR", cle_sonde)
    return signer_csr_sonde(csr, PROBE_ID, autorite)


def test_generer_jeton_enrolement_128_bits_et_hache():
    """Jeton : au moins 128 bits d'entropie (contrat v1), jamais stocké en
    clair côté collecteur -- l'empreinte SHA-256 suffit à le vérifier."""
    jeton = generer_jeton_enrolement()
    assert len(jeton) >= 22  # 128 bits en base64 URL
    assert hacher_jeton(jeton) != jeton
    assert hacher_jeton(jeton) == hacher_jeton(jeton)
    assert hacher_jeton(jeton) != hacher_jeton(generer_jeton_enrolement())


def test_certificat_sonde_porte_son_identite(autorite, cle_sonde, certificat_sonde):
    """Le certificat signé porte l'identité en SAN URI
    ``urn:netcross:probe:<probe_id>`` (contrat v1) et une expiration."""
    assert certificat_sonde.startswith("-----BEGIN CERTIFICATE-----")
    assert identifiant_sonde(certificat_sonde) == PROBE_ID
    assert expiration_certificat(certificat_sonde) > 0


def test_verifier_certificat_sonde_valide(autorite, certificat_sonde):
    assert verifier_certificat_sonde(certificat_sonde, autorite) == PROBE_ID


def test_verifier_certificat_sonde_revoquee_refusee(autorite, certificat_sonde):
    """Critère d'acceptation : une sonde révoquée est refusée -- le refus
    est explicite (exception), jamais silencieux."""
    with pytest.raises(EnrolementRefuseError, match="révoquée"):
        verifier_certificat_sonde(certificat_sonde, autorite, revoques={PROBE_ID})


def test_verifier_certificat_sonde_autorite_etrangere_refusee(certificat_sonde):
    """Un certificat signé par une autre autorité est refusé : l'épinglage
    ne dépend pas d'une PKI globale."""
    with pytest.raises(EnrolementRefuseError, match="autorité"):
        verifier_certificat_sonde(certificat_sonde, creer_autorite(nom="Autre CA"))


def test_verifier_certificat_sonde_sans_identite_refuse(autorite, cle_sonde):
    """Un certificat sans SAN URI netcross n'est pas une sonde : refus
    explicite (critère : certificat sans identité de sonde)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pas-une-sonde")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=1))
        .sign(cle, hashes.SHA256())
    )
    pem = certificat.public_bytes(serialization.Encoding.PEM).decode()
    assert identifiant_sonde(pem) is None
    with pytest.raises(EnrolementRefuseError, match="identité"):
        verifier_certificat_sonde(pem, autorite)


def test_verifier_certificat_sonde_expire_refuse(autorite, cle_sonde):
    """Un certificat expiré est refusé : signé par la bonne autorité mais
    sa fenêtre de validité est entièrement dans le passé."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    csr = generer_csr_sonde("SONDE-EXPIREE", cle_sonde)
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(x509.load_pem_x509_csr(csr.encode()).subject)
        .issuer_name(autorite._certificat.subject)
        .public_key(x509.load_pem_x509_csr(csr.encode()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(days=30))
        .not_valid_after(maintenant - datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:netcross:probe:{PROBE_ID}")]),
            critical=True,
        )
        .sign(autorite._cle, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding

    pem = certificat.public_bytes(Encoding.PEM).decode()
    with pytest.raises(EnrolementRefuseError, match="expiré"):
        verifier_certificat_sonde(pem, autorite)


# -- poignée de main TLS mutuelle (réelle) ----------------------------------------------------


class _ServeurMtls:
    """Vrai serveur TLS mutuel sur localhost : certificat client exigé
    PENDANT la poignée de main, écho d'un octet en retour."""

    def __init__(self, contexte):
        self.contexte = contexte
        self.serveur = socket.create_server(("127.0.0.1", 0))
        self.port = self.serveur.getsockname()[1]
        self.actif = True
        self.fil = threading.Thread(target=self._boucler, daemon=True)
        self.fil.start()

    def _boucler(self):
        while self.actif:
            try:
                connexion, _ = self.serveur.accept()
            except OSError:
                break
            with connexion:
                try:
                    tls = self.contexte.wrap_socket(connexion, server_side=True)
                except (ssl.SSLError, OSError):
                    continue  # client sans certificat : refusé, connexion close
                with tls:
                    tls.recv(1)
                    tls.send(b"ok")

    def fermer(self):
        self.actif = False
        self.serveur.close()


def _s_contexte_client(ca_pem, avec_certificat, certificat_pem=None, cle_pem=None):
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.check_hostname = False
    contexte.load_verify_locations(cadata=ca_pem)
    if avec_certificat:
        contexte.load_cert_chain(certfile=_ecrire(certificat_pem), keyfile=_ecrire(cle_pem))
    return contexte


def _ecrire(contenu: str) -> str:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fichier:
        fichier.write(contenu)
    return fichier.name


def test_mtls_poignee_de_main_sans_certificat_client_refusee(autorite, certificat_sonde, cle_sonde):
    """Critère d'acceptation : refus sans certificat client valide --
    refusé par la poignée de main TLS, aucune route n'est servie."""
    cle_ca = autorite.cle_pem
    serveur = _ServeurMtls(contexte_mtls_serveur(autorite.certificat_pem, cle_ca, autorite.certificat_pem))
    try:
        # Client SANS certificat : la poignée de main échoue.
        client = socket.create_connection(("127.0.0.1", serveur.port), timeout=5)
        tls = _s_contexte_client(autorite.certificat_pem, False).wrap_socket(client)
        with pytest.raises(ssl.SSLError):
            tls.send(b"x")
            tls.recv(1)
        tls.close()
    finally:
        serveur.fermer()


def test_mtls_poignee_de_main_avec_certificat_client_acceptee(autorite, certificat_sonde, cle_sonde):
    """Avec un certificat valide signé par l'autorité, l'échange passe."""
    serveur = _ServeurMtls(contexte_mtls_serveur(autorite.certificat_pem, autorite.cle_pem, autorite.certificat_pem))
    try:
        client = socket.create_connection(("127.0.0.1", serveur.port), timeout=5)
        tls = contexte_mtls_client(certificat_sonde, cle_sonde, autorite.certificat_pem).wrap_socket(client)
        tls.send(b"x")
        assert tls.recv(2) == b"ok"
        tls.close()
    finally:
        serveur.fermer()


def test_identifiant_sonde_sans_urn_netcross(autorite, cle_sonde):
    """Un certificat avec SAN mais sans URN netcross n'est pas une sonde."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "avec-san")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("sonde.example.net")]),
            critical=False,
        )
        .sign(cle, hashes.SHA256())
    )
    pem = certificat.public_bytes(serialization.Encoding.PEM).decode()
    assert identifiant_sonde(pem) is None


# -- collecteur : route d'enrôlement (contrat v1) --------------------------------------------

fastapi = pytest.importorskip("fastapi", reason="extra [api] non installé")


@pytest.fixture()
def client_probe():
    from fastapi.testclient import TestClient

    import netcross_api.probe_routes as probe_routes
    from netcross_api.app import app

    probe_routes.registre_sondes = probe_routes.RegistreSondes()
    return TestClient(app), probe_routes.registre_sondes


def _csr_valide(registre):
    cle = generer_cle_privee()
    return generer_csr_sonde("ROUTEUR", cle), cle


def test_enrolement_201_signe_et_repond_le_contrat(client_probe):
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    jeton = registre.creer_jeton()
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {jeton}"},
        json={
            "probe_name": "ROUTEUR",
            "csr_pem": csr_pem,
            "agent_version": "1.0",
            "api_versions": ["1.0"],
        },
    )
    assert reponse.status_code == 201
    assert reponse.headers["netcross-probe-api"] == "1.0"
    corps = reponse.json()
    assert re.fullmatch(r"prb_[a-z0-9]{24}", corps["probe_id"])
    assert corps["client_certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert corps["ca_chain_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert corps["certificate_expires_at"] > 0
    # le certificat signé est vérifiable et porte l'identité attribuée
    assert verifier_certificat_sonde(corps["client_certificate_pem"], registre.autorite) == corps["probe_id"]


def test_enrolement_jeton_reutilise_refuse(client_probe):
    """Critère d'acceptation : un jeton réutilisé est refusé (401,
    code stable ``token_consumed``)."""
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    jeton = registre.creer_jeton()
    entetes = {"Authorization": f"Bearer {jeton}"}
    corps = {"probe_name": "SW1", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["1.0"]}
    assert client.post("/probe/v1/enrollments", headers=entetes, json=corps).status_code == 201
    second = client.post("/probe/v1/enrollments", headers=entetes, json=corps)
    assert second.status_code == 401
    assert second.json()["error"] == "token_consumed"


def test_enrolement_jeton_inconnu_refuse(client_probe):
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": "Bearer jeton-qui-n-existe-pas"},
        json={"probe_name": "SW2", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["1.0"]},
    )
    assert reponse.status_code == 401
    assert reponse.json()["error"] == "token_unknown"


def test_enrolement_sans_jeton_refuse(client_probe):
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    reponse = client.post(
        "/probe/v1/enrollments",
        json={"probe_name": "SW3", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["1.0"]},
    )
    assert reponse.status_code == 401
    assert reponse.json()["error"] == "token_missing"


def test_enrolement_champ_manquant_refuse(client_probe):
    client, registre = client_probe
    jeton = registre.creer_jeton()
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {jeton}"},
        json={"probe_name": "SW4", "agent_version": "1.0", "api_versions": ["1.0"]},
    )
    assert reponse.status_code == 400
    assert reponse.json()["error"] == "invalid_request"


def test_enrolement_version_sans_commune_refuse(client_probe):
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {registre.creer_jeton()}"},
        json={"probe_name": "SW5", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["2.0"]},
    )
    assert reponse.status_code == 426
    assert reponse.json()["error"] == "incompatible_version"


def test_enrolement_nom_deja_inscrit_refuse(client_probe):
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    corps = {"probe_name": "DOUBLON", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["1.0"]}
    assert (
        client.post(
            "/probe/v1/enrollments", headers={"Authorization": f"Bearer {registre.creer_jeton()}"}, json=corps
        ).status_code
        == 201
    )
    second = client.post(
        "/probe/v1/enrollments", headers={"Authorization": f"Bearer {registre.creer_jeton()}"}, json=corps
    )
    assert second.status_code == 409
    assert second.json()["error"] == "probe_name_taken"


def test_enrolement_csr_illisible_refuse(client_probe):
    client, registre = client_probe
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {registre.creer_jeton()}"},
        json={
            "probe_name": "SW6",
            "csr_pem": "ceci-n-est-pas-une-csr",
            "agent_version": "1.0",
            "api_versions": ["1.0"],
        },
    )
    assert reponse.status_code == 400
    assert reponse.json()["error"] == "invalid_csr"


def test_enrolement_sonde_revoquee_refusee(client_probe):
    """Critère d'acceptation : une sonde révoquée est refusée (401,
    ``probe_revoked``) -- même avec un jeton tout neuf."""
    client, registre = client_probe
    csr_pem, _cle = _csr_valide(registre)
    corps = {"probe_name": "REVOQUEE", "csr_pem": csr_pem, "agent_version": "1.0", "api_versions": ["1.0"]}
    premiere = client.post(
        "/probe/v1/enrollments", headers={"Authorization": f"Bearer {registre.creer_jeton()}"}, json=corps
    )
    assert premiere.status_code == 201
    registre.revoquer(premiere.json()["probe_id"])
    seconde = client.post(
        "/probe/v1/enrollments", headers={"Authorization": f"Bearer {registre.creer_jeton()}"}, json=corps
    )
    assert seconde.status_code == 401
    assert seconde.json()["error"] == "probe_revoked"


def test_enrolement_corps_illisible_refuse(client_probe):
    client, registre = client_probe
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {registre.creer_jeton()}"},
        content=b"{pas du tout du json",
    )
    assert reponse.status_code == 400
    assert reponse.json()["error"] == "invalid_request"


# -- sonde : client d'enrôlement (la clé privée ne quitte pas la sonde) -----------------------


class _CollecteurFactice(ThreadingHTTPServer):
    """Vrai serveur HTTP local qui joue le collecteur : file de réponses
    (statut, corps JSON) consommées dans l'ordre des requêtes."""

    def __init__(self, reponses):
        self.reponses = list(reponses)
        super().__init__(("127.0.0.1", 0), _HandlerCollecteurFactice)
        self.fil = threading.Thread(target=self.serve_forever, daemon=True)
        self.fil.start()

    def reponse_suivante(self):
        return self.reponses.pop(0)

    def arreter(self):
        self.shutdown()
        self.server_close()


class _HandlerCollecteurFactice(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 -- imposé par BaseHTTPRequestHandler
        statut, corps = self.server.reponse_suivante()
        contenu = json.dumps(corps).encode()
        self.send_response(statut)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(contenu)))
        self.end_headers()
        self.wfile.write(contenu)

    def log_message(self, *_args):
        pass


def test_demander_enrolement_stocke_les_secrets(tmp_path):
    """La sonde s'inscrit : clé privée générée sur place, certificat et
    chaîne de l'autorité stockés dans son dossier."""
    reponse = {
        "probe_id": PROBE_ID,
        "api_version": "1.0",
        "client_certificate_pem": "-----BEGIN CERTIFICATE-----\nsonde\n-----END CERTIFICATE-----\n",
        "ca_chain_pem": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
        "certificate_expires_at": 4102444800.0,
    }
    serveur = _CollecteurFactice([(201, reponse)])
    try:
        url = f"http://127.0.0.1:{serveur.server_address[1]}/probe/v1/enrollments"
        enrolement = demander_enrolement(url, "jeton-admin", "ROUTEUR", tmp_path / "sonde")
    finally:
        serveur.arreter()
    assert enrolement.probe_id == PROBE_ID
    assert (tmp_path / "sonde" / FICHIER_CERTIFICAT).exists()
    assert (tmp_path / "sonde" / FICHIER_CLE).exists()
    assert (tmp_path / "sonde" / FICHIER_CA).exists()
    # la clé stockée est bien celle générée pour la CSR
    assert (tmp_path / "sonde" / FICHIER_CLE).read_text() == enrolement.cle_pem


def test_demander_enrolement_refus_transmis_sans_le_jeton(tmp_path):
    """Un refus du collecteur devient EnrolementError avec le code stable
    du contrat -- le message ne contient jamais le jeton."""
    serveur = _CollecteurFactice([(401, {"error": "token_consumed", "message": "jeton déjà utilisé"})])
    try:
        url = f"http://127.0.0.1:{serveur.server_address[1]}/probe/v1/enrollments"
        with pytest.raises(EnrolementError) as erreur:
            demander_enrolement(url, "jeton-secret", "ROUTEUR", tmp_path / "sonde")
    finally:
        serveur.arreter()
    assert erreur.value.statut == 401
    assert erreur.value.code == "token_consumed"
    assert "jeton-secret" not in str(erreur.value)


def test_demander_enrolement_reponse_illisible(monkeypatch, tmp_path):
    """Un refus HTTP au corps illisible devient quand même une
    EnrolementError -- la sonde ne plante jamais sur un collecteur
    défaillant (branche « réponse illisible »)."""

    def _urlopen_illisible(*_args, **_kwargs):
        import urllib.error as erreur_urllib

        erreur = erreur_urllib.HTTPError("url", 502, "Bad Gateway", {}, None)
        erreur.read = lambda: (_ for _ in ()).throw(ValueError("pas du JSON"))
        raise erreur

    monkeypatch.setattr("netcross_probe.enrolement.urllib.request.urlopen", _urlopen_illisible)
    with pytest.raises(EnrolementError) as erreur:
        demander_enrolement("http://collecteur/probe/v1/enrollments", "j", "ROUTEUR", tmp_path)
    assert erreur.value.statut == 502
    assert erreur.value.code == "reponse_illisible"


def test_demander_enrolement_collecteur_injoignable(tmp_path):
    port = secrets.randbelow(20000) + 40000  # très probablement fermé
    with pytest.raises(EnrolementError) as erreur:
        demander_enrolement(f"http://127.0.0.1:{port}/probe/v1/enrollments", "j", "ROUTEUR", tmp_path)
    assert erreur.value.code == "collecteur_injoignable"
