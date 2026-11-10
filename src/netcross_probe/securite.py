# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_probe.securite -- mTLS, enrôlement et révocation des sondes
(issue #1101, sous-issue 3/6 du chantier #1002).

« Aucune écoute ni transfert sans authentification mutuelle » : les
fenêtres de trafic ne circulent qu'entre pairs authentifiés par TLS
mutuel, chaque certificat portant l'identité de sa sonde dans un SAN URI
``urn:netcross:probe:<probe_id>``. Trois briques :

- une **autorité de confiance** locale au collecteur (certificat
  auto-signé) qui signe les certificats clients des sondes ; la clé
  privée de la sonde ne quitte jamais la sonde (CSR PKCS#10) ;
- des **contextes TLS mutuels** (serveur et client) : certificat client
  exigé pendant la poignée de main, aucune route n'est servie sans ;
- des **jetons d'enrôlement à usage unique** (au moins 128 bits
  d'entropie, stockés hachés côté collecteur) et la **révocation** d'une
  sonde (liste d'identifiants refusés).

Ce module est volontairement au bas de la pile (importable par le
collecteur ``netcross_api`` comme par la sonde) et ne dépend que de la
bibliothèque standard et de ``cryptography`` -- jamais de FastAPI.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
import ssl
import tempfile
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from loguru import logger

__all__ = [
    "AutoriteConfiance",
    "EnrolementRefuseError",
    "contexte_mtls_client",
    "contexte_mtls_serveur",
    "creer_autorite",
    "expiration_certificat",
    "generer_cle_privee",
    "generer_csr_sonde",
    "generer_jeton_enrolement",
    "hacher_jeton",
    "identifiant_sonde",
    "signer_csr_sonde",
    "verifier_certificat_sonde",
]

_URN_PREFIXE = "urn:netcross:probe:"


@dataclass(frozen=True)
class AutoriteConfiance:
    """Certificat auto-signé (et sa clé) de l'autorité du collecteur :
    signe les certificats clients des sondes, épinglé par chacune."""

    certificat_pem: str
    cle_pem: str

    @property
    def _certificat(self) -> x509.Certificate:
        logger.debug("AutoriteConfiance._certificat: retour certificat chargé")
        return x509.load_pem_x509_certificate(self.certificat_pem.encode())

    @property
    def _cle(self):
        logger.debug("AutoriteConfiance._cle: retour clé chargée")
        return serialization.load_pem_private_key(self.cle_pem.encode(), password=None)


class EnrolementRefuseError(Exception):
    """Le certificat proposé n'est pas signé par l'autorité de confiance,
    ou la sonde est révoquée : l'authentification mutuelle est refusée."""

    def __init__(self, raison: str):
        logger.debug("EnrolementRefuseError: entrée (raison {})", raison)
        self.raison = raison
        super().__init__(raison)
        logger.debug("EnrolementRefuseError: retour")


def generer_cle_privee() -> str:
    """Clé privée EC P-256 en PEM (PKCS#8) : propre à une sonde, jamais
    transmise -- la CSR seule voyage."""
    logger.debug("generer_cle_privee: entrée")
    cle = ec.generate_private_key(ec.SECP256R1())
    pem = cle.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    logger.debug("generer_cle_privee: retour clé PEM")
    return pem


def creer_autorite(nom: str = "Netcross Probe CA", jours: int = 3650) -> AutoriteConfiance:
    """Autorité auto-signée du collecteur : les certificats des sondes
    sont vérifiés contre elle (épinglage), sa clé signe les leurs."""
    logger.debug("creer_autorite: entrée (nom {})", nom)
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nom)])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(sujet)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=jours))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(cle, hashes.SHA256())
    )
    autorite = AutoriteConfiance(
        certificat_pem=certificat.public_bytes(serialization.Encoding.PEM).decode(),
        cle_pem=cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    logger.debug("creer_autorite: retour autorité")
    return autorite


def generer_csr_sonde(nom_sonde: str, cle_pem: str) -> str:
    """Demande de signature PKCS#10 pour une sonde : la clé privée reste
    sur la sonde, seule la CSR est envoyée au collecteur."""
    logger.debug("generer_csr_sonde: entrée (sonde {})", nom_sonde)
    cle = serialization.load_pem_private_key(cle_pem.encode(), password=None)
    if not isinstance(cle, ec.EllipticCurvePrivateKey):
        logger.debug("generer_csr_sonde: clé de type inattendu -> ValueError")
        raise ValueError("clé privée attendue : courbe elliptique P-256")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nom_sonde)]))
        .sign(cle, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    logger.debug("generer_csr_sonde: retour CSR PEM")
    return pem


def signer_csr_sonde(csr_pem: str, probe_id: str, autorite: AutoriteConfiance, jours: int = 365) -> str:
    """Signe la CSR d'une sonde : le certificat porte son identité en SAN
    URI ``urn:netcross:probe:<probe_id>`` (contrat v1)."""
    logger.debug("signer_csr_sonde: entrée (sonde {})", probe_id)
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    cle_autorite = autorite._cle
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(autorite._certificat.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=jours))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_URN_PREFIXE + probe_id)]),
            critical=True,
        )
        .sign(cle_autorite, hashes.SHA256())
    )
    pem = certificat.public_bytes(serialization.Encoding.PEM).decode()
    logger.debug("signer_csr_sonde: retour certificat PEM")
    return pem


def expiration_certificat(certificat_pem: str) -> float:
    """Date d'expiration du certificat en secondes Unix (contrat v1 :
    ``certificate_expires_at``) -- la sonde sait quand renouveler."""
    logger.debug("expiration_certificat: entrée")
    certificat = x509.load_pem_x509_certificate(certificat_pem.encode())
    expiration = certificat.not_valid_after_utc.timestamp()
    logger.debug("expiration_certificat: retour {}", expiration)
    return expiration


def identifiant_sonde(certificat_pem: str) -> str | None:
    """Identifiant de sonde lu dans le SAN URI du certificat, None si
    absent -- un certificat sans identité netcross n'est pas une sonde."""
    logger.debug("identifiant_sonde: entrée")
    certificat = x509.load_pem_x509_certificate(certificat_pem.encode())
    try:
        san = certificat.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        logger.debug("identifiant_sonde: pas de SAN -> retour None")
        return None
    for uri in san.value.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(_URN_PREFIXE):
            identifiant = uri[len(_URN_PREFIXE) :]
            logger.debug("identifiant_sonde: retour {}", identifiant)
            return identifiant
    logger.debug("identifiant_sonde: aucun URN netcross -> retour None")
    return None


def verifier_certificat_sonde(
    certificat_pem: str, autorite: AutoriteConfiance, revoques: frozenset[str] | set[str] = frozenset()
) -> str:
    """Vérifie le certificat d'une sonde : signé par l'autorité, pas
    expiré, sonde non révoquée. Renvoie l'identifiant de sonde ou lève
    :class:`EnrolementRefuseError` -- le refus est explicite, jamais
    silencieux (critère d'acceptation : sonde révoquée refusée)."""
    logger.debug("verifier_certificat_sonde: entrée")
    certificat = x509.load_pem_x509_certificate(certificat_pem.encode())
    identifiant = identifiant_sonde(certificat_pem)
    if identifiant is None:
        logger.debug("verifier_certificat_sonde: pas d'identité -> refus")
        raise EnrolementRefuseError("certificat sans identité de sonde (SAN URI netcross)")
    if identifiant in revoques:
        logger.debug("verifier_certificat_sonde: sonde {} révoquée -> refus", identifiant)
        raise EnrolementRefuseError(f"sonde {identifiant} révoquée")
    cle_publique_autorite = autorite._certificat.public_key()
    if not isinstance(cle_publique_autorite, ec.EllipticCurvePublicKey):
        logger.debug("verifier_certificat_sonde: autorité à clé inattendue -> refus")
        raise EnrolementRefuseError("autorité de confiance à clé non supportée")
    try:
        cle_publique_autorite.verify(
            certificat.signature,
            certificat.tbs_certificate_bytes,
            ec.ECDSA(certificat.signature_hash_algorithm or hashes.SHA256()),
        )
    except Exception as erreur:  # noqa: BLE001 -- tout échec de vérification est un refus
        logger.debug("verifier_certificat_sonde: signature invalide ({}) -> refus", erreur)
        raise EnrolementRefuseError("certificat non signé par l'autorité de confiance") from erreur
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    if maintenant > certificat.not_valid_after_utc or maintenant < certificat.not_valid_before_utc:
        logger.debug("verifier_certificat_sonde: certificat hors période de validité -> refus")
        raise EnrolementRefuseError("certificat expiré ou pas encore valide")
    logger.debug("verifier_certificat_sonde: retour sonde {}", identifiant)
    return identifiant


def contexte_mtls_serveur(certificat_pem: str, cle_pem: str, ca_pem: str) -> ssl.SSLContext:
    """Contexte TLS serveur : certificat client EXIGÉ pendant la poignée
    de main (CERT_REQUIRED) -- « aucune écoute sans authentification
    mutuelle » est refusé par la couche transport, pas par une route."""
    logger.debug("contexte_mtls_serveur: entrée")
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.minimum_version = ssl.TLSVersion.TLSv1_3
    contexte.load_cert_chain(certfile=_temporaire(certificat_pem, ".crt"), keyfile=_temporaire(cle_pem, ".key"))
    contexte.load_verify_locations(cadata=ca_pem)
    contexte.verify_mode = ssl.CERT_REQUIRED
    logger.debug("contexte_mtls_serveur: retour contexte CERT_REQUIRED")
    return contexte


def contexte_mtls_client(certificat_pem: str, cle_pem: str, ca_pem: str) -> ssl.SSLContext:
    """Contexte TLS client : le certificat du serveur doit être signé par
    la même autorité (épinglage), le nôtre est présenté d'office. Le nom
    d'hôte n'est pas vérifié : l'identité du pair EST son certificat
    (l'autorité commune est le mécanisme de confiance du contrat v1)."""
    logger.debug("contexte_mtls_client: entrée")
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.minimum_version = ssl.TLSVersion.TLSv1_3
    contexte.check_hostname = False
    contexte.load_cert_chain(certfile=_temporaire(certificat_pem, ".crt"), keyfile=_temporaire(cle_pem, ".key"))
    contexte.load_verify_locations(cadata=ca_pem)
    contexte.verify_mode = ssl.CERT_REQUIRED
    logger.debug("contexte_mtls_client: retour contexte")
    return contexte


def _temporaire(contenu_pem: str, suffixe: str):
    """Fichier temporaire pour load_cert_chain (qui lit un chemin, pas une
    chaîne) ; supprimé à la fermeture du processus."""
    logger.debug("_temporaire: entrée")
    with tempfile.NamedTemporaryFile("w", suffix=suffixe, delete=False) as fichier:
        fichier.write(contenu_pem)
    logger.debug("_temporaire: retour chemin {}", fichier.name)
    return fichier.name


def generer_jeton_enrolement() -> str:
    """Jeton d'enrôlement à usage unique : 256 bits d'entropie (le
    contrat v1 exige au moins 128), en base64 URL-safe."""
    logger.debug("generer_jeton_enrolement: entrée")
    jeton = secrets.token_urlsafe(32)
    logger.debug("generer_jeton_enrolement: retour jeton")
    return jeton


def hacher_jeton(jeton: str) -> str:
    """Empreinte SHA-256 du jeton : le collecteur ne stocke jamais le
    jeton en clair, un vol de base ne permet pas d'inscrire une sonde."""
    logger.debug("hacher_jeton: entrée")
    empreinte = hashlib.sha256(jeton.encode()).hexdigest()
    logger.debug("hacher_jeton: retour empreinte")
    return empreinte
