# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_probe.client -- client mTLS d'une sonde (issue #1105).

La moitié collecteur des appels : santé, métadonnées et fenêtres d'une
sonde, sur TLS 1.3 mutuel (certificat signé par l'autorité du
collecteur, épinglage de la même autorité). Le client sert autant la
CLI ``--live`` (point ``probe://``) que le collecteur ``netcross_api``
(inventaire et santé des sondes) : le contrat est le même des deux
côtés.

Coupure réseau pendant une demande de fenêtre : les requêtes
idempotentes (``GET``, ``DELETE``) sont rejouées une fois (« reprise »,
le pcapng servi est identique), la création d'une fenêtre (``POST``)
jamais -- rejouer créerait une seconde fenêtre ; l'échec est explicite
(:class:`SondeInjoignableError`), la fenêtre éventuellement créée
expirant seule côté sonde. Aucun secret ne figure dans un message
d'erreur.

Les identités (certificat client, clé, autorité) viennent de l'environnement
: :func:`client_depuis_env` lit ``NETCROSS_PROBE_CERT_PEM``,
``NETCROSS_PROBE_KEY_PEM`` et ``NETCROSS_PROBE_CA_PEM`` (chemin de
fichier ou PEM en clair) et ``NETCROSS_PROBE_TIMEOUT`` (secondes).
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from loguru import logger

from netcross_probe.securite import contexte_mtls_client
from pcap_parser.remote import ENV_PROBE_CA, ENV_PROBE_CERT, ENV_PROBE_KEY

__all__ = [
    "ENV_CA",
    "ENV_CERT",
    "ENV_CLE",
    "ENV_DELAI",
    "ClientSonde",
    "SondeInjoignableError",
    "SondeRefusError",
    "client_depuis_env",
]

# Noms des variables d'environnement : source de vérité unique dans
# pcap_parser.remote (l'URL probe:// y est analysée).
ENV_CERT = ENV_PROBE_CERT
ENV_CLE = ENV_PROBE_KEY
ENV_CA = ENV_PROBE_CA
ENV_DELAI = "NETCROSS_PROBE_TIMEOUT"
DELAI_DEFAUT = 10.0


class SondeInjoignableError(RuntimeError):
    """La sonde n'a pas répondu (réseau coupé, délai dépassé) : le
    message décrit la cause, sans jamais contenir un secret."""


class SondeRefusError(RuntimeError):
    """La sonde (ou le contrat) a refusé la requête : porte le statut
    HTTP et le code stable du contrat (``window_not_buffered``...)."""

    def __init__(self, statut: int, code: str, message: str):
        logger.debug("SondeRefusError: entrée ({} {})", statut, code)
        self.statut = statut
        self.code = code
        self.message = message
        super().__init__(f"sonde refusée ({statut} {code}) : {message}")
        logger.debug("SondeRefusError: retour")


def _lire_pem(valeur: str) -> str:
    """Une variable d'environnement : chemin de fichier ou PEM en clair."""
    logger.debug("_lire_pem: entrée")
    if "BEGIN CERTIFICATE" in valeur or "BEGIN PRIVATE KEY" in valeur:
        logger.debug("_lire_pem: retour PEM en clair")
        return valeur
    with open(valeur, encoding="utf-8") as fichier:
        contenu = fichier.read()
    logger.debug("_lire_pem: retour PEM lu dans {}", valeur)
    return contenu


class ClientSonde:
    """Client du contrat v1 d'une sonde, sur mTLS.

    ``url_base`` : ``https://hote:port`` (le schéma du contrat, port 9443
    par défaut côté sonde). ``delai`` : délai maximal d'une requête.
    """

    def __init__(
        self,
        url_base: str,
        certificat_pem: str,
        cle_pem: str,
        ca_pem: str,
        delai: float = DELAI_DEFAUT,
    ) -> None:
        logger.debug("ClientSonde.__init__: entrée ({})", url_base)
        self.url_base = url_base.rstrip("/")
        self.delai = delai
        self._contexte: ssl.SSLContext | None = None
        self._certificat_pem = certificat_pem
        self._cle_pem = cle_pem
        self._ca_pem = ca_pem
        logger.debug("ClientSonde.__init__: fin")

    # -- requêtes ------------------------------------------------------------------

    def _contexte_tls(self) -> ssl.SSLContext:
        """Contexte client : certificat présenté d'office, autorité du
        collecteur épinglée (mTLS, #1101)."""
        logger.debug("ClientSonde._contexte_tls: entrée")
        if self._contexte is None:
            self._contexte = contexte_mtls_client(self._certificat_pem, self._cle_pem, self._ca_pem)
        logger.debug("ClientSonde._contexte_tls: retour contexte")
        return self._contexte

    def _ouvrir(self, requete: urllib.request.Request, delai: float):
        """Ouverture injectable (les tests simulent les coupures réseau)."""
        logger.debug("ClientSonde._ouvrir: entrée ({})", requete.full_url)
        reponse = urllib.request.urlopen(requete, timeout=delai, context=self._contexte_tls())
        logger.debug("ClientSonde._ouvrir: retour réponse")
        return reponse

    def _refus_en_http(self, erreur: urllib.error.HTTPError, chemin: str) -> SondeRefusError:
        """Traduit un refus HTTP en :class:`SondeRefusError` (code stable)."""
        donnees = b""
        try:
            donnees = erreur.read()
        except OSError:
            logger.debug("ClientSonde._refus_en_http: corps d'erreur illisible (HTTP {})", erreur.code)
        code = f"http_{erreur.code}"
        message = f"refus HTTP {erreur.code}"
        try:
            document = json.loads(donnees)
            if isinstance(document, dict):
                code = str(document.get("error", code))
                message = str(document.get("message", message))
        except ValueError:
            logger.debug("ClientSonde._refus_en_http: corps d'erreur non JSON (HTTP {})", erreur.code)
        logger.debug("ClientSonde._refus_en_http: refus HTTP {} ({})", erreur.code, chemin)
        return SondeRefusError(erreur.code, code, message)

    def _tentative(self, requete: urllib.request.Request, chemin: str) -> tuple[int, Any, bytes]:
        """Un passage : succès, refus explicite (:class:`SondeRefusError`) ou
        coupure (``URLError``/``OSError``/``SSLError``) remontée telle quelle."""
        try:
            with self._ouvrir(requete, self.delai) as reponse:
                donnees = reponse.read()
                statut = reponse.status
                logger.debug("ClientSonde._tentative: {} -> {}", chemin, statut)
                return statut, dict(reponse.headers.items()), donnees
        except urllib.error.HTTPError as erreur:
            logger.debug("ClientSonde._tentative: refus HTTP {} ({})", erreur.code, chemin)
            raise self._refus_en_http(erreur, chemin) from erreur

    def _requete(self, chemin: str, methode: str, corps: bytes | None = None) -> tuple[int, Any, bytes]:
        """Une requête du contrat ; renvoie (statut, en-têtes, corps).

        Les requêtes idempotentes (``GET``/``DELETE``) sont rejouées une
        fois en cas de coupure (« reprise ») ; le ``POST`` jamais (une
        seconde fenêtre serait créée : l'échec est explicite à la place).
        """
        logger.debug("ClientSonde._requete: entrée ({} {})", methode, chemin)
        url = f"{self.url_base}{chemin}"
        entetes = {"Netcross-Probe-Api": "1.0"}
        if corps is not None:
            entetes["Content-Type"] = "application/json"
        requete = urllib.request.Request(url, data=corps, headers=entetes, method=methode)
        if methode not in ("GET", "DELETE"):
            try:
                reponse = self._tentative(requete, chemin)
                logger.debug("ClientSonde._requete: retour POST ({})", chemin)
                return reponse
            except (urllib.error.URLError, OSError, ssl.SSLError) as erreur:
                logger.debug("ClientSonde._requete: coupure ({} {})", methode, chemin)
                raise SondeInjoignableError(f"sonde injoignable ({self.url_base}) : {erreur}") from erreur
        try:
            reponse = self._tentative(requete, chemin)
            logger.debug("ClientSonde._requete: retour première passe ({} {})", methode, chemin)
            return reponse
        except (urllib.error.URLError, OSError, ssl.SSLError):
            logger.debug("ClientSonde._requete: coupure, reprise ({} {})", methode, chemin)
            time.sleep(0.1)
        logger.debug("ClientSonde._requete: reprise ({} {})", methode, chemin)
        try:
            reponse = self._tentative(requete, chemin)
            logger.debug("ClientSonde._requete: retour reprise ({} {})", methode, chemin)
            return reponse
        except (urllib.error.URLError, OSError, ssl.SSLError) as erreur:
            logger.debug("ClientSonde._requete: sonde injoignable ({})", chemin)
            raise SondeInjoignableError(f"sonde injoignable ({self.url_base}) : {erreur}") from erreur

    # -- routes du contrat -----------------------------------------------------------

    def sante(self) -> dict[str, Any]:
        """``GET /probe/v1/health`` : état de la capture, du tampon, de
        l'horloge."""
        logger.debug("ClientSonde.sante: entrée")
        _statut, _entetes, donnees = self._requete("/probe/v1/health", "GET")
        document = json.loads(donnees)
        logger.debug("ClientSonde.sante: retour {}", document.get("status"))
        return document

    def metadonnees(self) -> dict[str, Any]:
        """``GET /probe/v1/metadata`` : identité, interfaces, capacités."""
        logger.debug("ClientSonde.metadonnees: entrée")
        _statut, _entetes, donnees = self._requete("/probe/v1/metadata", "GET")
        document = json.loads(donnees)
        logger.debug("ClientSonde.metadonnees: retour sonde {}", document.get("probe_name"))
        return document

    def demander_fenetre(
        self,
        debut: float,
        fin: float,
        bpf: str | None = None,
        max_octets: int | None = None,
        inclure_inconnus: bool = False,
    ) -> dict[str, Any]:
        """``POST /probe/v1/windows`` : description de la fenêtre préparée."""
        logger.debug("ClientSonde.demander_fenetre: entrée ([{}, {}], bpf={!r})", debut, fin, bpf)
        demande: dict[str, Any] = {"start": debut, "end": fin}
        if bpf is not None:
            demande["bpf"] = bpf
        if max_octets is not None:
            demande["max_bytes"] = max_octets
        if inclure_inconnus:
            demande["include_unknown"] = True
        _statut, _entetes, donnees = self._requete("/probe/v1/windows", "POST", json.dumps(demande).encode())
        document = json.loads(donnees)
        logger.debug("ClientSonde.demander_fenetre: retour fenêtre {}", document.get("window_id"))
        return document

    def telecharger_fenetre(self, identifiant: str) -> bytes:
        """``GET /probe/v1/windows/{id}/pcapng`` : le pcapng de la fenêtre."""
        logger.debug("ClientSonde.telecharger_fenetre: entrée ({})", identifiant)
        _statut, _entetes, donnees = self._requete(f"/probe/v1/windows/{identifiant}/pcapng", "GET")
        logger.debug("ClientSonde.telecharger_fenetre: retour {} octet(s)", len(donnees))
        return donnees

    def liberer_fenetre(self, identifiant: str) -> None:
        """``DELETE /probe/v1/windows/{id}`` : libère la fenêtre. Une
        fenêtre déjà expirée (404) est un succès -- le but est atteint."""
        logger.debug("ClientSonde.liberer_fenetre: entrée ({})", identifiant)
        try:
            self._requete(f"/probe/v1/windows/{identifiant}", "DELETE")
        except SondeRefusError as refus:
            if refus.statut != 404:
                logger.debug("ClientSonde.liberer_fenetre: refus {} -> relance", refus.statut)
                raise
            logger.debug("ClientSonde.liberer_fenetre: déjà expirée -> succès")
        logger.debug("ClientSonde.liberer_fenetre: fin")

    def extraire_pcapng(
        self,
        debut: float,
        fin: float,
        bpf: str | None = None,
        max_octets: int | None = None,
        inclure_inconnus: bool = False,
    ) -> bytes:
        """Fenêtre complète en un appel : création, téléchargement
        (rejoué une fois en cas de coupure), libération.

        La libération est faite au mieux : une sonde redevenue injoignable
        après le téléchargement n'invalide pas le résultat -- la fenêtre
        expire seule côté sonde.
        """
        logger.debug("ClientSonde.extraire_pcapng: entrée ([{}, {}], bpf={!r})", debut, fin, bpf)
        fenetre = self.demander_fenetre(debut, fin, bpf=bpf, max_octets=max_octets, inclure_inconnus=inclure_inconnus)
        identifiant = fenetre["window_id"]
        try:
            donnees = self.telecharger_fenetre(identifiant)
        finally:
            try:
                self.liberer_fenetre(identifiant)
            except (SondeInjoignableError, SondeRefusError) as erreur:
                logger.warning("ClientSonde.extraire_pcapng: fenêtre {} non libérée ({})", identifiant, erreur)
        logger.debug("ClientSonde.extraire_pcapng: retour {} octet(s)", len(donnees))
        return donnees


def client_depuis_env(url_base: str, env: Mapping[str, str] | None = None) -> ClientSonde:
    """Client configuré par l'environnement (identités mTLS).

    Manque une des trois identités : :class:`SondeInjoignableError`
    explicite -- sans certificat client, la sonde refuserait de toute
    façon la poignée de main (« aucune écoute sans authentification
    mutuelle »).
    """
    logger.debug("client_depuis_env: entrée ({})", url_base)
    variables = os.environ if env is None else env
    manquantes = [nom for nom in (ENV_CERT, ENV_CLE, ENV_CA) if not variables.get(nom, "").strip()]
    if manquantes:
        logger.debug("client_depuis_env: identités manquantes {}", manquantes)
        raise SondeInjoignableError(
            "identité mTLS de sonde incomplète : définir "
            + ", ".join(manquantes)
            + " (chemin de fichier ou PEM en clair)"
        )
    try:
        delai = float(variables.get(ENV_DELAI, "").strip() or DELAI_DEFAUT)
    except ValueError:
        logger.debug("client_depuis_env: {} illisible -> délai par défaut", ENV_DELAI)
        delai = DELAI_DEFAUT
    if delai <= 0:
        logger.debug("client_depuis_env: délai non positif -> délai par défaut")
        delai = DELAI_DEFAUT
    client = ClientSonde(
        url_base,
        _lire_pem(variables[ENV_CERT]),
        _lire_pem(variables[ENV_CLE]),
        _lire_pem(variables[ENV_CA]),
        delai=delai,
    )
    logger.debug("client_depuis_env: retour client")
    return client
