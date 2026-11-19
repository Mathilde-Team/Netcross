# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_api.probe_routes -- collecteur : enrôlement, inventaire et
santé des sondes (issues #1101 et #1105, chantier #1002 ; contrat v1
``docs/probe-api-v1.yaml``).

Le collecteur (cette API) expose l'unique route du contrat sans
certificat client : ``POST /probe/v1/enrollments``. Tout le reste du
contrat (santé, métadonnées, fenêtres) est servi par les sondes en TLS
mutuel -- voir ``netcross_probe.securite`` pour les contextes mTLS et la
vérification des certificats, ``netcross_probe.client`` pour l'appel.

Issue #1105, l'inventaire et la santé côté collecteur :

- ``GET /probes`` : chaque sonde inscrite -- identité, adresse annoncée
  à l'inscription (``listen_base_url``, contrat 1.1), révocation,
  expiration du certificat, dernière santé connue ;
- ``GET /probes/{probe_id}/health`` : la santé **actuelle**, lue en
  direct auprès de la sonde en mTLS avec le certificat client du
  collecteur (SAN ``urn:netcross:collector:<id>``, forgé par l'autorité
  du collecteur) ; une sonde muette est une erreur explicite (502),
  jamais une santé inventée.

Invariants de sécurité (critères d'acceptation de #1101) :

- **mTLS obligatoire** : les contextes TLS exigent le certificat client
  pendant la poignée de main, aucune route n'est servie sans ;
- **jeton à usage unique** : le jeton d'enrôlement n'est stocké qu'haché
  (SHA-256) ; un second usage répond 401 ``token_consumed`` ;
- **révocation** : une sonde révoquée est refusée (401 ``probe_revoked``
  à la ré-inscription, refus à la vérification du certificat).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger

from netcross_probe.client import ClientSonde, SondeInjoignableError, SondeRefusError
from netcross_probe.securite import (
    creer_autorite,
    creer_certificat_collecteur,
    expiration_certificat,
    generer_jeton_enrolement,
    hacher_jeton,
    signer_csr_sonde,
)

API_VERSION = "1.0"
VERSIONS_SUPPORTÉES = frozenset({"1.0", "1.1"})
_EN_TETE_CONTRAT = {"Netcross-Probe-Api": API_VERSION}


def _erreur(statut: int, code: str, message: str) -> JSONResponse:
    """Réponse d'erreur du contrat : code stable en snake_case, message
    lisible sans jamais de secret."""
    logger.debug("_erreur: retour {} {}", statut, code)
    return JSONResponse(
        status_code=statut,
        content={"error": code, "message": message},
        headers=_EN_TETE_CONTRAT,
    )


class RegistreSondes:
    """État collecteur des inscriptions : jetons hachés (à usage unique),
    sondes inscrites (nom -> identifiant), sondes révoquées, autorité de
    confiance qui signe les certificats clients."""

    def __init__(self) -> None:
        logger.debug("RegistreSondes.__init__: entrée")
        self.autorite = creer_autorite()
        self.jetons: dict[str, dict[str, Any]] = {}  # hachage -> {consommé}
        self.inscrites: dict[str, str] = {}  # nom -> probe_id
        self.par_identifiant: dict[str, dict[str, Any]] = {}  # probe_id -> fiche
        self.revoquees: set[str] = set()
        self.sante_derniere: dict[str, dict[str, Any]] = {}  # probe_id -> santé + relevé
        logger.debug("RegistreSondes.__init__: retour registre")

    def creer_jeton(self) -> str:
        """Jeton d'enrôlement remis par l'administrateur à une sonde :
        stocké haché, un seul usage possible."""
        logger.debug("RegistreSondes.creer_jeton: entrée")
        jeton = generer_jeton_enrolement()
        self.jetons[hacher_jeton(jeton)] = {"consommé": False}
        logger.debug("RegistreSondes.creer_jeton: retour jeton")
        return jeton

    def _consommer_jeton(self, jeton: str) -> str:
        """Vérifie et consomme le jeton ; lève ValueError (jeton inconnu,
        déjà consommé) -- l'appelant traduit en 401."""
        logger.debug("RegistreSondes._consommer_jeton: entrée")
        empreinte = hacher_jeton(jeton)
        fiche = self.jetons.get(empreinte)
        if fiche is None:
            logger.debug("RegistreSondes._consommer_jeton: jeton inconnu -> refus")
            raise ValueError("token_unknown")
        if fiche["consommé"]:
            logger.debug("RegistreSondes._consommer_jeton: jeton déjà consommé -> refus")
            raise ValueError("token_consumed")
        fiche["consommé"] = True
        logger.debug("RegistreSondes._consommer_jeton: retour jeton consommé")
        return empreinte

    def revoquer(self, probe_id: str) -> None:
        """Révoque une sonde : son certificat sera refusé par la
        vérification mTLS et sa ré-inscription rejetée."""
        logger.debug("RegistreSondes.revoquer: entrée (sonde {})", probe_id)
        self.revoquees.add(probe_id)
        logger.debug("RegistreSondes.revoquer: retour")

    def _version_negociee(self, versions: list[str]) -> str:
        """Plus haute version commune entre la sonde et le collecteur."""
        logger.debug("RegistreSondes._version_negociee: entrée")
        communes = sorted(set(versions) & VERSIONS_SUPPORTÉES)
        if not communes:
            logger.debug("RegistreSondes._version_negociee: aucune commune -> levée ValueError")
            raise ValueError("aucune version de contrat commune")
        version = communes[-1]
        logger.debug("RegistreSondes._version_negociee: retour {}", version)
        return version

    def inscrire(self, demande: dict[str, Any]) -> tuple[int, dict[str, Any] | JSONResponse]:
        """Traite une demande d'inscription (contrat v1) : (statut,
        corps). 201 et le certificat signé, ou un refus explicite.

        Issue #1105 (contrat 1.1) : ``listen_base_url`` (facultatif)
        annonce l'URL où la sonde sert ses routes mTLS -- c'est elle que
        ``GET /probes/{id}/health`` appelle. Absente : la sonde est
        inscrite, simplement sans suivi de santé possible (erreur
        explicite le cas échéant, jamais une santé inventée).
        """
        logger.debug("RegistreSondes.inscrire: entrée")
        for champ in ("probe_name", "csr_pem", "agent_version", "api_versions"):
            if not demande.get(champ):
                logger.debug("RegistreSondes.inscrire: champ {} manquant -> 400", champ)
                return 400, {"error": "invalid_request", "message": f"champ {champ} manquant ou vide"}
        versions = demande["api_versions"]
        if not isinstance(versions, list):
            logger.debug("RegistreSondes.inscrire: versions non liste -> 426")
            return 426, {"error": "incompatible_version", "message": "aucune version de contrat commune"}
        try:
            version = self._version_negociee(versions)
        except ValueError:
            logger.debug("RegistreSondes.inscrire: aucune version commune -> 426")
            return 426, {"error": "incompatible_version", "message": "aucune version de contrat commune"}
        nom = demande["probe_name"]
        ancien = self.inscrites.get(nom)
        if ancien is not None and ancien in self.revoquees:
            logger.debug("RegistreSondes.inscrire: sonde révoquée -> 401")
            return 401, {"error": "probe_revoked", "message": f"sonde {nom} révoquée"}
        if nom in self.inscrites:
            logger.debug("RegistreSondes.inscrire: nom déjà inscrit -> 409")
            return 409, {"error": "probe_name_taken", "message": f"sonde {nom} déjà inscrite"}
        probe_id = ancien or f"prb_{secrets.token_hex(12)}"
        try:
            certificat_pem = signer_csr_sonde(demande["csr_pem"], probe_id, self.autorite)
        except Exception:  # noqa: BLE001 -- toute CSR illisible est un refus
            logger.debug("RegistreSondes.inscrire: CSR illisible -> 400")
            return 400, {"error": "invalid_csr", "message": "demande de signature illisible"}
        adresse = demande.get("listen_base_url") or None
        if adresse is not None and (not isinstance(adresse, str) or not adresse.startswith("https://")):
            logger.debug("RegistreSondes.inscrire: listen_base_url invalide -> 400")
            return 400, {
                "error": "invalid_request",
                "message": "listen_base_url doit être une URL https://",
            }
        self.inscrites[nom] = probe_id
        self.par_identifiant[probe_id] = {
            "probe_name": nom,
            "listen_base_url": adresse,
            "revoked": False,
            "enrolled_at": time.time(),
            "certificate_expires_at": expiration_certificat(certificat_pem),
        }
        reponse = {
            "probe_id": probe_id,
            "api_version": version,
            "client_certificate_pem": certificat_pem,
            "ca_chain_pem": self.autorite.certificat_pem,
            "certificate_expires_at": expiration_certificat(certificat_pem),
        }
        logger.debug("RegistreSondes.inscrire: retour 201 sonde {}", probe_id)
        return 201, reponse

    def fiche(self, probe_id: str) -> dict[str, Any] | None:
        """Fiche d'une sonde inscrite (ou None)."""
        logger.debug("RegistreSondes.fiche: entrée ({})", probe_id)
        fiche = self.par_identifiant.get(probe_id)
        logger.debug("RegistreSondes.fiche: retour {}", "fiche" if fiche else "None")
        return fiche

    def inventaire(self) -> list[dict[str, Any]]:
        """Inventaire des sondes (issue #1105) : identité, adresse,
        révocation, expiration, dernière santé connue."""
        logger.debug("RegistreSondes.inventaire: entrée")
        sondes = []
        for probe_id, fiche in self.par_identifiant.items():
            sante = self.sante_derniere.get(probe_id)
            sondes.append(
                {
                    "probe_id": probe_id,
                    "probe_name": fiche["probe_name"],
                    "listen_base_url": fiche["listen_base_url"],
                    "revoked": probe_id in self.revoquees,
                    "enrolled_at": fiche["enrolled_at"],
                    "certificate_expires_at": fiche["certificate_expires_at"],
                    "health": sante,
                }
            )
        logger.debug("RegistreSondes.inventaire: retour {} sonde(s)", len(sondes))
        return sondes

    def maj_sante(self, probe_id: str, document: dict[str, Any]) -> None:
        """Mémorise la dernière santé lue (avec l'heure du relevé)."""
        logger.debug("RegistreSondes.maj_sante: entrée ({})", probe_id)
        self.sante_derniere[probe_id] = {
            "status": document.get("status"),
            "checked_at": time.time(),
            "health": document,
        }
        logger.debug("RegistreSondes.maj_sante: retour")

    def identite_collecteur(self) -> tuple[str, str, str]:
        """Identité mTLS du collecteur (certificat client, clé, autorité),
        forgée une fois par processus à partir de sa propre autorité."""
        logger.debug("RegistreSondes.identite_collecteur: entrée")
        if not hasattr(self, "_identite_collecteur"):
            certificat, cle = creer_certificat_collecteur(self.autorite)
            self._identite_collecteur = (certificat, cle, self.autorite.certificat_pem)
        logger.debug("RegistreSondes.identite_collecteur: retour identité")
        return self._identite_collecteur


registre_sondes = RegistreSondes()


def _lire_sante(probe_id: str) -> tuple[int, dict[str, Any]]:
    """Santé actuelle d'une sonde, lue en mTLS par le collecteur : (statut,
    corps). Refus explicites : 404 sonde inconnue, 409 sonde sans adresse
    annoncée, 502 sonde muette ou refusante."""
    logger.debug("_lire_sante: entrée ({})", probe_id)
    fiche = registre_sondes.fiche(probe_id)
    if fiche is None:
        logger.debug("_lire_sante: sonde inconnue -> 404")
        return 404, {"error": "probe_unknown", "message": f"sonde {probe_id} inconnue"}
    if probe_id in registre_sondes.revoquees:
        logger.debug("_lire_sante: sonde révoquée -> 401")
        return 401, {"error": "probe_revoked", "message": f"sonde {probe_id} révoquée"}
    adresse = fiche.get("listen_base_url")
    if not adresse:
        logger.debug("_lire_sante: pas d'adresse annoncée -> 409")
        return 409, {
            "error": "probe_address_unknown",
            "message": "la sonde n'a pas annoncé d'adresse à l'inscription (listen_base_url)",
        }
    certificat, cle, ca = registre_sondes.identite_collecteur()
    client = ClientSonde(adresse, certificat, cle, ca)
    try:
        document = client.sante()
    except SondeInjoignableError as exc:
        logger.debug("_lire_sante: sonde injoignable -> 502")
        return 502, {"error": "sonde_injoignable", "message": str(exc)}
    except SondeRefusError as exc:
        logger.debug("_lire_sante: sonde refusante -> 502")
        return 502, {"error": "sonde_refus", "message": str(exc)}
    registre_sondes.maj_sante(probe_id, document)
    logger.debug("_lire_sante: retour 200")
    return 200, document


def register(app: FastAPI, verify: Callable[..., Any]) -> None:
    """Déclare les routes du collecteur. ``verify`` : dépendance
    d'authentification de l'API (clé) appliquée aux routes d'inventaire
    -- l'enrôlement reste authentifié par le jeton à usage unique (la
    sonde n'a pas encore de certificat, ni de clé API)."""
    logger.debug("probe_routes.register: entrée")
    auth = [Depends(verify)]

    @app.post(
        "/probe/v1/enrollments",
        tags=["probe"],
        responses={
            201: {"description": "Sonde inscrite, certificat client signé."},
            400: {"description": "Requête ou CSR invalide."},
            401: {"description": "Jeton inconnu, consommé ou sonde révoquée."},
            409: {"description": "Nom de sonde déjà inscrit."},
            426: {"description": "Aucune version de contrat commune."},
        },
    )
    async def enroller_sonde(request: Request) -> JSONResponse:
        """Inscription d'une sonde : jeton à usage unique + CSR, le
        collecteur signe le certificat client (SAN URI netcross)."""
        logger.debug("enroller_sonde: entrée")
        autorisation = request.headers.get("authorization", "")
        if not autorisation.startswith("Bearer "):
            logger.debug("enroller_sonde: pas de jeton -> 401")
            return _erreur(401, "token_missing", "jeton d'enrôlement absent")
        jeton = autorisation[len("Bearer ") :].strip()
        try:
            registre_sondes._consommer_jeton(jeton)
        except ValueError as refus:
            logger.debug("enroller_sonde: jeton refusé ({}) -> 401", refus)
            return _erreur(401, str(refus), f"jeton d'enrôlement refusé ({refus})")
        try:
            demande = await request.json()
        except Exception:  # noqa: BLE001 -- un corps illisible est un refus
            logger.debug("enroller_sonde: corps illisible -> 400")
            return _erreur(400, "invalid_request", "corps JSON illisible")
        statut, corps = registre_sondes.inscrire(demande)
        logger.debug("enroller_sonde: retour {}", statut)
        return JSONResponse(status_code=statut, content=corps, headers=_EN_TETE_CONTRAT)

    @app.get("/probes", tags=["probe"], dependencies=auth)
    def inventaire_sondes() -> dict[str, Any]:
        """Inventaire des sondes inscrites (issue #1105) : identité, adresse
        annoncée, révocation, expiration du certificat, dernière santé."""
        logger.debug("inventaire_sondes: entrée")
        return {"probes": registre_sondes.inventaire()}

    @app.get("/probes/{probe_id}/health", tags=["probe"], dependencies=auth)
    def sante_sonde(probe_id: str) -> JSONResponse:
        """Santé actuelle d'une sonde, lue en direct en mTLS par le
        collecteur (issue #1105). Une sonde muette est un refus explicite,
        jamais une santé inventée."""
        logger.debug("sante_sonde: entrée ({})", probe_id)
        statut, corps = _lire_sante(probe_id)
        logger.debug("sante_sonde: retour {} ({})", statut, probe_id)
        return JSONResponse(status_code=statut, content=corps)

    logger.debug("probe_routes.register: retour")
