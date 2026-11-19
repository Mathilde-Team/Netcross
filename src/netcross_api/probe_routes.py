# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_api.probe_routes -- enrôlement des sondes auprès du collecteur
(issue #1101, chantier #1002 ; contrat v1 ``docs/probe-api-v1.yaml``).

Le collecteur (cette API) expose l'unique route sans certificat client :
``POST /probe/v1/enrollments``. Tout le reste du contrat (santé,
métadonnées, fenêtres) est servi par les sondes en TLS mutuel -- voir
``netcross_probe.securite`` pour les contextes mTLS et la vérification
des certificats.

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
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger

from netcross_probe.securite import (
    creer_autorite,
    expiration_certificat,
    generer_jeton_enrolement,
    hacher_jeton,
    signer_csr_sonde,
)

API_VERSION = "1.0"
VERSIONS_SUPPORTÉES = frozenset({"1.0"})
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
        self.par_identifiant: dict[str, str] = {}  # probe_id -> nom
        self.revoquees: set[str] = set()
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

    def inscrire(self, demande: dict[str, Any]) -> tuple[int, dict[str, Any] | JSONResponse]:
        """Traite une demande d'inscription (contrat v1) : (statut,
        corps). 201 et le certificat signé, ou un refus explicite."""
        logger.debug("RegistreSondes.inscrire: entrée")
        for champ in ("probe_name", "csr_pem", "agent_version", "api_versions"):
            if not demande.get(champ):
                logger.debug("RegistreSondes.inscrire: champ {} manquant -> 400", champ)
                return 400, {"error": "invalid_request", "message": f"champ {champ} manquant ou vide"}
        versions = demande["api_versions"]
        if not isinstance(versions, list) or not set(versions) & VERSIONS_SUPPORTÉES:
            logger.debug("RegistreSondes.inscrire: aucune version commune -> 426")
            return 426, {"error": "incompatible_version", "message": "aucune version de contrat commune"}
        nom = demande["probe_name"]
        probe_id = self.inscrites.get(nom)
        if probe_id is not None and probe_id in self.revoquees:
            logger.debug("RegistreSondes.inscrire: sonde révoquée -> 401")
            return 401, {"error": "probe_revoked", "message": f"sonde {nom} révoquée"}
        if nom in self.inscrites:
            logger.debug("RegistreSondes.inscrire: nom déjà inscrit -> 409")
            return 409, {"error": "probe_name_taken", "message": f"sonde {nom} déjà inscrite"}
        if probe_id is None:
            probe_id = f"prb_{secrets.token_hex(12)}"
        try:
            certificat_pem = signer_csr_sonde(demande["csr_pem"], probe_id, self.autorite)
        except Exception:  # noqa: BLE001 -- toute CSR illisible est un refus
            logger.debug("RegistreSondes.inscrire: CSR illisible -> 400")
            return 400, {"error": "invalid_csr", "message": "demande de signature illisible"}
        self.inscrites[nom] = probe_id
        self.par_identifiant[probe_id] = nom
        reponse = {
            "probe_id": probe_id,
            "api_version": API_VERSION,
            "client_certificate_pem": certificat_pem,
            "ca_chain_pem": self.autorite.certificat_pem,
            "certificate_expires_at": expiration_certificat(certificat_pem),
        }
        logger.debug("RegistreSondes.inscrire: retour 201 sonde {}", probe_id)
        return 201, reponse


registre_sondes = RegistreSondes()


def register(app: FastAPI) -> None:
    """Ajoute la route d'enrôlement au collecteur (seule route du contrat
    sans certificat client : la sonde n'en possède pas encore)."""
    logger.debug("probe_routes.register: entrée")

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

    logger.debug("probe_routes.register: retour")
