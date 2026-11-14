# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_probe.enrolement -- inscription d'une sonde auprès du collecteur
(issue #1101 ; contrat v1 ``docs/probe-api-v1.yaml``).

Côté sonde de l'enrôlement : la clé privée est générée sur place et ne
quitte jamais la sonde ; seule la CSR PKCS#10 est envoyée au collecteur,
avec le jeton à usage unique remis par l'administrateur. La réponse (le
certificat client signé et la chaîne de l'autorité) est stockée dans le
dossier de la sonde, prête pour les contextes TLS mutuels de
``netcross_probe.securite``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from netcross_probe.securite import generer_cle_privee, generer_csr_sonde

VERSION_AGENT = "1.0"
VERSIONS_API = ["1.0"]

FICHIER_CERTIFICAT = "sonde-certificat.pem"
FICHIER_CLE = "sonde-cle-privee.pem"
FICHIER_CA = "collecteur-ca.pem"


class EnrolementError(Exception):
    """Le collecteur a refusé l'inscription (jeton consommé, version sans
    commune...) : le message ne contient jamais le jeton."""

    def __init__(self, statut: int, code: str, message: str):
        logger.debug("EnrolementError: entrée ({} {})", statut, code)
        self.statut = statut
        self.code = code
        self.message = message
        super().__init__(f"enrôlement refusé ({statut} {code}) : {message}")
        logger.debug("EnrolementError: retour")


@dataclass(frozen=True)
class Enrolement:
    """Résultat d'une inscription réussie, tel que stocké sur la sonde."""

    probe_id: str
    certificat_pem: str
    cle_pem: str
    ca_pem: str
    api_version: str
    certificate_expires_at: float


def demander_enrolement(
    url_collecteur: str,
    jeton: str,
    nom_sonde: str,
    dossier: str | Path,
    version_agent: str = VERSION_AGENT,
    versions_api: list[str] | None = None,
) -> Enrolement:
    """Inscrit la sonde auprès du collecteur et stocke ses secrets.

    La clé privée est générée ici, sur la sonde ; seule la CSR part sur le
    réseau. Le jeton n'apparaît jamais dans les messages d'erreur. En cas
    de refus, :class:`EnrolementError` porte le code stable du contrat.
    """
    logger.debug("demander_enrolement: entrée (collecteur {})", url_collecteur)
    dossier = Path(dossier)
    cle_pem = generer_cle_privee()
    csr_pem = generer_csr_sonde(nom_sonde, cle_pem)
    demande = json.dumps(
        {
            "probe_name": nom_sonde,
            "csr_pem": csr_pem,
            "agent_version": version_agent,
            "api_versions": versions_api or VERSIONS_API,
            "capabilities": ["bpf", "pcapng_isb", "clock_status"],
        }
    ).encode()
    requete = urllib.request.Request(
        url_collecteur,
        data=demande,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {jeton}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(requete, timeout=30) as reponse:
            corps = json.loads(reponse.read())
    except urllib.error.HTTPError as erreur:
        try:
            corps = json.loads(erreur.read())
        except (ValueError, OSError):
            logger.debug("demander_enrolement: corps d'erreur illisible (HTTP {})", erreur.code)
            corps = {"error": "reponse_illisible", "message": str(erreur.code)}
        logger.debug("demander_enrolement: refus HTTP {}", erreur.code)
        raise EnrolementError(
            erreur.code, corps.get("error", "erreur_collecteur"), corps.get("message", "")
        ) from erreur
    except urllib.error.URLError as erreur:
        logger.debug("demander_enrolement: collecteur injoignable")
        raise EnrolementError(0, "collecteur_injoignable", str(erreur.reason)) from erreur
    dossier.mkdir(parents=True, exist_ok=True)
    (dossier / FICHIER_CERTIFICAT).write_text(corps["client_certificate_pem"], encoding="utf-8")
    (dossier / FICHIER_CLE).write_text(cle_pem, encoding="utf-8")
    (dossier / FICHIER_CA).write_text(corps["ca_chain_pem"], encoding="utf-8")
    enrolement = Enrolement(
        probe_id=corps["probe_id"],
        certificat_pem=corps["client_certificate_pem"],
        cle_pem=cle_pem,
        ca_pem=corps["ca_chain_pem"],
        api_version=corps["api_version"],
        certificate_expires_at=corps["certificate_expires_at"],
    )
    logger.debug("demander_enrolement: retour sonde {}", enrolement.probe_id)
    return enrolement
