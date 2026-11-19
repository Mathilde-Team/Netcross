# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_probe.serveur -- service HTTP mTLS de la sonde (issue #1105).

La moitié sonde du contrat v1 (``docs/probe-api-v1.yaml``) : santé,
métadonnées et fenêtres de trafic, servis sur TLS 1.3 avec certificat
client **obligatoire** pendant la poignée de main (« aucune écoute sans
authentification mutuelle »). Le certificat présenté est celui signé par
le collecteur à l'inscription (SAN URI ``urn:netcross:probe:<probe_id>``),
l'autorité de confiance est celle reçue à l'enrôlement.

Serveur volontairement minimal : ``http.server`` de la bibliothèque
standard, enroulé dans le contexte TLS de ``netcross_probe.securite`` --
aucune dépendance ajoutée (pas de FastAPI dans la sonde), fidèle au
principe « agent léger » du chantier #1002. Les réponses portent
l'en-tête ``Netcross-Probe-Api`` et les erreurs suivent le contrat :
``{"error": code_stable, "message": ...}``, jamais de secret dans un
message.

Rôles :

- ``GET /probe/v1/health`` : capture en cours, tampon (fichiers, octets,
  bornes), horloge annoncée ;
- ``GET /probe/v1/metadata`` : identité, interface, réglages du tampon,
  capacités ;
- ``POST /probe/v1/windows`` : extraction d'une fenêtre [start, end]
  filtrée BPF (l'agent la retient jusqu'à expiration) ;
- ``GET /probe/v1/windows/{id}`` / ``DELETE ...`` : métadonnées,
  libération ;
- ``GET /probe/v1/windows/{id}/pcapng`` : téléchargement, en-tête
  ``Digest`` identique à ``Window.sha256``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from loguru import logger

from netcross_probe.agent import AgentProbe
from netcross_probe.bpf import FiltreBpfInvalideError
from netcross_probe.etat import lire_etat_horloge
from netcross_probe.fenetres import (
    FenetreInvalideError,
    FenetreResultat,
    FenetreTropGrandeError,
    FenetreVideError,
)
from netcross_probe.securite import contexte_mtls_serveur

__all__ = ["ServeurSonde", "construire_metadonnees", "construire_sante", "fenetre_vers_dict"]

API_VERSION = "1.0"
EN_TETE_CONTRAT = "Netcross-Probe-Api"
_CAPACITES = ["bpf", "pcapng_isb", "clock_status"]
_RE_FENETRE = re.compile(r"^/probe/v1/windows/([A-Za-z0-9_-]+)$")
_RE_PCAPNG = re.compile(r"^/probe/v1/windows/([A-Za-z0-9_-]+)/pcapng$")


def _taille(chemin: str) -> int:
    logger.debug("_taille: entrée ({})", chemin)
    try:
        valeur = os.path.getsize(chemin)
    except OSError:
        logger.debug("_taille: taille illisible -> retour 0")
        return 0
    logger.debug("_taille: retour {}", valeur)
    return valeur


def construire_sante(
    agent: AgentProbe, api_version: str = API_VERSION, demarrage: float | None = None
) -> dict[str, Any]:
    """Document ``Health`` du contrat v1 : état de la capture, du tampon et
    de l'horloge, sans jamais rien inventer (bornes inconnues à ``None``).

    ``status`` : ``ok`` (capture en cours, horloge synchronisée),
    ``degraded`` (capture arrêtée ou horloge non synchronisée) ou
    ``failing`` (capture arrêtée ET tampon vide : la sonde ne peut rien
    servir).
    """
    logger.debug("construire_sante: entrée")
    fichiers = agent.capture.inventaire()
    octets = sum(_taille(f.path) for f in fichiers)
    debuts = [f.start for f in fichiers if f.start is not None]
    fins = [f.end for f in fichiers if f.end is not None]
    horloge = lire_etat_horloge()
    capture_en_cours = agent.capture.en_cours
    if capture_en_cours and horloge.synchronized:
        statut = "ok"
    elif not capture_en_cours and not fichiers:
        statut = "failing"
    else:
        statut = "degraded"
    sante: dict[str, Any] = {
        "status": statut,
        "api_version": api_version,
        "capturing": capture_en_cours,
        "buffer": {
            "files": len(fichiers),
            "bytes": octets,
            "oldest": min(debuts) if debuts else None,
            "newest": max(fins) if fins else None,
        },
        "clock": horloge.vers_dict(),
    }
    if demarrage is not None:
        sante["uptime_s"] = max(0.0, time.monotonic() - demarrage)
    logger.debug("construire_sante: retour {} ({} fichier(s))", statut, len(fichiers))
    return sante


def construire_metadonnees(
    agent: AgentProbe,
    probe_id: str,
    probe_name: str,
    agent_version: str,
    api_versions: list[str] | None = None,
    api_version: str = API_VERSION,
) -> dict[str, Any]:
    """Document ``ProbeMetadata`` du contrat v1."""
    logger.debug("construire_metadonnees: entrée (sonde {})", probe_name)
    reglages = agent.capture.reglages
    document: dict[str, Any] = {
        "probe_id": probe_id,
        "probe_name": probe_name,
        "agent_version": agent_version,
        "api_versions": api_versions or [api_version],
        "interfaces": [{"name": reglages.interface, "link_type": None, "snaplen": None}],
        "buffer": {
            "max_files": reglages.nb_fichiers,
            "file_duration_s": int(reglages.duree_par_fichier),
            "max_bytes": None,
        },
        "capabilities": list(_CAPACITES),
        "api_version": api_version,
    }
    logger.debug("construire_metadonnees: retour document")
    return document


def fenetre_vers_dict(
    resultat: FenetreResultat, probe_id: str, expires_at: float, bpf: str | None = None
) -> dict[str, Any]:
    """Document ``Window`` du contrat v1 : miroir de :class:`FenetreResultat`.

    ``capture_loss`` et ``clock`` valent ``None`` quand la sonde n'a rien
    pu lire (fichiers sans ISB, démon d'horloge muet) : jamais inventées,
    jamais confondues avec zéro.
    """
    logger.debug("fenetre_vers_dict: entrée (fenêtre {})", resultat.identifiant)
    document: dict[str, Any] = {
        "window_id": resultat.identifiant,
        "probe_id": probe_id,
        "requested": {"start": resultat.demande[0], "end": resultat.demande[1]},
        "covered": (
            {"start": resultat.couvert[0], "end": resultat.couvert[1]} if resultat.couvert is not None else None
        ),
        "bpf": bpf,
        "packet_count": resultat.nb_paquets,
        "bytes": resultat.octets,
        "sha256": resultat.sha256,
        "capture_loss": resultat.pertes.vers_dict() if resultat.pertes is not None else None,
        "clock": resultat.horloge.vers_dict() if resultat.horloge is not None else None,
        "expires_at": expires_at,
    }
    logger.debug("fenetre_vers_dict: retour document")
    return document


class ServeurSonde:
    """La sonde au travail : capture en tampon circulaire + service HTTP
    mTLS des fenêtres (issue #1105).

    ``identite`` : triplet (certificat PEM, clé privée PEM, autorité PEM)
    reçus à l'enrôlement ; la clé ne quitte jamais le processus.
    ``demarrer_capture`` : lancer l'enregistreur dès le service (défaut :
    oui -- une sonde qui n'écrit pas ne peut rien servir).
    """

    def __init__(
        self,
        agent: AgentProbe,
        identite: tuple[str, str, str],
        probe_id: str,
        probe_name: str,
        agent_version: str = "1.0",
        demarrer_capture: bool = True,
    ) -> None:
        logger.debug("ServeurSonde.__init__: entrée (sonde {})", probe_name)
        self.agent = agent
        self.certificat_pem, self.cle_pem, self.ca_pem = identite
        self.probe_id = probe_id
        self.probe_name = probe_name
        self.agent_version = agent_version
        self._serveur: ThreadingHTTPServer | None = None
        self._demarrage: float | None = None
        self._verrou = threading.Lock()
        if demarrer_capture and not agent.capture.en_cours:
            agent.capture.demarrer()
        logger.debug("ServeurSonde.__init__: fin")

    # -- cycle de vie --------------------------------------------------------------

    def demarrer(self, hote: str, port: int) -> str:
        """Écoute sur ``hote:port`` (mTLS). Renvoie l'URL de base. Le
        service tourne dans un thread démon ; ``arreter`` l'éteint."""
        logger.debug("ServeurSonde.demarrer: entrée ({}:{})", hote, port)
        serveur_sonde = self

        class _Requete(BaseHTTPRequestHandler):
            """Une requête mTLS servie par cette sonde."""

            def _repondre(self, statut: int, corps: bytes, type_mime: str = "application/json") -> None:
                logger.debug("_Requete._repondre: entrée ({})", statut)
                self.send_response(statut)
                self.send_header("Content-Type", type_mime)
                self.send_header("Content-Length", str(len(corps)))
                self.send_header(EN_TETE_CONTRAT, API_VERSION)
                self.end_headers()
                self.wfile.write(corps)
                logger.debug("_Requete._repondre: retour ({} octet(s))", len(corps))

            def _erreur(self, statut: int, code: str, message: str) -> None:
                logger.debug("_Requete._erreur: entrée ({} {})", statut, code)
                self._repondre(statut, json.dumps({"error": code, "message": message}, ensure_ascii=False).encode())
                logger.debug("_Requete._erreur: fin ({} {})", statut, code)

            def _corps_json(self) -> dict[str, Any] | None:
                logger.debug("_Requete._corps_json: entrée")
                try:
                    longueur = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    logger.debug("_Requete._corps_json: Content-Length illisible -> retour None")
                    return None
                brut = self.rfile.read(longueur) if longueur > 0 else b"{}"
                try:
                    document = json.loads(brut)
                except ValueError:
                    logger.debug("_Requete._corps_json: corps illisible -> retour None")
                    return None
                if not isinstance(document, dict):
                    logger.debug("_Requete._corps_json: corps non objet -> retour None")
                    return None
                logger.debug("_Requete._corps_json: retour document")
                return document

            def _servir_fenetre(self, identifiant: str, bpf: str | None = None) -> None:
                logger.debug("_Requete._servir_fenetre: entrée ({})", identifiant)
                resultat = serveur_sonde.agent.fenetre(identifiant)
                if resultat is None:
                    self._erreur(404, "window_unknown", "fenêtre inconnue ou expirée")
                    logger.debug("_Requete._servir_fenetre: retour (fenêtre inconnue)")
                    return
                document = fenetre_vers_dict(
                    resultat,
                    serveur_sonde.probe_id,
                    serveur_sonde._expiration(identifiant),
                    bpf=bpf,
                )
                self._repondre(200, json.dumps(document, ensure_ascii=False).encode())
                logger.debug("_Requete._servir_fenetre: fin")

            def do_GET(self) -> None:  # noqa: N802 -- nom imposé par http.server
                logger.debug("_Requete.do_GET: entrée ({})", self.path)
                if self.path == "/probe/v1/health":
                    document = construire_sante(serveur_sonde.agent, demarrage=serveur_sonde._demarrage)
                    self._repondre(200, json.dumps(document, ensure_ascii=False).encode())
                    logger.debug("_Requete.do_GET: fin (santé)")
                    return
                if self.path == "/probe/v1/metadata":
                    document = construire_metadonnees(
                        serveur_sonde.agent,
                        serveur_sonde.probe_id,
                        serveur_sonde.probe_name,
                        serveur_sonde.agent_version,
                    )
                    self._repondre(200, json.dumps(document, ensure_ascii=False).encode())
                    logger.debug("_Requete.do_GET: fin (métadonnées)")
                    return
                fenetre = _RE_FENETRE.match(self.path)
                if fenetre is not None:
                    self._servir_fenetre(fenetre.group(1))
                    logger.debug("_Requete.do_GET: fin (description de fenêtre)")
                    return
                pcapng = _RE_PCAPNG.match(self.path)
                if pcapng is not None:
                    identifiant = pcapng.group(1)
                    resultat = serveur_sonde.agent.fenetre(identifiant)
                    if resultat is None:
                        self._erreur(404, "window_unknown", "fenêtre inconnue ou expirée")
                        logger.debug("_Requete.do_GET: fin (fenêtre inconnue)")
                        return
                    try:
                        with open(resultat.chemin, "rb") as fichier:
                            donnees = fichier.read()
                    except OSError as exc:
                        logger.exception("échec dans _Requete.do_GET: lecture du pcapng impossible")
                        self._erreur(500, "internal_error", f"pcapng de la fenêtre illisible ({exc})")
                        logger.debug("_Requete.do_GET: fin (pcapng illisible)")
                        return
                    digest = base64.b64encode(hashlib.sha256(donnees).digest()).decode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-pcapng")
                    self.send_header("Content-Length", str(len(donnees)))
                    self.send_header(EN_TETE_CONTRAT, API_VERSION)
                    self.send_header("Digest", f"sha-256={digest}")
                    self.end_headers()
                    self.wfile.write(donnees)
                    logger.debug("_Requete.do_GET: fin (pcapng, {} octet(s))", len(donnees))
                    return
                self._erreur(404, "not_found", f"route inconnue : {self.path}")
                logger.debug("_Requete.do_GET: fin (route inconnue)")

            def do_POST(self) -> None:  # noqa: N802 -- nom imposé par http.server
                logger.debug("_Requete.do_POST: entrée ({})", self.path)
                if self.path != "/probe/v1/windows":
                    self._erreur(404, "not_found", f"route inconnue : {self.path}")
                    logger.debug("_Requete.do_POST: fin (route inconnue)")
                    return
                document = self._corps_json()
                if document is None:
                    self._erreur(400, "invalid_request", "corps JSON illisible ou non objet")
                    logger.debug("_Requete.do_POST: fin (corps illisible)")
                    return
                try:
                    debut = float(document["start"])
                    fin = float(document["end"])
                except (KeyError, TypeError, ValueError):
                    logger.debug("_Requete.do_POST: bornes manquantes ou non numériques")
                    self._erreur(400, "invalid_request", "bornes start/end manquantes ou non numériques")
                    logger.debug("_Requete.do_POST: fin (bornes invalides)")
                    return
                bpf = document.get("bpf") or None
                if bpf is not None and not isinstance(bpf, str):
                    self._erreur(400, "invalid_bpf", "bpf doit être une chaîne")
                    logger.debug("_Requete.do_POST: fin (bpf non texte)")
                    return
                max_octets = document.get("max_bytes")
                if max_octets is not None:
                    try:
                        max_octets = int(max_octets)
                    except (TypeError, ValueError):
                        self._erreur(400, "invalid_request", "max_bytes doit être un entier")
                        logger.debug("_Requete.do_POST: fin (max_bytes invalide)")
                        return
                inclure_inconnus = bool(document.get("include_unknown", False))
                try:
                    resultat = serveur_sonde.agent.extraire(
                        debut, fin, filtre_bpf=bpf, inclure_inconnus=inclure_inconnus, max_octets=max_octets
                    )
                except FiltreBpfInvalideError as exc:
                    logger.debug("_Requete.do_POST: filtre BPF refusé ({})", exc)
                    self._erreur(400, "invalid_bpf", f"filtre BPF refusé par la sonde : {exc}")
                    logger.debug("_Requete.do_POST: fin (filtre BPF refusé)")
                    return
                except FenetreInvalideError as exc:
                    logger.debug("_Requete.do_POST: fenêtre refusée ({})", exc)
                    self._erreur(400, "invalid_window", f"fenêtre refusée : {exc}")
                    logger.debug("_Requete.do_POST: fin (fenêtre refusée)")
                    return
                except FenetreVideError as exc:
                    logger.debug("_Requete.do_POST: rien dans le tampon ({})", exc)
                    self._erreur(404, "window_not_buffered", f"rien dans le tampon pour cette fenêtre : {exc}")
                    logger.debug("_Requete.do_POST: fin (tampon vide)")
                    return
                except FenetreTropGrandeError as exc:
                    logger.debug("_Requete.do_POST: fenêtre trop grande ({})", exc)
                    self._erreur(413, "window_too_large", f"fenêtre trop grande : {exc}")
                    logger.debug("_Requete.do_POST: fin (fenêtre trop grande)")
                    return
                except Exception as exc:  # noqa: BLE001 -- toute erreur interne doit être explicite, pas un crash
                    logger.exception("échec dans _Requete.do_POST: extraction de fenêtre")
                    self._erreur(500, "internal_error", f"extraction de fenêtre impossible ({exc})")
                    logger.debug("_Requete.do_POST: fin (erreur interne)")
                    return
                reponse = fenetre_vers_dict(
                    resultat,
                    serveur_sonde.probe_id,
                    serveur_sonde._expiration(resultat.identifiant),
                    bpf=bpf,
                )
                self._repondre(201, json.dumps(reponse, ensure_ascii=False).encode())
                logger.debug("_Requete.do_POST: fin (fenêtre {})", resultat.identifiant)

            def do_DELETE(self) -> None:  # noqa: N802 -- nom imposé par http.server
                logger.debug("_Requete.do_DELETE: entrée ({})", self.path)
                fenetre = _RE_FENETRE.match(self.path)
                if fenetre is None:
                    self._erreur(404, "not_found", f"route inconnue : {self.path}")
                    logger.debug("_Requete.do_DELETE: fin (route inconnue)")
                    return
                if serveur_sonde.agent.liberer(fenetre.group(1)):
                    self._repondre(204, b"")
                    logger.debug("_Requete.do_DELETE: fin (fenêtre libérée)")
                    return
                self._erreur(404, "window_unknown", "fenêtre inconnue ou expirée")
                logger.debug("_Requete.do_DELETE: fin (fenêtre inconnue)")

            def log_message(self, format: str, *args: Any) -> None:
                """Journalise via loguru (aucun secret n'apparaît dans les
                lignes de requête : URLs et corps restent hors journal)."""
                logger.debug("sonde: {} {}", self.command, format % args)

        with self._verrou:
            if self._serveur is not None:
                logger.debug("ServeurSonde.demarrer: déjà démarré -> retour URL existante")
                return self._url_de_base()
            contexte = self._contexte_tls()
            serveur = ThreadingHTTPServer((hote, port), _Requete)
            serveur.socket = contexte.wrap_socket(serveur.socket, server_side=True)
            self._demarrage = time.monotonic()
            self._serveur = serveur
        thread = threading.Thread(target=serveur.serve_forever, daemon=True)
        thread.start()
        url = self._url_de_base()
        logger.info("sonde {} à l'écoute sur {}", self.probe_name, url)
        logger.debug("ServeurSonde.demarrer: retour {}", url)
        return url

    def arreter(self) -> None:
        """Éteint le service (la capture, elle, continue)."""
        logger.debug("ServeurSonde.arreter: entrée")
        with self._verrou:
            serveur = self._serveur
            self._serveur = None
        if serveur is None:
            logger.debug("ServeurSonde.arreter: déjà arrêté -> retour")
            return
        serveur.shutdown()
        serveur.server_close()
        logger.info("sonde {} : service arrêté", self.probe_name)
        logger.debug("ServeurSonde.arreter: fin")

    # -- interne -------------------------------------------------------------------

    def _contexte_tls(self) -> ssl.SSLContext:
        """Contexte serveur : certificat client exigé (mTLS, #1101)."""
        logger.debug("ServeurSonde._contexte_tls: entrée")
        contexte = contexte_mtls_serveur(self.certificat_pem, self.cle_pem, self.ca_pem)
        logger.debug("ServeurSonde._contexte_tls: retour contexte")
        return contexte

    def _url_de_base(self) -> str:
        logger.debug("ServeurSonde._url_de_base: entrée")
        assert self._serveur is not None  # garde : appelé sous verrou après création
        hote, port = self._serveur.server_address[:2]
        url = f"https://{hote!s}:{port!s}"
        logger.debug("ServeurSonde._url_de_base: retour {}", url)
        return url

    def _expiration(self, identifiant: str) -> float:
        """Date d'expiration (secondes Unix) d'une fenêtre retenue ; dans
        le passé si la fenêtre a déjà expiré (elle ne sera plus servie)."""
        logger.debug("ServeurSonde._expiration: entrée ({})", identifiant)
        expiration = self.agent.expiration_fenetre(identifiant)
        if expiration is None:
            logger.debug("ServeurSonde._expiration: fenêtre inconnue -> retour maintenant")
            return time.time()
        logger.debug("ServeurSonde._expiration: retour {}", expiration)
        return expiration
