# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.incident_chain — orchestration production de la chaîne
d'incident (issue #1001 : enregistrement rétroactif déclenché par alarme).

Les briques existaient mais ne se parlaient pas (audit de l'issue #1001) :
GelManager protégeait les fichiers à l'alarme (#1087) sans que rien
n'enchaîne, archiver_incident (#1090) et analyser_incident (#1091)
n'étaient appelés que manuellement (bouton GUI, route API), et les
réglages partagés (gel_settings) n'étaient raccordés à aucun moteur.

Ce module fournit le chaînon manquant, ChaineIncidents : branché sur le
moteur live (LiveDiffEngine, paramètre ``gel=``) à la place du GelManager
nu, il orchestre le parcours complet à chaque alarme :

1. **gel** — GelManager.on_alarm(event) protège les fichiers du tampon
   sur tous les points (lien dur, fenêtre translatée par point) ;
2. **attente effective de la fenêtre** — la fenêtre s'étend à
   [t - avant, t + après] : au moment de l'alarme, la moitié « après »
   n'est PAS encore capturée. Le traitement attend (horloge murale, la
   capture live avance au même rythme) que la fenêtre soit révolue
   avant de découper — les fichiers protégés survivent à la rotation
   pendant l'attente (lien dur), les paquets post-alarme s'y ajoutent ;
3. **découpe + archivage + manifeste** — archiver_incident (#1090),
   empreintes SHA-256 ;
4. **analyse multi-points** — analyser_incident (#1091) : vérification
   de la chaîne de preuve, correlate + analyse + constats, rapport JSON
   (et HTML si générateur injecté) rangé avec les segments ;
5. **notification** — portée par analyser_incident (résumé + chemin de
   l'archive).

Le traitement (2-5) tourne dans un thread dédié, un par incident : le
moteur live n'est JAMAIS bloqué par la chaîne. Un échec à une étape est
journalisé (logger.exception) et n'interrompt ni le moteur, ni les
autres incidents.

chaine_incidents_depuis_reglages() construit la chaîne depuis les
réglages partagés (gel_settings) : c'est l'appel de production qui
raccorde réglages + tampon multi-points au moteur live.

Contrat de couches : netcross_core uniquement — les dépendances
montantes (score netcross_report, rendu HTML) restent injectées par
l'appelant, comme dans incident_analysis.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from netcross_core.alarms import AlarmEvent
from netcross_core.config import NotifyConfig
from netcross_core.gel_settings import vers_gel_config
from netcross_core.incident_analysis import RapportIncident, analyser_incident
from netcross_core.logging_config import get_logger, summarize
from netcross_core.retro_capture import (
    GelManager,
    GelReport,
    PointDeGel,
    archiver_incident,
)
from pcap_parser.capture import cut_capture_window

logger = get_logger(__name__)

# Marge de sécurité sur l'attente de fin de fenêtre : la dernière
# évaluation du diff peut dater de eval_interval_seconds, et l'horloge
# murale n'avance pas exactement au rythme de l'horloge de capture.
MARGE_ATTENTE_DEFAUT = 1.0


class ChaineIncidents:
    """Orchestrateur : alarme → gel → attente → découpe/manifeste →
    analyse → notification (issue #1001).

    S'utilise comme un GelManager auprès de LiveDiffEngine (même
    méthode on_alarm, même retour GelReport | None) — d'où le nom du
    paramètre moteur ``gel=chaine`` — mais chaque gel déclenché donne
    naissance à un incident complet, traité en arrière-plan :

        chaine = ChaineIncidents(gel, parseur=..., notificateur=...)
        engine = LiveDiffEngine(..., gel=chaine)

    Le moteur live passe à on_alarm l'horodatage du dernier paquet
    (ts_courant) : l'attente de fin de fenêtre est calculée depuis lui
    (et non depuis l'horloge murale au moment de l'appel), ce qui rend
    l'attente effective même quand l'évaluation du diff a du retard.

    Dépendances injectables (mêmes signatures que analyser_incident) :
    decoupeur, parseur, scanner, evaluateur, generateur_html,
    notificateur, cfg_notification — plus attendre/horloge pour les
    tests (remplacer time.sleep par un enregistreur).
    """

    def __init__(
        self,
        gel: GelManager,
        *,
        decoupeur: Callable[[str, str, float, float], None] = cut_capture_window,
        parseur: Callable[[str, str], list[Any]] | None = None,
        scanner: Callable[[str, str], Sequence[Any]] | None = None,
        evaluateur: Callable[[Any], tuple[int, str | None]] | None = None,
        generateur_html: Callable[[Any, str], str | None] | None = None,
        notificateur: Callable[[Any], Sequence[Any]] | None = None,
        cfg_notification: NotifyConfig | None = None,
        seuil_notification: str = "elevee",
        attendre: Callable[[float], None] = time.sleep,
        marge_attente: float = MARGE_ATTENTE_DEFAUT,
    ) -> None:
        logger.debug("ChaineIncidents.__init__: entrée (gel={})", summarize(gel, "gel"))
        self.gel = gel
        self._decoupeur = decoupeur
        self._parseur = parseur
        self._scanner = scanner
        self._evaluateur = evaluateur
        self._generateur_html = generateur_html
        self._notificateur = notificateur
        self._cfg_notification = cfg_notification
        self._seuil_notification = seuil_notification
        self._attendre = attendre
        self._marge_attente = marge_attente
        self._verrou = threading.Lock()
        self._threads: list[threading.Thread] = []
        # Résultats des incidents traités (un RapportIncident par
        # incident mené à terme), dans l'ordre d'achèvement.
        self.rapports: list[RapportIncident] = []
        logger.debug("ChaineIncidents.__init__: fin")

    def on_alarm(self, event: AlarmEvent, ts_courant: float | None = None) -> GelReport | None:
        """Point d'entrée moteur : déclenche le gel (GelManager), puis
        planifie le traitement complet de l'incident en arrière-plan.

        ``ts_courant`` : horodatage du dernier paquet vu par le moteur
        live (horloge de capture) au moment de l'alarme — sert à calculer
        l'attente résiduelle de fin de fenêtre. None (appel manuel) :
        repli sur l'horodatage de l'alarme elle-même.

        Retourne le GelReport du gel (ou None si ignoré), comme
        GelManager.on_alarm — le moteur live n'a pas à distinguer.
        """
        logger.debug("ChaineIncidents.on_alarm: entrée (ts_courant={})", ts_courant)
        rapport = self.gel.on_alarm(event)
        if rapport is None or rapport.ignored_reason is not None:
            logger.debug("ChaineIncidents.on_alarm: gel ignoré -> retour rapport/None")
            return rapport
        if not any(rapport.files.values()):
            # Fenêtre hors tampon (aucun fichier protégé) : rien à
            # archiver ni à analyser — l'incident est signalé, pas muet.
            logger.warning(
                "Incident {} : gel sans fichier protégé (fenêtre [{:.0f}, {:.0f}] hors tampon), pas d'archive",
                rapport.dossier or "?",
                rapport.start,
                rapport.end,
            )
            logger.debug("ChaineIncidents.on_alarm: gel vide -> retour rapport")
            return rapport
        thread = threading.Thread(
            target=self._traiter,
            args=(rapport, ts_courant),
            daemon=True,
            name=f"netcross-incident-{os.path.basename(rapport.dossier) if rapport.dossier else 'anonyme'}",
        )
        with self._verrou:
            self._threads.append(thread)
        thread.start()
        logger.debug("ChaineIncidents.on_alarm: traitement planifié, retour rapport")
        return rapport

    def _traiter(self, rapport: GelReport, ts_courant: float | None) -> None:
        """Parcours complet d'UN incident, en arrière-plan : attente de
        la fenêtre, découpe + manifeste, analyse, notification. Aucune
        exception ne remonte — un échec est journalisé, la chaîne et le
        moteur continuent."""
        logger.debug("ChaineIncidents._traiter: entrée ({})", rapport.dossier)
        try:
            self._attendre_fin_de_fenetre(rapport, ts_courant)
            manifeste = archiver_incident(rapport, decoupeur=self._decoupeur)
            resultat = analyser_incident(
                manifeste,
                parseur=self._parseur,
                scanner=self._scanner,
                evaluateur=self._evaluateur,
                generateur_html=self._generateur_html,
                notificateur=self._notificateur,
                cfg_notification=self._cfg_notification,
                seuil_notification=self._seuil_notification,
            )
            with self._verrou:
                self.rapports.append(resultat)
            logger.info(
                "Incident {} mené à terme : rapport {} ({} notification(s))",
                resultat.incident,
                resultat.chemin_rapport,
                len(resultat.notifications),
            )
        except Exception:
            logger.exception("échec du traitement de l'incident {}", rapport.dossier)
        logger.debug("ChaineIncidents._traiter: fin")

    def _attendre_fin_de_fenetre(self, rapport: GelReport, ts_courant: float | None) -> None:
        """Attend que la fenêtre [start, end] soit révolue en horloge de
        capture : la partie « après » de la fenêtre n'est capturée qu'à
        partir de maintenant. Le calcul part de ts_courant (dernier
        paquet vu) quand le moteur le fournit, sinon de l'horodatage de
        l'alarme — l'attente est majorée d'une marge de sécurité."""
        logger.debug("ChaineIncidents._attendre_fin_de_fenetre: entrée")
        reference = ts_courant if ts_courant is not None else rapport.horodatage_alarme
        if reference is None:
            # Cas défensif : ni paquet ni horodatage — on attend la
            # totalité de la partie « après » (prudence).
            reference = rapport.start
        reste = rapport.end - reference + self._marge_attente
        if reste > 0:
            logger.info(
                "Incident {} : attente de {:.1f}s avant archivage (fenêtre jusqu'à {:.1f})",
                rapport.dossier or "?",
                reste,
                rapport.end,
            )
            self._attendre(reste)
        logger.debug("ChaineIncidents._attendre_fin_de_fenetre: retour None")

    def attendre_termine(self, timeout: float = 10.0) -> bool:
        """Attend la fin des traitements en cours (tests et arrêt
        propre). Renvoie True si tous les threads sont terminés."""
        logger.debug("ChaineIncidents.attendre_termine: entrée (timeout={})", timeout)
        with self._verrou:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=timeout)
        termines = all(not thread.is_alive() for thread in threads)
        logger.debug("ChaineIncidents.attendre_termine: retour {}", termines)
        return termines


def chaine_incidents_depuis_reglages(
    reglages: Mapping[str, Any],
    points: Mapping[str, PointDeGel],
    **injectables: Any,
) -> ChaineIncidents:
    """Construit la chaîne complète depuis les réglages partagés
    (gel_settings.lire_reglages) et les points de capture en direct :
    l'appel de production qui raccorde réglages + tampon multi-points au
    moteur live (LiveDiffEngine(..., gel=chaine)).

    ``injectables`` : dépendances montantes passées telles quelles à
    ChaineIncidents (parseur, evaluateur, generateur_html,
    notificateur, cfg_notification, decoupeur, attendre...).

        reglages = lire_reglages()
        points = {"LAN": PointDeGel(inventory=partial(ring_inventory, ...)), ...}
        chaine = chaine_incidents_depuis_reglages(reglages, points)
        engine = LiveDiffEngine(..., gel=chaine)
    """
    logger.debug("chaine_incidents_depuis_reglages: entrée ({} point(s))", len(points))
    config, archives_dir = vers_gel_config(reglages)
    gel = GelManager(config, archives_dir, points)
    chaine = ChaineIncidents(gel, **injectables)
    logger.debug("chaine_incidents_depuis_reglages: retour ChaineIncidents")
    return chaine


__all__ = [
    "MARGE_ATTENTE_DEFAUT",
    "ChaineIncidents",
    "chaine_incidents_depuis_reglages",
]
