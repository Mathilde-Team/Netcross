# SPDX-License-Identifier: GPL-3.0-or-later
"""Historique TCP temporaire sur disque, sans rétention par flux en RAM."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import weakref
from collections.abc import Iterator
from pathlib import Path

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def _fermer(connexion: sqlite3.Connection, repertoire: tempfile.TemporaryDirectory) -> None:
    logger.debug("flow_history._fermer: entrée")
    try:
        connexion.close()
    finally:
        repertoire.cleanup()
    logger.debug("flow_history._fermer: fin")


class FlowHistory:
    """SQLite privé et éphémère ; cache natif plafonné à 1 Mio.

    Les résumés et les coupures déjà comptées restent exacts même après
    une longue inactivité. Le disque croît avec les conversations, pas la
    RAM ; aucun paquet ni contenu applicatif n'est conservé ici.
    """

    def __init__(self) -> None:
        logger.debug("FlowHistory.__init__: entrée")
        repertoire = tempfile.TemporaryDirectory(prefix="netcross-flux-")
        self.path = Path(repertoire.name) / "historique.sqlite3"
        try:
            # La finalisation peut survenir depuis un autre thread ; les
            # alimentations restent séquentielles, comme celles de FlowTable.
            connexion = sqlite3.connect(self.path, check_same_thread=False)
        except sqlite3.Error:
            logger.exception("Impossible d'ouvrir l'historique temporaire des flux")
            repertoire.cleanup()
            logger.debug("FlowHistory.__init__: ouverture impossible -> propagation")
            raise
        try:
            connexion.execute("PRAGMA cache_size = -1024")
            connexion.execute("PRAGMA temp_store = FILE")
            connexion.execute("CREATE TABLE resumes (cle TEXT PRIMARY KEY, document TEXT NOT NULL) WITHOUT ROWID")
            connexion.execute(
                "CREATE TABLE coupures (cle TEXT, amont TEXT, aval TEXT, PRIMARY KEY (cle, amont, aval)) WITHOUT ROWID"
            )
        except sqlite3.Error:
            logger.exception("Impossible d'initialiser l'historique temporaire des flux")
            _fermer(connexion, repertoire)
            logger.debug("FlowHistory.__init__: initialisation impossible -> propagation")
            raise
        self._connexion = connexion
        self._finalisation = weakref.finalize(self, _fermer, connexion, repertoire)
        logger.debug("FlowHistory.__init__: fin")

    def resume(self, cle: tuple) -> dict | None:
        logger.debug("FlowHistory.resume: entrée")
        ligne = self._connexion.execute("SELECT document FROM resumes WHERE cle = ?", (json.dumps(cle),)).fetchone()
        resultat = json.loads(ligne[0]) if ligne is not None else None
        logger.debug("FlowHistory.resume: retour (présent={})", resultat is not None)
        return resultat

    def enregistrer(
        self, cle: tuple, points: frozenset[str], paquets: dict, raison: str, statistiques: dict | None = None
    ) -> None:
        logger.debug("FlowHistory.enregistrer: entrée")
        donnees = {"points": sorted(points), "packets": paquets, "raison": raison}
        if statistiques is not None:
            donnees["stats"] = statistiques
        document = json.dumps(donnees)
        self._connexion.execute(
            "INSERT INTO resumes VALUES (?, ?) ON CONFLICT(cle) DO UPDATE SET document = excluded.document",
            (json.dumps(cle), document),
        )
        logger.debug("FlowHistory.enregistrer: fin")

    def resumes(self) -> Iterator[tuple[tuple, dict]]:
        """Parcourt les conversations une à une, jamais avec fetchall()."""
        logger.debug("FlowHistory.resumes: entrée")
        for cle, document in self._connexion.execute("SELECT cle, document FROM resumes"):
            yield tuple(json.loads(cle)), json.loads(document)
        logger.debug("FlowHistory.resumes: fin")

    def coupure_comptee(self, cle: tuple, amont: str, aval: str) -> bool:
        logger.debug("FlowHistory.coupure_comptee: entrée")
        ligne = self._connexion.execute(
            "SELECT 1 FROM coupures WHERE cle = ? AND amont = ? AND aval = ?",
            (json.dumps(cle), amont, aval),
        ).fetchone()
        logger.debug("FlowHistory.coupure_comptee: retour (présent={})", ligne is not None)
        return ligne is not None

    def compter_coupure(self, cle: tuple, amont: str, aval: str) -> None:
        logger.debug("FlowHistory.compter_coupure: entrée")
        self._connexion.execute("INSERT OR IGNORE INTO coupures VALUES (?, ?, ?)", (json.dumps(cle), amont, aval))
        logger.debug("FlowHistory.compter_coupure: fin")

    def close(self) -> None:
        logger.debug("FlowHistory.close: entrée")
        self._finalisation()
        logger.debug("FlowHistory.close: fin")
