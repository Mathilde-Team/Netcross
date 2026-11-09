# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.spill -- debordement sur disque (SQLite) des structures de
l'etat par flux (issue #1024, sous-issue 5/6 du chantier #995).

FlowTable (#1023) borne deja la memoire par le nombre de flux ACTIFS, mais
deux de ses structures grandissent avec le nombre TOTAL de conversations
vues pendant la capture :

- ``_tcp_prev`` : resume compact du dernier enregistrement TCP de chaque
  cle, pour le detecteur de coupure NAT -- une entree par conversation TCP ;
- ``_cutoff_seen`` : coupures deja comptees par cle et par segment, pour
  ne compter chaque coupure qu'une fois.

Sur une capture de plusieurs millions de paquets, des millions de
conversations TCP representent des centaines de Mo : c'est ce debordement
que ce module elimine.

Principe (meme famille qu'Arkime, qui ecrit les pcap sur disque et n'envoie
que des metadonnees de session) : au-dela d'un seuil d'entrees en memoire,
les moins recentement utilisees sont deportees dans une base SQLite
temporaire ; une lecture manquante en memoire y est retrouvee et rechargee
(promotion). Les resultats sont identiques avec ou sans debordement --
seul l'ordre de stockage change, jamais les valeurs. Le fichier temporaire
est supprime a la fermeture.

``SpillDict`` et ``SpillSet`` servent aussi en mode purement memoire
(seuil nul) : meme code, meme comportement, pas de fichier cree.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import tempfile
from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Ecritures regroupees avant insertion SQLite : une insertion par lot
# plutot qu'une par entree deportee.
_TAILLE_LOT = 256

K = TypeVar("K")
V = TypeVar("V")


class SpillBackend:
    """Fichier SQLite temporaire partage par les tables de debordement.

    Une seule base pour toute l'analyse (une table par structure) : un seul
    fichier temporaire a creer et a supprimer. La suppression a lieu dans
    ``close()``, idempotent.
    """

    __slots__ = ("_chemin", "_conn", "_ferme")

    def __init__(self) -> None:
        logger.debug("SpillBackend.__init__: entrée")
        fd, chemin = tempfile.mkstemp(prefix="netcross-spill-", suffix=".sqlite")
        os.close(fd)
        os.unlink(chemin)  # sqlite recree un fichier propre
        self._chemin = chemin
        self._conn = sqlite3.connect(chemin)
        self._conn.execute("PRAGMA journal_mode=OFF")
        self._conn.execute("PRAGMA synchronous=OFF")
        self._ferme = False
        logger.debug("SpillBackend.__init__: retour ({})", chemin)

    @property
    def chemin(self) -> str:
        """Chemin du fichier temporaire (pour les tests et le diagnostic)."""
        logger.debug("SpillBackend.chemin: entrée")
        logger.debug("SpillBackend.chemin: retour")
        return self._chemin

    def table(self, nom: str) -> None:
        """Cree la table ``nom`` (cle textuelle primaire, valeur textuelle)."""
        logger.debug("SpillBackend.table: entrée ({})", nom)
        self._conn.execute(f'CREATE TABLE IF NOT EXISTS "{nom}" (k TEXT PRIMARY KEY, v TEXT)')
        logger.debug("SpillBackend.table: retour None")

    def inserer(self, nom: str, lignes: list[tuple[str, str]]) -> None:
        """Remplace (INSERT OR REPLACE) un lot d'entrees de la table ``nom``."""
        logger.debug("SpillBackend.inserer: entrée ({} ligne(s), {})", len(lignes), nom)
        if lignes:
            self._conn.executemany(f'INSERT OR REPLACE INTO "{nom}" (k, v) VALUES (?, ?)', lignes)
        logger.debug("SpillBackend.inserer: retour None")

    def lire(self, nom: str, cle: str) -> str | None:
        """Valeur associee a ``cle`` dans la table ``nom``, ou None."""
        logger.debug("SpillBackend.lire: entrée ({})", nom)
        curseur = self._conn.execute(f'SELECT v FROM "{nom}" WHERE k = ?', (cle,))
        ligne = curseur.fetchone()
        logger.debug("SpillBackend.lire: retour trouvé={}", ligne is not None)
        return ligne[0] if ligne is not None else None

    def supprimer(self, nom: str, cle: str) -> None:
        """Retire ``cle`` de la table ``nom`` (promotion vers la memoire)."""
        logger.debug("SpillBackend.supprimer: entrée ({})", nom)
        self._conn.execute(f'DELETE FROM "{nom}" WHERE k = ?', (cle,))
        logger.debug("SpillBackend.supprimer: retour None")

    def close(self) -> None:
        """Ferme la connexion et supprime le fichier temporaire ; idempotent."""
        logger.debug("SpillBackend.close: entrée")
        if self._ferme:
            logger.debug("SpillBackend.close: déjà fermé -> retour")
            return
        self._ferme = True
        self._conn.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._chemin)
        logger.debug("SpillBackend.close: retour None")


class SpillDict(Generic[K, V]):
    """Table associative bornee en memoire, debordement SQLite au-dela du seuil.

    Les ``seuil`` entrees les plus recentes restent en memoire (LRU) ; une
    ecriture au-dela deporte la plus ancienne vers SQLite. Une lecture
    manquante en memoire est retrouvee sur disque et rechargee (promotion).
    Avec ``seuil`` nul : memoire non bornee, aucun fichier cree -- le
    comportement d'une table purement en RAM, meme code, memes resultats.
    """

    __slots__ = (
        "_backend",
        "_cle",
        "_dump",
        "_en_attente",
        "_load",
        "_mem",
        "_nom",
        "_own",
        "_seuil",
    )

    def __init__(
        self,
        seuil: int,
        cle: Callable[[K], str],
        dump: Callable[[V], str],
        load: Callable[[str], V],
        backend: SpillBackend | None = None,
        nom: str = "entrees",
    ) -> None:
        logger.debug("SpillDict.__init__: entrée (seuil={}, nom={})", seuil, nom)
        self._seuil = max(0, int(seuil))
        self._cle = cle
        self._dump = dump
        self._load = load
        self._mem: OrderedDict[str, V] = OrderedDict()
        self._nom = nom
        self._en_attente: list[tuple[str, str]] = []
        self._backend: SpillBackend | None = None
        if self._seuil > 0:
            self._own = backend is None
            self._backend = backend if backend is not None else SpillBackend()
            self._backend.table(nom)
        else:
            self._own = False
        logger.debug("SpillDict.__init__: fin")

    def get(self, cle: K) -> V | None:
        """Valeur associee a ``cle`` ; la recharge (et la promeut) si elle
        n'est qu'en memoire de disque. None si absente des deux."""
        logger.debug("SpillDict.get: entrée")
        sk = self._cle(cle)
        if sk in self._mem:
            self._mem.move_to_end(sk)
            logger.debug("SpillDict.get: retour (en mémoire)")
            return self._mem[sk]
        if self._backend is None:
            logger.debug("SpillDict.get: retour None (sans débordement)")
            return None
        self._vider_attente()
        brute = self._backend.lire(self._nom, sk)
        if brute is None:
            logger.debug("SpillDict.get: retour None (absente)")
            return None
        # promotion : l'entree revient en memoire, la plus ancienne part
        # sur disque -- l'ordre de stockage change, pas les valeurs.
        self._backend.supprimer(self._nom, sk)
        if len(self._mem) >= self._seuil and self._mem:
            sk_vieux, v_vieux = self._mem.popitem(last=False)
            self._en_attente.append((sk_vieux, self._dump(v_vieux)))
        valeur = self._load(brute)
        self._mem[sk] = valeur
        self._vider_attente()
        logger.debug("SpillDict.get: retour (promue depuis le disque)")
        return valeur

    def put(self, cle: K, valeur: V) -> None:
        """Associe ``valeur`` a ``cle`` ; deporter la plus ancienne si le
        seuil memoire est atteint."""
        logger.debug("SpillDict.put: entrée")
        sk = self._cle(cle)
        if sk in self._mem:
            self._mem.move_to_end(sk)
            self._mem[sk] = valeur
            logger.debug("SpillDict.put: retour (mise à jour en mémoire)")
            return
        if self._backend is not None and self._seuil > 0 and len(self._mem) >= self._seuil and self._mem:
            sk_vieux, v_vieux = self._mem.popitem(last=False)
            self._en_attente.append((sk_vieux, self._dump(v_vieux)))
            self._vider_attente()
        self._mem[sk] = valeur
        logger.debug("SpillDict.put: retour None")

    def __contains__(self, cle: K) -> bool:
        logger.debug("SpillDict.__contains__: entrée")
        sk = self._cle(cle)
        if sk in self._mem:
            logger.debug("SpillDict.__contains__: retour True (mémoire)")
            return True
        if self._backend is None:
            logger.debug("SpillDict.__contains__: retour False")
            return False
        self._vider_attente()
        present = self._backend.lire(self._nom, sk) is not None
        logger.debug("SpillDict.__contains__: retour {}", present)
        return present

    def _vider_attente(self) -> None:
        """Ecrit le lot d'entrees deportees en attente, puis le vide."""
        logger.debug("SpillDict._vider_attente: entrée ({} en attente)", len(self._en_attente))
        if self._en_attente and self._backend is not None:
            self._backend.inserer(self._nom, self._en_attente)
            self._en_attente = []
        logger.debug("SpillDict._vider_attente: retour None")

    def close(self) -> None:
        """Ecrit ce qui reste en attente ; supprime le fichier si le
        backend lui appartient."""
        logger.debug("SpillDict.close: entrée")
        self._vider_attente()
        if self._own and self._backend is not None:
            self._backend.close()
        logger.debug("SpillDict.close: retour None")


class SpillSet(Generic[K]):
    """Ensemble borne en memoire, debordement SQLite au-dela du seuil.

    Les ``seuil`` elements les plus recents restent en memoire ; les
    suivants sont ecrits sur disque sans les relire (un ensemble n'a ni
    valeur a promouvoir, ni ordre a retenir). ``__contains__`` regarde
    la memoire puis le disque. Avec ``seuil`` nul : ensemble en RAM,
    aucun fichier cree.
    """

    __slots__ = ("_backend", "_cle", "_en_attente", "_mem", "_nom", "_own", "_seuil")

    def __init__(
        self,
        seuil: int,
        cle: Callable[[K], str],
        backend: SpillBackend | None = None,
        nom: str = "elements",
    ) -> None:
        logger.debug("SpillSet.__init__: entrée (seuil={}, nom={})", seuil, nom)
        self._seuil = max(0, int(seuil))
        self._cle = cle
        self._mem: set[str] = set()
        self._nom = nom
        self._en_attente: list[tuple[str, str]] = []
        self._backend: SpillBackend | None = None
        if self._seuil > 0:
            self._own = backend is None
            self._backend = backend if backend is not None else SpillBackend()
            self._backend.table(nom)
        else:
            self._own = False
        logger.debug("SpillSet.__init__: fin")

    def add(self, cle: K) -> None:
        """Ajoute ``cle`` : en memoire tant que le seuil n'est pas atteint,
        sinon directement sur disque."""
        logger.debug("SpillSet.add: entrée")
        sk = self._cle(cle)
        if sk in self._mem:
            logger.debug("SpillSet.add: retour (déjà présent)")
            return
        if self._backend is not None and self._seuil > 0 and len(self._mem) >= self._seuil:
            self._en_attente.append((sk, ""))
            if len(self._en_attente) >= _TAILLE_LOT:
                self._vider_attente()
            logger.debug("SpillSet.add: retour (déporté sur disque)")
            return
        self._mem.add(sk)
        logger.debug("SpillSet.add: retour None")

    def __contains__(self, cle: K) -> bool:
        logger.debug("SpillSet.__contains__: entrée")
        sk = self._cle(cle)
        if sk in self._mem:
            logger.debug("SpillSet.__contains__: retour True (mémoire)")
            return True
        if self._backend is None:
            logger.debug("SpillSet.__contains__: retour False")
            return False
        self._vider_attente()
        present = self._backend.lire(self._nom, sk) is not None
        logger.debug("SpillSet.__contains__: retour {}", present)
        return present

    def _vider_attente(self) -> None:
        """Ecrit le lot d'elements deportes en attente, puis le vide."""
        logger.debug("SpillSet._vider_attente: entrée ({} en attente)", len(self._en_attente))
        if self._en_attente and self._backend is not None:
            self._backend.inserer(self._nom, self._en_attente)
            self._en_attente = []
        logger.debug("SpillSet._vider_attente: retour None")

    def close(self) -> None:
        """Ecrit ce qui reste en attente ; supprime le fichier si le
        backend lui appartient."""
        logger.debug("SpillSet.close: entrée")
        self._vider_attente()
        if self._own and self._backend is not None:
            self._backend.close()
        logger.debug("SpillSet.close: retour None")


def cle_json(cle: tuple) -> str:
    """Cle de flux (ou couple (cle, segment)) sous forme canonique JSON :
    meme cle, meme chaine -- condition de l'egalite entre memoire et disque."""
    logger.debug("cle_json: entrée")
    texte = json.dumps(cle, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    logger.debug("cle_json: retour")
    return texte
