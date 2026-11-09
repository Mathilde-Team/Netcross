# SPDX-License-Identifier: GPL-3.0-or-later
"""L'historique privé garde les preuves, puis efface ses fichiers."""

import gc
import sqlite3
from pathlib import Path

import pytest

from netcross_core import flow_history

CLE = ("TCP", "192.0.2.1", 41000, "198.51.100.1", 443)


def test_resume_remplacement_coupures_et_nettoyage():
    historique = flow_history.FlowHistory()
    repertoire = historique.path.parent
    try:
        assert repertoire.stat().st_mode & 0o777 == 0o700
        assert historique._connexion.execute("PRAGMA cache_size").fetchone()[0] == -1024
        assert historique._connexion.execute("PRAGMA temp_store").fetchone()[0] == 1
        assert historique.resume(CLE) is None
        historique.enregistrer(CLE, frozenset({"A", "B"}), {"A": 2, "B": 1}, "expiration")
        assert historique.resume(CLE) == {
            "points": ["A", "B"],
            "packets": {"A": 2, "B": 1},
            "raison": "expiration",
        }
        historique.enregistrer(CLE, frozenset({"A"}), {"A": 3}, "fin")
        assert historique.resume(CLE)["packets"] == {"A": 3}
        assert not historique.coupure_comptee(CLE, "A", "B")
        historique.compter_coupure(CLE, "A", "B")
        historique.compter_coupure(CLE, "A", "B")
        assert historique.coupure_comptee(CLE, "A", "B")
        assert not historique.coupure_comptee(CLE, "B", "A")
    finally:
        historique.close()
    historique.close()
    assert not repertoire.exists()


def test_finalisation_sans_fermeture_explicite():
    historique = flow_history.FlowHistory()
    repertoire = historique.path.parent
    del historique
    gc.collect()
    assert not repertoire.exists()


def test_echec_ouverture_nettoie_et_propage(monkeypatch):
    repertoires = []

    def refuser(chemin, **_kwargs):
        repertoires.append(Path(chemin).parent)
        raise sqlite3.OperationalError("échec simulé")

    monkeypatch.setattr(flow_history.sqlite3, "connect", refuser)
    with pytest.raises(sqlite3.OperationalError, match="échec simulé"):
        flow_history.FlowHistory()
    assert not repertoires[0].exists()


def test_echec_initialisation_ferme_et_nettoie(monkeypatch):
    repertoires = []

    class ConnexionDefaillante:
        fermee = False

        def execute(self, _sql):
            raise sqlite3.OperationalError("initialisation simulée")

        def close(self):
            self.fermee = True

    connexion = ConnexionDefaillante()

    def ouvrir(chemin, **_kwargs):
        repertoires.append(Path(chemin).parent)
        return connexion

    monkeypatch.setattr(flow_history.sqlite3, "connect", ouvrir)
    with pytest.raises(sqlite3.OperationalError, match="initialisation simulée"):
        flow_history.FlowHistory()
    assert connexion.fermee
    assert not repertoires[0].exists()


def test_nettoyage_meme_si_la_fermeture_echoue():
    nettoye = []

    class ConnexionDefaillante:
        def close(self):
            raise sqlite3.OperationalError("fermeture simulée")

    class Repertoire:
        def cleanup(self):
            nettoye.append(True)

    with pytest.raises(sqlite3.OperationalError, match="fermeture simulée"):
        flow_history._fermer(ConnexionDefaillante(), Repertoire())
    assert nettoye == [True]
