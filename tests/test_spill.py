# SPDX-License-Identifier: GPL-3.0-or-later
"""Débordement sur disque de l'état par flux (issue #1024)."""

from __future__ import annotations

import os

from conftest import make_pkt

from netcross_core.flow_state import FlowTable
from netcross_core.spill import SpillBackend, SpillDict, SpillSet, cle_json

DELAIS = {"TCP": 60.0, "UDP": 60.0, "ICMP": 60.0, "AUTRE": 60.0}
CONN = {"src": "10.0.0.1", "dst": "192.0.2.10", "sport": 40000, "dport": 443}


def _rss_mib() -> float:
    """RSS du processus en MiB (/proc/self/status, Linux)."""
    with open("/proc/self/status", encoding="utf-8") as f:
        for ligne in f:
            if ligne.startswith("VmRSS"):
                return int(ligne.split()[1]) / 1024.0
    raise AssertionError("VmRSS introuvable dans /proc/self/status")


def test_dict_lru_et_promotion_depuis_le_disque():
    d = SpillDict(2, str, str, str)
    d.put("a", "1")
    d.put("b", "2")
    d.put("c", "3")  # "a" (la plus ancienne) part sur disque
    assert d.get("a") == "1"  # retrouvee et promue depuis le disque
    assert d.get("b") == "2"
    assert d.get("c") == "3"
    assert d.get("inconnu") is None
    d.close()


def test_dict_mise_a_jour_en_memoire():
    d = SpillDict(2, str, str, str)
    d.put("a", "1")
    d.put("a", "2")
    assert d.get("a") == "2"
    d.close()


def test_ensemble_debordement():
    s = SpillSet(2, str)
    for k in ("a", "b", "c", "d"):  # "c" et "d" partent sur disque
        s.add(k)
    for k in ("a", "b", "c", "d"):
        assert k in s
    assert "e" not in s
    s.close()


def test_seuil_nul_purement_en_ram():
    # seuil nul : aucun fichier, comportement d'une structure en RAM
    d = SpillDict(0, str, str, str)
    d.put("a", "1")
    assert d.get("a") == "1"
    assert "a" in d
    assert d.get("b") is None
    d.close()
    s = SpillSet(0, str)
    s.add("x")
    assert "x" in s
    assert "y" not in s
    s.close()


def test_fichier_temporaire_supprime_a_la_fermeture():
    d = SpillDict(1, str, str, str)
    d.put("a", "1")
    d.put("b", "2")  # deporte "a" -> le fichier existe
    chemin = d._backend.chemin
    assert os.path.exists(chemin)
    d.close()
    assert not os.path.exists(chemin)


def test_backend_suppression_idempotente():
    b = SpillBackend()
    b.table("t")
    b.inserer("t", [("k", "v")])
    assert b.lire("t", "k") == "v"
    chemin = b.chemin
    b.close()
    b.close()  # idempotent
    assert not os.path.exists(chemin)


def test_cle_json_canonique():
    # meme cle (tuple ou couple imbrique) -> meme chaine : condition de
    # l'egalite entre memoire et disque
    assert cle_json(("TCP", "a", 1, "b", 2)) == cle_json(("TCP", "a", 1, "b", 2))
    assert cle_json((("TCP", "a", 1, "b", 2), ("X", "Y"))) != cle_json((("TCP", "a", 1, "b", 2), ("X", "Z")))


def _scenario_coupures(n_conversations=6):
    """Conversations TCP vues aux deux points, la moitié coupées : le
    détecteur de coupure NAT s'appuie sur _tcp_prev et _cutoff_seen, les
    deux structures qui débordent."""
    paquets = []
    for i in range(n_conversations):
        conn = {"src": f"10.0.0.{i + 1}", "dst": "192.0.2.10", "sport": 40000 + i, "dport": 443}
        for t in (0.0, 1.0, 2.0):
            paquets.append(make_pkt(point="CLIENT", ts=t, seq=100, key_id=100, **conn))
            paquets.append(make_pkt(point="SERVEUR", ts=t + 0.01, seq=100, key_id=100, **conn))
        # réveil en CLIENT seulement pour une conversation sur deux
        if i % 2 == 0:
            paquets.append(make_pkt(point="CLIENT", ts=102.0, seq=900, key_id=900, **conn))
            paquets.append(make_pkt(point="CLIENT", ts=103.0, seq=901, key_id=901, **conn))
        else:
            # flux repris aux deux points : reouverture comptée, pas de coupure
            paquets.append(make_pkt(point="CLIENT", ts=102.0, seq=900, key_id=900, **conn))
            paquets.append(make_pkt(point="SERVEUR", ts=102.01, seq=900, key_id=900, **conn))
    paquets.sort(key=lambda pk: pk.ts)
    return paquets


def test_equivalence_avec_et_sans_debordement():
    # meme scenario, seuil debordement minuscule (2) pour forcer evictions
    # et promotions dans _tcp_prev et _cutoff_seen
    paquets = _scenario_coupures()
    sans = FlowTable(["CLIENT", "SERVEUR"], timeouts=DELAIS)
    avec = FlowTable(["CLIENT", "SERVEUR"], timeouts=DELAIS, spill_seuil=2)
    for pk in paquets:
        sans.feed(pk)
        avec.feed(pk)
    sans.finish()
    avec.finish()
    assert sans.to_dict() == avec.to_dict()
    assert sans.summary_lines() == avec.summary_lines()
    # le scenario produit bien des coupures et des reouvertures (sinon
    # l'equivalence ne dirait rien des structures qui debordent)
    doc = sans.to_dict()
    assert sum(doc["nat_cutoffs"].values()) >= 1
    assert sum(doc["reopened"].values()) >= 1


def test_memoire_bornee_sur_un_million_de_paquets():
    # issue #1024 : 10^6 conversations TCP distinctes, seuil de
    # debordement bas : la croissance du RSS doit rester tres en dessous
    # des ~650 Mo que les memes entrees occupent sans debordement
    # (mesure sur la machine de developpement, 2 cœurs).
    table = FlowTable(["A"], timeouts=DELAIS, spill_seuil=5000)
    rss_avant = _rss_mib()
    for i in range(1_000_000):
        src = f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256 + 1}"
        table.feed(make_pkt(point="A", ts=i * 100.0, src=src, dst="192.0.2.9", sport=20000, dport=443))
    table.finish()
    croissance = _rss_mib() - rss_avant
    assert table.total_records == 1_000_000
    assert table.expired == 999_999
    assert croissance < 250.0, f"RSS +{croissance:.0f} MiB : le débordement n'a pas borné la mémoire"
