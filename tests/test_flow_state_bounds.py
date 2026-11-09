# SPDX-License-Identifier: GPL-3.0-or-later
"""Les délais hétérogènes et l'historique ne doivent pas gonfler la RAM."""

import tracemalloc
from types import SimpleNamespace

import pytest
from conftest import make_pkt

from netcross_core import flow_state
from netcross_core.analysis import analyse
from netcross_core.correlate import correlate


def test_un_tcp_long_ne_bloque_pas_les_expirations_udp():
    table = flow_state.FlowTable(["A"], timeouts={"TCP": 3600.0, "UDP": 1.0})
    try:
        table.feed(make_pkt(point="A", ts=0.0, proto="TCP", sport=50000))
        table.feed(make_pkt(point="A", ts=1.0, proto="UDP", sport=10001))
        table.feed(make_pkt(point="A", ts=2.0, proto="UDP", sport=10002))
        assert table.expired == 1
        assert table.peak_active == 2
    finally:
        table.finish()
    assert not table.reopened
    assert all("réouverture" not in ligne for ligne in table.summary_lines())


@pytest.mark.parametrize("valeur", ["nan", "inf", "-inf"])
def test_delai_non_fini_refuse_par_le_parseur(valeur):
    with pytest.raises(ValueError):
        flow_state.parse_flow_timeouts(f"TCP={valeur}")


@pytest.mark.parametrize("valeur", [float("nan"), float("inf"), -1.0, 0.0])
def test_delai_invalide_refuse_par_la_table(valeur):
    with pytest.raises(ValueError):
        flow_state.FlowTable(["A"], timeouts={"TCP": valeur})


def test_historique_tcp_ne_croit_pas_en_ram_avec_les_flux_termines(monkeypatch):
    # Le cache de réouverture est volontairement minuscule pour mesurer
    # l'historique TCP, pas la montée initiale de ce cache déjà borné.
    monkeypatch.setattr(flow_state, "_SEEN_CAP", 16)
    monkeypatch.setattr(flow_state, "logger", SimpleNamespace(debug=lambda *_a, **_k: None))
    table = flow_state.FlowTable(["A", "B"], timeouts={"TCP": 1.0})

    def alimenter(debut, fin):
        for i in range(debut, fin):
            for point, delta in (("A", 0.0), ("B", 0.01)):
                table.feed(make_pkt(point=point, ts=i * 3.0 + delta, sport=10000 + i))

    tracemalloc.start()
    try:
        alimenter(0, 500)
        memoire_initiale = tracemalloc.get_traced_memory()[0]
        alimenter(500, 5000)
        croissance = tracemalloc.get_traced_memory()[0] - memoire_initiale
        assert table.peak_active == 1
        assert croissance < 512 * 1024, croissance
    finally:
        table.finish()
        tracemalloc.stop()


def test_un_flux_tres_actif_ne_fait_pas_grossir_l_index():
    table = flow_state.FlowTable(["A"], timeouts={"UDP": 3600.0})
    try:
        for i in range(10000):
            table.feed(make_pkt(point="A", ts=i / 10000, proto="UDP"))
        assert table.peak_active == 1
        assert len(table._expiry) <= 66
    finally:
        table.finish()
    assert table._expiry == []
    with pytest.raises(ValueError, match="terminée"):
        table.feed(make_pkt(point="A", ts=2.0))


def test_coupure_tardive_conservee_apres_eviction_du_cache_recent(monkeypatch):
    monkeypatch.setattr(flow_state, "_SEEN_CAP", 2)
    table = flow_state.FlowTable(["A", "B"], timeouts={"TCP": 1.0})
    for point, ts in (("A", 0.0), ("A", 0.1), ("B", 0.2)):
        table.feed(make_pkt(point=point, ts=ts, sport=41000))
    for i in range(10):
        table.feed(make_pkt(point="A", ts=10 + i * 3.0, sport=20000 + i))
    assert table._history is not None
    repertoire = table._history.path.parent
    table.feed(make_pkt(point="A", ts=1000.0, sport=41000))
    table.finish()
    assert table.nat_cutoffs[("A", "B")] == 1
    assert not repertoire.exists()


def test_echeances_identiques_ne_ferment_pas_deux_fois():
    table = flow_state.FlowTable(["A", "B"], timeouts={"TCP": 1.0})
    table.feed(make_pkt(point="A", ts=0.0))
    table.feed(make_pkt(point="B", ts=0.0))
    table.feed(make_pkt(point="A", ts=2.0, proto="UDP"))
    assert table.expired == 1
    table.finish()
    assert table.total_records == 2


@pytest.mark.parametrize("delai", [1.0, 60.0, 3600.0])
@pytest.mark.parametrize(
    ("amont", "aval"),
    [
        ([0, 1, 201, 202, 302], [0.01, 1.01, 250]),
        ([0, 1, 101], [0.01, 1.01, 401]),
        ([0, 1, 101, 102, 202], [0.01, 1.01, 150]),
        ([0, 1, 101, 102, 302], [0.01, 1.01, 150]),
        ([0, 1, 101], [150]),
    ],
)
def test_constats_identiques_avec_plusieurs_silences(amont, aval, delai):
    facteur = delai / 60.0
    paquets = [make_pkt(point=point, ts=t * facteur) for point, temps in (("A", amont), ("B", aval)) for t in temps]
    reference = analyse(correlate(paquets), ["A", "B"], paquets, idle_timeout_seconds=delai)
    table = flow_state.run_flow_table(
        [sorted((p for p in paquets if p.point == point), key=lambda p: p.ts) for point in ("A", "B")],
        ["A", "B"],
        timeouts={"TCP": delai},
    )
    assert table.nat_cutoffs[("A", "B")] == reference.idle_timeout_dropped[("A", "B")]


def test_un_seul_paquet_avant_le_silence_puis_reprise():
    paquets = [
        make_pkt(point="A", ts=0.0),
        make_pkt(point="B", ts=0.01),
        make_pkt(point="A", ts=100.0),
    ]
    table = flow_state.run_flow_table([paquets], ["A", "B"], timeouts={"TCP": 60.0})
    assert table.nat_cutoffs[("A", "B")] == 1


def test_dix_coupures_comptent_dix_avec_cinq_exemples_seulement():
    table = flow_state.FlowTable(["A", "B"], timeouts={"TCP": 1.0})
    for i in range(10):
        for point, delta in (("A", 0.0), ("A", 0.1), ("B", 0.2), ("A", 100.0)):
            table.feed(make_pkt(point=point, ts=i * 1000.0 + delta, sport=20000 + i))
    table.finish()
    assert table.nat_cutoffs[("A", "B")] == 10
    assert len(table.cutoff_examples[("A", "B")]) == 5
