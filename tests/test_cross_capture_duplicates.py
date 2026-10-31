# SPDX-License-Identifier: GPL-3.0-or-later
"""
Job 41/issue #161 -- detection de doublons inter-captures (multi-point) :
netcross_core.forensic.detect_cross_capture_duplicates(), Pkt.is_duplicate,
exclusion optionnelle dans correlate()/analyse(), Report.duplicate_count.

Tous les Pkt sont synthetiques (conftest.make_pkt) -- aucun test ne depend
de tshark.
"""

import json
import sys

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.forensic import DEFAULT_DUPLICATE_THRESHOLD_MS, detect_cross_capture_duplicates
from netcross_core.models import Pkt, Report
from netcross_core.report_text import print_report
from netcross_report.json_report import generate_json_report


def _common_packets(n=10, delta_s=0.0002, point_a="A", point_b="B", base_ts=100.0):
    """n paquets vus aux DEUX points : meme flux, meme payload_hash, le
    point_b les voit `delta_s` secondes apres le point_a. Un flux (sport)
    et un hash distincts par paquet, comme un vrai trafic."""
    pkts = []
    for i in range(n):
        common = {"sport": 1000 + i, "key_id": i, "payload_hash": f"hash{i}", "length": 200}
        ts = base_ts + i * 0.01
        pkts.append(make_pkt(point=point_a, ts=ts, **common))
        pkts.append(make_pkt(point=point_b, ts=ts + delta_s, **common))
    return pkts


# -- Modele ----------------------------------------------------------------


def test_pkt_is_duplicate_faux_par_defaut():
    assert make_pkt().is_duplicate is False


def test_pkt_is_duplicate_reste_optionnel_pour_l_api_historique():
    # make_pkt() ne le passe jamais : le champ doit avoir une valeur par
    # defaut, sinon tous les constructeurs existants (parsing, netflow...)
    # casseraient.
    assert Pkt.__dataclass_fields__["is_duplicate"].default is False


def test_report_duplicate_count_vide_par_defaut():
    r = Report()
    assert not r.duplicate_count
    assert r.duplicates_excluded is False


# -- detect_cross_capture_duplicates ------------------------------------------


def test_deux_captures_dix_paquets_communs_sont_detectes():
    pkts = _common_packets(10)

    counts = detect_cross_capture_duplicates(pkts)

    assert counts == {("A", "B"): 10}
    # l'original (le plus ancien, point A) n'est jamais marque, la copie
    # vue plus tard au point B l'est.
    assert [pk.is_duplicate for pk in pkts if pk.point == "A"] == [False] * 10
    assert [pk.is_duplicate for pk in pkts if pk.point == "B"] == [True] * 10


def test_au_dela_du_seuil_ce_n_est_pas_un_doublon():
    # 5 ms entre les deux points : c'est le trafic normal d'un segment,
    # pas un port miroir -- seuil par defaut 1 ms.
    pkts = _common_packets(10, delta_s=0.005)

    assert detect_cross_capture_duplicates(pkts) == {}
    assert not any(pk.is_duplicate for pk in pkts)


def test_seuil_configurable():
    pkts = _common_packets(10, delta_s=0.005)

    counts = detect_cross_capture_duplicates(pkts, threshold_ms=10.0)

    assert counts == {("A", "B"): 10}


def test_seuil_par_defaut_expose():
    assert DEFAULT_DUPLICATE_THRESHOLD_MS == 1.0


def test_delta_egal_au_seuil_n_est_pas_un_doublon():
    # critere STRICTEMENT inferieur (issue #161 : « delta < seuil »).
    a = make_pkt(point="A", ts=1.0, payload_hash="h")
    b = make_pkt(point="B", ts=1.5, payload_hash="h")

    assert detect_cross_capture_duplicates([a, b], threshold_ms=500.0) == {}
    assert not b.is_duplicate


def test_payload_hash_different_n_est_pas_un_doublon():
    a = make_pkt(point="A", ts=1.0, payload_hash="h1")
    b = make_pkt(point="B", ts=1.0001, payload_hash="h2")

    assert detect_cross_capture_duplicates([a, b]) == {}


def test_paquets_sans_payload_hash_ignores():
    # ACK/SYN purs : aucun contenu, rien ne dit que c'est le meme paquet.
    a = make_pkt(point="A", ts=1.0, payload_hash=None)
    b = make_pkt(point="B", ts=1.0001, payload_hash=None)

    assert detect_cross_capture_duplicates([a, b]) == {}
    assert not a.is_duplicate
    assert not b.is_duplicate


def test_meme_point_n_est_jamais_un_doublon_inter_captures():
    # deux paquets identiques rapproches au MEME point = retransmission
    # (autre detecteur), pas un doublon inter-captures.
    a1 = make_pkt(point="A", ts=1.0, payload_hash="h")
    a2 = make_pkt(point="A", ts=1.0001, payload_hash="h")

    assert detect_cross_capture_duplicates([a1, a2]) == {}
    assert not a2.is_duplicate


def test_paire_de_points_non_ordonnee():
    # B voit le paquet AVANT A (ordre d'arrivee variable d'un port miroir) :
    # la paire reste ("A", "B"), pas ("B", "A"). C'est le PLUS TARDIF qui
    # est marque doublon.
    b = make_pkt(point="B", ts=1.0000, payload_hash="h")
    a = make_pkt(point="A", ts=1.0002, payload_hash="h")

    counts = detect_cross_capture_duplicates([a, b])

    assert counts == {("A", "B"): 1}
    assert a.is_duplicate is True
    assert b.is_duplicate is False


def test_trois_points_dans_la_fenetre_comptes_par_paire():
    a = make_pkt(point="A", ts=1.0000, payload_hash="h")
    b = make_pkt(point="B", ts=1.0002, payload_hash="h")
    c = make_pkt(point="C", ts=1.0004, payload_hash="h")

    counts = detect_cross_capture_duplicates([a, b, c])

    assert counts == {("A", "B"): 1, ("A", "C"): 1}
    assert (a.is_duplicate, b.is_duplicate, c.is_duplicate) == (False, True, True)


def test_pas_de_derive_en_chaine_un_doublon_n_est_pas_un_original():
    # A -> B a 0,9 ms (doublon de A) -> C a 0,9 ms de B mais 1,8 ms de A :
    # C n'est compare qu'aux originaux (A), hors fenetre -> pas un doublon.
    a = make_pkt(point="A", ts=1.0000, payload_hash="h")
    b = make_pkt(point="B", ts=1.0009, payload_hash="h")
    c = make_pkt(point="C", ts=1.0018, payload_hash="h")

    counts = detect_cross_capture_duplicates([a, b, c])

    assert counts == {("A", "B"): 1}
    assert c.is_duplicate is False


def test_ordre_de_la_liste_sans_importance():
    pkts = _common_packets(10)
    reversed_pkts = list(reversed(_common_packets(10)))

    assert detect_cross_capture_duplicates(pkts) == detect_cross_capture_duplicates(reversed_pkts)


def test_egalite_stricte_de_ts_departagee_par_l_ordre_de_la_liste():
    a = make_pkt(point="A", ts=1.0, payload_hash="h")
    b = make_pkt(point="B", ts=1.0, payload_hash="h")

    detect_cross_capture_duplicates([a, b])

    assert (a.is_duplicate, b.is_duplicate) == (False, True)


def test_reappel_reinitialise_les_marques_perimees():
    pkts = _common_packets(10, delta_s=0.005)
    assert detect_cross_capture_duplicates(pkts, threshold_ms=10.0) == {("A", "B"): 10}
    assert sum(pk.is_duplicate for pk in pkts) == 10

    # meme liste, seuil plus strict : plus aucune marque ne doit subsister
    assert detect_cross_capture_duplicates(pkts, threshold_ms=1.0) == {}
    assert not any(pk.is_duplicate for pk in pkts)


def test_seuil_zero_ne_detecte_rien():
    assert detect_cross_capture_duplicates(_common_packets(3), threshold_ms=0.0) == {}


def test_seuil_negatif_leve_value_error():
    with pytest.raises(ValueError, match="threshold_ms"):
        detect_cross_capture_duplicates(_common_packets(1), threshold_ms=-1.0)


def test_liste_vide():
    assert detect_cross_capture_duplicates([]) == {}


def test_payload_tres_repete_a_un_seul_point_reste_lineaire_et_sans_doublon():
    # keepalive identique 5000 fois au meme point : jamais de doublon, et la
    # fenetre glissante evite le O(n^2) (le test doit rester quasi instantane).
    pkts = [make_pkt(point="A", ts=i * 0.0001, payload_hash="keepalive") for i in range(5000)]

    assert detect_cross_capture_duplicates(pkts) == {}


# -- correlate(exclude_duplicates=...) ----------------------------------------


def test_correlate_par_defaut_garde_les_doublons():
    pkts = _common_packets(10)
    detect_cross_capture_duplicates(pkts)

    flows = correlate(pkts)

    assert len(flows) == 10
    assert all(set(per_point) == {"A", "B"} for per_point in flows.values())


def test_correlate_exclude_duplicates_retire_les_doublons():
    pkts = _common_packets(10)
    detect_cross_capture_duplicates(pkts)

    flows = correlate(pkts, exclude_duplicates=True)

    assert len(flows) == 10
    # le flux n'existe plus qu'au point A : la copie du point B est exclue
    assert all(set(per_point) == {"A"} for per_point in flows.values())
    assert sum(len(p) for per_point in flows.values() for p in per_point.values()) == 10


def test_correlate_exclude_duplicates_sans_detection_prealable_ne_change_rien():
    # aucun paquet marque -> exclude_duplicates est sans effet
    pkts = _common_packets(10)

    assert correlate(pkts, exclude_duplicates=True).keys() == correlate(pkts).keys()
    flows = correlate(pkts, exclude_duplicates=True)
    assert all(set(per_point) == {"A", "B"} for per_point in flows.values())


# -- analyse(exclude_duplicates=..., duplicate_counts=...) ---------------------


def _run_analyse(pkts, exclude, counts, points_order=None):
    flows = correlate(pkts, exclude_duplicates=exclude)
    return analyse(
        flows,
        points_order,
        pkts,
        exclude_duplicates=exclude,
        duplicate_counts=counts,
    )


def test_analyse_par_defaut_compte_les_doublons_et_les_rapporte():
    pkts = _common_packets(10)
    counts = detect_cross_capture_duplicates(pkts)

    r = _run_analyse(pkts, exclude=False, counts=counts, points_order=["A", "B"])

    assert r.duplicate_count[("A", "B")] == 10
    assert r.duplicates_excluded is False
    # les doublons sont toujours dans les statistiques : les 10 flux sont
    # comptes aux deux points, et 2 x 10 x 200 octets sont dans le debit
    assert r.seen_count["A"] == 10
    assert r.seen_count["B"] == 10
    assert sum(sum(b.values()) for b in r.throughput.values()) == 2 * 10 * 200


def test_analyse_exclude_duplicates_retire_les_doublons_du_comptage():
    pkts = _common_packets(10)
    counts = detect_cross_capture_duplicates(pkts)

    r = _run_analyse(pkts, exclude=True, counts=counts, points_order=["A", "B"])

    assert r.duplicate_count[("A", "B")] == 10  # toujours rapporte...
    assert r.duplicates_excluded is True
    assert r.seen_count["A"] == 10
    assert r.seen_count["B"] == 0  # ...mais plus compte
    # octets : seulement les 10 originaux du point A
    assert sum(r.throughput["A"].values()) == 10 * 200
    assert sum(r.throughput.get("B", {}).values()) == 0


def test_analyse_exclude_duplicates_ne_depend_pas_de_la_facon_dont_flows_a_ete_construit():
    # correlate() SANS exclusion, puis analyse(exclude_duplicates=True) : le
    # resultat doit etre le meme que si correlate() avait deja exclu.
    pkts = _common_packets(10)
    counts = detect_cross_capture_duplicates(pkts)

    flows_not_excluded = correlate(pkts)
    r = analyse(
        flows_not_excluded,
        ["A", "B"],
        pkts,
        exclude_duplicates=True,
        duplicate_counts=counts,
    )

    assert r.seen_count["A"] == 10
    assert r.seen_count["B"] == 0


def test_analyse_sans_options_reste_identique_a_l_existant():
    pkts = _common_packets(10)  # aucune detection : rien n'est marque

    r = analyse(correlate(pkts), ["A", "B"], pkts)

    assert not r.duplicate_count
    assert r.duplicates_excluded is False
    assert r.seen_count["A"] == r.seen_count["B"] == 10


# -- print_report ---------------------------------------------------------------


def test_print_report_signale_les_doublons_encore_comptes(capsys):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.duplicate_count[("A", "B")] = 10

    print_report(r)
    out = capsys.readouterr().out

    assert "Doublons inter-captures" in out
    assert "A <-> B : 10 paquet(s) duplique(s)" in out
    assert "ENCORE COMPTES" in out


def test_print_report_signale_les_doublons_exclus(capsys):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.duplicate_count[("A", "B")] = 10
    r.duplicates_excluded = True

    print_report(r)
    out = capsys.readouterr().out

    assert "A <-> B : 10 paquet(s) duplique(s)" in out
    assert "EXCLUS" in out
    assert "ENCORE COMPTES" not in out


def test_print_report_sans_doublon_sortie_inchangee(capsys):
    print_report(Report(points=["A", "B"], pairs=[("A", "B")]))

    assert "Doublons" not in capsys.readouterr().out


# -- rapport JSON -----------------------------------------------------------------


def test_json_report_expose_les_doublons_par_paire(tmp_path):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.duplicate_count[("A", "B")] = 10
    r.duplicates_excluded = True

    out = tmp_path / "report.json"
    generate_json_report(r, out)
    with open(out, encoding="utf-8") as fh:
        doc = json.load(fh)

    assert doc["duplicates"] == {"excluded": True, "by_pair": [{"points": ["A", "B"], "count": 10}]}


def test_json_report_sans_doublon_pas_de_cle(tmp_path):
    out = tmp_path / "report.json"
    generate_json_report(Report(points=["A"]), out)
    with open(out, encoding="utf-8") as fh:
        doc = json.load(fh)

    assert "duplicates" not in doc


# -- CLI ----------------------------------------------------------------------------


def test_cli_expose_les_trois_options(monkeypatch, capsys):
    import cross_capture_analyzer_cli

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        cross_capture_analyzer_cli.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--detect-duplicates" in out
    assert "--exclude-duplicates" in out
    assert "--duplicate-threshold-ms" in out
