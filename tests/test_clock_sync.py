# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de l'estimation robuste du decalage et de la derive d'horloge
(issue #996) : estimateur isole (clock_sync.py) et integration dans
analyse() (correction par paquet, sources TCP et DNS, option
--clock-offset).

Aucune dependance externe : les jeux synthetiques utilisent le meme
generateur que la validation manuelle (files d'attente episodiques,
bruit d'horodatage), et les paquets sont construits par la fabrique
partagee ``conftest.make_pkt``.
"""

from __future__ import annotations

import random

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.clock_sync import (
    EchantillonHorloge,
    EstimationHorloge,
    analyser_decalages_manuels,
    estimation_manuelle,
    estimer_decalage,
)
from netcross_core.correlate import correlate


def _jeu_syntheque(n=60, duree=3600.0, decalage_ms=37.0, derive_ppm=15.0, seed=42):
    """Echanges synthetiques : decalage + derive injectes, files episodiques.

    Chaque echange est un aller-retour complet observe des deux cotes
    (t1..t4) : chemin de base 5 ms par sens, file d'attente episodique
    (25 % des sens, uniforme 1..30 ms) et bruit d'horodatage de
    +/- 0,3 ms (resolution microseconde d'une carte d'acquisition).
    """
    random.seed(seed)
    echantillons = []
    for i in range(n):
        t = i * duree / n
        vrai_decalage_ms = decalage_ms + derive_ppm * 1e-6 * t * 1000.0

        def file_attente():
            return random.uniform(1, 30) if random.random() < 0.25 else 0.0

        q1, q2 = file_attente(), file_attente()

        def bruit():
            return random.uniform(-0.0003, 0.0003)

        t1 = t + bruit()
        t2 = t1 + (5 + q1) / 1000 + vrai_decalage_ms / 1000 + bruit()
        t3 = t2 + 0.002 + bruit()
        t4 = t3 + (5 + q2) / 1000 - vrai_decalage_ms / 1000 + bruit()
        decalage_obs = ((t2 - t1) - (t4 - t3)) / 2 * 1000.0
        delai_obs = (t4 - t1) - (t3 - t2)
        echantillons.append(EchantillonHorloge(t=t, decalage_ms=decalage_obs, delai_ms=delai_obs * 1000.0))
    return echantillons


# ---------------------------------------------------------------------------
# Estimateur isole (clock_sync.estimer_decalage)
# ---------------------------------------------------------------------------


def test_critere_d_acceptation_37ms_15ppm():
    """Jeu avec +37 ms et +15 ppm injectes : erreur < 1 ms et < 2 ppm."""
    estimation = estimer_decalage(_jeu_syntheque())
    assert estimation is not None
    assert abs(estimation.decalage_ms - 37.0) < 1.0
    assert abs(estimation.derive_ppm - 15.0) < 2.0
    assert estimation.n_echantillons == 60
    # Le filtre au delai minimal a bien ecarte les echanges files.
    assert estimation.n_conserves <= 8
    assert "Theil-Sen" in estimation.methode


def test_le_filtre_ecarte_les_echanges_files():
    """Les files d'attente biaisent la formule NTP : le filtre les ecarte.

    Un echange biaisé (file d'attente dans UN sens seulement) pousse le
    decalage observe loin de la verite ; l'estimateur doit rester dans
    le vrai a +/- 1 ms.
    """
    echantillons = []
    for i in range(40):
        t = i * 30.0
        vrai = 10.0
        # La moitie des echanges subissent une file asymetrique de 40 ms.
        q = 0.040 if i % 2 == 0 else 0.0
        t1 = t
        t2 = t1 + 0.005 + q + vrai / 1000
        t3 = t2 + 0.001
        t4 = t3 + 0.005 - vrai / 1000
        decalage = ((t2 - t1) - (t4 - t3)) / 2 * 1000.0
        delai = (t4 - t1) - (t3 - t2)
        echantillons.append(EchantillonHorloge(t=t, decalage_ms=decalage, delai_ms=delai * 1000.0))
    estimation = estimer_decalage(echantillons)
    # Une moyenne naive serait biaisee d'environ 10 ms (20 ms / 2).
    assert abs(estimation.decalage_ms - 10.0) < 1.0


def test_estimation_sans_echantillon():
    """Aucun echantillon : pas d'estimation, pas d'exception."""
    assert estimer_decalage([]) is None


def test_estimation_echantillon_unique():
    """Un seul echange : decalage tel quel, derive nulle, methode annoncée."""
    estimation = estimer_decalage([EchantillonHorloge(t=5.0, decalage_ms=12.5, delai_ms=10.0)])
    assert estimation.decalage_ms == 12.5
    assert estimation.derive_ppm == 0.0
    assert estimation.n_conserves == 1


def test_estimation_instants_identiques():
    """Tous les echanges au meme instant : derive nulle, l'echantillon
    au delai minimal seul conserve (fenetre unique)."""
    echantillons = [
        EchantillonHorloge(t=1.0, decalage_ms=8.0, delai_ms=10.0),
        EchantillonHorloge(t=1.0, decalage_ms=12.0, delai_ms=11.0),
        EchantillonHorloge(t=1.0, decalage_ms=10.0, delai_ms=12.0),
    ]
    estimation = estimer_decalage(echantillons)
    assert estimation.derive_ppm == 0.0
    assert estimation.n_conserves == 1
    assert estimation.decalage_ms == pytest.approx(8.0)


def test_decalage_a_extrapole_la_derive():
    """decalage_a() : decalage a t0 PLUS derive x duree ecoulee."""
    estimation = EstimationHorloge(decalage_ms=37.0, t0=0.0, derive_ppm=15.0)
    # 15 ppm pendant 1000 s : 15 us/s x 1000 = 15 ms.
    assert estimation.decalage_a(1000.0) == pytest.approx(37.0 + 15.0)


def test_estimation_manuelle():
    """Valeur imposee : derive et intervalles nuls, methode annoncee."""
    estimation = estimation_manuelle(12.5)
    assert estimation.manuel is True
    assert estimation.decalage_ms == 12.5
    assert estimation.derive_ppm == 0.0
    assert estimation.ic_decalage_ms == 0.0
    assert "imposée" in estimation.methode
    assert estimation.decalage_a(9999.0) == 12.5


def test_analyser_decalages_manuels():
    """Analyse des --clock-offset : unites ms/us/s, erreurs claires."""
    decalages = analyser_decalages_manuels(["LAN:WAN=+12.5ms", "WAN:DC=-3s", "A:B=100us", "C:D=+0.25"])
    assert decalages == {
        ("LAN", "WAN"): 12.5,
        ("WAN", "DC"): -3000.0,
        ("A", "B"): 0.1,
        ("C", "D"): 0.25,
    }
    with pytest.raises(ValueError, match="invalide"):
        analyser_decalages_manuels(["LAN=WAN+12.5ms"])
    # Unite inconnue (min) : la specification ne matche pas le motif,
    # l'erreur nomme le format attendu.
    with pytest.raises(ValueError, match="invalide"):
        analyser_decalages_manuels(["LAN:WAN=+1min"])


# ---------------------------------------------------------------------------
# Integration dans analyse()
# ---------------------------------------------------------------------------


def _analyse(pkts, points_order=("A", "B"), **kwargs):
    """Analyse d'un petit jeu de paquets (memes conventions que les autres tests)."""
    flows = correlate(pkts)
    return analyse(flows, points_order=list(points_order), all_packets=pkts, **kwargs)


def _handshake(pkts, t1, ts_a, ts_b, ts_ba, ts_a2, seq=1000):
    """Ajoute un aller-retour SYN/SYN-ACK vu aux deux points."""
    base = {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 5000, "dport": 443}
    pkts.append(make_pkt(point="A", flags="S", seq=seq, ts=ts_a, **base))
    pkts.append(make_pkt(point="B", flags="S", seq=seq, ts=ts_b, **base))
    pkts.append(
        make_pkt(
            point="B",
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=443,
            dport=5000,
            flags="SA",
            seq=2000,
            ack=seq + 1,
            ts=ts_ba,
        )
    )
    pkts.append(
        make_pkt(
            point="A",
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=443,
            dport=5000,
            flags="SA",
            seq=2000,
            ack=seq + 1,
            ts=ts_a2,
        )
    )


def test_analyse_estime_et_corrige_la_latence():
    """Un handshake + un paquet : la latence corrigee vaut le delai reel.

    Horloge de B avance de 37 ms : sans correction, la latence A->B
    mesurerait ~37 ms ; corrigee au temps du paquet, elle retombe sur
    le delai reel de 5 ms.
    """
    pkts = []
    # Handshake a t=1 : B avance de 37 ms, chemin 5 ms par sens.
    # t1=1.0 (SYN en A), t2=1.042 (SYN en B), t3=1.047 (SYN-ACK en B),
    # t4=1.015 (SYN-ACK en A) : aller 42 ms, retour -32 ms -> decalage 37 ms, RTT 10 ms.
    _handshake(pkts, 1, 1.0, 1.042, 1.047, 1.015)
    # Paquet de donnees a t=10, delai reel 5 ms.
    pkts.append(make_pkt(point="A", src="10.0.0.3", dst="10.0.0.4", sport=6000, dport=80, ts=10.0))
    pkts.append(make_pkt(point="B", src="10.0.0.3", dst="10.0.0.4", sport=6000, dport=80, ts=10.042))
    r = _analyse(pkts)
    estimation = r.clock_offset_estimate.get(("A", "B"))
    assert estimation is not None
    assert abs(estimation.decalage_ms - 37.0) < 1.0
    # Latence corrigee : 42 ms observes - 37 ms de decalage = 5 ms reels.
    assert abs(r.latency[("A", "B")][0] - 5.0) < 1.0


def test_analyse_echantillons_dns_sans_handshake():
    """Trafic DNS pur : l'estimation vit aussi des couples requete/reponse.

    Sans aucun handshake TCP, un couple requete/reponse DNS vu aux deux
    points fournit l'aller-retour complet (t1..t4) et suffit a estimer le
    decalage.
    """
    pkts = []
    for i, t in enumerate(range(0, 3600, 60)):
        vrai_ms = 20.0 + 10e-6 * t * 1000.0
        pkts.append(
            make_pkt(
                point="A",
                proto="UDP",
                src="10.0.0.1",
                dst="10.0.0.9",
                sport=5300,
                dport=53,
                ts=float(t),
                dns_txn_id=1000 + i,
                dns_is_response=False,
                dns_qry_name="exemple.fr",
            )
        )
        pkts.append(
            make_pkt(
                point="B",
                proto="UDP",
                src="10.0.0.1",
                dst="10.0.0.9",
                sport=5300,
                dport=53,
                ts=float(t) + 0.005 + vrai_ms / 1000,
                dns_txn_id=1000 + i,
                dns_is_response=False,
            )
        )
        pkts.append(
            make_pkt(
                point="B",
                proto="UDP",
                src="10.0.0.9",
                dst="10.0.0.1",
                sport=53,
                dport=5300,
                ts=float(t) + 0.006 + vrai_ms / 1000,
                dns_txn_id=1000 + i,
                dns_is_response=True,
                dns_qry_name="exemple.fr",
            )
        )
        pkts.append(
            make_pkt(
                point="A",
                proto="UDP",
                src="10.0.0.9",
                dst="10.0.0.1",
                sport=53,
                dport=5300,
                ts=float(t) + 0.011,
                dns_txn_id=1000 + i,
                dns_is_response=True,
            )
        )
    r = _analyse(pkts)
    estimation = r.clock_offset_estimate.get(("A", "B"))
    assert estimation is not None
    assert abs(estimation.decalage_ms - 20.0) < 1.0
    assert abs(estimation.derive_ppm - 10.0) < 2.0


def test_analyse_clock_offset_impose_desactive_l_estimation():
    """--clock-offset A:B=+12.5ms : estimation remplacee, annoncée dans le rapport."""
    pkts = []
    _handshake(pkts, 1, 1.0, 1.042, 1.047, 1.015)
    pkts.append(make_pkt(point="A", src="10.0.0.3", dst="10.0.0.4", sport=6000, dport=80, ts=10.0))
    pkts.append(make_pkt(point="B", src="10.0.0.3", dst="10.0.0.4", sport=6000, dport=80, ts=10.042))
    r = _analyse(pkts, clock_offsets=["A:B=+12.5ms"])
    estimation = r.clock_offset_estimate[("A", "B")]
    assert estimation.manuel is True
    assert estimation.decalage_ms == 12.5
    # La latence est corrigee de la valeur imposee : 42 - 12,5 = 29,5 ms.
    assert abs(r.latency[("A", "B")][0] - 29.5) < 1e-6


def test_analyse_clock_offset_dict():
    """clock_offsets accepte aussi le dict deja analyse (API programmatique)."""
    pkts = []
    _handshake(pkts, 1, 1.0, 1.042, 1.047, 1.015)
    r = _analyse(pkts, clock_offsets={("A", "B"): -8.0})
    assert r.clock_offset_estimate[("A", "B")].decalage_ms == -8.0


def test_analyse_specification_invalide_relevee():
    """Une specification --clock-offset invalide leve une erreur claire."""
    pkts = [make_pkt(point="A", ts=1.0), make_pkt(point="B", ts=1.001)]
    with pytest.raises(ValueError, match="invalide"):
        _analyse(pkts, clock_offsets=["A:B=12.5 parsecs"])


def test_analyse_nat_tolerant_garde_les_echantillons_dns():
    """En mode --nat-tolerant, le couplage SYN est omis : DNS reste exploitable."""
    pkts = [
        make_pkt(
            point="A",
            proto="UDP",
            sport=5300,
            dport=53,
            ts=0.0,
            dns_txn_id=7,
            dns_is_response=False,
        ),
        make_pkt(
            point="B",
            proto="UDP",
            sport=5300,
            dport=53,
            ts=0.025,
            dns_txn_id=7,
            dns_is_response=False,
        ),
        make_pkt(
            point="B",
            proto="UDP",
            sport=53,
            dport=5300,
            src="10.0.0.2",
            dst="10.0.0.1",
            ts=0.026,
            dns_txn_id=7,
            dns_is_response=True,
        ),
        make_pkt(
            point="A",
            proto="UDP",
            sport=53,
            dport=5300,
            src="10.0.0.2",
            dst="10.0.0.1",
            ts=0.001,
            dns_txn_id=7,
            dns_is_response=True,
        ),
    ]
    r = _analyse(pkts, nat_tolerant=True)
    estimation = r.clock_offset_estimate.get(("A", "B"))
    assert estimation is not None
    # decalage = ((t2-t1)-(t4-t3))/2 = ((25ms) - (-25ms))/2 = 25 ms
    assert estimation.decalage_ms == pytest.approx(25.0)


# ---------------------------------------------------------------------------
# Branches defensives : listes vides, instants identiques, unite inconnue
# ---------------------------------------------------------------------------


def test_mediane_vide_renvoie_zero():
    """Une liste vide de valeurs a une mediane neutre (0.0)."""
    from netcross_core.clock_sync import _mediane

    assert _mediane([]) == 0.0
    assert _mediane([5.0, 1.0, 3.0]) == 3.0


def test_filtre_delais_minimaux_liste_vide():
    """Une liste vide d'echantillons reste vide apres filtrage."""
    from netcross_core.clock_sync import _filtre_delais_minimaux

    assert _filtre_delais_minimaux([]) == []


def test_theil_sen_instants_identiques():
    """Deux echantillons au meme instant : pas de derive, mediane des decalages."""
    from netcross_core.clock_sync import _theil_sen, _theil_sen_ic

    echantillons = [
        EchantillonHorloge(t=100.0, decalage_ms=30.0, delai_ms=8.0),
        EchantillonHorloge(t=100.0, decalage_ms=34.0, delai_ms=2.0),
    ]
    decalage, derive = _theil_sen(echantillons, t0=100.0)
    assert decalage == pytest.approx(32.0)
    assert derive == 0.0

    _ic_decalage, ic_derive = _theil_sen_ic(echantillons)
    assert ic_derive == 0.0


def test_vers_ms_unite_inconnue_requete():
    """Une unite inconnue (ex. « ns ») est refusee avec un message clair."""
    from netcross_core.clock_sync import _vers_ms

    with pytest.raises(ValueError, match="unité inconnue"):
        _vers_ms("5", "ns")
