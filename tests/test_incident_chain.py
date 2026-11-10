# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_incident_chain.py — orchestration production de la chaîne
d'incident (issue #1001 : enregistrement rétroactif déclenché par alarme).

Test d'intégration du parcours réel demandé par l'audit de l'issue :
réglages + tampon multi-points → alarme (moteur live) → gel → attente
EFFECTIVE de la fenêtre après alarme → découpe/manifeste → analyse
multi-points → notification — sans jamais bloquer le moteur live.

Les briques externes (editcap, tshark, notification) restent injectées :
ces tests ne dépendent d'aucun binaire Wireshark ni canal configuré.
"""

import json
import os

from test_incident_analysis import _faux_parseur
from test_live_diff import _pkt, _stub_analyse_et_correlate
from test_retro_capture import _alarme, _FauxTampon

from netcross_core.alarms import AlarmConfig, AlarmEngine
from netcross_core.baseline_diff import DiffFinding
from netcross_core.incident_chain import ChaineIncidents, chaine_incidents_depuis_reglages
from netcross_core.live_diff import LiveDiffConfig, LiveDiffEngine
from netcross_core.models import Report
from netcross_core.retro_capture import GelConfig, GelManager, PointDeGel

# -- helpers ------------------------------------------------------------------


def _faux_finding(severite: str = "anomalie") -> DiffFinding:
    return DiffFinding(
        severity=severite,
        category="loss_per_segment",
        segment="LAN -> WAN",
        message="Perte 8% (baseline 0%)",
        before=0.0,
        after=8.0,
        sample_size=200,
        evidence=[],
    )


def _points_de_gel(tmp_path, points=("LAN", "WAN"), bornes=(950.0, 990.0)):
    """Deux tampons (un par point, comme en production) couvrant les
    bornes données — l'inventaire est relu à chaque gel (rotation
    simulable). ``bornes`` peut être un tuple (une fenêtre) ou une liste
    de tuples (plusieurs fichiers du tampon)."""
    fenetres = [bornes] if isinstance(bornes[0], (int, float)) else list(bornes)
    points_gel = {}
    for point in points:
        tampon = _FauxTampon(tmp_path, prefix=point)
        for numero, (debut, fin) in enumerate(fenetres, start=1):
            tampon.ajouter(
                f"capture_{numero:05d}_20260101115900.pcapng",
                debut,
                fin,
                contenu=f"paquets {point}".encode(),
            )
        points_gel[point] = PointDeGel(inventory=tampon.inventaire)
    return points_gel


def _faux_decoupeur(source, destination, debut, fin):
    """Découpeur injecté : recopie la source (le faux editcap de #1090)."""
    with open(source, "rb") as src, open(destination, "wb") as fic:
        fic.write(src.read())


def _chaine(tmp_path, points_gel, **kwargs):
    """ChaineIncidents prête à l'emploi : découpeur et parseur injectés,
    attente enregistrée (jamais de vrai sleep), notificateur espion."""
    attentes: list[float] = []
    resumes: list[object] = []
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), points_gel)
    chaine = ChaineIncidents(
        gel,
        decoupeur=_faux_decoupeur,
        parseur=_faux_parseur,
        notificateur=resumes.append,
        attendre=attentes.append,
        marge_attente=0.0,
        **kwargs,
    )
    return chaine, attentes, resumes


# -- parcours complet : alarme -> gel -> attente -> archivage -> analyse -> notification


def test_parcours_complet_alarme_vers_rapport_et_notification(tmp_path, monkeypatch):
    """Le parcours réel de l'issue #1001 : une alarme levée par le moteur
    live déclenche la chaîne complète en arrière-plan — le moteur n'est
    pas bloqué, la fenêtre « après » est attendue AVANT la découpe, et
    l'analyste reçoit archive + rapport + notification."""
    monkeypatch.setattr("netcross_core.live_diff.diff_reports", lambda base, current: [_faux_finding()])
    _stub_analyse_et_correlate(monkeypatch)

    chaine, attentes, resumes = _chaine(tmp_path, _points_de_gel(tmp_path))
    alarm_engine = AlarmEngine(
        [AlarmConfig(rule_id="loss_per_segment", segment="LAN -> WAN", min_persistence_seconds=0.0)]
    )
    engine = LiveDiffEngine(
        baseline_report=Report(points=["LAN", "WAN"]),
        config=LiveDiffConfig(min_packets_for_diff=1),
        alarm_engine=alarm_engine,
        gel=chaine,
    )

    # Le moteur live lève l'alarme au fil de l'eau — la chaîne est
    # déclenchée par le MÊME appel qu'un GelManager nu (paramètre gel=).
    engine._add_packet(_pkt(ts=1000.0))
    findings = engine._evaluate_diff()
    assert findings == [_faux_finding()]
    assert len(alarm_engine.active_alarms) == 1

    # La chaîne a planifié le traitement : le moteur n'attend PAS la fin
    # de la fenêtre (il est déjà revenu ci-dessus).
    assert chaine.attendre_termine()

    # ... et le parcours complet a été mené : attente effective de la
    # partie « après » de la fenêtre (t_alarme=1000, après=30, marge 0),
    # archivage signé, analyse multi-points, notification.
    assert attentes == [30.0]
    assert len(chaine.rapports) == 1
    resultat = chaine.rapports[0]
    dossier = resultat.dossier
    assert os.path.basename(dossier) == "incident"
    assert os.path.exists(resultat.chemin_rapport)
    with open(resultat.chemin_rapport, encoding="utf-8") as fic:
        charge = json.load(fic)
    assert charge["alarme"]["rule_id"] == "loss_per_segment"
    assert charge["points"], "l'analyse doit couvrir les deux points du gel"
    manifeste = os.path.join(dossier, "manifeste.json")
    assert os.path.exists(manifeste)
    # Notification émise (résumé + chemin de l'archive, cf. #1091).
    assert len(resumes) == 1


def test_alarme_ignoree_par_le_gel_ne_declenche_rien(tmp_path):
    """Sévérité sous le seuil : le gel (et la chaîne) ignore l'alarme —
    aucun thread, aucune attente, aucun rapport."""
    chaine, attentes, resumes = _chaine(tmp_path, _points_de_gel(tmp_path))
    rapport = chaine.on_alarm(_alarme(timestamp=1000.0, severity="info"))
    assert rapport is None
    assert chaine.attendre_termine()
    assert attentes == []
    assert resumes == []
    assert chaine.rapports == []


def test_gel_hors_tampon_signale_sans_archiver(tmp_path):
    """Fenêtre ne couvrant aucun fichier du tampon : le gel est déclenché
    (rapport non nul) mais la chaîne n'archive ni n'analyse rien —
    l'incident est signalé dans le journal, pas muet ni en échec."""
    # Tampon très loin de la fenêtre [940, 1030].
    chaine, attentes, resumes = _chaine(tmp_path, _points_de_gel(tmp_path, bornes=(10.0, 50.0)))
    rapport = chaine.on_alarm(_alarme(timestamp=1000.0))
    assert rapport is not None
    assert not any(rapport.files.values())
    assert chaine.attendre_termine()
    assert attentes == []
    assert resumes == []
    assert chaine.rapports == []


def test_echec_d_archivage_ne_casse_pas_la_chaine(tmp_path):
    """Un décideur qui échoue (editcap absent, disque plein...) est
    journalisé : le thread d'incident meurt proprement, aucun rapport,
    et la chaîne reste utilisable pour l'incident suivant."""

    def decoupeur_brisé(source, destination, debut, fin):
        raise OSError("disque plein (test)")

    points_gel = _points_de_gel(tmp_path, bornes=[(950.0, 990.0), (1950.0, 2020.0)])
    gel = GelManager(GelConfig(min_delay_between_gels=0.0), str(tmp_path / "archives"), points_gel)
    attentes: list[float] = []
    chaine = ChaineIncidents(
        gel,
        decoupeur=decoupeur_brisé,
        parseur=_faux_parseur,
        notificateur=lambda resume: [],
        attendre=attentes.append,
        marge_attente=0.0,
    )
    assert chaine.on_alarm(_alarme(timestamp=1000.0)) is not None
    assert chaine.attendre_termine()
    assert chaine.rapports == []
    # Incident suivant : la chaîne réessaie et aboutit.
    chaine2_decoupeur = _faux_decoupeur
    chaine._decoupeur = chaine2_decoupeur  # réparé
    assert chaine.on_alarm(_alarme(timestamp=2000.0)) is not None
    assert chaine.attendre_termine()
    assert len(chaine.rapports) == 1


def test_attente_de_repli_sans_ts_courant(tmp_path):
    """Appel manuel sans ts_courant : l'attente se calcule depuis
    l'horodatage de l'alarme (t + après), pas depuis l'horloge murale."""
    chaine, attentes, _ = _chaine(tmp_path, _points_de_gel(tmp_path, bornes=(950.0, 1020.0)))
    rapport = chaine.on_alarm(_alarme(timestamp=1000.0), ts_courant=None)
    assert rapport is not None
    assert chaine.attendre_termine()
    # end = 1000 + 30, référence = horodatage_alarme = 1000, marge 0.
    assert attentes == [30.0]


def test_chaine_depuis_reglages_raccorde_les_reglages(tmp_path):
    """L'appel de production : les réglages partagés (gel_settings)
    construisent le GelManager de la chaîne — sévérité minimale, fenêtre
    et répertoire d'archives lus depuis les réglages, pas codés."""
    reglages = {
        "seconds_before": 5.0,
        "seconds_after": 10.0,
        "min_severity": "a_surveiller",
        "archives_dir": str(tmp_path / "archives-reglages"),
    }
    points_gel = _points_de_gel(tmp_path, bornes=(950.0, 1020.0))
    attentes: list[float] = []
    chaine = chaine_incidents_depuis_reglages(
        reglages,
        points_gel,
        decoupeur=_faux_decoupeur,
        parseur=_faux_parseur,
        notificateur=lambda resume: [],
        attendre=attentes.append,
        marge_attente=0.0,
    )
    # Sévérité « à surveiller » suffisante (réglage), et l'archive atterrit
    # dans le répertoire des réglages.
    rapport = chaine.on_alarm(_alarme(timestamp=1000.0, severity="a_surveiller"), ts_courant=1000.0)
    assert rapport is not None
    assert rapport.dossier.startswith(str(tmp_path / "archives-reglages"))
    # Fenêtre des réglages : 5 s avant / 10 s après -> attente = 10.
    assert chaine.attendre_termine()
    assert attentes == [10.0]
    assert len(chaine.rapports) == 1


def test_moteur_avec_gel_nu_comportement_inchange(tmp_path, monkeypatch):
    """Contrôle de non-régression : un GelManager nu reste admis au
    paramètre gel= (gel seul, sans chaîne), comme avant #1001."""
    monkeypatch.setattr("netcross_core.live_diff.diff_reports", lambda base, current: [_faux_finding()])
    _stub_analyse_et_correlate(monkeypatch)

    gels = []
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), _points_de_gel(tmp_path))
    gel.on_alarm = lambda event: gels.append(event) or None  # espion

    alarm_engine = AlarmEngine(
        [AlarmConfig(rule_id="loss_per_segment", segment="LAN -> WAN", min_persistence_seconds=0.0)]
    )
    engine = LiveDiffEngine(
        baseline_report=Report(points=["LAN", "WAN"]),
        config=LiveDiffConfig(min_packets_for_diff=1),
        alarm_engine=alarm_engine,
        gel=gel,
    )
    engine._add_packet(_pkt(ts=1000.0))
    assert engine._evaluate_diff()
    assert len(gels) == 1
