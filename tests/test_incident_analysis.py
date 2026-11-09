# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_incident_analysis.py — analyse multi-points de la fenêtre gelée
et notification enrichie (issue #1091, chantier #1001).

Tests du module netcross_core.incident_analysis : analyse des segments
archivés (issue #1090) avec le socle standard (correlate + analyse +
apply_security_findings), rapport JSON rangé avec les segments (et HTML
si générateur injecté), notification avec résumé et chemin de l'archive.

Le test d'intégration couvre le critère d'acceptation : « alarme simulée
⇒ rapport archivé et notification émise » — du gel (GelManager) à la
notification, en passant par l'archivage signé. Le décodage (tshark) est
injecté : ces tests ne dépendent d'aucun binaire Wireshark.
"""

import json
import os
from pathlib import Path

import pytest
from test_live_diff import _pkt
from test_retro_capture import _alarme, _FauxTampon

from netcross_core.incident_analysis import (
    SCHEMA_RAPPORT,
    RapportIncident,
    analyser_incident,
)
from netcross_core.retro_capture import (
    GelConfig,
    GelManager,
    PointDeGel,
    archiver_incident,
)


def _archive(tmp_path, points=("LAN", "WAN")):
    """Alarme simulée -> gel -> archive signée. Renvoie le manifeste et
    le répertoire de l'archive (réutilise le faux tampon de #1087/#1090 :
    un tampon par point, comme en production)."""
    points_gel = {}
    for point in points:
        tampon = _FauxTampon(tmp_path, prefix=point)
        tampon.ajouter(
            "capture_00001_20260101115900.pcapng",
            950.0,
            990.0,
            contenu=f"paquets {point}".encode(),
        )
        points_gel[point] = PointDeGel(inventory=tampon.inventaire)
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), points_gel)
    rapport = gel.on_alarm(_alarme(timestamp=1000.0))
    assert rapport is not None

    def faux_decoupeur(source, destination, debut, fin):
        with open(source, "rb") as src, open(destination, "wb") as fic:
            fic.write(src.read())

    manifeste = archiver_incident(rapport, decoupeur=faux_decoupeur)
    dossier = os.path.dirname(manifeste.fichiers[0].segment)
    while os.path.basename(dossier) != "incident":
        dossier = os.path.dirname(dossier)
        assert dossier != "/", "segment hors archive d'incident"
    return manifeste, dossier


def _faux_parseur(point, chemin):
    """Décodeur injecté : renvoie des paquets plausibles par point, dont
    un certificat TLS « pas encore valide » qui lève un constat réel."""
    if point == "LAN":
        return [
            _pkt(point="LAN", ts=1000.0, src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=443, proto="TLS"),
            _pkt(
                point="LAN",
                ts=1000.5,
                src="10.0.0.2",
                dst="10.0.0.1",
                sport=443,
                dport=50000,
                proto="TLS",
                tls_server_hello=True,
                tls_cert_serial="10:01",
                tls_cert_not_before="2020-01-01 00:00:00 (UTC)",
                tls_cert_not_after="2020-06-01 00:00:00 (UTC)",
                tls_cert_san=("www.example.com",),
                tls_cert_issuer="CN=Lab Intermediate CA,O=Lab",
                tls_cert_subject="CN=www.example.com,O=Lab",
                tls_cert_sig_hash="sha256",
                tls_cert_key_type="RSA",
                tls_cert_key_bits=2048,
                tls_cert_chain_len=2,
            ),
        ]
    return [
        _pkt(point="WAN", ts=1000.2, src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=80, proto="TCP"),
        _pkt(point="WAN", ts=1000.7, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=50000, proto="TCP"),
    ]


def test_analyse_incident_rapport_et_notification(tmp_path):
    """Critère d'acceptation de l'issue #1091 : alarme simulée ⇒ rapport
    archivé (JSON + HTML rangés avec les segments) et notification émise
    (résumé + chemin de l'archive). Analyse multi-points réelle (correlate
    + analyse + apply_security_findings) et score/level réels."""
    from netcross_report.security_report import build_security_report

    manifeste, dossier = _archive(tmp_path)

    def evaluateur(rapport):
        dash = build_security_report(rapport).dashboard
        return dash.score, dash.level

    def generateur_html(rapport, dossier_cible):
        chemin = os.path.join(dossier_cible, "rapport.html")
        with open(chemin, "w", encoding="utf-8") as fic:
            fic.write("<html><body>rapport incident</body></html>")
        return chemin

    resumes = []

    def notificateur(resume):
        resumes.append(resume)
        return [{"canal": "webhook", "statut": "livre"}]

    resultat = analyser_incident(
        manifeste,
        parseur=_faux_parseur,
        evaluateur=evaluateur,
        generateur_html=generateur_html,
        seuil_notification="faible",
        notificateur=notificateur,
    )

    # Rapport JSON rangé AVEC les segments, schéma versionné.
    assert isinstance(resultat, RapportIncident)
    assert resultat.dossier == dossier
    assert resultat.chemin_rapport == os.path.join(dossier, "rapport.json")
    assert os.path.isfile(resultat.chemin_rapport)
    charge = json.loads(Path(resultat.chemin_rapport).read_text(encoding="utf-8"))
    assert charge["schema"] == SCHEMA_RAPPORT
    assert charge["incident"] == manifeste.incident
    assert charge["alarme"]["rule_id"] == "loss_per_segment"
    assert {p["point"] for p in charge["points"]} == {"LAN", "WAN"}
    for p in charge["points"]:
        assert p["segments"], "chaque point porte ses segments de preuve"
        for s in p["segments"]:
            assert os.path.isfile(s["segment"])
    assert charge["constats"], "le constat TLS doit figurer dans le rapport"
    assert charge["score"] == resultat.score and charge["level"] == resultat.level
    assert resultat.score > 0

    # HTML rangé avec eux.
    assert resultat.chemin_html == os.path.join(dossier, "rapport.html")
    assert os.path.isfile(resultat.chemin_html)

    # Notification émise : résumé (constats au-dessus du seuil) et chemin
    # de l'archive.
    assert len(resumes) == 1
    resume = resumes[0]
    assert resume.report_path == dossier
    assert resume.total >= 1
    assert resume.by_severity["moyenne"] >= 1
    assert resume.top, "le résumé porte les constats principaux"
    assert resume.top[0]["category"] == "anomalie"
    assert resultat.notifications == ({"canal": "webhook", "statut": "livre"},)

    # Le rapport est rechargeable et cohérent avec le manifeste.
    assert set(resultat.points) == {"LAN", "WAN"}


def test_analyse_incident_sans_evaluateur_ni_html(tmp_path):
    """Défauts honnêtes : sans évaluateur (netcross_report non injecté),
    score 0 / level None ; sans générateur HTML, pas de rapport.html —
    le JSON reste complet et la notification part quand même."""
    manifeste, dossier = _archive(tmp_path, points=("LAN",))
    resumes = []

    resultat = analyser_incident(
        manifeste,
        parseur=_faux_parseur,
        seuil_notification="faible",
        notificateur=resumes.append,
    )

    assert resultat.score == 0
    assert resultat.level is None
    assert resultat.chemin_html is None
    assert not os.path.exists(os.path.join(dossier, "rapport.html"))
    charge = json.loads(Path(resultat.chemin_rapport).read_text(encoding="utf-8"))
    assert charge["score"] == 0 and charge["level"] is None
    assert charge["constats"]
    assert len(resumes) == 1


def test_analyse_incident_refuse_manifeste_vide():
    """Cas défensif : un manifeste sans fichier n'a rien à analyser."""
    from netcross_core.retro_capture import ManifesteIncident

    manifeste = ManifesteIncident(incident="gel-1", alarme={}, fenetre=(0.0, 1.0), fichiers=())
    with pytest.raises(ValueError, match="sans fichier"):
        analyser_incident(manifeste, parseur=_faux_parseur)


def test_analyse_incident_refuse_archive_alteree(tmp_path):
    """Chaîne de preuve : une archive dont un segment ne correspond plus
    à son empreinte n'est PAS analysée (le rapport doit reposer sur des
    preuves intègres)."""
    manifeste, _dossier = _archive(tmp_path, points=("LAN",))
    with open(manifeste.fichiers[0].segment, "wb") as fic:
        fic.write(b"truque")
    with pytest.raises(ValueError, match="non conformes"):
        analyser_incident(manifeste, parseur=_faux_parseur)


def test_analyse_incident_refuse_aucun_paquet(tmp_path):
    """Cas défensif : des segments indécodables (parseur muet) font
    échouer l'analyse explicitement plutôt que produire un rapport vide."""
    manifeste, _ = _archive(tmp_path, points=("LAN",))
    with pytest.raises(ValueError, match="aucun paquet"):
        analyser_incident(manifeste, parseur=lambda point, chemin: [])


def test_analyse_incident_dossier_derive_des_segments(tmp_path):
    """Sans dossier_incident explicite, le rapport est rangé à côté du
    manifeste : parent du répertoire du premier segment."""
    manifeste, dossier = _archive(tmp_path, points=("LAN",))
    assert dossier.endswith("incident")
    resultat = analyser_incident(
        manifeste, parseur=_faux_parseur, seuil_notification="faible", notificateur=lambda r: []
    )
    assert os.path.dirname(resultat.chemin_rapport) == dossier
    assert os.path.isfile(os.path.join(dossier, "manifeste.json"))


def test_analyse_incident_scanner_appele_par_segment(tmp_path):
    """Le scanner d'exploits (CVE-2, injectable) est appelé une fois par
    segment avec le label du point — câblage vérifié, le traitement des
    détections vivant dans apply_security_findings."""
    manifeste, _ = _archive(tmp_path, points=("LAN", "WAN"))
    appels = []

    def scanner(point, chemin):
        appels.append((point, chemin))
        return []

    analyser_incident(
        manifeste,
        parseur=_faux_parseur,
        scanner=scanner,
        seuil_notification="faible",
        notificateur=lambda r: [],
    )
    assert len(appels) == len(manifeste.fichiers)
    for point, chemin in appels:
        assert any(f.point == point and f.segment == chemin for f in manifeste.fichiers)


def test_notificateur_defaut_passe_le_resume_a_run_notifications(tmp_path, monkeypatch):
    """Sans notificateur injecté, le résumé part dans run_notifications
    avec le seuil explicite et la configuration donnée."""
    import netcross_core.incident_analysis as module

    manifeste, _ = _archive(tmp_path, points=("LAN",))
    appels = {}

    def faux_run_notifications(summary_factory, *, threshold, cfg, **kwargs):
        appels["factory"] = summary_factory
        appels["threshold"] = threshold
        appels["cfg"] = cfg
        return [{"canal": "webhook", "statut": "livre"}]

    monkeypatch.setattr(module, "run_notifications", faux_run_notifications)

    resultat = analyser_incident(
        manifeste,
        parseur=_faux_parseur,
        seuil_notification="moyenne",
        cfg_notification=module.NotifyConfig(webhook="https://exemple.fr/hook"),
    )
    assert appels["threshold"] == "moyenne"
    assert appels["cfg"].webhook == "https://exemple.fr/hook"
    resume = appels["factory"]("moyenne")
    assert resume.threshold == "moyenne"
    assert resume.report_path  # chemin de l'archive dans la notification
    assert resultat.notifications == ({"canal": "webhook", "statut": "livre"},)
