# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.history -- verifie l'enregistrement (record_run/
record_diff_run) et la lecture (list_history/print_history) de
l'historique SQLite inter-runs : schema cree a la volee, coherence du
score de sante avec triage.health_score, integration tls/quic sur un run
d'analyse simple mais PAS sur un diff (meme asymetrie assumee que
generate_json_report/generate_json_diff, voir docstring de module),
etiquette/filtre --history-label, et absence d'effet de bord (pas de
fichier cree) quand on interroge une base qui n'existe pas encore.
"""

import sqlite3

from netcross_core.baseline_diff import DiffFinding
from netcross_core.models import Report
from netcross_report.history import list_history, print_history, record_diff_run, record_run
from netcross_report.synthesis import Finding
from netcross_report.triage import health_label, health_score, rank_segments


def test_record_run_structure_de_base(tmp_path):
    r = Report(points=["A", "B"], pairs=[("A", "B")])
    r.loss_count["A"] = 10
    r.seen_count["A"] = 100  # 10% -> anomalie (Pertes)

    db = tmp_path / "history.db"
    row_id = record_run(r, db)
    assert row_id == 1

    entries = list_history(db)
    assert len(entries) == 1
    e = entries[0]
    assert e.id == 1
    assert e.run_type == "analyse"
    assert e.label is None
    assert e.points == ["A", "B"]
    assert e.recorded_at  # non vide
    assert e.total_findings >= 1
    assert e.finding_counts.get("anomalie", 0) >= 1
    assert e.meta == {}
    # coherence avec un calcul independant via triage (memes fonctions
    # que record_run() sous le capot, mais recalcule ici a partir de
    # build_findings pour verifier qu'aucun ecart ne s'est glisse).
    from netcross_report.synthesis import build_findings

    ranked = rank_segments(build_findings(r))
    score = health_score(ranked)
    assert e.health_score == score
    assert e.health_label == health_label(score)


def test_record_run_findings_precalcules_pas_recalcules(tmp_path):
    r = Report(points=["A"])
    r.loss_count["A"] = 50
    r.seen_count["A"] = 100  # aurait declenche un finding "Pertes" si recalcule
    db = tmp_path / "history.db"
    record_run(r, db, findings=[])
    e = list_history(db)[0]
    assert e.total_findings == 0
    assert e.finding_counts == {}
    assert e.health_score == 100
    assert e.health_label == "bon"


def test_record_run_integre_tls_quic_au_score(tmp_path):
    r = Report(points=["A", "B"])
    tls_findings = [Finding("anomalie", "TLS", "A -> B", "handshake qui echoue")]
    quic_findings = [Finding("info", "QUIC", "A", "vu a tous les points")]
    db = tmp_path / "history.db"
    record_run(r, db, findings=[], tls_findings=tls_findings, quic_findings=quic_findings)
    e = list_history(db)[0]
    assert e.total_findings == 2
    assert e.finding_counts == {"anomalie": 1, "info": 1}
    # une anomalie TLS pese sur le score, contrairement a un run sans elle
    assert e.health_score < 100


def test_record_run_meta_et_label_reportes(tmp_path):
    r = Report(points=["A"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[], meta={"Ticket": "INC-1234"}, label="Site-A")
    e = list_history(db)[0]
    assert e.meta == {"Ticket": "INC-1234"}
    assert e.label == "Site-A"


def test_record_diff_run_structure_de_base(tmp_path):
    baseline = Report(points=["LAN", "WAN"])
    current = Report(points=["LAN", "WAN"])
    findings = [DiffFinding("regression", "Pertes", "WAN", "pertes en hausse", before=0.0, after=10.0)]
    db = tmp_path / "history.db"
    record_diff_run(findings, baseline, current, db, label="Site-B")

    e = list_history(db)[0]
    assert e.run_type == "diff"
    assert e.label == "Site-B"
    assert e.points == {"baseline": ["LAN", "WAN"], "current": ["LAN", "WAN"]}
    assert e.total_findings == 1
    assert e.finding_counts == {"regression": 1}
    ranked = rank_segments(findings)
    score = health_score(ranked)
    assert e.health_score == score


def test_record_diff_run_naccepte_pas_tls_quic():
    # Choix de conception assume (voir docstring de module) : contrairement
    # a record_run(), pas de parametres tls_findings_*/quic_findings_* --
    # verifie ici que la signature ne les accepte pas silencieusement.
    import inspect

    params = inspect.signature(record_diff_run).parameters
    assert "tls_findings_baseline" not in params
    assert "quic_findings_baseline" not in params


def test_list_history_base_absente_renvoie_liste_vide_sans_creer_le_fichier(tmp_path):
    db = tmp_path / "jamais_cree.db"
    assert list_history(db) == []
    assert not db.exists()


def test_list_history_ordre_plus_recent_dabord_et_limit(tmp_path):
    r = Report(points=["A"])
    db = tmp_path / "history.db"
    for _ in range(3):
        record_run(r, db, findings=[])

    entries = list_history(db)
    assert [e.id for e in entries] == [3, 2, 1]

    limited = list_history(db, limit=2)
    assert [e.id for e in limited] == [3, 2]


def test_list_history_filtre_par_label(tmp_path):
    r = Report(points=["A"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[], label="Site-A")
    record_run(r, db, findings=[], label="Site-B")
    record_run(r, db, findings=[], label="Site-A")

    site_a = list_history(db, label="Site-A")
    assert len(site_a) == 2
    assert all(e.label == "Site-A" for e in site_a)


def test_list_history_filtre_par_run_type(tmp_path):
    r = Report(points=["A"])
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[])
    record_diff_run([], baseline, current, db)
    record_run(r, db, findings=[])

    analyses = list_history(db, run_type="analyse")
    assert len(analyses) == 2
    assert all(e.run_type == "analyse" for e in analyses)

    diffs = list_history(db, run_type="diff")
    assert len(diffs) == 1
    assert diffs[0].run_type == "diff"


def test_list_history_filtre_label_et_run_type_combines(tmp_path):
    r = Report(points=["A"])
    baseline = Report(points=["A"])
    current = Report(points=["A"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[], label="Site-A")
    record_diff_run([], baseline, current, db, label="Site-A")
    record_run(r, db, findings=[], label="Site-B")

    entries = list_history(db, label="Site-A", run_type="analyse")
    assert len(entries) == 1
    assert entries[0].label == "Site-A"
    assert entries[0].run_type == "analyse"


def test_record_run_reutilise_la_meme_base_sqlite_valide(tmp_path):
    # Verifie que le fichier produit est bien une base SQLite exploitable
    # par un outil tiers (pas seulement par list_history) -- lecture brute
    # via sqlite3, sans passer par le module.
    r = Report(points=["A"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[])
    record_run(r, db, findings=[])

    conn = sqlite3.connect(db)
    try:
        (count,) = conn.execute("SELECT COUNT(*) FROM runs").fetchone()
    finally:
        conn.close()
    assert count == 2


def test_print_history_ne_leve_pas_sur_liste_vide(capsys):
    print_history([])
    out = capsys.readouterr().out
    assert "Aucun run" in out


def test_print_history_affiche_label_points_et_score(tmp_path, capsys):
    r = Report(points=["A", "B"])
    db = tmp_path / "history.db"
    record_run(r, db, findings=[], label="Site-A")
    print_history(list_history(db))
    out = capsys.readouterr().out
    assert "Site-A" in out
    assert "A,B" in out
    assert "100/100" in out


def test_print_history_diff_affiche_baseline_et_courant(tmp_path, capsys):
    baseline = Report(points=["LAN"])
    current = Report(points=["LAN"])
    db = tmp_path / "history.db"
    record_diff_run([], baseline, current, db)
    print_history(list_history(db))
    out = capsys.readouterr().out
    assert "baseline=LAN" in out
    assert "courant=LAN" in out
