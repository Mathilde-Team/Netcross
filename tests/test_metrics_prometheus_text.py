# SPDX-License-Identifier: GPL-3.0-or-later
"""Exposition texte Prometheus / OpenMetrics et fichier .prom (issue #1112).

La validation passe par les parseurs de reference de ``prometheus_client``
(dependance de test) a la place de ``promtool check metrics``.
"""

from __future__ import annotations

import math
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from prometheus_client.openmetrics.parser import text_string_to_metric_families as parse_openmetrics
from prometheus_client.parser import text_string_to_metric_families as parse_prometheus

from netcross_core.models import Report
from netcross_core.redact import AddressRedactor
from netcross_report import metrics_export as me
from netcross_report.metrics_export import (
    METRICS,
    Sample,
    collect_samples,
    redact_samples,
    render_openmetrics,
    render_prometheus_text,
    write_prom_file,
)

RACINE = Path(__file__).resolve().parent.parent
CLI = RACINE / "src" / "cross_capture_analyzer_cli.py"
EXEMPLES = RACINE / "docs" / "guide" / "exemples"
DOC = RACINE / "docs" / "metriques-prometheus.md"
# la CLI lit les captures avec tshark (absent du job Couverture de la CI)
requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")


def _report(points=("CLIENT", "ROUTEUR", "SERVEUR")):
    r = Report(points=list(points), pairs=list(zip(points, points[1:], strict=False)))
    for i, p in enumerate(points):
        r.packet_count[p] = 1000 - 10 * i
        r.seen_count[p] = 100 - i
        r.retrans[p] = i
    r.loss_count[points[-1]] = 9
    r.latency[(points[0], points[1])] = [10.0, 20.0, 30.0, 40.0]
    return r


def _samples(points=("CLIENT", "ROUTEUR", "SERVEUR"), run="r1"):
    return collect_samples(_report(points), run, findings=[])


# -- format Prometheus 0.0.4 -------------------------------------------------------------


def test_texte_prometheus_valide_par_le_parseur_de_reference():
    samples = _samples()
    texte = render_prometheus_text(samples)
    familles = {f.name: f for f in parse_prometheus(texte)}
    # le parseur Prometheus retire _total du nom de famille d'un compteur
    attendus = {m.name.removesuffix("_total") if m.type == me.COUNTER else m.name for m in METRICS}
    assert set(familles) <= attendus
    assert familles["netcross_point_packets"].type == "counter"
    assert familles["netcross_segment_delay_seconds"].type == "summary"
    assert familles["netcross_health_score"].type == "gauge"
    lues = sum(len(f.samples) for f in familles.values())
    assert lues == len(samples)
    paquets = {s.labels["point"]: s.value for s in familles["netcross_point_packets"].samples}
    assert paquets == {"CLIENT": 1000, "ROUTEUR": 990, "SERVEUR": 980}


def test_texte_prometheus_help_et_type_par_famille():
    texte = render_prometheus_text(_samples())
    lignes = texte.splitlines()
    assert texte.endswith("\n")
    for spec in METRICS:
        types = [li for li in lignes if li.startswith(f"# TYPE {spec.name} ")]
        assert types == [f"# TYPE {spec.name} {spec.type}"], spec.name
        assert sum(li.startswith(f"# HELP {spec.name} ") for li in lignes) == 1
    # chaque famille est contigue : aucune serie d'une famille apres le TYPE suivant
    vus = [li.split()[2] for li in lignes if li.startswith("# TYPE ")]
    assert len(vus) == len(set(vus))


def test_commentaire_en_tete_sur_une_ligne():
    texte = render_prometheus_text(_samples(), comment="adresses\nanonymisees")
    assert texte.splitlines()[0] == "# adresses anonymisees"
    list(parse_prometheus(texte))


def test_echappement_des_etiquettes_et_de_l_aide():
    s = Sample("netcross_point_packets_total", (("run", 'a"b\\c\nd'), ("point", "P")), 3.0)
    texte = render_prometheus_text([s])
    assert 'run="a\\"b\\\\c\\nd"' in texte
    (famille,) = parse_prometheus(texte)
    assert famille.samples[0].labels["run"] == 'a"b\\c\nd'
    assert me._escape_help("a\\b\nc") == "a\\\\b\\nc"


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [(3.0, "3"), (0.25, "0.25"), (float("nan"), "NaN"), (math.inf, "+Inf"), (-math.inf, "-Inf"), (1e20, "1e+20")],
)
def test_format_des_valeurs(valeur, attendu):
    assert me._format_value(valeur) == attendu


def test_serie_sans_etiquette():
    assert me._sample_line(Sample("netcross_health_score", (), 7.0)) == "netcross_health_score 7"


def test_delai_nan_lisible():
    s = Sample("netcross_segment_delay_seconds", (("run", "r"), ("segment", "A -> B"), ("quantile", "0.5")), math.nan)
    (famille,) = parse_prometheus(render_prometheus_text([s]))
    assert math.isnan(famille.samples[0].value)


def test_serie_hors_catalogue_refusee():
    with pytest.raises(ValueError, match="hors catalogue"):
        render_prometheus_text([Sample("netcross_invente", (), 1.0)])
    with pytest.raises(ValueError, match="hors catalogue"):
        render_openmetrics([Sample("autre_metrique_count", (), 1.0)])


def test_family_count_et_sum():
    assert me._family("netcross_segment_delay_seconds_count").name == "netcross_segment_delay_seconds"
    assert me._family("netcross_segment_delay_seconds_sum").name == "netcross_segment_delay_seconds"
    assert me._family("netcross_health_score").name == "netcross_health_score"
    assert me._family("rien_du_tout") is None


# -- OpenMetrics ---------------------------------------------------------------------------


def test_openmetrics_valide_par_le_parseur_de_reference():
    samples = _samples()
    texte = render_openmetrics(samples)
    assert texte.endswith("# EOF\n")
    familles = {f.name: f for f in parse_openmetrics(texte)}
    assert familles["netcross_point_packets"].type == "counter"
    assert familles["netcross_point_packets"].unit == "packets"
    assert familles["netcross_segment_delay_seconds"].unit == "seconds"
    assert familles["netcross_segment_loss_ratio"].unit == "ratio"
    assert familles["netcross_health_score"].unit == ""
    # compteurs : famille sans _total, series en _total
    noms = {s.name for s in familles["netcross_findings"].samples}
    assert noms == {"netcross_findings_total"}
    assert sum(len(f.samples) for f in familles.values()) == len(samples)


def test_openmetrics_pas_d_unit_sans_suffixe():
    texte = render_openmetrics(_samples())
    assert "# UNIT netcross_health_score" not in texte
    assert "# UNIT netcross_segment_triage_score" not in texte
    assert "# UNIT netcross_point_lost_flows flows" in texte


def test_openmetrics_vide():
    assert render_openmetrics([]) == "# EOF\n"
    list(parse_openmetrics(render_openmetrics([])))


# -- fichier .prom atomique -----------------------------------------------------------------


def test_ecriture_atomique(tmp_path):
    cible = tmp_path / "netcross.prom"
    cible.write_text("ancien\n", encoding="utf-8")
    texte = render_prometheus_text(_samples())
    assert write_prom_file(texte, cible) == str(cible)
    assert cible.read_text(encoding="utf-8") == texte
    assert sorted(p.name for p in tmp_path.iterdir()) == ["netcross.prom"]
    assert oct(cible.stat().st_mode & 0o777) == oct(0o644)


def test_ecriture_echouee_supprime_le_temporaire(tmp_path, monkeypatch):
    def refus(src, dst):
        raise OSError("disque plein")

    monkeypatch.setattr(me.os, "replace", refus)
    with pytest.raises(OSError, match="disque plein"):
        write_prom_file("x 1\n", tmp_path / "netcross.prom")
    assert list(tmp_path.iterdir()) == []


def test_ecriture_dossier_absent(tmp_path):
    with pytest.raises(OSError):
        write_prom_file("x 1\n", tmp_path / "absent" / "netcross.prom")


# -- --redact ---------------------------------------------------------------------------------


def test_redact_remplace_les_adresses_des_etiquettes():
    points = ("192.168.1.10", "aa:bb:cc:dd:ee:ff", "fd12:3456::5")
    samples = _samples(points, run="run-10.0.0.5")
    redactor = AddressRedactor()
    anonymes = redact_samples(samples, redactor)
    texte = render_prometheus_text(anonymes)
    for adresse in (*points, "10.0.0.5"):
        assert adresse not in texte
    # meme pseudonyme que dans les paquets et la table --redact-map
    assert redactor.pseudonymize_address("192.168.1.10") in texte
    assert len(redactor) == 4
    list(parse_prometheus(texte))
    list(parse_openmetrics(render_openmetrics(anonymes)))


def test_redact_laisse_les_noms_ordinaires():
    samples = _samples()
    anonymes = redact_samples(samples, AddressRedactor())
    assert [(s.name, s.labels, repr(s.value)) for s in anonymes] == [(s.name, s.labels, repr(s.value)) for s in samples]


def test_pseudonymize_address_valeur_ordinaire():
    redactor = AddressRedactor()
    assert redactor.pseudonymize_address("ROUTEUR") == "ROUTEUR"
    assert redactor.pseudonymize_address("1.2.3.4") == redactor.pseudonymize_address("1.2.3.4")
    assert len(redactor) == 1


# -- CLI ---------------------------------------------------------------------------------------


def _cli(*args):
    env = dict(os.environ, PYTHONPATH=str(RACINE / "src"))
    return subprocess.run(
        [sys.executable, str(CLI), *args], capture_output=True, text=True, env=env, timeout=300, check=False
    )


def _captures():
    return ["--capture", f"LAN={EXEMPLES / 'lan.pcap'}", "--capture", f"WAN={EXEMPLES / 'wan.pcap'}"]


@requires_tshark
def test_cli_prom_et_openmetrics(tmp_path):
    prom = tmp_path / "netcross.prom"
    om = tmp_path / "netcross.om"
    res = _cli(*_captures(), "--prom-file", str(prom), "--openmetrics-file", str(om), "--metrics-run", "essai")
    assert res.returncode == 0, res.stderr
    assert "Metriques Prometheus" in res.stdout
    familles = {f.name: f for f in parse_prometheus(prom.read_text(encoding="utf-8"))}
    points = {s.labels["point"] for s in familles["netcross_point_packets"].samples}
    assert points == {"LAN", "WAN"}
    assert {s.labels["run"] for f in familles.values() for s in f.samples} == {"essai"}
    assert om.read_text(encoding="utf-8").endswith("# EOF\n")
    list(parse_openmetrics(om.read_text(encoding="utf-8")))


@requires_tshark
def test_cli_redact(tmp_path):
    prom = tmp_path / "netcross.prom"
    res = _cli(*_captures(), "--redact", "--prom-file", str(prom), "--metrics-run", "192.168.0.1")
    assert res.returncode == 0, res.stderr
    texte = prom.read_text(encoding="utf-8")
    assert texte.startswith("# adresses IP/MAC et noms DNS/HTTP/TLS/SIP anonymises (--redact)\n")
    assert "192.168.0.1" not in texte
    list(parse_prometheus(texte))


def test_write_metrics_files_sans_redact(tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(RACINE / "src"))
    import cross_capture_analyzer_cli as cli

    class Args:
        metrics_run = "r"
        prom_file = str(tmp_path / "a.prom")
        openmetrics_file = None

    cli._write_metrics_files(Args, _report(), [], None)
    texte = Path(Args.prom_file).read_text(encoding="utf-8")
    assert not texte.startswith("#  ")
    assert "anonymisees" not in texte
    assert "Metriques Prometheus" in capsys.readouterr().out


def test_documentation_textfile_collector():
    doc = DOC.read_text(encoding="utf-8")
    for mot in ("--prom-file", "--openmetrics-file", "--metrics-run", "textfile", "promtool", "--redact"):
        assert mot in doc, mot
