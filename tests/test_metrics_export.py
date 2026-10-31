"""Catalogue des metriques Prometheus et cardinalite bornee (issue #1110)."""

from __future__ import annotations

import ipaddress
import math
import re
from pathlib import Path

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.models import Report
from netcross_report import metrics_export as me
from netcross_report.metrics_export import (
    ALLOWED_LABELS,
    COUNTER,
    DELAY_QUANTILES,
    METRICS,
    METRICS_BY_NAME,
    OVERFLOW_LABEL,
    SEVERITIES,
    SUMMARY,
    Sample,
    collect_samples,
    segment_label,
    series_upper_bound,
)
from netcross_report.synthesis import Finding

DOC = Path(__file__).resolve().parent.parent / "docs" / "metriques-prometheus.md"
NOM = re.compile(r"^netcross_[a-z][a-z0-9_]*[a-z0-9]$")


def _report(points=("CLIENT", "ROUTEUR", "SERVEUR")):
    r = Report(points=list(points), pairs=list(zip(points, points[1:], strict=False)))
    for i, p in enumerate(points):
        r.packet_count[p] = 1000 - 10 * i
        r.seen_count[p] = 100 - i
        r.retrans[p] = i
    r.loss_count[points[-1]] = 9
    r.latency[(points[0], points[1])] = [10.0, 20.0, 30.0, 40.0]
    return r


def _by(samples, name, **labels):
    return [s for s in samples if s.name == name and all(s.label(k) == v for k, v in labels.items())]


# -- conventions du catalogue ----------------------------------------------------------


def test_noms_conformes_aux_conventions():
    attendus = {
        "netcross_segment_loss_ratio",
        "netcross_segment_delay_seconds",
        "netcross_point_packets_total",
        "netcross_health_score",
        "netcross_findings_total",
    }
    assert attendus <= set(METRICS_BY_NAME)
    assert len(METRICS_BY_NAME) == len(METRICS)
    for m in METRICS:
        assert NOM.fullmatch(m.name), m.name
        assert m.type in (COUNTER, me.GAUGE, SUMMARY)
        assert m.name.endswith("_total") == (m.type == COUNTER), m.name
        if m.unit in ("seconds", "ratio"):
            assert m.name.endswith(f"_{m.unit}"), m.name
        assert "_ms" not in m.name
        assert m.help and m.help.endswith(".")
        assert m.labels[0] == "run"
        assert set(m.labels) <= ALLOWED_LABELS
        assert ("quantile" in m.labels) == (m.type == SUMMARY)


def test_aucune_etiquette_de_flux_autorisee():
    assert not ALLOWED_LABELS & {"ip", "src", "dst", "host", "address", "port", "flow", "sni"}


# -- production des series ---------------------------------------------------------------


def test_series_sur_un_rapport_simple():
    s = collect_samples(_report(), "inc-42", findings=[Finding("anomalie", "Pertes", "SERVEUR", "m")])
    assert _by(s, "netcross_point_packets_total", point="ROUTEUR")[0].value == 990
    assert _by(s, "netcross_point_flows_total", point="CLIENT")[0].value == 100
    assert _by(s, "netcross_point_lost_flows_total", point="SERVEUR")[0].value == 9
    assert _by(s, "netcross_point_retransmissions_total", point="SERVEUR")[0].value == 2
    assert [x.value for x in _by(s, "netcross_findings_total")] == [1, 0, 0]
    assert [x.label("severity") for x in _by(s, "netcross_findings_total")] == list(SEVERITIES)
    assert 0 <= _by(s, "netcross_health_score")[0].value <= 100
    assert all(x.label("run") == "inc-42" for x in s)


def test_ratio_de_perte_par_segment():
    s = collect_samples(_report(), "r", findings=[])
    assert _by(s, "netcross_segment_loss_ratio", segment="CLIENT -> ROUTEUR")[0].value == 0
    assert _by(s, "netcross_segment_loss_ratio", segment="ROUTEUR -> SERVEUR")[0].value == pytest.approx(9 / 99)


def test_ratio_borne_et_base_nulle():
    r = _report()
    r.seen_count["ROUTEUR"] = 0
    r.loss_count["SERVEUR"] = 5
    assert _by(collect_samples(r, "r", findings=[]), "netcross_segment_loss_ratio", segment="ROUTEUR -> SERVEUR")[
        0
    ].value == (0.0)
    r.seen_count["ROUTEUR"] = 2
    assert _by(collect_samples(r, "r", findings=[]), "netcross_segment_loss_ratio", segment="ROUTEUR -> SERVEUR")[
        0
    ].value == (1.0)


def test_delai_en_secondes_quantiles_count_sum():
    s = collect_samples(_report(), "r", findings=[])
    q = {x.label("quantile"): x.value for x in _by(s, "netcross_segment_delay_seconds", segment="CLIENT -> ROUTEUR")}
    assert list(q) == list(DELAY_QUANTILES)
    assert q["0.5"] == pytest.approx(0.025)
    assert q["0.95"] == pytest.approx(0.0385)
    assert q["0.99"] == pytest.approx(0.0397)
    assert _by(s, "netcross_segment_delay_seconds_count", segment="CLIENT -> ROUTEUR")[0].value == 4
    assert _by(s, "netcross_segment_delay_seconds_sum", segment="CLIENT -> ROUTEUR")[0].value == pytest.approx(0.1)
    vide = _by(s, "netcross_segment_delay_seconds", segment="ROUTEUR -> SERVEUR")
    assert all(math.isnan(x.value) for x in vide)  # aucun echantillon : NaN (convention Prometheus)
    assert _by(s, "netcross_segment_delay_seconds_count", segment="ROUTEUR -> SERVEUR")[0].value == 0


def test_quantile_un_seul_echantillon():
    assert me._quantile([0.5], 0.99) == 0.5


def test_score_de_triage_par_segment():
    f = [Finding("anomalie", "Saturation", "ROUTEUR -> SERVEUR", "m"), Finding("info", "DNS", "global", "m")]
    s = collect_samples(_report(), "r", findings=f)
    assert _by(s, "netcross_segment_triage_score", segment="ROUTEUR -> SERVEUR")[0].value > 0
    assert _by(s, "netcross_segment_triage_score", segment="CLIENT -> ROUTEUR")[0].value == 0


def test_constats_calcules_par_defaut(monkeypatch):
    import netcross_report.synthesis as synthesis

    monkeypatch.setattr(synthesis, "build_findings", lambda r: [Finding("info", "x", "y", "z")])
    assert [x.value for x in _by(collect_samples(_report(), "r"), "netcross_findings_total")] == [0, 0, 1]


def test_rapport_sans_packet_count_tolere():
    r = _report()
    del r.packet_count
    assert all(x.value == 0 for x in _by(collect_samples(r, "r", findings=[]), "netcross_point_packets_total"))


def test_sortie_deterministe_et_noms_du_catalogue():
    a = collect_samples(_report(), "r", findings=[])
    b = collect_samples(_report(), "r", findings=[])
    assert [(x.name, x.labels) for x in a] == [(x.name, x.labels) for x in b]
    assert [repr(x.value) for x in a] == [repr(x.value) for x in b]  # NaN != NaN
    for x in a:
        base = re.sub(r"_(count|sum)$", "", x.name) if x.name.startswith("netcross_segment_delay") else x.name
        spec = METRICS_BY_NAME[base]
        attendues = set(spec.labels) - ({"quantile"} if x.name != base else set())
        assert {k for k, _ in x.labels} == attendues, x


def test_sample_label_absente():
    assert Sample("n", (("run", "r"),), 1.0).label("point") is None


def test_segment_label():
    assert segment_label("A", "B") == "A -> B"


# -- cardinalite ---------------------------------------------------------------------------


def _gros_jeu(n_flux: int):
    """n_flux flux UDP distincts (n_flux / 10 couples d'hotes) vus a 3 points."""
    flows: dict = {}
    paquets = []
    points = ["A", "B", "C"]
    for i in range(n_flux):
        # groupes de 10 flux par couple d'hotes : le flux perdu partage sa
        # conversation avec des flux vus a C (sinon : hors chemin, #352)
        src = str(ipaddress.IPv4Address(0x0A000000 + i // 10))
        dst = str(ipaddress.IPv4Address(0xC0000200 + (i // 10) % 250))
        key = ("UDP", src, 1024 + i % 60000, dst, 53, None)
        per_point = {}
        for j, p in enumerate(points[: 3 if i % 10 else 2]):  # 10 % de pertes avant C
            pk = make_pkt(
                point=p,
                ts=1000.0 + i * 0.001 + j * 0.002,
                proto="UDP",
                src=src,
                dst=dst,
                sport=key[2],
                dport=53,
                flags=None,
                seq=None,
                ack=None,
                key_id=i,
            )
            per_point[p] = [pk]
            paquets.append(pk)
        flows[key] = per_point
    return analyse(flows, points, paquets)


def test_cardinalite_bornee_sur_un_gros_jeu():
    petit = collect_samples(_gros_jeu(50), "r")
    gros = collect_samples(_gros_jeu(5000), "r")
    assert len(gros) == len(petit) == series_upper_bound(3, 2)
    assert {x.labels for x in gros} == {x.labels for x in petit}
    assert _by(gros, "netcross_point_packets_total", point="A")[0].value == 5000
    assert _by(gros, "netcross_segment_loss_ratio", segment="B -> C")[0].value == pytest.approx(0.1)


def test_aucune_adresse_ip_dans_les_etiquettes():
    for x in collect_samples(_gros_jeu(500), "r"):
        for _, v in x.labels:
            with pytest.raises(ValueError):
                ipaddress.ip_address(v)


def test_plafonnement_des_points_et_segments():
    points = [f"P{i}" for i in range(100)]
    r = _report(points)
    s = collect_samples(r, "r", findings=[], max_points=8, max_segments=5)
    assert len(s) <= series_upper_bound(8, 5)
    pts = [x.label("point") for x in _by(s, "netcross_point_packets_total")]
    assert pts == [*points[:7], OVERFLOW_LABEL]
    autres = _by(s, "netcross_point_packets_total", point=OVERFLOW_LABEL)[0].value
    assert autres == sum(r.packet_count[p] for p in points[7:])
    segs = [x.label("segment") for x in _by(s, "netcross_segment_loss_ratio")]
    assert segs == [segment_label(a, b) for a, b in r.pairs[:4]] + [OVERFLOW_LABEL]
    assert len(_by(s, "netcross_segment_triage_score")) == 5


@pytest.mark.parametrize(("mp", "ms"), [(1, 10), (10, 1)])
def test_plafonds_invalides(mp, ms):
    with pytest.raises(ValueError):
        collect_samples(_report(), "r", findings=[], max_points=mp, max_segments=ms)


def test_analyse_compte_les_paquets_par_point():
    r = _gros_jeu(20)
    assert r.packet_count == {"A": 20, "B": 20, "C": 18}


# -- documentation ----------------------------------------------------------------------------


def test_documentation_liste_tout_le_catalogue():
    doc = DOC.read_text(encoding="utf-8")
    for m in METRICS:
        assert f"`{m.name}`" in doc, m.name
    for label in ALLOWED_LABELS:
        assert f"`{label}`" in doc
    assert "mkdocs" not in doc.lower()
    assert "metriques-prometheus.md" in (DOC.parent.parent / "mkdocs.yml").read_text(encoding="utf-8")
