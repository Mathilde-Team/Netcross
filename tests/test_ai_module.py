# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #146 (FLOW-5) : module IA/ML optionnel et local.

Les tests ML sont ignores si scikit-learn est absent ; le reste (features,
gabarit de resume, garde-fous reseau, repli gracieux, CLI) tourne partout.
"""

from __future__ import annotations

import json
import random
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
import netcross_ai.optional as optional
from netcross_ai import FEATURE_NAMES, AIUnavailableError, flow_features
from netcross_ai.anomaly import Baseline, BaselineError, detect_anomalies
from netcross_ai.flow_classifier import FlowClassifier, TrainingSetError, export_training_set, load_training_set
from netcross_ai.pipeline import AIOptions, format_ai, run_ai
from netcross_ai.report_writer import (
    WriterConfigError,
    build_prompt,
    check_local_endpoint,
    collect_facts,
    template_summary,
    write_summary,
)

needs_ml = pytest.mark.skipif(not optional.ml_available(), reason="scikit-learn absent (extra ai)")


def _flow(src, dst, sizes, gaps, upload_ratio, classification="normal"):
    dist: dict[int, int] = {}
    for s in sizes:
        dist[s] = dist.get(s, 0) + 1
    return {
        "src": src,
        "dst": dst,
        "packet_count": len(sizes),
        "byte_count": sum(sizes),
        "splt": [[s, g] for s, g in zip(sizes[:20], [0.0, *gaps][:20])],
        "size_distribution": dist,
        "upload_bytes": int(sum(sizes) * upload_ratio),
        "download_bytes": int(sum(sizes) * (1 - upload_ratio)),
        "inter_arrivals": gaps,
        "classification": classification,
        "entropy": 3.0,
        "median_size": sorted(sizes)[len(sizes) // 2],
        "upload_ratio": upload_ratio,
        "regularity_cv": 0.9,
    }


def _web_flows(n, seed=1):
    rng = random.Random(seed)
    flows = []
    for i in range(n):
        count = rng.randint(20, 60)
        sizes = [rng.choice([60, 60, 120, 576, 1400, 1400]) for _ in range(count)]
        gaps = [rng.expovariate(20) for _ in range(count - 1)]
        flows.append(_flow(f"10.0.0.{i % 50 + 1}", "93.184.216.34", sizes, gaps, rng.uniform(0.1, 0.3)))
    return flows


def _exfil():
    f = _flow("10.0.0.66", "203.0.113.9", [1400] * 3000, [0.001] * 2999, 0.99, "transfert")
    f["regularity_cv"] = 0.05
    return f


# -- features & disponibilite ------------------------------------------------------


def test_features_bornees_et_tolerantes():
    vec = flow_features(_web_flows(1)[0])
    assert len(vec) == len(FEATURE_NAMES) and all(isinstance(x, float) for x in vec)
    assert flow_features({}) == [0.0] * len(FEATURE_NAMES)
    assert flow_features({"size_distribution": {"x": 1}, "splt": [["a", 1]], "entropy": float("nan")})[2] == 0.0


def test_sans_scikit_learn_erreur_explicite(monkeypatch):
    monkeypatch.setattr(optional, "ml_available", lambda: False)
    with pytest.raises(AIUnavailableError, match=r"netcross\[ai\]"):
        detect_anomalies(Baseline.from_flows(_web_flows(30)), _web_flows(2))
    with pytest.raises(AIUnavailableError):
        FlowClassifier([])


def test_baseline_json_sans_pickle(tmp_path):
    path = tmp_path / "base.json"
    Baseline.from_flows(_web_flows(5), "bureau").save(path)
    data = json.loads(path.read_text())
    assert data["schema"] == "netcross.ai.baseline/1" and data["features"] == list(FEATURE_NAMES)
    assert Baseline.load(path).label == "bureau"
    data["vectors"][0] = ["__import__('os')"] * len(FEATURE_NAMES)
    path.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="vecteurs invalides"):
        Baseline.load(path)
    path.write_text("{}")
    with pytest.raises(BaselineError, match="n'est pas une baseline"):
        Baseline.load(path)


# -- ML ---------------------------------------------------------------------------


@needs_ml
def test_anomalies_exfiltration_en_tete():
    baseline = Baseline.from_flows(_web_flows(200))
    results = detect_anomalies(baseline, [*_web_flows(20, seed=7), _exfil()])
    assert results[0].flow == "10.0.0.66 -> 203.0.113.9" and results[0].is_anomaly
    assert any(r.startswith("ratio_montant") for r in results[0].reasons)
    typical = [r for r in results if r.flow != results[0].flow]
    assert sum(r.is_anomaly for r in typical) <= 4  # peu de faux positifs sur du trafic semblable
    # graine fixe : resultat reproductible
    assert [r.score for r in detect_anomalies(baseline, [_exfil()])] == [results[0].score]


@needs_ml
def test_baseline_trop_petite():
    with pytest.raises(BaselineError, match="trop petite"):
        detect_anomalies(Baseline.from_flows(_web_flows(5)), _web_flows(1))


@needs_ml
def test_classification_avec_confiance(tmp_path):
    path = tmp_path / "train.json"
    export_training_set(_web_flows(40), path)
    data = json.loads(path.read_text())
    data["samples"] += [{"flow": _exfil() | {"src": f"10.9.0.{i}"}, "label": "exfiltration"} for i in range(10)]
    path.write_text(json.dumps(data))
    clf = FlowClassifier(load_training_set(path))
    preds = {p.flow: p for p in clf.predict([_exfil(), _web_flows(1, seed=99)[0]])}
    assert preds["10.0.0.66 -> 203.0.113.9"].label == "exfiltration"
    assert preds["10.0.0.66 -> 203.0.113.9"].confidence >= 0.8
    assert clf.labels == {"normal": 40, "exfiltration": 10}


def test_jeu_d_entrainement_invalide(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"schema": "netcross.ai.training/1", "samples": [{"flow": {}}]}))
    with pytest.raises(TrainingSetError, match="exemple 0"):
        load_training_set(path)


@needs_ml
def test_une_seule_classe_refusee():
    with pytest.raises(TrainingSetError, match="2 classes"):
        FlowClassifier([(f, "normal") for f in _web_flows(12)])


# -- redaction -------------------------------------------------------------------------


def _report():
    return SimpleNamespace(
        security_findings=[
            {"severity": "moyenne", "category": "anomalie", "detail": "flux obfusque", "host": "10.0.0.66"},
            {
                "severity": "critique",
                "category": "cve",
                "detail": "Apache 2.4.49 vulnerable",
                "host": "10.0.0.5",
                "service": "Apache",
                "version": "2.4.49",
                "cve_id": "CVE-2021-41773",
                "cvss": 7.5,
            },
            {"severity": "elevee", "category": "exploit", "detail": "path traversal", "host": "10.0.0.5"},
        ],
        service_fingerprints=[{"service": "Apache", "version": "2.4.49", "host": "10.0.0.5", "port": 80}],
        flow_anomalies=[_exfil(), {"classification": "obfusque"}],
        dga_alerts=[],
        lateral_movement_events=[],
    )


def test_resume_gabarit_correlations_recommandations():
    s = template_summary(_report())
    assert s.text.startswith("L'analyse releve 3 constat(s) de securite (1 critique, 1 elevee, 1 moyenne).")
    assert "Apache 2.4.49 vulnerable" in s.text
    assert s.correlations == [
        "10.0.0.5 cumule 2 signaux (CVE CVE-2021-41773, exploit) : exploitation d'une vulnerabilite connue probable."
    ]
    assert s.recommendations[0] == "Mettre a jour Apache 2.4.49 sur 10.0.0.5 (CVE-2021-41773, CVSS 7.5)."
    assert any("obfuscation" in r for r in s.recommendations)


def test_rapport_vide():
    empty = SimpleNamespace()
    assert template_summary(empty).text == "Aucun constat de securite n'a ete releve sur cette capture."


@pytest.mark.parametrize(
    "url", ["http://192.168.1.10:11434", "https://api.openai.com", "http://ollama.local:1", "ftp://127.0.0.1"]
)
def test_point_d_acces_non_local_refuse(url):
    with pytest.raises(WriterConfigError):
        check_local_endpoint(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:8080", "http://[::1]:11434"])
def test_point_d_acces_local_accepte(url):
    check_local_endpoint(url)


def test_moteur_inconnu_ou_modele_manquant():
    with pytest.raises(WriterConfigError, match="moteur inconnu"):
        write_summary(_report(), engine="openai:gpt")
    with pytest.raises(WriterConfigError, match="preciser le modele"):
        write_summary(_report(), engine="ollama")


class _FakeLLM(BaseHTTPRequestHandler):
    received: list = []  # noqa: RUF012 -- etat de test partage

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).received.append((self.path, body))
        answer = {"response": "Resume du modele."} if self.path == "/api/generate" else {"content": "Resume llama."}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_llm():
    _FakeLLM.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_ollama_local_ne_recoit_que_les_faits(fake_llm):
    s = write_summary(_report(), engine="ollama:llama3", endpoint=fake_llm)
    assert s.engine == "ollama:llama3" and s.text == "Resume du modele." and s.recommendations
    path, body = _FakeLLM.received[0]
    assert path == "/api/generate" and body["model"] == "llama3" and body["stream"] is False
    assert "CVE-2021-41773" in body["prompt"] and "N'invente aucun fait" in body["prompt"]
    assert "inter_arrivals" not in body["prompt"]  # pas de donnees brutes de flux


def test_llamacpp_local(fake_llm):
    s = write_summary(_report(), engine="llamacpp", endpoint=fake_llm)
    assert s.text == "Resume llama." and _FakeLLM.received[0][0] == "/completion"


def test_modele_injoignable_repli_gabarit():
    s = write_summary(_report(), engine="ollama:llama3", endpoint="http://127.0.0.1:9")
    assert s.engine == "template" and s.fallback_reason.startswith("modele local indisponible")


def test_prompt_serialisable():
    assert json.loads(build_prompt(collect_facts(_report())).split("FAITS (JSON) :\n", 1)[1])["services"]


# -- pipeline & CLI ------------------------------------------------------------------


def test_pipeline_export_baseline_cumulative_et_resume(tmp_path):
    opts = AIOptions(
        baseline_save=str(tmp_path / "b.json"),
        training_export=str(tmp_path / "t.json"),
        summary_engine="template",
    )
    run_ai(_report(), _web_flows(3), opts)
    result = run_ai(_report(), _web_flows(4), opts)
    assert result["baseline_saved"]["flows"] == 7  # enrichie, pas ecrasee
    assert result["training_exported"]["samples"] == 4
    text = format_ai(result)
    assert "Baseline enregistree" in text and "Recommandations :" in text


@needs_ml
def test_run_ai_cli_de_bout_en_bout(tmp_path, capsys):
    base = tmp_path / "b.json"
    Baseline.from_flows(_web_flows(60)).save(base)
    packets = [make_pkt(src="10.0.0.66", dst="203.0.113.9", length=1400, ts=i * 0.001) for i in range(500)]
    args = SimpleNamespace(ai_report=str(tmp_path / "ai.json"))
    report = SimpleNamespace(flow_anomalies=[])
    cli._run_ai(args, AIOptions(baseline_path=str(base), summary_engine="template"), report, packets)
    out = capsys.readouterr().out
    assert "MODULE IA LOCAL" in out and "10.0.0.66 -> 203.0.113.9" in out
    saved = json.loads((tmp_path / "ai.json").read_text())
    assert saved["schema"] == "netcross.ai/1" and saved["anomalies"][0]["is_anomaly"]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--ai-report", "x.json"], "necessitent une option --ai-*"),
        (["--ai-summary", "ollama:llama3", "--ai-endpoint", "http://10.1.1.1:11434"], "refuse"),
        (["--ai-anomalies", "absent.json"], "fichier introuvable"),
        (["--ai-endpoint", "http://127.0.0.1:1", "--ai-training-export", "t.json"], "necessite --ai-summary"),
        (["--ai-baseline-label", "x", "--ai-summary"], "necessite --ai-baseline-save"),
    ],
)
def test_validations_cli(monkeypatch, capsys, tmp_path, extra, message):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.pcap").write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", "A=x.pcap", *extra])
    with pytest.raises(SystemExit):
        cli.main()
    assert message in capsys.readouterr().err


def test_cli_sans_scikit_learn(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.pcap").write_bytes(b"")
    (tmp_path / "b.json").write_text("{}")
    monkeypatch.setattr(optional, "ml_available", lambda: False)
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", "A=x.pcap", "--ai-anomalies", "b.json"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "netcross[ai]" in capsys.readouterr().err


# -- couverture des branches manquantes (issue #246) -------------------------


def test_baseline_from_dict_caracteristiques_differentes(tmp_path):
    """Line 65 : features != FEATURE_NAMES -> BaselineError."""
    from netcross_ai.anomaly import BASELINE_SCHEMA, BaselineError
    from netcross_ai.features import FEATURE_NAMES

    data = {
        "schema": BASELINE_SCHEMA,
        "features": [*FEATURE_NAMES, "extra"],
        "label": "",
        "created_at": "",
        "vectors": [[0.0] * len(FEATURE_NAMES)],
    }
    with pytest.raises(BaselineError, match="caracteristiques differentes"):
        Baseline.from_dict(data)


def test_baseline_load_fichier_inexistant():
    """Lines 77-79 : OSError sur fichier illisible."""
    from netcross_ai.anomaly import BaselineError

    with pytest.raises(BaselineError, match="baseline illisible"):
        Baseline.load("/chemin/inexistant/baseline.json")


def test_baseline_load_json_invalide(tmp_path):
    """Lines 77-79 : JSONDecodeError sur contenu non-JSON."""
    from netcross_ai.anomaly import BaselineError

    path = tmp_path / "bad.json"
    path.write_text("ceci n'est pas du json")
    with pytest.raises(BaselineError, match="baseline illisible"):
        Baseline.load(path)


def test_flow_anomaly_to_dict():
    """Line 92 : FlowAnomaly.to_dict() renvoie tous les champs."""
    from netcross_ai.anomaly import FlowAnomaly

    a = FlowAnomaly(
        flow="10.0.0.1 -> 10.0.0.2",
        score=0.75,
        is_anomaly=True,
        classification="exfiltration",
        reasons=["ratio_montant = 0.99"],
    )
    d = a.to_dict()
    assert d["flow"] == "10.0.0.1 -> 10.0.0.2"
    assert d["score"] == 0.75
    assert d["is_anomaly"] is True
    assert d["classification"] == "exfiltration"
    assert d["reasons"] == ["ratio_montant = 0.99"]


def test_explain_z_score_eleve():
    """Lines 102-107 : _explain signale les ecarts > _Z_EXPLAIN."""
    from netcross_ai.anomaly import _explain
    from netcross_ai.features import FEATURE_NAMES

    # un vecteur dont le 5e element (ratio_montant) est a +4 sigma
    means = [1.0] * len(FEATURE_NAMES)
    stds = [0.1] * len(FEATURE_NAMES)
    vector = [1.0] * len(FEATURE_NAMES)
    vector[4] = 1.0 + 4.0 * 0.1  # z = 4.0 > 3.0
    reasons = _explain(vector, means, stds)
    assert any("ratio_montant" in r for r in reasons)


def test_explain_z_zero_std_deviation_non_nulle():
    """Line 104 branche s ~= 0 mais value != mean -> inf."""
    from netcross_ai.anomaly import _explain
    from netcross_ai.features import FEATURE_NAMES

    means = [5.0] * len(FEATURE_NAMES)
    stds = [0.0] * len(FEATURE_NAMES)
    vector = [5.0] * len(FEATURE_NAMES)
    vector[0] = 6.0  # |value - mean| > 0 avec std=0 -> inf -> >= 3.0
    reasons = _explain(vector, means, stds)
    assert any("log_paquets" in r for r in reasons)


def test_explain_aucun_ecart():
    """Lines 102-107 : aucun z >= seuil -> liste vide."""
    from netcross_ai.anomaly import _explain
    from netcross_ai.features import FEATURE_NAMES

    means = [1.0] * len(FEATURE_NAMES)
    stds = [1.0] * len(FEATURE_NAMES)
    vector = [1.0] * len(FEATURE_NAMES)  # z = 0 partout
    assert _explain(vector, means, stds) == []


def test_detect_anomalies_flux_vide_ne_leve_pas(monkeypatch):
    """Lines 119-120 : flows vide -> [] (apres require_ml)."""
    import _fake_sklearn

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        from netcross_ai.anomaly import Baseline, detect_anomalies

        baseline = Baseline.from_flows(_web_flows(30))
        assert detect_anomalies(baseline, []) == []
    finally:
        _fake_sklearn.uninstall()


def test_detect_anomalies_pipeline_complet_avec_fake_sklearn(monkeypatch):
    """Lines 114-142 : detect_anomalies avec un faux modele sklearn."""
    import _fake_sklearn

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        from netcross_ai.anomaly import Baseline, detect_anomalies

        baseline = Baseline.from_flows(_web_flows(30))
        flows = [*_web_flows(5, seed=42), _exfil()]
        results = detect_anomalies(baseline, flows)
        assert len(results) == len(flows)
        assert all(r.flow for r in results)
        # le premier flux (index 0) est marque anomalie par le fake modele
        assert results[0].is_anomaly is True
        # verifie que to_dict est appele indirectement et que le tri est bon
        assert results == sorted(results, key=lambda a: a.score, reverse=True)
        # les raisons sont calculees (peut etre vide si aucun z > 3)
        assert isinstance(results[0].reasons, list)
    finally:
        _fake_sklearn.uninstall()


# -- flow_classifier : branches manquantes (issue #246) ----------------------


def test_load_training_set_fichier_inexistant():
    """Lines 48-50 : OSError sur fichier illisible."""
    from netcross_ai.flow_classifier import TrainingSetError

    with pytest.raises(TrainingSetError, match="jeu d'entrainement illisible"):
        load_training_set("/chemin/inexistant/train.json")


def test_load_training_set_json_invalide(tmp_path):
    """Lines 48-50 : JSONDecodeError sur contenu non-JSON."""
    from netcross_ai.flow_classifier import TrainingSetError

    path = tmp_path / "bad.json"
    path.write_text("pas du json")
    with pytest.raises(TrainingSetError, match="jeu d'entrainement illisible"):
        load_training_set(path)


def test_load_training_set_schema_faux(tmp_path):
    """Line 52 : schema != TRAINING_SCHEMA."""
    from netcross_ai.flow_classifier import TrainingSetError

    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"schema": "autre.chose", "samples": []}))
    with pytest.raises(TrainingSetError, match="n'est pas un jeu"):
        load_training_set(path)


def test_flow_prediction_to_dict():
    """Line 93 : FlowPrediction.to_dict()."""
    from netcross_ai.flow_classifier import FlowPrediction

    p = FlowPrediction(
        flow="10.0.0.1 -> 10.0.0.2",
        label="tunnel",
        confidence=0.87,
        rule_classification="obfusque",
    )
    d = p.to_dict()
    assert d["flow"] == "10.0.0.1 -> 10.0.0.2"
    assert d["label"] == "tunnel"
    assert d["confidence"] == 0.87
    assert d["rule_classification"] == "obfusque"


def test_flow_classifier_init_et_predict_avec_fake_sklearn(monkeypatch):
    """Lines 104-114, 117-133 : FlowClassifier.__init__ et predict."""
    import _fake_sklearn

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        normal = [(f, "normal") for f in _web_flows(8)]
        tunnel = [(f, "tunnel") for f in _web_flows(3, seed=99)]
        clf = FlowClassifier(normal + tunnel)
        assert "normal" in clf.labels and "tunnel" in clf.labels

        flows = [*_web_flows(2, seed=7), _exfil()]
        preds = clf.predict(flows)
        assert len(preds) == len(flows)
        assert all(isinstance(p.confidence, float) for p in preds)
        assert all(p.flow for p in preds)
    finally:
        _fake_sklearn.uninstall()


def test_flow_classifier_predict_flux_vide(monkeypatch):
    """Line 118 : predict([]) -> []."""
    import _fake_sklearn

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        normal = [(f, "normal") for f in _web_flows(8)]
        tunnel = [(f, "tunnel") for f in _web_flows(3, seed=99)]
        clf = FlowClassifier(normal + tunnel)
        assert clf.predict([]) == []
    finally:
        _fake_sklearn.uninstall()


# -- pipeline : branches manquantes (issue #246) ----------------------------


def test_run_ai_anomalies_avec_baseline(monkeypatch, tmp_path):
    """Lines 43-45 : run_ai avec baseline_path -> detect_anomalies."""
    from netcross_ai import pipeline as pipeline_mod
    from netcross_ai.anomaly import Baseline, FlowAnomaly

    base = tmp_path / "b.json"
    Baseline.from_flows(_web_flows(30), "ref").save(base)

    fake_anomalies = [
        FlowAnomaly(
            flow="10.0.0.1 -> 10.0.0.2",
            score=0.9,
            is_anomaly=True,
            classification="exfiltration",
            reasons=["ratio_montant = 0.99"],
        )
    ]
    monkeypatch.setattr(pipeline_mod, "detect_anomalies", lambda baseline, flows: fake_anomalies)

    opts = AIOptions(baseline_path=str(base))
    result = run_ai(_report(), _web_flows(3), opts)
    assert "anomalies" in result
    assert result["anomalies"][0]["is_anomaly"] is True
    assert result["baseline"]["flows"] == 30


def test_run_ai_classification_avec_training(monkeypatch, tmp_path):
    """Lines 52-54 : run_ai avec training_path -> FlowClassifier.predict."""
    from netcross_ai import pipeline as pipeline_mod
    from netcross_ai.flow_classifier import FlowPrediction

    path = tmp_path / "t.json"
    export_training_set(_web_flows(20), path)

    fake_clf = type(
        "FakeClf",
        (),
        {
            "labels": {"normal": 20},
            "predict": lambda self, flows: [
                FlowPrediction(flow="x -> y", label="normal", confidence=0.5, rule_classification="")
            ],
        },
    )()
    monkeypatch.setattr(pipeline_mod, "FlowClassifier", lambda samples: fake_clf)

    opts = AIOptions(training_path=str(path))
    result = run_ai(_report(), _web_flows(2), opts)
    assert "classification" in result
    assert result["classification"][0]["label"] == "normal"
    assert result["training"]["path"] == str(path)


def test_format_ai_section_anomalies():
    """Lines 67-72 : format_ai avec anomalies dans le resultat."""
    result = {
        "schema": "netcross.ai/1",
        "flows": 5,
        "anomalies": [
            {
                "flow": "10.0.0.1 -> 10.0.0.2",
                "score": 0.9,
                "is_anomaly": True,
                "classification": "exfiltration",
                "reasons": ["ratio_montant = 0.99"],
            }
        ],
        "baseline": {"path": "b.json", "flows": 30, "label": "ref"},
    }
    text = format_ai(result)
    assert "Anomalies vs baseline" in text
    assert "10.0.0.1 -> 10.0.0.2" in text
    assert "ratio_montant = 0.99" in text


def test_format_ai_section_classification():
    """Lines 77-79 : format_ai avec classification dans le resultat."""
    result = {
        "schema": "netcross.ai/1",
        "flows": 5,
        "classification": [
            {
                "flow": "10.0.0.1 -> 10.0.0.2",
                "label": "tunnel",
                "confidence": 0.87,
                "rule_classification": "obfusque",
            }
        ],
        "training": {"path": "t.json", "labels": {"normal": 10, "tunnel": 5}},
    }
    text = format_ai(result)
    assert "Classification" in text
    assert "tunnel" in text
    assert "10.0.0.1 -> 10.0.0.2" in text


def test_format_ai_resume_avec_fallback_reason():
    """Line 87 : format_ai avec summary.fallback_reason non vide."""
    result = {
        "schema": "netcross.ai/1",
        "flows": 3,
        "summary": {
            "engine": "template",
            "text": "Resume du gabarit.",
            "fallback_reason": "modele local indisponible",
            "correlations": ["correlation 1"],
            "recommendations": ["recommandation 1"],
        },
    }
    text = format_ai(result)
    assert "Resume executif" in text
    assert "modele local indisponible" in text
    assert "correlation 1" in text
    assert "recommandation 1" in text


# -- couverture des dernieres lignes manquantes (issue #246) ----------------


def test_detect_anomalies_baseline_trop_petite(monkeypatch):
    """Line 115 : BaselineError si baseline < MIN_BASELINE_FLOWS (20)."""
    import _fake_sklearn

    from netcross_ai.anomaly import Baseline, BaselineError

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        # Baseline avec moins de 20 flux
        base = Baseline.from_flows(_web_flows(10), "ref")
        with pytest.raises(BaselineError, match="baseline trop petite"):
            detect_anomalies(base, _web_flows(3))
    finally:
        _fake_sklearn.uninstall()


def test_flow_classifier_training_set_insuffisant(monkeypatch):
    """Line 106 : TrainingSetError si < MIN_SAMPLES ou < 2 classes."""
    import _fake_sklearn

    from netcross_ai.flow_classifier import TrainingSetError

    _fake_sklearn.install()
    monkeypatch.setattr(optional, "ml_available", lambda: True)
    try:
        # Trop peu d'exemples (3 < 10)
        with pytest.raises(TrainingSetError, match="jeu d'entrainement insuffisant"):
            FlowClassifier([(f, "normal") for f in _web_flows(3)])

        # Assez d'exemples mais une seule classe
        with pytest.raises(TrainingSetError, match="jeu d'entrainement insuffisant"):
            FlowClassifier([(f, "normal") for f in _web_flows(12)])
    finally:
        _fake_sklearn.uninstall()


def test_format_ai_resume_sans_correlations_ni_recommandations():
    """Lines 89->92, 92->95 : summary sans correlations ni recommendations."""
    result = {
        "schema": "netcross.ai/1",
        "flows": 3,
        "summary": {
            "engine": "template",
            "text": "Resume simple.",
            "fallback_reason": "",
            "correlations": [],
            "recommendations": [],
        },
    }
    text = format_ai(result)
    assert "Resume executif" in text
    assert "Resume simple." in text
    assert "Correlations" not in text
    assert "Recommandations" not in text
