"""Tests du rapport HTML autonome (issue #1073)."""

from __future__ import annotations

import html
import json
import re

import pytest

from netcross_core.models import Report
from netcross_report import html_report
from netcross_report.html_report import (
    DATA_ELEMENT_ID,
    _json_for_script,
    generate_html_report,
    render_html_report,
    write_html_report,
)
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import Finding

HOSTILE = '</script><script>alert("x")</script><img src=x onerror=alert(1)> & \u2028'


def _doc(findings=None, **kwargs):
    r = Report(points=["CLIENT", "ROUTEUR", "SERVEUR"])
    if findings is None:
        findings = [
            Finding("anomalie", "Perte", "ROUTEUR->SERVEUR", "12 paquet(s) perdus entre ROUTEUR et SERVEUR"),
            Finding("a_surveiller", "Latence", "CLIENT->ROUTEUR", "latence en hausse"),
            Finding("info", "DNS", "global", "3 requete(s) DNS"),
        ]
    return build_json_report_document(r, title="Incident INC-42", findings=findings, **kwargs)


def _embedded(page: str, element_id: str = DATA_ELEMENT_ID):
    m = re.search(rf'<script type="application/json" id="{element_id}">(.*?)</script>', page, re.S)
    assert m is not None
    return json.loads(m.group(1))


def _noscript(page: str) -> str:
    m = re.search(r"<noscript>(.*)</noscript>", page, re.S)
    assert m is not None
    return m.group(1)


# -- autonomie ----------------------------------------------------------------------


def test_aucune_url_externe_chargee():
    page = render_html_report(_doc())
    assert not re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", page, re.I)
    assert not re.search(r"@import|url\(\s*['\"]?(?:https?:)?//", page, re.I)
    assert "<link" not in page.lower()
    assert "default-src 'none'" in page  # CSP : toute ressource externe bloquee


def test_un_seul_fichier_ecrit(tmp_path):
    out = tmp_path / "rapport.html"
    assert write_html_report(_doc(), out) == str(out)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["rapport.html"]
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_generate_html_report_depuis_report(tmp_path):
    out = tmp_path / "r.html"
    f = Finding("anomalie", "Perte", "A->B", "perte localisee")
    generate_html_report(Report(points=["A", "B"]), out, title="T", findings=[f])
    page = out.read_text(encoding="utf-8")
    assert _embedded(page)["title"] == "T"
    assert "perte localisee" in _noscript(page)


# -- JSON embarque --------------------------------------------------------------------


def test_json_embarque_identique_au_document():
    doc = _doc()
    assert _embedded(render_html_report(doc)) == json.loads(json.dumps(doc, default=str))


def test_tous_les_constats_presents_dans_le_html():
    doc = _doc()
    page = render_html_report(doc)
    statique = _noscript(page)
    assert len(_embedded(page)["findings"]) == len(doc["findings"]) == 3
    for f in doc["findings"]:
        assert html.escape(f["message"]) in statique
        assert html.escape(f["segment"]) in statique


def test_synthese_et_score():
    doc = _doc()
    statique = _noscript(render_html_report(doc))
    assert f"Score de sante : {doc['health_score']}/100" in statique
    assert "CLIENT -&gt; ROUTEUR -&gt; SERVEUR" in statique
    assert "Constats : 3 (Anomalie : 1, A surveiller : 1, Information : 1)" in statique
    assert "ROUTEUR-&gt;SERVEUR" in statique  # triage


def test_sans_constat_sections_ecrites():
    statique = _noscript(render_html_report(_doc(findings=[])))
    assert "Aucun constat : rien d&#x27;anormal detecte." in statique
    assert "Aucun segment a prioriser." in statique


def test_document_minimal_tolere():
    page = render_html_report({})
    assert "<title>Rapport Netcross</title>" in page
    assert _embedded(page) == {}


# -- injection ---------------------------------------------------------------------------


def test_contenu_hostile_reste_du_texte():
    doc = _doc(findings=[Finding("anomalie", HOSTILE, HOSTILE, HOSTILE)])
    doc["title"] = HOSTILE
    page = render_html_report(doc)
    # une seule fermeture de chaque script legitime : rien d'injecte
    assert page.count("</script>") == 3
    assert "<img" not in page
    assert "onerror=alert(1)>" not in page.replace("onerror=alert(1)&gt;", "")
    assert _embedded(page)["findings"][0]["message"] == HOSTILE
    assert html.escape(HOSTILE) in _noscript(page)


def test_json_for_script_echappe_les_caracteres_dangereux():
    texte = _json_for_script({"a": "</script>&\u2028\u2029"})
    assert not set("<>&") & set(texte)
    assert "\u2028" not in texte
    assert "\u2029" not in texte
    assert json.loads(texte) == {"a": "</script>&\u2028\u2029"}


def test_js_n_utilise_jamais_innerhtml():
    assert "innerHTML" not in html_report._JS
    assert "outerHTML" not in html_report._JS
    assert "eval(" not in html_report._JS
    assert "fetch(" not in html_report._JS
    assert "XMLHttpRequest" not in html_report._JS


# -- accessibilite et i18n --------------------------------------------------------------


def test_accessibilite_de_base():
    page = render_html_report(_doc())
    assert '<html lang="fr">' in page
    assert '<meta charset="utf-8">' in page
    assert "<h1>Incident INC-42</h1>" in page
    assert '<th scope="col">' in page
    assert "<caption>" in page
    assert '"aria-live": "polite"' in html_report._JS
    assert "aria-labelledby" in html_report._JS


def test_libelles_transmis_au_js():
    labels = _embedded(render_html_report(_doc()), "netcross-labels")
    assert labels["severities"] == {"anomalie": "Anomalie", "a_surveiller": "A surveiller", "info": "Information"}
    assert labels["severity_order"] == ["anomalie", "a_surveiller", "info"]
    assert set(labels["health"]) == {"bon", "a_surveiller", "degrade", "critique"}


def test_traduction_via_i18n(monkeypatch):
    monkeypatch.setattr(html_report, "_", lambda s: f"[{s}]")
    monkeypatch.setattr(html_report, "active_language", lambda: "pt_BR")
    page = render_html_report(_doc())
    assert '<html lang="pt-BR">' in page
    assert "[Synthese]" in _noscript(page)
    assert _embedded(page, "netcross-labels")["severities"]["anomalie"] == "[Anomalie]"


@pytest.mark.parametrize("label", ["bon", "a_surveiller", "degrade", "critique", "inconnu"])
def test_libelle_de_sante(label):
    doc = _doc()
    doc["health_label"] = label
    statique = _noscript(render_html_report(doc))
    attendu = {"bon": "Bon", "a_surveiller": "A surveiller", "degrade": "Degrade", "critique": "Critique"}
    assert f"({attendu.get(label, label)})" in statique
