"""
netcross_report.html_report -- rapport HTML autonome alimente par le JSON
du rapport (issue #1073, sous-issue 1/6 du chantier #1000).

Socle du futur ``--html-report FICHIER.html`` (branchement CLI, API, GUI et
``--redact`` : #1083). Partis pris :

1. **Un seul fichier, aucune ressource externe.** CSS et JavaScript sont
   embarques ; aucune URL http(s) n'est chargee a l'ouverture (pas de
   police, d'image, de script ou de feuille de style distante). Le rapport
   reste lisible sur un poste isole, archive dans un ticket ou des mois
   plus tard.

2. **Les donnees viennent du JSON embarque.** Le document produit par
   ``json_report.build_json_report_document()`` (le meme que
   ``--json-report`` et ``GET /analyses/{id}/report``) est inclus tel quel
   dans un ``<script type="application/json">`` ; le JavaScript embarque le
   lit et construit la synthese, le score, le triage et la liste des
   constats. Les vues suivantes du chantier (#1075 chemin, #1077 filtres,
   #1079 diagramme) liront la meme source.

3. **Aucune injection.** Le JSON est serialise avec ``<``, ``>``, ``&`` et
   U+2028/U+2029 echappes (impossible de fermer la balise ``<script>``) ;
   le JavaScript n'utilise que ``textContent`` / ``createElement``, jamais
   ``innerHTML`` : un message de constat hostile reste du texte.

4. **Lisible sans JavaScript.** Un rendu statique equivalent (synthese,
   score, constats), genere cote Python depuis le meme document et echappe,
   est place dans ``<noscript>`` : impression, lecteurs restreints,
   accessibilite. Tous les constats du JSON y figurent.

5. **Accessibilite de base et i18n.** ``lang`` du document, titres
   hierarchises, tableaux avec ``<caption>`` et ``scope``, region
   ``aria-live`` pour la synthese, severite toujours ecrite en texte (pas
   seulement en couleur). Libelles en francais par defaut, traduits via
   ``netcross_core.i18n`` (gettext).
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from netcross_core.i18n import N_, _, active_language
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# Identifiant de la balise qui porte le JSON embarque (lu par le JS).
DATA_ELEMENT_ID = "netcross-data"

_SEVERITY_LABELS = {
    "anomalie": N_("Anomalie"),
    "a_surveiller": N_("A surveiller"),
    "info": N_("Information"),
}
_HEALTH_LABELS = {
    "bon": N_("Bon"),
    "a_surveiller": N_("A surveiller"),
    "degrade": N_("Degrade"),
    "critique": N_("Critique"),
}
_SEVERITY_ORDER = ("anomalie", "a_surveiller", "info")

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 2rem 1.5rem 4rem; max-width: 1200px; color: #111827; background: #fff;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.25rem 0 .75rem; padding-bottom: .35rem; border-bottom: 2px solid #e5e7eb; }
.sous-titre { color: #4b5563; font-size: .875rem; margin: 0 0 1.5rem; }
.cartes { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .75rem; }
.carte { border: 1px solid #e5e7eb; border-radius: 8px; padding: .85rem 1rem; }
.carte .valeur { font-size: 1.75rem; font-weight: 650; line-height: 1.1; }
.carte .etiquette { color: #4b5563; font-size: .8rem; margin-top: .2rem; }
table { width: 100%; border-collapse: collapse; font-size: .875rem; }
caption { text-align: left; color: #4b5563; font-size: .8rem; padding-bottom: .4rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
th { background: #f9fafb; font-weight: 600; color: #374151; }
.badge { display: inline-block; padding: .05rem .5rem; border-radius: 99px; font-size: .78rem; font-weight: 600;
  border: 1px solid currentColor; }
.sev-anomalie { color: #7f1d1d; background: #fee2e2; }
.sev-a_surveiller { color: #854d0e; background: #fef9c3; }
.sev-info { color: #1e3a8a; background: #dbeafe; }
.sante-bon { color: #14532d; } .sante-a_surveiller { color: #854d0e; }
.sante-degrade { color: #9a3412; } .sante-critique { color: #7f1d1d; }
.vide { color: #4b5563; font-style: italic; }
@media print { body { padding: 0; } th { position: static; } }
"""

# JavaScript embarque : lit le JSON, construit le DOM par createElement /
# textContent uniquement (jamais innerHTML). Aucune requete reseau.
_JS = """
(function () {
  "use strict";
  var source = document.getElementById("netcross-data");
  var racine = document.getElementById("rapport");
  if (!source || !racine) { return; }
  var doc = JSON.parse(source.textContent);
  var L = JSON.parse(document.getElementById("netcross-labels").textContent);

  function el(tag, attrs, texte) {
    var n = document.createElement(tag);
    if (attrs) { Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); }); }
    if (texte !== undefined && texte !== null) { n.textContent = String(texte); }
    return n;
  }
  function badge(sev) {
    return el("span", {"class": "badge sev-" + sev}, L.severities[sev] || sev);
  }
  function tableau(legende, entetes, lignes, vide) {
    if (!lignes.length) { return el("p", {"class": "vide"}, vide); }
    var t = el("table");
    t.appendChild(el("caption", null, legende));
    var tr = el("tr");
    entetes.forEach(function (h) { tr.appendChild(el("th", {"scope": "col"}, h)); });
    t.appendChild(el("thead")).appendChild(tr);
    var corps = t.appendChild(el("tbody"));
    lignes.forEach(function (cellules) {
      var ligne = corps.appendChild(el("tr"));
      cellules.forEach(function (c) {
        var td = ligne.appendChild(el("td"));
        if (c instanceof Node) { td.appendChild(c); } else { td.textContent = c === null ? "" : String(c); }
      });
    });
    return t;
  }

  var findings = doc.findings || [];
  var parSev = {};
  findings.forEach(function (f) { parSev[f.severity] = (parSev[f.severity] || 0) + 1; });

  var synthese = el("section", {"aria-labelledby": "titre-synthese", "aria-live": "polite"});
  synthese.appendChild(el("h2", {"id": "titre-synthese"}, L.summary));
  var cartes = synthese.appendChild(el("div", {"class": "cartes"}));
  function carte(valeur, etiquette, classe) {
    var c = cartes.appendChild(el("div", {"class": "carte" + (classe ? " " + classe : "")}));
    c.appendChild(el("div", {"class": "valeur"}, valeur));
    c.appendChild(el("div", {"class": "etiquette"}, etiquette));
    return c;
  }
  var sante = L.health[doc.health_label] || doc.health_label;
  var score = carte(doc.health_score + "/100", L.health_score + " : " + sante, "sante-" + doc.health_label);
  score.setAttribute("id", "score-sante");
  carte((doc.points || []).length, L.points);
  carte(findings.length, L.findings_count);
  L.severity_order.forEach(function (s) { carte(parSev[s] || 0, L.severities[s] || s, "sev-" + s); });
  if ((doc.points || []).length) {
    synthese.appendChild(el("p", null, L.points + " : " + doc.points.join(" \\u2192 ")));
  }
  racine.appendChild(synthese);

  var triage = el("section", {"aria-labelledby": "titre-triage"});
  triage.appendChild(el("h2", {"id": "titre-triage"}, L.triage));
  triage.appendChild(tableau(L.triage_caption, [L.segment, L.score, L.categories, L.findings_count],
    (doc.triage || []).map(function (s) {
      return [s.segment, s.score, (s.categories || []).join(", "), s.finding_count];
    }), L.no_triage));
  racine.appendChild(triage);

  var constats = el("section", {"aria-labelledby": "titre-constats"});
  constats.appendChild(el("h2", {"id": "titre-constats"}, L.findings));
  var tc = tableau(L.findings_caption, [L.severity, L.category, L.segment, L.message],
    findings.map(function (f) { return [badge(f.severity), f.category, f.segment, f.message]; }), L.no_findings);
  tc.setAttribute("id", "table-constats");
  constats.appendChild(tc);
  racine.appendChild(constats);
  racine.setAttribute("data-rendu", "js");
})();
"""


def _labels() -> dict:
    """Libelles d'interface traduits, transmis au JS (JSON) et au rendu statique."""
    logger.debug("_labels: entrée")
    labels = {
        "summary": _("Synthese"),
        "health_score": _("Score de sante"),
        "points": _("Points de capture"),
        "findings_count": _("Constats"),
        "triage": _("Segments par priorite"),
        "triage_caption": _("Segments classes du plus au moins prioritaire"),
        "findings": _("Constats"),
        "findings_caption": _("Tous les constats de l'analyse"),
        "segment": _("Segment"),
        "score": _("Score"),
        "categories": _("Categories"),
        "severity": _("Severite"),
        "category": _("Categorie"),
        "message": _("Message"),
        "no_findings": _("Aucun constat : rien d'anormal detecte."),
        "no_triage": _("Aucun segment a prioriser."),
        "severities": {k: _(v) for k, v in _SEVERITY_LABELS.items()},
        "health": {k: _(v) for k, v in _HEALTH_LABELS.items()},
        "severity_order": list(_SEVERITY_ORDER),
    }
    logger.debug("_labels: retour dict")
    return labels


def _json_for_script(value) -> str:
    """JSON inerte dans ``<script type="application/json">`` : aucun ``<``,
    ``>`` ou ``&`` litteral (pas de ``</script>`` possible), U+2028/2029
    echappes."""
    logger.debug("_json_for_script: entrée")
    texte = json.dumps(value, ensure_ascii=False, default=str, sort_keys=False)
    for brut, echappe in (
        ("&", "\\u0026"),
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        texte = texte.replace(brut, echappe)
    logger.debug("_json_for_script: retour {} caractere(s)", len(texte))
    return texte


def _e(value) -> str:
    """Echappement HTML de toute valeur (None -> chaine vide)."""
    logger.debug("_e: retour str")
    return html.escape("" if value is None else str(value), quote=True)


def _static_table(caption: str, headers: list[str], rows: list[list[str]], empty: str) -> str:
    """Tableau HTML statique ; les cellules sont DEJA echappees."""
    logger.debug("_static_table: entrée ({} ligne(s))", len(rows))
    if not rows:
        logger.debug("_static_table: si aucune ligne -> retour paragraphe vide")
        return f'<p class="vide">{_e(empty)}</p>'
    entetes = "".join(f'<th scope="col">{_e(h)}</th>' for h in headers)
    corps = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    logger.debug("_static_table: retour tableau")
    return f"<table><caption>{_e(caption)}</caption><thead><tr>{entetes}</tr></thead><tbody>{corps}</tbody></table>"


def _static_body(doc: dict, labels: dict) -> str:
    """Rendu sans JavaScript (``<noscript>``) : synthese, score, triage, constats."""
    logger.debug("_static_body: entrée")
    findings = doc.get("findings") or []
    label_sante = labels["health"].get(doc.get("health_label"), doc.get("health_label"))
    par_sev = {s: sum(1 for f in findings if f.get("severity") == s) for s in _SEVERITY_ORDER}
    resume = ", ".join(f"{labels['severities'][s]} : {n}" for s, n in par_sev.items())
    triage = _static_table(
        labels["triage_caption"],
        [labels["segment"], labels["score"], labels["categories"], labels["findings_count"]],
        [
            [
                _e(s.get("segment")),
                _e(s.get("score")),
                _e(", ".join(s.get("categories") or [])),
                _e(s.get("finding_count")),
            ]
            for s in doc.get("triage") or []
        ],
        labels["no_triage"],
    )
    constats = _static_table(
        labels["findings_caption"],
        [labels["severity"], labels["category"], labels["segment"], labels["message"]],
        [
            [
                f'<span class="badge sev-{_e(f.get("severity"))}">'
                f"{_e(labels['severities'].get(f.get('severity'), f.get('severity')))}</span>",
                _e(f.get("category")),
                _e(f.get("segment")),
                _e(f.get("message")),
            ]
            for f in findings
        ],
        labels["no_findings"],
    )
    corps = (
        f"<h2>{_e(labels['summary'])}</h2>"
        f"<p>{_e(labels['health_score'])} : {_e(doc.get('health_score'))}/100 ({_e(label_sante)})</p>"
        f"<p>{_e(labels['points'])} : {_e(' -> '.join(doc.get('points') or []))}</p>"
        f"<p>{_e(labels['findings_count'])} : {len(findings)} ({_e(resume)})</p>"
        f"<h2>{_e(labels['triage'])}</h2>{triage}"
        f"<h2>{_e(labels['findings'])}</h2>{constats}"
    )
    logger.debug("_static_body: retour {} caractere(s)", len(corps))
    return corps


def render_html_report(doc: dict) -> str:
    """HTML autonome d'un document de ``build_json_report_document()``."""
    logger.debug("render_html_report: entrée ({} constat(s))", len(doc.get("findings") or []))
    labels = _labels()
    langue = (active_language() or "fr").replace("_", "-")
    titre = doc.get("title") or _("Rapport Netcross")
    genere = doc.get("generated_at") or ""
    page = (
        "<!DOCTYPE html>\n"
        f'<html lang="{_e(langue)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        # Interdit toute ressource externe, meme si un futur gabarit en ajoutait.
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">"
        f"<title>{_e(titre)}</title><style>{_CSS}</style></head><body>"
        f'<header><h1>{_e(titre)}</h1><p class="sous-titre">{_e(_("Genere le"))} {_e(genere)}</p></header>'
        f'<main id="rapport"><noscript>{_static_body(doc, labels)}</noscript></main>'
        f'<script type="application/json" id="{DATA_ELEMENT_ID}">{_json_for_script(doc)}</script>'
        f'<script type="application/json" id="netcross-labels">{_json_for_script(labels)}</script>'
        f"<script>{_JS}</script>"
        "</body></html>\n"
    )
    logger.debug("render_html_report: retour {} caractere(s)", len(page))
    return page


def write_html_report(doc: dict, output_path) -> str:
    """Ecrit le rapport HTML de ``doc`` dans ``output_path`` et retourne le chemin."""
    logger.debug("write_html_report: entrée")
    chemin = Path(output_path)
    chemin.write_text(render_html_report(doc), encoding="utf-8")
    logger.debug("write_html_report: retour chemin")
    return str(chemin)


def generate_html_report(r, output_path, title="Analyse croisee de captures reseau", **kwargs) -> str:
    """Comme ``json_report.generate_json_report`` (memes arguments nommes),
    mais ecrit le rapport HTML autonome."""
    logger.debug("generate_html_report: entrée")
    from netcross_report.json_report import build_json_report_document

    doc = build_json_report_document(r, title=title, **kwargs)
    chemin = write_html_report(doc, output_path)
    logger.debug("generate_html_report: retour chemin")
    return chemin
