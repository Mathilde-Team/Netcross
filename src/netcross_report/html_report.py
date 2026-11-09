# SPDX-License-Identifier: GPL-3.0-or-later
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

5. **Vue « Chemin » (issue #1075).** Les points de capture dans l'ordre du
   chemin deduit, relies par leurs segments (cle ``path_metrics`` du JSON,
   memes chiffres que le PDF). Chaque segment est un bouton : survol, focus
   clavier ou clic affichent son detail (delai, percentiles, gigue, pertes,
   debit, sauts, horloge) dans un panneau ``aria-live``. Fleches, Debut et
   Fin passent d'un segment a l'autre. Un segment sans aucune mesure est
   ecrit « non mesurable » (texte et bordure pointillee, jamais la seule
   couleur) et ses valeurs « non mesure » : une valeur inconnue ne
   s'affiche jamais comme un zero.

6. **Echelle SIP multi-points (issue #1125).** Cle ``sip_ladders`` du
   JSON : par appel, un tableau message x point de capture. Un message
   perdu (« ABSENT »), retransmis ou reecrit (SDP, Via, Contact) est ecrit
   en toutes lettres dans sa cellule, la couleur ne faisant que doubler le
   texte. Section absente sans SIP.

7. **Accessibilite de base et i18n.** ``lang`` du document, titres
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
from netcross_report.evidence_frames import CATEGORY_PROTOCOLS, GENERIC_PROTOCOL, finding_protocol

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

# Detail d'un segment de la vue chemin (#1075) : cle de path_metrics,
# libelle (traduit dans _labels), unite et nombre de decimales.
_SEGMENT_FIELDS = (
    {"cle": "samples", "libelle": N_("Echantillons")},
    {"cle": "delay_avg_ms", "libelle": N_("Delai moyen"), "unite": "ms", "decimales": 3},
    {"cle": "delay_p50_ms", "libelle": N_("Delai P50"), "unite": "ms", "decimales": 3},
    {"cle": "delay_p95_ms", "libelle": N_("Delai P95"), "unite": "ms", "decimales": 3},
    {"cle": "delay_p99_ms", "libelle": N_("Delai P99"), "unite": "ms", "decimales": 3},
    {"cle": "jitter_ms", "libelle": N_("Gigue"), "unite": "ms", "decimales": 3},
    {"cle": "loss_count", "libelle": N_("Paquets perdus")},
    {"cle": "loss_pct", "libelle": N_("Taux de perte"), "unite": "%", "decimales": 2},
    {"cle": "throughput_bps", "libelle": N_("Debit au point aval"), "format": "debit"},
    {"cle": "retrans", "libelle": N_("Retransmissions")},
    {"cle": "dscp_changes", "libelle": N_("Changements DSCP")},
    {"cle": "frag_new", "libelle": N_("Fragmentations nouvelles")},
    {"cle": "pmtud_blackhole", "libelle": N_("Trous noirs PMTUD")},
    {"cle": "hops", "libelle": N_("Sauts IP")},
    {"cle": "hop_outliers", "libelle": N_("Ecarts de sauts")},
    {"cle": "clock_offset_ms", "libelle": N_("Decalage d'horloge"), "unite": "ms", "decimales": 3},
    {"cle": "clock_drift_ppm", "libelle": N_("Derive d'horloge"), "unite": "ppm", "decimales": 2},
)

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
.chemin { list-style: none; display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; padding: 0; margin: 0; }
.chemin .point { font-weight: 650; padding: .45rem .8rem; border: 2px solid #374151; border-radius: 8px; }
.chemin .segment { font: inherit; font-size: .82rem; cursor: pointer; background: #f9fafb; color: #111827;
  border: 2px solid #2563eb; border-radius: 99px; padding: .3rem .8rem; }
.chemin .segment::before { content: "\\2192  "; }
.chemin .segment:hover, .chemin .segment:focus-visible, .chemin .segment[aria-pressed="true"] {
  background: #dbeafe; outline: 3px solid #1d4ed8; outline-offset: 2px; }
.chemin .segment.non-mesurable { border-style: dashed; border-color: #6b7280; color: #374151; }
.detail-segment { margin-top: 1rem; border: 1px solid #e5e7eb; border-radius: 8px; padding: .85rem 1rem; }
.detail-segment h3 { font-size: 1rem; margin: 0 0 .5rem; }
.detail-segment dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem 1.25rem; margin: 0; }
.detail-segment dt { color: #4b5563; } .detail-segment dd { margin: 0; font-variant-numeric: tabular-nums; }
.sip-perdu { background: #fee2e2; color: #7f1d1d; font-weight: 600; }
.sip-reecrit { background: #ffedd5; color: #7c2d12; }
.sip-retransmis { background: #fef9c3; color: #713f12; }
.sip-resume { color: #374151; font-size: .875rem; margin: .25rem 0 .5rem; }
.filtres { display: flex; flex-wrap: wrap; gap: .5rem 1.25rem; margin: 0 0 .5rem; font-size: .875rem; }
.filtres select { font: inherit; margin-left: .35rem; }
.compteur { color: #374151; font-size: .82rem; margin: 0 0 .5rem; }
.preuves { display: flex; flex-wrap: wrap; gap: .25rem; }
.preuve { font: inherit; font-size: .78rem; cursor: pointer; background: #f9fafb; color: #111827;
  border: 1px solid #2563eb; border-radius: 6px; padding: .05rem .45rem; }
.preuve:hover, .preuve:focus-visible, .preuve[aria-pressed="true"] { background: #dbeafe; outline: 2px solid #1d4ed8; }
.detail-preuve { margin-top: 1rem; border: 1px solid #e5e7eb; border-radius: 8px; padding: .85rem 1rem; }
.detail-preuve h3 { font-size: 1rem; margin: 0 0 .5rem; }
.detail-preuve dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem 1.25rem; margin: .75rem 0 0; }
.detail-preuve dt { color: #4b5563; } .detail-preuve dd { margin: 0; font-variant-numeric: tabular-nums; }
.diagramme-preuve td { font-variant-numeric: tabular-nums; }
.trame-preuve th, .trame-preuve td { background: #dbeafe; font-weight: 650; }
.boutons-diagramme { display: flex; flex-wrap: wrap; gap: .5rem; margin: .5rem 0; font-size: .82rem; }
.sequence-conteneur { max-height: 26rem; overflow-y: auto; border: 1px solid #e5e7eb; border-radius: 8px;
  background: #fff; }
.sequence-conteneur svg { display: block; width: 100%; }
.compteur-diagramme { color: #374151; font-size: .82rem; margin: .25rem 0 .5rem; }
.carte-svg { max-width: 100%; }
.trame-retr { stroke: #b91c1c; }
.hote-anormal { stroke: #b91c1c; }
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

  var findings = (doc.findings || []).map(function (f) {
    var copie = {};
    Object.keys(f).forEach(function (k) { copie[k] = f[k]; });
    copie.protocol = f.protocol || L.category_protocols[f.category] || L.generic_protocol;
    return copie;
  });
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

  // -- Vue chemin (issue #1075) --
  function fixe(v, n) { return Number(v).toFixed(n).replace(".", L.decimal); }
  function valeur(seg, champ) {
    var v = seg[champ.cle];
    if (v === null || v === undefined) { return L.not_measured; }
    if (champ.format === "debit") {
      if (v >= 1e6) { return fixe(v / 1e6, 2) + " Mbit/s"; }
      return fixe(v / 1e3, 1) + " kbit/s";
    }
    if (champ.decimales !== undefined) { v = fixe(v, champ.decimales); }
    return String(v) + (champ.unite ? " " + champ.unite : "");
  }
  function resume(seg) {
    if (!seg.measured) { return L.not_measurable; }
    var morceaux = [];
    if (seg.delay_avg_ms !== null && seg.delay_avg_ms !== undefined) {
      morceaux.push(fixe(seg.delay_avg_ms, 2) + " ms");
    }
    if (seg.loss_pct !== null && seg.loss_pct !== undefined) {
      morceaux.push(fixe(seg.loss_pct, 1) + " % " + L.losses);
    }
    return morceaux.length ? morceaux.join(" / ") : L.measured;
  }
  var segments = doc.path_metrics || [];
  var chemin = el("section", {"aria-labelledby": "titre-chemin"});
  chemin.appendChild(el("h2", {"id": "titre-chemin"}, L.path));
  if (!segments.length) {
    chemin.appendChild(el("p", {"class": "vide"}, L.no_path));
  } else {
    chemin.appendChild(el("p", {"class": "sous-titre", "id": "aide-chemin"}, L.path_help));
    var liste = chemin.appendChild(el("ol", {"class": "chemin", "id": "vue-chemin", "aria-label": L.path}));
    var detail = el("div", {"class": "detail-segment", "id": "detail-segment", "aria-live": "polite"});
    detail.appendChild(el("p", {"class": "vide"}, L.path_hint));
    var boutons = [];
    var dernier = null;
    function montrer(i) {
      var seg = segments[i];
      while (detail.firstChild) { detail.removeChild(detail.firstChild); }
      detail.setAttribute("data-segment", seg.segment);
      detail.appendChild(el("h3", null, L.segment + " " + seg.segment + " : "
        + (seg.measured ? L.measured : L.not_measurable)));
      if (!seg.measured) { detail.appendChild(el("p", null, L.not_measurable_help)); }
      var dl = detail.appendChild(el("dl"));
      L.segment_fields.forEach(function (champ) {
        dl.appendChild(el("dt", null, champ.libelle));
        dl.appendChild(el("dd", {"data-champ": champ.cle}, valeur(seg, champ)));
      });
      boutons.forEach(function (b, j) { b.setAttribute("aria-pressed", j === i ? "true" : "false"); });
    }
    function point(nom) {
      liste.appendChild(el("li", {"class": "point"}, nom));
      dernier = nom;
    }
    segments.forEach(function (seg, i) {
      if (seg.upstream !== dernier) { point(seg.upstream); }
      var li = liste.appendChild(el("li"));
      var b = li.appendChild(el("button", {
        "type": "button", "class": "segment" + (seg.measured ? "" : " non-mesurable"),
        "data-index": String(i), "aria-pressed": "false", "aria-controls": "detail-segment",
        "aria-describedby": "aide-chemin",
        "aria-label": L.segment + " " + seg.segment + " : " + resume(seg)
      }, resume(seg)));
      boutons.push(b);
      b.addEventListener("mouseenter", function () { montrer(i); });
      b.addEventListener("focus", function () { montrer(i); });
      b.addEventListener("click", function () { montrer(i); });
      b.addEventListener("keydown", function (ev) {
        var cible = null;
        if (ev.key === "ArrowRight" || ev.key === "ArrowDown") { cible = Math.min(i + 1, boutons.length - 1); }
        if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") { cible = Math.max(i - 1, 0); }
        if (ev.key === "Home") { cible = 0; }
        if (ev.key === "End") { cible = boutons.length - 1; }
        if (cible !== null) { ev.preventDefault(); boutons[cible].focus(); }
      });
      point(seg.downstream);
    });
    chemin.appendChild(detail);
  }
  racine.appendChild(chemin);

  // -- Echelle SIP multi-points (issue #1125) --
  var CHAMPS_SIP = {"sdp": "SDP", "via": "Via", "contact": "Contact"};
  function celluleSip(m, p) {
    var c = (m.cells || {})[p];
    if (!c) {
      if ((m.lost_at || []).indexOf(p) >= 0) { return [L.sip_absent, "sip-perdu"]; }
      return ["\u2014 (" + L.sip_hop + ")", ""];
    }
    var parts = [fixe(c.rel_ms, 1) + " ms"];
    var classe = "";
    if (c.count > 1) { parts.push("x" + c.count + " (" + L.sip_retransmitted + ")"); classe = "sip-retransmis"; }
    if ((c.rewritten || []).length) {
      parts.push(L.sip_rewritten + " : " + c.rewritten.map(function (f) { return CHAMPS_SIP[f] || f; }).join(", "));
      classe = "sip-reecrit";
    }
    return [parts.join(" ; "), classe];
  }
  var echelles = doc.sip_ladders || [];
  if (echelles.length) {
    var sip = el("section", {"aria-labelledby": "titre-sip", "id": "echelle-sip"});
    sip.appendChild(el("h2", {"id": "titre-sip"}, L.sip));
    sip.appendChild(el("p", {"class": "sous-titre"}, L.sip_help));
    echelles.forEach(function (e) {
      sip.appendChild(el("h3", null, "Call-ID " + e.call_id));
      sip.appendChild(el("p", {"class": "sip-resume"}, L.sip_summary
        .replace("{total}", e.total_messages).replace("{lost}", e.lost)
        .replace("{retransmitted}", e.retransmitted).replace("{rewritten}", e.rewritten)
        + (e.truncated ? " " + L.sip_truncated.replace("{n}", e.truncated) : "")));
      var lignes = (e.messages || []).map(function (m) {
        return [m.message + " (" + m.cseq + ")"].concat(e.points.map(function (p) {
          var r = celluleSip(m, p);
          var span = el("span", r[1] ? {"class": r[1]} : null, r[0]);
          return span;
        }));
      });
      var t = tableau(L.sip_caption, [L.message].concat(e.points), lignes, L.no_sip);
      t.setAttribute("data-call-id", e.call_id);
      sip.appendChild(t);
    });
    racine.appendChild(sip);
  }

  // -- Diagrammes de sequence non tronques + carte (issue #1079) --
  var NS_SVG = "http://www.w3.org/2000/svg";
  function svg(tag, attrs) {
    var n = document.createElementNS(NS_SVG, tag);
    if (attrs) { Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); }); }
    return n;
  }
  function texteSvg(x, y, contenu, attrs) {
    var t = svg("text", Object.assign({"x": x, "y": y}, attrs || {}));
    t.textContent = String(contenu);
    return t;
  }
  var sectionDiagrammes = el("section", {"aria-labelledby": "titre-diagrammes"});
  sectionDiagrammes.appendChild(el("h2", {"id": "titre-diagrammes"}, L.diagrams));
  var diagrams = doc.sequence_diagrams || [];
  if (!diagrams.length) {
    sectionDiagrammes.appendChild(el("p", {"class": "vide"}, L.sequence_no_flows));
  } else {
    sectionDiagrammes.appendChild(el("p", {"class": "sous-titre"}, L.sequence_help));
  }
  diagrams.forEach(function (d, di) {
    sectionDiagrammes.appendChild(el("h3", null, d.title));
    if ((d.sampled_step || 1) > 1) {
      sectionDiagrammes.appendChild(el("p", {"class": "vide"}, L.sequence_sampled
        .replace("{step}", d.sampled_step).replace("{total}", d.total_steps)));
    }
    var etapes = d.steps || [];
    if (!etapes.length) { return; }
    var boutons = el("div", {"class": "boutons-diagramme", "role": "group", "aria-label": L.diagrams});
    var cont = el("div", {"class": "sequence-conteneur", "data-conteneur-sequence": String(di),
      "role": "region", "aria-label": d.title});
    var compteurD = el("p", {"class": "compteur-diagramme", "aria-live": "polite"});
    var pxParMs = 0.08;
    var duree = (etapes[etapes.length - 1].rel_ms - etapes[0].rel_ms) || 1;
    var MARGE_HAUT = 28;
    var espace = svg("svg", {"data-role": "svg-sequence", "data-diagramme": String(di)});
    var nomsColonnes = d.hosts || [];
    var xColonne = function (hote) {
      return nomsColonnes.indexOf(hote) < 0 ? 0
        : ((nomsColonnes.indexOf(hote) + 1) / (nomsColonnes.length + 1)) * 100;
    };
    function dessinerLignesDeVie() {
      nomsColonnes.forEach(function (h) {
        var x = xColonne(h) + "%";
        espace.appendChild(svg("line", {"x1": x, "y1": 12, "x2": x, "y2": 99999,
          "stroke": "#e5e7eb", "stroke-width": 1}));
        var texte = texteSvg(xColonne(h) + 0.5, 10, h, {"font-size": "11px", "font-weight": "650"});
        texte.setAttribute("x", xColonne(h) + "%");
        espace.appendChild(texte);
      });
    }
    function dessinerFenetre() {
      var st = cont.scrollTop || 0;
      var hauteur = cont.clientHeight || 416;
      var yMin = st - 120, yMax = st + hauteur + 120;
      while (espace.childNodes.length) { espace.removeChild(espace.lastChild); }
      dessinerLignesDeVie();
      var rendues = 0;
      etapes.forEach(function (etape) {
        var y = MARGE_HAUT + (etape.rel_ms - etapes[0].rel_ms) * pxParMs;
        if (y < yMin || y > yMax) { return; }
        rendues += 1;
        var x1 = xColonne(etape.src) + "%", x2 = xColonne(etape.dst) + "%";
        var fleche = svg("line", {"x1": x1, "y1": y, "x2": x2, "y2": y,
          "stroke": etape.is_retransmission ? "#b91c1c" : "#2563eb", "stroke-width": 1.2});
        if (etape.is_retransmission) { fleche.setAttribute("class", "trame-retr"); }
        espace.appendChild(fleche);
        espace.appendChild(texteSvg((xColonne(etape.src) + xColonne(etape.dst)) / 2 + "%", y - 3,
          etape.label + " -- " + etape.point + " " + fixe(etape.rel_ms, 1) + " ms",
          {"font-size": "9.5px", "fill": "#374151"}));
      });
      compteurD.textContent = L.sequence_rendered
        .replace("{shown}", rendues).replace("{total}", etapes.length);
      espace.setAttribute("data-rendues", String(rendues));
    }
    function majEchelle() {
      var hauteurTotale = MARGE_HAUT + duree * pxParMs + 24;
      espace.setAttribute("height", String(Math.max(hauteurTotale, 60)));
      espace.setAttribute("viewBox", "0 0 100 " + Math.max(hauteurTotale, 60));
      espace.setAttribute("data-px-ms", String(pxParMs));
    }
    ["zoom-in", "zoom-out", "zoom-reset"].forEach(function (action) {
      var b = el("button", {"type": "button", "data-diagramme": String(di), "data-action": action},
        action === "zoom-in" ? L.sequence_zoom_in
          : action === "zoom-out" ? L.sequence_zoom_out : L.sequence_zoom_reset);
      b.addEventListener("click", function () {
        var st = cont.scrollTop || 0;
        var tHaut = st / pxParMs;
        if (action === "zoom-in") { pxParMs = Math.min(pxParMs * 2, 100); }
        if (action === "zoom-out") { pxParMs = Math.max(pxParMs / 2, 0.0005); }
        if (action === "zoom-reset") { pxParMs = 0.08; }
        majEchelle();
        dessinerFenetre();
        cont.scrollTop = tHaut * pxParMs;
      });
      boutons.appendChild(b);
    });
    cont.appendChild(espace);
    cont.addEventListener("scroll", dessinerFenetre);
    sectionDiagrammes.appendChild(boutons);
    sectionDiagrammes.appendChild(cont);
    sectionDiagrammes.appendChild(compteurD);
    majEchelle();
    dessinerFenetre();
  });
  var carte = doc.comm_map;
  if (carte && (carte.edges || []).length) {
    sectionDiagrammes.appendChild(el("h2", {"id": "titre-carte"}, L.comm_map));
    sectionDiagrammes.appendChild(el("p", {"class": "sous-titre"}, L.comm_map_help));
    var svgCarte = svg("svg", {"class": "carte-svg", "data-role": "svg-carte",
      "role": "img", "aria-label": L.comm_map});
    var hotes = carte.nodes || [];
    var rayon = Math.max(120, 24 * hotes.length);
    var position = {};
    hotes.forEach(function (n, i) {
      var angle = (2 * Math.PI * i) / Math.max(hotes.length, 1);
      position[n.host] = [60 + rayon + rayon * Math.cos(angle), 60 + rayon + rayon * Math.sin(angle)];
    });
    (carte.edges || []).forEach(function (a) {
      var p1 = position[a.src] || [0, 0], p2 = position[a.dst] || [0, 0];
      var ligne = svg("line", {"x1": p1[0], "y1": p1[1], "x2": p2[0], "y2": p2[1],
        "stroke": a.anomalies ? "#b91c1c" : "#2563eb", "stroke-width": 1.2});
      svgCarte.appendChild(ligne);
      svgCarte.appendChild(texteSvg((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2 - 3,
        (a.protocols || []).join(",") + " " + a.bytes + " o", {"font-size": "9px", "fill": "#374151"}));
    });
    hotes.forEach(function (n) {
      var p = position[n.host] || [0, 0];
      var cercle = svg("circle", {"cx": p[0], "cy": p[1], "r": 14,
        "fill": "#f9fafb", "stroke": n.anomalies ? "#b91c1c" : "#374151", "stroke-width": 1.5});
      if (n.anomalies) { cercle.setAttribute("class", "hote-anormal"); }
      svgCarte.appendChild(cercle);
      svgCarte.appendChild(texteSvg(p[0], p[1] + 28, n.host + " (" + n.packets + ")", {"font-size": "10px"}));
    });
    svgCarte.setAttribute("width", String(2 * rayon + 120));
    svgCarte.setAttribute("height", String(2 * rayon + 120));
    sectionDiagrammes.appendChild(svgCarte);
  }
  racine.appendChild(sectionDiagrammes);

  var triage = el("section", {"aria-labelledby": "titre-triage"});
  triage.appendChild(el("h2", {"id": "titre-triage"}, L.triage));
  triage.appendChild(tableau(L.triage_caption, [L.segment, L.score, L.categories, L.findings_count],
    (doc.triage || []).map(function (s) {
      return [s.segment, s.score, (s.categories || []).join(", "), s.finding_count];
    }), L.no_triage));
  racine.appendChild(triage);

  var constats = el("section", {"aria-labelledby": "titre-constats"});
  constats.appendChild(el("h2", {"id": "titre-constats"}, L.findings));
  var preuves = {};
  (doc.evidence_frames || []).forEach(function (p) { preuves[p.ref] = p; });
  var panneauPreuve = el("div", {"id": "detail-preuve", "class": "detail-preuve", "aria-live": "polite"});
  function texteTrame(c) { return "#" + c.frame_number + " (" + fixe(c.rel_ms, 3) + " ms)"; }
  function montrerPreuve(ref, bouton) {
    panneauPreuve.textContent = "";
    panneauPreuve.setAttribute("data-preuve", ref);
    var p = preuves[ref];
    var morceaux = ref.split("#");
    var titre = L.evidence_title.replace("{point}", morceaux[0]).replace("{frame}", morceaux[1]);
    panneauPreuve.appendChild(el("h3", p ? {"id": p.anchor} : null, titre));
    boutonsPreuve.forEach(function (b) { b.setAttribute("aria-pressed", b === bouton ? "true" : "false"); });
    if (!p || !p.found) { panneauPreuve.appendChild(el("p", {"class": "vide"}, L.evidence_not_found)); return; }
    panneauPreuve.appendChild(el("p", null, p.summary));
    var t = panneauPreuve.appendChild(el("table", {"class": "diagramme-preuve"}));
    t.appendChild(el("caption", null, L.evidence_caption));
    var tr = el("tr");
    tr.appendChild(el("th", {"scope": "col"}, L.evidence_frame));
    p.points.forEach(function (pt) { tr.appendChild(el("th", {"scope": "col"}, pt)); });
    t.appendChild(el("thead")).appendChild(tr);
    var corps = t.appendChild(el("tbody"));
    p.rows.forEach(function (r) {
      var ligne = corps.appendChild(el("tr", r.evidence ? {"class": "trame-preuve", "aria-current": "true"} : null));
      ligne.appendChild(el("th", {"scope": "row"}, r.summary));
      p.points.forEach(function (pt) {
        var c = r.cells[pt];
        ligne.appendChild(el("td", c ? null : {"class": "sip-perdu"}, c ? texteTrame(c) : L.evidence_absent));
      });
    });
    if (p.transits.length) {
      var dl = panneauPreuve.appendChild(el("dl"));
      p.transits.forEach(function (tr2) {
        dl.appendChild(el("dt", null, L.transit + " " + tr2.segment));
        var brut = tr2.corrected ? "" : " (" + L.transit_raw + ")";
        dl.appendChild(el("dd", null, fixe(tr2.transit_ms, 3) + " ms" + brut));
      });
    }
  }
  var boutonsPreuve = [];
  function cellulePreuves(f) {
    var refs = (f.evidence || []).filter(function (e) {
      return e.frame_number !== undefined && e.frame_number !== null;
    });
    if (!refs.length) { return ""; }
    var span = el("span", {"class": "preuves"});
    refs.forEach(function (e) {
      var ref = e.point + "#" + e.frame_number;
      var aria = L.evidence_title.replace("{point}", e.point).replace("{frame}", e.frame_number);
      var b = el("button", {"type": "button", "class": "preuve", "data-preuve": ref, "aria-controls": "detail-preuve",
        "aria-pressed": "false", "aria-label": aria}, e.point + " #" + e.frame_number);
      b.addEventListener("click", function () { montrerPreuve(ref, b); });
      boutonsPreuve.push(b);
      span.appendChild(b);
    });
    return span;
  }
  var filtres = el("div", {"class": "filtres", "role": "group", "aria-label": L.filters});
  var criteres = [["severite", L.severity, "severity"], ["segment", L.segment, "segment"],
    ["protocole", L.protocol, "protocol"]];
  var menus = criteres.map(function (c) {
    var id = "filtre-" + c[0];
    var lab = filtres.appendChild(el("label", {"for": id}, c[1] + " "));
    var menu = el("select", {"id": id});
    menu.appendChild(el("option", {"value": ""}, L.filter_all));
    var vus = [];
    findings.forEach(function (f) {
      var v = f[c[2]];
      if (v !== null && v !== undefined && vus.indexOf(v) < 0) { vus.push(v); }
    });
    if (c[2] === "severity") {
      vus.sort(function (a, b) { return L.severity_order.indexOf(a) - L.severity_order.indexOf(b); });
    } else { vus.sort(); }
    vus.forEach(function (v) {
      menu.appendChild(el("option", {"value": v}, c[2] === "severity" ? (L.severities[v] || v) : v));
    });
    lab.appendChild(menu);
    return menu;
  });
  var compteur = el("p", {"id": "compteur-constats", "class": "compteur", "aria-live": "polite"});
  var lignesConstats = [];
  function filtrer() {
    var choix = menus.map(function (m) { return m.value || ""; });
    var n = 0;
    lignesConstats.forEach(function (ligne, i) {
      var f = findings[i];
      var garde = criteres.every(function (c, j) { return !choix[j] || String(f[c[2]]) === choix[j]; });
      if (garde) { ligne.removeAttribute("hidden"); n += 1; } else { ligne.setAttribute("hidden", ""); }
    });
    compteur.textContent = L.counter.replace("{shown}", n).replace("{total}", findings.length);
  }
  menus.forEach(function (m) { m.addEventListener("change", filtrer); });
  var tc = tableau(L.findings_caption, [L.severity, L.category, L.protocol, L.segment, L.message, L.evidence],
    findings.map(function (f) {
      return [badge(f.severity), f.category, f.protocol, f.segment, f.message, cellulePreuves(f)];
    }), L.no_findings);
  tc.setAttribute("id", "table-constats");
  if (findings.length) {
    constats.appendChild(filtres);
    constats.appendChild(compteur);
    tc.childNodes[tc.childNodes.length - 1].childNodes.forEach(function (ligne) { lignesConstats.push(ligne); });
    filtrer();
  }
  constats.appendChild(tc);
  if (boutonsPreuve.length) {
    panneauPreuve.appendChild(el("p", {"class": "vide"}, L.evidence_hint));
    constats.appendChild(panneauPreuve);
  }
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
        "path": _("Chemin observe"),
        "path_help": _("Survoler un segment, ou le selectionner au clavier (Tab puis fleches), pour voir son detail."),
        "path_hint": _("Aucun segment selectionne."),
        "no_path": _("Aucun segment : une seule capture, ou aucun couple de points correle."),
        "path_caption": _("Metriques par segment, dans l'ordre du chemin"),
        "measured": _("mesure"),
        "not_measurable": _("non mesurable"),
        "not_measurable_help": _(
            "Aucun paquet correle ni aucune perte observee sur ce segment : ses valeurs sont inconnues, pas nulles."
        ),
        "not_measured": _("non mesure"),
        "losses": _("pertes"),
        "state": _("Etat"),
        "sip": _("Echelle SIP multi-points"),
        "sip_help": _(
            "Chaque message SIP de l'appel, point de capture par point (date en ms depuis le debut de l'appel). "
            "ABSENT : vu a un autre point mais pas a celui-ci. Retransmis : vu plusieurs fois au meme point. "
            "Reecrit : SDP, premier Via ou Contact differents du premier point ou le message a ete vu "
            "(ALG, SBC ; un proxy ajoute aussi son propre Via). Les 100 Trying, produits a chaque saut, "
            "ne sont jamais declares perdus."
        ),
        "sip_caption": _("Messages SIP de l'appel, une colonne par point de capture"),
        "sip_summary": _("{total} message(s) : {lost} perdu(s), {retransmitted} retransmis, {rewritten} reecrit(s)."),
        "sip_truncated": _("{n} message(s) non represente(s)."),
        "sip_absent": _("ABSENT"),
        "sip_hop": _("saut par saut"),
        "sip_retransmitted": _("retransmis"),
        "sip_rewritten": _("reecrit"),
        "no_sip": _("Aucun message SIP pour cet appel."),
        "protocol": _("Protocole"),
        "filters": _("Filtrer les constats"),
        "filter_all": _("Tous"),
        "counter": _("{shown} / {total} constat(s) affiche(s)"),
        "diagrams": _("Diagrammes de sequence"),
        "sequence_help": _(
            "Echange des flux principaux, NON TRONQUE : defilez et zoomez dans le temps. "
            "Chaque fleche est un paquet vu a un point de capture ; le meme paquet vu a "
            "deux points donne deux fleches, et leur ecart vertical mesure le temps de transit."
        ),
        "sequence_sampled": _(
            "Echantillonnage : 1 ligne sur {step} ({total} paquets dans le flux) -- "
            "au-dela, le fichier aurait depasse le poids vise."
        ),
        "sequence_no_flows": _("Aucun flux corrélé : aucun diagramme."),
        "sequence_zoom_in": _("Zoom temporel +"),
        "sequence_zoom_out": _("Zoom temporel -"),
        "sequence_zoom_reset": _("Échelle initiale"),
        "sequence_rendered": _("{shown}/{total} ligne(s) rendue(s) dans la fenêtre visible"),
        "comm_map": _("Carte des communications"),
        "comm_map_help": _(
            "Qui parle a qui : aretes orientees, protocoles, volumes et signaux "
            "(retransmissions, expertise) ; les hotes anormaux sont en rouge."
        ),
        "comm_map_caption": _("Communications observées"),
        "comm_map_empty": _("Aucune communication corrélée."),
        "source": _("Source"),
        "destination": _("Destination"),
        "protocols": _("Protocoles"),
        "packets": _("Paquets"),
        "octets": _("Octets"),
        "anomalies": _("Anomalies"),
        "evidence": _("Preuves"),
        "evidence_hint": _("Selectionner une preuve pour voir la trame a chaque point de capture."),
        "evidence_title": _("Preuve : trame {frame} au point {point}"),
        "evidence_not_found": _("Trame introuvable dans les paquets correles : aucun diagramme."),
        "evidence_caption": _(
            "Trame de preuve et ses voisines de la meme conversation, vues a chaque point (date en ms depuis la preuve)"
        ),
        "evidence_frame": _("Trame"),
        "evidence_absent": _("non vue"),
        "evidence_static": _("Preuves vues a chaque point"),
        "transit": _("Transit"),
        "transit_raw": _("non corrige du decalage d'horloge"),
        # Protocole filtrable d'un constat sans cle ``protocol`` (#1077).
        "category_protocols": dict(CATEGORY_PROTOCOLS),
        "generic_protocol": GENERIC_PROTOCOL,
        # Separateur decimal des valeurs affichees (« . » en anglais).
        "decimal": _(","),
        "segment_fields": [{**champ, "libelle": _(str(champ["libelle"]))} for champ in _SEGMENT_FIELDS],
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


def _static_value(seg: dict, champ: dict, labels: dict) -> str:
    """Valeur affichee d'une metrique de segment, meme format que le JS."""
    logger.debug("_static_value: entrée ({})", champ["cle"])
    v = seg.get(champ["cle"])
    if v is None:
        logger.debug("_static_value: si valeur inconnue -> retour libelle non mesure")
        return labels["not_measured"]
    if champ.get("format") == "debit":
        texte = f"{v / 1e6:.2f} Mbit/s" if v >= 1e6 else f"{v / 1e3:.1f} kbit/s"
        logger.debug("_static_value: si debit -> retour {}", texte)
        return texte.replace(".", labels["decimal"])
    texte = f"{v:.{champ['decimales']}f}".replace(".", labels["decimal"]) if "decimales" in champ else str(v)
    if champ.get("unite"):
        texte += " " + champ["unite"]
    logger.debug("_static_value: retour {}", texte)
    return texte


def _static_path(doc: dict, labels: dict) -> str:
    """Vue chemin sans JavaScript : un tableau, une ligne par segment."""
    logger.debug("_static_path: entrée")
    segments = doc.get("path_metrics") or []
    champs = labels["segment_fields"]
    tableau = _static_table(
        labels["path_caption"],
        [labels["segment"], labels["state"], *(c["libelle"] for c in champs)],
        [
            [
                _e(s.get("segment")),
                _e(labels["measured"] if s.get("measured") else labels["not_measurable"]),
                *(_e(_static_value(s, c, labels)) for c in champs),
            ]
            for s in segments
        ],
        labels["no_path"],
    )
    logger.debug("_static_path: retour ({} segment(s))", len(segments))
    return f"<h2>{_e(labels['path'])}</h2>{tableau}"


_SIP_FIELD_NAMES = {"sdp": "SDP", "via": "Via", "contact": "Contact"}


def _sip_cell(message: dict, point: str, labels: dict) -> tuple[str, str]:
    """Texte et classe CSS d'une cellule de l'echelle SIP (meme rendu que le JS)."""
    logger.debug("_sip_cell: entrée ({})", point)
    cell = (message.get("cells") or {}).get(point)
    if cell is None:
        if point in (message.get("lost_at") or []):
            logger.debug("_sip_cell: si message perdu -> retour absent")
            return labels["sip_absent"], "sip-perdu"
        logger.debug("_sip_cell: si saut par saut -> retour tiret")
        return f"\u2014 ({labels['sip_hop']})", ""
    parts = [f"{cell['rel_ms']:.1f}".replace(".", labels["decimal"]) + " ms"]
    classe = ""
    if cell.get("count", 1) > 1:
        parts.append(f"x{cell['count']} ({labels['sip_retransmitted']})")
        classe = "sip-retransmis"
    if cell.get("rewritten"):
        noms = ", ".join(_SIP_FIELD_NAMES.get(f, f) for f in cell["rewritten"])
        parts.append(f"{labels['sip_rewritten']} : {noms}")
        classe = "sip-reecrit"
    logger.debug("_sip_cell: retour texte de cellule")
    return " ; ".join(parts), classe


def _static_sip(doc: dict, labels: dict) -> str:
    """Echelle SIP sans JavaScript ; chaine vide sans SIP."""
    logger.debug("_static_sip: entrée")
    echelles = doc.get("sip_ladders") or []
    if not echelles:
        logger.debug("_static_sip: si aucune echelle -> retour chaine vide")
        return ""
    blocs = [f"<h2>{_e(labels['sip'])}</h2><p>{_e(labels['sip_help'])}</p>"]
    for e in echelles:
        resume = labels["sip_summary"].format(
            total=e["total_messages"], lost=e["lost"], retransmitted=e["retransmitted"], rewritten=e["rewritten"]
        )
        if e.get("truncated"):
            resume += " " + labels["sip_truncated"].format(n=e["truncated"])
        lignes = []
        for m in e.get("messages") or []:
            cellules = [_e(f"{m['message']} ({m['cseq']})")]
            for p in e["points"]:
                texte, classe = _sip_cell(m, p, labels)
                cellules.append(f'<span class="{classe}">{_e(texte)}</span>' if classe else _e(texte))
            lignes.append(cellules)
        blocs.append(
            f"<h3>Call-ID {_e(e['call_id'])}</h3><p>{_e(resume)}</p>"
            + _static_table(labels["sip_caption"], [labels["message"], *e["points"]], lignes, labels["no_sip"])
        )
    logger.debug("_static_sip: retour ({} appel(s))", len(echelles))
    return "".join(blocs)


def _static_evidence_links(finding: dict, ancres: dict) -> str:
    """Preuves d'un constat (sans JS) : lien vers le diagramme statique s'il existe."""
    logger.debug("_static_evidence_links: entrée")
    liens = []
    for e in finding.get("evidence") or []:
        if e.get("frame_number") is None:
            continue
        texte = _e(f"{e['point']} #{e['frame_number']}")
        ancre = ancres.get(f"{e['point']}#{e['frame_number']}")
        liens.append(f'<a href="#{_e(ancre)}">{texte}</a>' if ancre else texte)
    logger.debug("_static_evidence_links: retour {} preuve(s)", len(liens))
    return ", ".join(liens)


def _static_sequence(doc: dict, labels: dict) -> str:
    """Diagrammes de sequence sans JS : le tableau integral des lignes
    (l'echantillonnage, s'il y en a, est signe) -- meme information que le
    rendu interactif, sans defilement ni zoom."""
    logger.debug("_static_sequence: entrée")
    blocs = []
    for i, d in enumerate(doc.get("sequence_diagrams") or []):
        titre = f"{_e(d.get('title') or labels['diagrams'])} ({_e(i)})"
        entete = f"<h3>{titre}</h3>"
        if (d.get("sampled_step") or 1) > 1:
            entete += (
                '<p class="vide">'
                + _e(labels["sequence_sampled"].format(step=d.get("sampled_step"), total=d.get("total_steps")))
                + "</p>"
            )
        lignes = [
            [
                _ms(etape.get("rel_ms", 0.0), labels),
                _e(etape.get("label") or "?"),
                _e(etape.get("src")),
                _e(etape.get("dst")),
                _e(etape.get("point")),
            ]
            for etape in d.get("steps") or []
        ]
        blocs.append(
            entete
            + _static_table(
                labels["comm_map_caption"],
                [
                    labels["evidence_frame"],
                    labels["category"],
                    labels["source"],
                    labels["destination"],
                    labels["segment"],
                ],
                lignes,
                labels["sequence_no_flows"],
            )
        )
    if not blocs:
        logger.debug("_static_sequence: retour vide")
        return ""
    corps = f"<h2>{_e(labels['diagrams'])}</h2>" + "".join(blocs)
    logger.debug("_static_sequence: retour {} caractere(s)", len(corps))
    return corps


def _static_comm_map(doc: dict, labels: dict) -> str:
    """Carte des communications sans JS : tableau des aretes orientees
    (source, destination, protocoles, paquets, octets, anomalies)."""
    logger.debug("_static_comm_map: entrée")
    carte = doc.get("comm_map") or {}
    lignes = [
        [
            _e(a.get("src")),
            _e(a.get("dst")),
            _e(", ".join(a.get("protocols") or [])),
            _e(a.get("packets")),
            _e(a.get("bytes")),
            _e(a.get("anomalies") or 0),
        ]
        for a in carte.get("edges") or []
    ]
    corps = f"<h2>{_e(labels['comm_map'])}</h2>" + _static_table(
        labels["comm_map_caption"],
        [
            labels["source"],
            labels["destination"],
            labels["protocols"],
            labels["packets"],
            labels["octets"],
            labels["anomalies"],
        ],
        lignes,
        labels["comm_map_empty"],
    )
    logger.debug("_static_comm_map: retour {} caractere(s)", len(corps))
    return corps


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
    ancres = {p["ref"]: p["anchor"] for p in doc.get("evidence_frames") or [] if p.get("found")}
    constats = _static_table(
        labels["findings_caption"],
        [
            labels["severity"],
            labels["category"],
            labels["protocol"],
            labels["segment"],
            labels["message"],
            labels["evidence"],
        ],
        [
            [
                f'<span class="badge sev-{_e(f.get("severity"))}">'
                f"{_e(labels['severities'].get(f.get('severity'), f.get('severity')))}</span>",
                _e(f.get("category")),
                _e(f.get("protocol") or finding_protocol(f.get("category"))),
                _e(f.get("segment")),
                _e(f.get("message")),
                _static_evidence_links(f, ancres),
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
        f"{_static_path(doc, labels)}"
        f"{_static_sip(doc, labels)}"
        f"{_static_sequence(doc, labels)}"
        f"{_static_comm_map(doc, labels)}"
        f"<h2>{_e(labels['triage'])}</h2>{triage}"
        f"<h2>{_e(labels['findings'])}</h2>{constats}"
        f"{_static_evidence(doc, labels)}"
    )
    logger.debug("_static_body: retour {} caractere(s)", len(corps))
    return corps


def _ms(v: float, labels: dict) -> str:
    """Duree en ms a 3 decimales, separateur decimal de la langue (comme ``fixe`` en JS)."""
    logger.debug("_ms: entrée")
    texte = f"{v:.3f}".replace(".", labels["decimal"])
    logger.debug("_ms: retour {}", texte)
    return texte


def _static_evidence(doc: dict, labels: dict) -> str:
    """Diagrammes de preuve statiques (sans JS) : un tableau par preuve
    trouvee, ancre ``preuve-<point>-<trame>`` comme le rendu JS."""
    logger.debug("_static_evidence: entrée")
    blocs = []
    for p in doc.get("evidence_frames") or []:
        if not p.get("found"):
            continue
        ev_point = p["ref"].rsplit("#", 1)[0]
        titre = labels["evidence_title"].format(point=ev_point, frame=p["frame_number"])
        lignes = [
            [_e(r["summary"])]
            + [
                _e(f"#{c['frame_number']} ({_ms(c['rel_ms'], labels)} ms)")
                if (c := r["cells"].get(pt))
                else _e(labels["evidence_absent"])
                for pt in p["points"]
            ]
            for r in p["rows"]
        ]
        transits = "".join(
            f"<li>{_e(labels['transit'])} {_e(t['segment'])} : {_ms(t['transit_ms'], labels)} ms"
            f"{'' if t['corrected'] else ' (' + _e(labels['transit_raw']) + ')'}</li>"
            for t in p["transits"]
        )
        blocs.append(
            f'<h3 id="{_e(p["anchor"])}">{_e(titre)}</h3>'
            + _static_table(labels["evidence_caption"], [labels["evidence_frame"], *p["points"]], lignes, "")
            + (f"<ul>{transits}</ul>" if transits else "")
        )
    if not blocs:
        logger.debug("_static_evidence: retour vide")
        return ""
    corps = f"<h2>{_e(labels['evidence_static'])}</h2>" + "".join(blocs)
    logger.debug("_static_evidence: retour {} preuve(s)", len(blocs))
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
