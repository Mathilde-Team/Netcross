// SPDX-License-Identifier: GPL-3.0-or-later
// Rendu headless du JavaScript embarque du rapport HTML (issue #1075).
//
// DOM minimal, sans dependance npm : juste ce qu'utilise le script du
// rapport (createElement, setAttribute, appendChild, removeChild,
// textContent, addEventListener, focus). Entree (stdin, JSON) :
//   {"script": "...", "elements": {"id": "texte"}, "actions": [...]}
// Sortie (stdout, JSON) : l'arbre de #rapport et l'etat apres chaque action.
"use strict";

class Node {
  constructor(tag) {
    this.tagName = tag;
    this.attributes = {};
    this.childNodes = [];
    this.parentNode = null;
    this._texte = "";
    this._ecouteurs = {};
  }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  removeAttribute(k) { delete this.attributes[k]; }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  appendChild(n) { n.parentNode = this; this.childNodes.push(n); return n; }
  removeChild(n) { this.childNodes = this.childNodes.filter((c) => c !== n); n.parentNode = null; return n; }
  get firstChild() { return this.childNodes[0] || null; }
  get textContent() { return this._texte + this.childNodes.map((c) => c.textContent).join(""); }
  set textContent(v) { this.childNodes = []; this._texte = String(v); }
  addEventListener(type, f) { (this._ecouteurs[type] = this._ecouteurs[type] || []).push(f); }
  dispatch(type, init) {
    const ev = Object.assign({ type: type, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } }, init);
    (this._ecouteurs[type] || []).forEach((f) => f.call(this, ev));
    return ev;
  }
  focus() { document.activeElement = this; this.dispatch("focus"); }
}

function parcourir(n, f) { f(n); n.childNodes.forEach((c) => parcourir(c, f)); }

const entree = JSON.parse(require("fs").readFileSync(0, "utf8"));
const elements = {};
Object.keys(entree.elements).forEach((id) => {
  const n = new Node(id === "rapport" ? "main" : "script");
  n.setAttribute("id", id);
  n.textContent = entree.elements[id];
  elements[id] = n;
});
const document = {
  activeElement: null,
  createElement: (tag) => new Node(tag),
  getElementById(id) {
    if (elements[id]) { return elements[id]; }
    let trouve = null;
    Object.values(elements).forEach((r) => parcourir(r, (n) => { if (!trouve && n.getAttribute("id") === id) { trouve = n; } }));
    return trouve;
  },
};
global.Node = Node;
global.document = document;
// Le rendu ne doit jamais toucher au reseau ni a innerHTML.
global.fetch = () => { throw new Error("requete reseau interdite"); };
global.XMLHttpRequest = function () { throw new Error("requete reseau interdite"); };

function serialiser(n) {
  return {
    tag: n.tagName,
    attrs: n.attributes,
    text: n._texte,
    children: n.childNodes.map(serialiser),
  };
}
function parAttribut(attr, valeur) {
  let b = null;
  parcourir(elements.rapport, (n) => { if (!b && n.getAttribute(attr) === String(valeur)) { b = n; } });
  if (!b) { throw new Error("element absent : " + attr + "=" + valeur); }
  return b;
}
function bouton(i) {
  let b = null;
  parcourir(elements.rapport, (n) => { if (n.tagName === "button" && n.getAttribute("data-index") === String(i)) { b = n; } });
  if (!b) { throw new Error("segment absent : " + i); }
  return b;
}
function etat() {
  const d = document.getElementById("detail-segment");
  const actif = document.activeElement;
  const p = document.getElementById("detail-preuve");
  const c = document.getElementById("compteur-constats");
  return {
    preuve: p ? p.textContent : null,
    compteur: c ? c.textContent : null,
    detail: d ? d.textContent : null,
    detail_segment: d ? d.getAttribute("data-segment") : null,
    actif: actif ? actif.getAttribute("data-index") : null,
  };
}

new Function(entree.script)();
const etats = [];
(entree.actions || []).forEach((a) => {
  // Menu deroulant (#1077) : on fixe sa valeur puis on declenche « change ».
  if (a.type === "choix") {
    const m = parAttribut("id", a.id);
    m.value = a.value;
    m.dispatch("change");
    etats.push(Object.assign(etat(), { empeche: false }));
    return;
  }
  const b = a.attr ? parAttribut(a.attr, a.valeur) : bouton(a.index);
  let ev = null;
  if (a.type === "survol") { ev = b.dispatch("mouseenter"); }
  if (a.type === "focus") { b.focus(); }
  if (a.type === "clic") { ev = b.dispatch("click"); }
  if (a.type === "touche") { ev = b.dispatch("keydown", { key: a.key }); }
  etats.push(Object.assign(etat(), { empeche: ev ? ev.defaultPrevented : false }));
});
process.stdout.write(JSON.stringify({ rapport: serialiser(elements.rapport), etats: etats }));
