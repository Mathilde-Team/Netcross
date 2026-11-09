# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.metrics_export -- catalogue des metriques Prometheus /
OpenMetrics de Netcross et production des series depuis un rapport
(issue #1110, sous-issue 1/5 du chantier #1003).

Ce module FIGE les noms, types, unites et etiquettes AVANT toute exposition :
l'ecriture du texte OpenMetrics et du fichier ``.prom`` (#1112), la route
``/metrics`` (#1113) et le tableau de bord Grafana (#1118) s'appuieront sur
``METRICS`` et ``collect_samples()`` sans redefinir de nom.

Conventions (https://prometheus.io/docs/practices/naming/) :

- prefixe ``netcross_`` puis domaine (``point``, ``segment``, ``health``,
  ``findings``), snake_case ;
- unite de base SI en suffixe (``_seconds``, jamais de millisecondes) et
  ``_ratio`` pour une proportion dans [0, 1] ;
- ``_total`` pour les compteurs ; un resume (``summary``) porte l'etiquette
  ``quantile`` et ses series ``_count`` / ``_sum``.

Cardinalite bornee : seules les etiquettes ``run``, ``point``, ``segment``,
``severity`` et ``quantile`` existent. **Aucune adresse IP, aucun port,
aucun nom d'hote ni aucun identifiant de flux** n'est jamais une valeur
d'etiquette : le nombre de series ne depend que du nombre de points de
capture et de segments, jamais du volume de trafic (voir
``series_upper_bound``). Les points au-dela de ``max_points`` sont
regroupes sous ``point="_autres"`` (idem pour les segments) afin de garder
la borne meme si l'appelant fournit un nombre anormal de points.

Exposition texte (issue #1112, sous-issue 2/5) :

- ``render_prometheus_text()`` : format texte Prometheus 0.0.4, celui que lit
  le *textfile collector* de node_exporter et que valide
  ``promtool check metrics`` ; ``write_prom_file()`` l'ecrit de facon
  atomique (fichier temporaire du meme dossier puis ``os.replace``) pour que
  node_exporter ne lise jamais un fichier a moitie ecrit ;
- ``render_openmetrics()`` : OpenMetrics 1.0 (``# UNIT``, famille sans
  ``_total``, ``# EOF`` final), pour la route ``/metrics`` (#1113) ;
- ``redact_samples()`` : avec ``--redact``, toute adresse IP ou MAC presente
  dans une valeur d'etiquette (point de capture nomme d'apres son adresse,
  identifiant de run) est remplacee par le pseudonyme du run (meme table que
  les paquets et ``--redact-map``). Les series elles-memes ne portent
  jamais d'adresse (voir ci-dessus).
"""

from __future__ import annotations

import contextlib
import math
import os
import re
import tempfile
from dataclasses import dataclass, replace

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

COUNTER = "counter"
GAUGE = "gauge"
SUMMARY = "summary"

ALLOWED_LABELS = frozenset({"run", "point", "segment", "severity", "quantile"})
SEVERITIES = ("anomalie", "a_surveiller", "info")
DELAY_QUANTILES = ("0.5", "0.95", "0.99")
OVERFLOW_LABEL = "_autres"
DEFAULT_MAX_POINTS = 32
DEFAULT_MAX_SEGMENTS = 64


@dataclass(frozen=True)
class MetricSpec:
    """Definition figee d'une metrique (nom, type, unite, aide, etiquettes)."""

    name: str
    type: str  # COUNTER | GAUGE | SUMMARY
    unit: str  # "" (sans unite), "seconds", "ratio", "packets", "flows"
    help: str
    labels: tuple[str, ...]


METRICS: tuple[MetricSpec, ...] = (
    MetricSpec("netcross_health_score", GAUGE, "", "Score de sante global de l'analyse (0 a 100).", ("run",)),
    MetricSpec(
        "netcross_findings_total",
        COUNTER,
        "",
        "Nombre de constats de l'analyse par severite.",
        ("run", "severity"),
    ),
    MetricSpec(
        "netcross_point_packets_total", COUNTER, "packets", "Paquets vus au point de capture.", ("run", "point")
    ),
    MetricSpec("netcross_point_flows_total", COUNTER, "flows", "Flux vus au point de capture.", ("run", "point")),
    MetricSpec(
        "netcross_point_lost_flows_total",
        COUNTER,
        "flows",
        "Flux vus au point precedent et absents de ce point (pertes).",
        ("run", "point"),
    ),
    MetricSpec(
        "netcross_point_retransmissions_total",
        COUNTER,
        "packets",
        "Retransmissions TCP observees au point de capture.",
        ("run", "point"),
    ),
    MetricSpec(
        "netcross_segment_loss_ratio",
        GAUGE,
        "ratio",
        "Part des flux vus en amont du segment et perdus en aval (0 a 1).",
        ("run", "segment"),
    ),
    MetricSpec(
        "netcross_segment_delay_seconds",
        SUMMARY,
        "seconds",
        "Delai de transit des flux entre les deux points du segment.",
        ("run", "segment", "quantile"),
    ),
    MetricSpec(
        "netcross_segment_triage_score",
        GAUGE,
        "",
        "Score de priorite du segment dans le triage (plus haut = plus prioritaire).",
        ("run", "segment"),
    ),
)

METRICS_BY_NAME = {m.name: m for m in METRICS}


@dataclass(frozen=True)
class Sample:
    """Une serie : nom (eventuellement suffixe ``_count``/``_sum``), etiquettes, valeur."""

    name: str
    labels: tuple[tuple[str, str], ...]
    value: float

    def label(self, key: str) -> str | None:
        """Valeur de l'etiquette ``key`` (None si absente)."""
        logger.debug("Sample.label: retour valeur")
        return dict(self.labels).get(key)


def series_upper_bound(n_points: int, n_segments: int) -> int:
    """Nombre maximal de series pour ``n_points`` points et ``n_segments``
    segments (apres plafonnement). Independant du volume de trafic."""
    logger.debug("series_upper_bound: entrée ({} point(s), {} segment(s))", n_points, n_segments)
    per_point = 4  # packets, flows, lost_flows, retransmissions
    per_segment = 1 + len(DELAY_QUANTILES) + 2 + 1  # loss_ratio, quantiles, _count/_sum, triage
    borne = 1 + len(SEVERITIES) + per_point * n_points + per_segment * n_segments
    logger.debug("series_upper_bound: retour {}", borne)
    return borne


def _cap(values: list[str], limit: int) -> dict[str, str]:
    """Associe chaque valeur a son etiquette : les ``limit - 1`` premieres
    gardent leur nom, les suivantes sont regroupees sous OVERFLOW_LABEL."""
    logger.debug("_cap: entrée ({} valeur(s), limite {})", len(values), limit)
    if len(values) <= limit:
        logger.debug("_cap: si sous la limite -> retour identite")
        return {v: v for v in values}
    garde = values[: limit - 1]
    mapping = {v: (v if v in garde else OVERFLOW_LABEL) for v in values}
    logger.debug("_cap: retour avec regroupement de {} valeur(s)", len(values) - len(garde))
    return mapping


def _quantile(sorted_values: list[float], q: float) -> float:
    """Quantile par interpolation lineaire (meme definition que numpy par defaut)."""
    logger.debug("_quantile: entrée")
    pos = (len(sorted_values) - 1) * q
    bas = int(pos)
    haut = min(bas + 1, len(sorted_values) - 1)
    valeur = sorted_values[bas] + (sorted_values[haut] - sorted_values[bas]) * (pos - bas)
    logger.debug("_quantile: retour float")
    return valeur


def segment_label(a: str, b: str) -> str:
    """Etiquette ``segment`` d'une paire de points (meme forme que les constats)."""
    logger.debug("segment_label: retour str")
    return f"{a} -> {b}"


def collect_samples(
    r,
    run: str,
    findings=None,
    max_points: int = DEFAULT_MAX_POINTS,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
) -> list[Sample]:
    """Series du catalogue pour le rapport ``r`` (``netcross_core.models.Report``).

    ``run`` : identifiant de l'analyse (etiquette ``run``). ``findings`` :
    constats deja calcules (sinon ``synthesis.build_findings(r)``). Ordre de
    sortie deterministe : ordre de ``METRICS``, puis ordre des points/segments.
    """
    logger.debug("collect_samples: entrée (run={})", run)
    if max_points < 2 or max_segments < 2:
        logger.debug("collect_samples: si plafond < 2 -> ValueError")
        raise ValueError("max_points et max_segments doivent etre >= 2")
    from netcross_report.synthesis import build_findings
    from netcross_report.triage import health_score, rank_segments

    if findings is None:
        findings = build_findings(r)
    findings = list(findings)
    ranked = rank_segments(findings)
    points = list(r.points)
    pairs = [tuple(p) for p in r.pairs]
    point_of = _cap(points, max_points)
    segment_of = _cap([segment_label(a, b) for a, b in pairs], max_segments)

    out: list[Sample] = []

    def add(name: str, value: float, **labels: str) -> None:
        out.append(Sample(name, (("run", run), *sorted(labels.items())), float(value)))
        logger.debug("collect_samples.add: retour (serie {})", name)

    add("netcross_health_score", health_score(ranked))
    for sev in SEVERITIES:
        add("netcross_findings_total", sum(1 for f in findings if f.severity == sev), severity=sev)

    for metric, source in (
        ("netcross_point_packets_total", getattr(r, "packet_count", {})),
        ("netcross_point_flows_total", r.seen_count),
        ("netcross_point_lost_flows_total", r.loss_count),
        ("netcross_point_retransmissions_total", r.retrans),
    ):
        cumul: dict[str, float] = {}
        for p in points:
            cumul[point_of[p]] = cumul.get(point_of[p], 0) + source.get(p, 0)
        for lbl, v in cumul.items():
            add(metric, v, point=lbl)

    # Pertes : un flux absent de b est compte au premier point manquant
    # (Report.loss_count[b]) ; base = flux vus au point amont a.
    pertes: dict[str, list[float]] = {}
    for a, b in pairs:
        acc = pertes.setdefault(segment_of[segment_label(a, b)], [0, 0])
        acc[0] += r.loss_count.get(b, 0)
        acc[1] += r.seen_count.get(a, 0)
    for lbl, (lost, base) in pertes.items():
        add("netcross_segment_loss_ratio", min(lost / base, 1.0) if base else 0.0, segment=lbl)

    delais: dict[str, list[float]] = {}
    for a, b in pairs:
        delais.setdefault(segment_of[segment_label(a, b)], []).extend(ms / 1000.0 for ms in r.latency.get((a, b), []))
    for lbl, valeurs in delais.items():
        valeurs.sort()
        for q in DELAY_QUANTILES:
            add(
                "netcross_segment_delay_seconds",
                _quantile(valeurs, float(q)) if valeurs else float("nan"),
                segment=lbl,
                quantile=q,
            )
        add("netcross_segment_delay_seconds_count", len(valeurs), segment=lbl)
        add("netcross_segment_delay_seconds_sum", sum(valeurs), segment=lbl)

    scores = {s.segment: s.score for s in ranked}
    vus: set[str] = set()
    for a, b in pairs:
        lbl = segment_of[segment_label(a, b)]
        if lbl in vus:
            continue
        vus.add(lbl)
        brut = [k for k, v in segment_of.items() if v == lbl]
        add("netcross_segment_triage_score", sum(scores.get(k, 0) for k in brut), segment=lbl)

    logger.debug("collect_samples: retour {} serie(s)", len(out))
    return out


# -- exposition texte (issue #1112) ------------------------------------------------------


def collect_live_samples(snapshot: dict, run: str) -> list[Sample]:
    """Compteurs réellement mesurés au dernier relevé direct, sans faux zéros."""
    logger.debug("collect_live_samples: entrée")
    points = snapshot["points"]
    labels = _cap(list(points), DEFAULT_MAX_POINTS)
    samples: list[Sample] = []
    for metric, field in (
        ("netcross_point_packets_total", "packets"),
        ("netcross_point_retransmissions_total", "retransmissions"),
    ):
        totals: dict[str, float] = {}
        for point, values in points.items():
            label = labels[point]
            totals[label] = totals.get(label, 0.0) + values[field]
        samples.extend(
            Sample(metric, (("run", run), ("point", label)), float(value)) for label, value in totals.items()
        )
    logger.debug("collect_live_samples: retour {} série(s)", len(samples))
    return samples


def _family(sample_name: str) -> MetricSpec | None:
    """Metrique du catalogue a laquelle appartient une serie (``_count`` et
    ``_sum`` d'un resume compris)."""
    logger.debug("_family: entrée ({})", sample_name)
    spec = METRICS_BY_NAME.get(sample_name)
    if spec is None:
        for suffixe in ("_count", "_sum"):
            if sample_name.endswith(suffixe):
                spec = METRICS_BY_NAME.get(sample_name[: -len(suffixe)])
                break
    logger.debug("_family: retour {}", spec.name if spec else None)
    return spec


def _escape_help(texte: str) -> str:
    """Echappement d'une ligne ``# HELP`` (barre oblique inverse et saut de ligne)."""
    logger.debug("_escape_help: retour str")
    return texte.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label(valeur: str) -> str:
    """Echappement d'une valeur d'etiquette (``\\``, ``"`` et saut de ligne)."""
    logger.debug("_escape_label: retour str")
    return valeur.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_value(valeur: float) -> str:
    """Valeur d'une serie : entier sans decimale, ``NaN``, ``+Inf``/``-Inf``,
    sinon la representation exacte la plus courte (``repr``)."""
    logger.debug("_format_value: entrée")
    if math.isnan(valeur):
        logger.debug("_format_value: si NaN -> retour NaN")
        return "NaN"
    if math.isinf(valeur):
        logger.debug("_format_value: si infini -> retour Inf signe")
        return "+Inf" if valeur > 0 else "-Inf"
    if valeur.is_integer() and abs(valeur) < 1e15:
        logger.debug("_format_value: si entier -> retour sans decimale")
        return str(int(valeur))
    logger.debug("_format_value: retour repr")
    return repr(valeur)


def _sample_line(sample: Sample) -> str:
    """Ligne ``nom{etiquettes} valeur`` d'une serie."""
    logger.debug("_sample_line: entrée ({})", sample.name)
    etiquettes = ",".join(f'{k}="{_escape_label(v)}"' for k, v in sample.labels)
    nom = f"{sample.name}{{{etiquettes}}}" if etiquettes else sample.name
    ligne = f"{nom} {_format_value(sample.value)}"
    logger.debug("_sample_line: retour str")
    return ligne


def _grouped(samples) -> list[tuple[MetricSpec, list[Sample]]]:
    """Series regroupees par metrique, dans l'ordre de ``METRICS`` (une
    famille ne doit apparaitre qu'une fois dans le texte). Une serie hors
    catalogue est refusee : aucun nom ne s'invente a l'exposition."""
    logger.debug("_grouped: entrée")
    par_famille: dict[str, list[Sample]] = {}
    for sample in samples:
        spec = _family(sample.name)
        if spec is None:
            logger.debug("_grouped: serie hors catalogue -> ValueError")
            raise ValueError(f"serie hors catalogue : {sample.name}")
        par_famille.setdefault(spec.name, []).append(sample)
    groupes = [(m, par_famille[m.name]) for m in METRICS if m.name in par_famille]
    logger.debug("_grouped: retour {} famille(s)", len(groupes))
    return groupes


def render_prometheus_text(samples, comment: str | None = None) -> str:
    """Texte Prometheus 0.0.4 (textfile collector de node_exporter, promtool).

    ``# HELP`` et ``# TYPE`` precedent chaque famille ; un compteur garde son
    nom complet en ``_total``. ``comment`` (une ligne, facultatif) est ecrit
    en tete comme commentaire, par exemple pour signaler ``--redact``.
    """
    logger.debug("render_prometheus_text: entrée")
    lignes = []
    if comment:
        lignes.append("# " + " ".join(comment.split()))
    for spec, series in _grouped(samples):
        lignes.append(f"# HELP {spec.name} {_escape_help(spec.help)}")
        lignes.append(f"# TYPE {spec.name} {spec.type}")
        lignes.extend(_sample_line(s) for s in series)
    texte = "\n".join(lignes) + "\n"
    logger.debug("render_prometheus_text: retour {} ligne(s)", len(lignes))
    return texte


def render_openmetrics(samples) -> str:
    """Texte OpenMetrics 1.0 : famille sans ``_total`` pour un compteur,
    ``# UNIT`` quand le nom se termine par l'unite, ``# EOF`` final."""
    logger.debug("render_openmetrics: entrée")
    lignes = []
    for spec, series in _grouped(samples):
        famille = spec.name.removesuffix("_total") if spec.type == COUNTER else spec.name
        lignes.append(f"# TYPE {famille} {spec.type}")
        if spec.unit and famille.endswith("_" + spec.unit):
            lignes.append(f"# UNIT {famille} {spec.unit}")
        lignes.append(f"# HELP {famille} {_escape_help(spec.help)}")
        lignes.extend(_sample_line(s) for s in series)
    lignes.append("# EOF")
    logger.debug("render_openmetrics: retour {} ligne(s)", len(lignes))
    return "\n".join(lignes) + "\n"


def write_prom_file(texte: str, path) -> str:
    """Ecrit ``texte`` dans ``path`` de facon atomique : fichier temporaire du
    meme dossier puis ``os.replace``. node_exporter ignore les fichiers qui
    ne finissent pas par ``.prom`` : le temporaire n'est donc jamais lu, et
    le fichier final est toujours complet."""
    logger.debug("write_prom_file: entrée")
    chemin = os.fspath(path)
    dossier = os.path.dirname(os.path.abspath(chemin))
    fd, temporaire = tempfile.mkstemp(prefix=".netcross-", suffix=".tmp", dir=dossier)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(texte)
        os.chmod(temporaire, 0o644)
        os.replace(temporaire, chemin)
    except OSError as exc:
        logger.debug("write_prom_file: echec d'ecriture ({}) -> suppression du temporaire", exc)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporaire)
        logger.debug("write_prom_file: levee propagee")
        raise
    logger.debug("write_prom_file: retour chemin")
    return chemin


_ADRESSE = re.compile(
    r"(?<![0-9A-Za-z:.])(?:"
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"  # MAC
    r"|(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"  # IPv6
    r")(?![0-9A-Za-z:.])"
)


def redact_samples(samples, redactor) -> list[Sample]:
    """Series dont les valeurs d'etiquette ne contiennent plus aucune
    adresse IP ou MAC reelle : chacune est remplacee par son pseudonyme dans
    ``redactor`` (``netcross_core.redact.AddressRedactor`` du run, donc meme
    pseudonyme que dans les paquets et ``--redact-map``)."""
    logger.debug("redact_samples: entrée")

    def anonymiser(valeur: str) -> str:
        resultat = _ADRESSE.sub(lambda m: redactor.pseudonymize_address(m.group(0)), valeur)
        logger.debug("redact_samples.anonymiser: retour str")
        return resultat

    sortie = [replace(s, labels=tuple((k, anonymiser(v)) for k, v in s.labels)) for s in samples]
    logger.debug("redact_samples: retour {} serie(s)", len(sortie))
    return sortie
