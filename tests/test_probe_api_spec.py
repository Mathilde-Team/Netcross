"""Validation du contrat agent netcross-probe <-> collecteur (issue #1098).

- le schema docs/probe-api-v1.yaml est un document OpenAPI 3.1 valide
  (meta-schema officiel recopie dans tests/data, source :
  https://spec.openapis.org/oas/3.1/schema/2022-10-07, licence Apache-2.0) ;
- ses schemas sont des JSON Schema 2020-12 valides, ses $ref se resolvent
  et ses exemples respectent ses propres schemas ;
- routes, versionnement et securite exiges par l'issue sont presents ;
- la specification lisible docs/probe-api.md reste alignee.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

RACINE = Path(__file__).resolve().parent.parent
SPEC_PATH = RACINE / "docs" / "probe-api-v1.yaml"
DOC_PATH = RACINE / "docs" / "probe-api.md"
OAS31_SCHEMA = RACINE / "tests" / "data" / "openapi-3.1-schema-2022-10-07.json"
SPEC_URI = "urn:netcross:probe-api-v1"
METHODES = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


@pytest.fixture(scope="module")
def spec():
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry(spec):
    return Registry().with_resource(SPEC_URI, Resource.from_contents(spec, default_specification=_draft()))


def _draft():
    from referencing.jsonschema import DRAFT202012

    return DRAFT202012


def _validateur(nom, registry):
    return Draft202012Validator({"$ref": f"{SPEC_URI}#/components/schemas/{nom}"}, registry=registry)


def _operations(spec):
    for chemin, item in spec["paths"].items():
        for methode in METHODES:
            if methode in item:
                yield chemin, methode, item[methode]


def _refs(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref":
                yield v
            else:
                yield from _refs(v)
    elif isinstance(node, list):
        for v in node:
            yield from _refs(v)


def _resoudre(spec, ref):
    assert ref.startswith("#/"), ref
    node = spec
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


# -- validite structurelle -------------------------------------------------------------


def test_document_openapi_31_valide(spec):
    assert spec["openapi"] == "3.1.0"
    meta = json.loads(OAS31_SCHEMA.read_text(encoding="utf-8"))
    erreurs = sorted(Draft202012Validator(meta).iter_errors(spec), key=lambda e: list(e.path))
    assert not erreurs, [f"{list(e.path)}: {e.message}" for e in erreurs]


def test_meta_schema_rejette_un_document_invalide(spec):
    meta = json.loads(OAS31_SCHEMA.read_text(encoding="utf-8"))
    casse = {**spec, "info": {"title": "sans version"}}
    assert not Draft202012Validator(meta).is_valid(casse)


def test_schemas_json_schema_2020_12_valides(spec):
    for nom, schema in spec["components"]["schemas"].items():
        assert nom
        Draft202012Validator.check_schema(schema)


def test_toutes_les_references_se_resolvent(spec):
    refs = set(_refs(spec))
    assert refs
    for ref in refs:
        assert _resoudre(spec, ref) is not None


def test_operation_ids_uniques(spec):
    ids = [op["operationId"] for _, _, op in _operations(spec)]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    "nom", ["EnrollmentRequest", "EnrollmentResponse", "Health", "ProbeMetadata", "WindowRequest", "Window"]
)
def test_exemples_conformes_aux_schemas(spec, registry, nom):
    exemple = spec["components"]["examples"][nom]["value"]
    erreurs = list(_validateur(nom, registry).iter_errors(exemple))
    assert not erreurs, [e.message for e in erreurs]


@pytest.mark.parametrize(
    ("nom", "invalide"),
    [
        ("WindowRequest", {"end": 1.0}),  # start manquant
        ("WindowRequest", {"start": -1, "end": 1.0}),
        ("Window", {"window_id": "x"}),
        ("ClockStatus", {"source": "gps", "synchronized": True}),  # source hors enumeration
        ("EnrollmentRequest", {"probe_name": "ROUTEUR", "csr_pem": "x", "agent_version": "1", "api_versions": []}),
        ("Interval", {"start": 0, "end": 1, "extra": 2}),
        ("Error", {"error": "Majuscule", "message": "m"}),
    ],
)
def test_schemas_rejettent_les_donnees_invalides(registry, nom, invalide):
    assert not _validateur(nom, registry).is_valid(invalide)


def test_exemples_de_fenetre_coherents(spec):
    ex = spec["components"]["examples"]
    assert ex["WindowRequest"]["value"]["start"] <= ex["WindowRequest"]["value"]["end"]
    w = ex["Window"]["value"]
    assert w["covered"]["start"] >= w["requested"]["start"]
    assert w["covered"]["end"] <= w["requested"]["end"]
    assert w["capture_loss"]["packets_dropped"] == w["capture_loss"]["ifdrop"] + w["capture_loss"]["osdrop"]


# -- criteres d'acceptation -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("chemin", "methode"),
    [
        ("/probe/v1/enrollments", "post"),  # inscription
        ("/probe/v1/health", "get"),  # sante
        ("/probe/v1/windows", "post"),  # fenetre [t1, t2] + BPF
        ("/probe/v1/metadata", "get"),  # metadonnees
        ("/probe/v1/windows/{window_id}", "get"),
        ("/probe/v1/windows/{window_id}/pcapng", "get"),
    ],
)
def test_routes_exigees(spec, chemin, methode):
    assert methode in spec["paths"][chemin]


def test_fenetre_porte_intervalle_bpf_pertes_et_horloge(spec):
    s = spec["components"]["schemas"]
    assert {"start", "end", "bpf"} <= set(s["WindowRequest"]["properties"])
    assert {"covered", "capture_loss", "clock"} <= set(s["Window"]["required"])
    assert {"ifdrop", "osdrop"} <= set(s["CaptureLoss"]["properties"])
    assert {"ptp", "chrony", "ntpd"} <= set(s["ClockSource"]["enum"])
    pcapng = spec["paths"]["/probe/v1/windows/{window_id}/pcapng"]["get"]["responses"]["200"]["content"]
    assert list(pcapng) == ["application/x-pcapng"]


def test_versionnement(spec):
    majeur = spec["info"]["version"].split(".")[0]
    assert re.fullmatch(r"\d+\.\d+\.\d+", spec["info"]["version"])
    for chemin in spec["paths"]:
        assert chemin.startswith(f"/probe/v{majeur}/"), chemin
    for chemin, methode, op in _operations(spec):
        for code, rep in op["responses"].items():
            if code.startswith("2") and "content" in rep:
                assert "Netcross-Probe-Api" in rep.get("headers", {}), (chemin, methode, code)
    assert "api_versions" in spec["components"]["schemas"]["EnrollmentRequest"]["required"]
    assert "api_version" in spec["components"]["schemas"]["EnrollmentResponse"]["required"]
    assert "426" in spec["paths"]["/probe/v1/enrollments"]["post"]["responses"]


def test_modele_de_securite(spec):
    schemes = spec["components"]["securitySchemes"]
    assert schemes["mtls"]["type"] == "mutualTLS"
    assert schemes["enrollmentToken"] == {**schemes["enrollmentToken"], "type": "http", "scheme": "bearer"}
    assert spec["security"] == [{"mtls": []}]  # par defaut : mTLS partout
    for chemin, methode, op in _operations(spec):
        if op["operationId"] == "enroll_probe":
            assert op["security"] == [{"enrollmentToken": []}]
        else:
            assert "security" not in op, (chemin, methode)  # aucune route agent sans mTLS
            assert op["tags"] == ["agent"]
            assert "401" in op["responses"], (chemin, methode)


def test_aucun_secret_dans_les_exemples(spec):
    texte = json.dumps(spec["components"]["examples"])
    assert "PRIVATE KEY" not in texte
    assert "Bearer" not in texte


# -- documentation ------------------------------------------------------------------------------


def test_documentation_alignee(spec):
    doc = DOC_PATH.read_text(encoding="utf-8")
    assert spec["info"]["version"] in doc
    assert "probe-api-v1.yaml" in doc
    for chemin, methode, op in _operations(spec):
        assert f"`{methode.upper()}` | `{chemin}`" in doc, (methode, chemin)
        assert op["operationId"] in doc
    for section in ("## Versionnement et compatibilité", "## Modèle de sécurité", "mTLS", "jeton d'enrôlement"):
        assert section.lower() in doc.lower()


def test_documentation_dans_la_navigation():
    assert "probe-api.md" in (RACINE / "mkdocs.yml").read_text(encoding="utf-8")
