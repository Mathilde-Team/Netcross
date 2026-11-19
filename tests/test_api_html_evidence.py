# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests des exports HTML et extraits pcap de preuve de l'API (issue #1083).

GET /analyses/{id}/report/html  — rapport HTML autonome (équivalent --html-report)
GET /analyses/{id}/evidence-pcaps — zip des extraits pcap de preuve (équivalent --evidence-pcaps)

Mêmes patterns que tests/test_api_exports.py : mock de parse_capture,
paquets synthétiques via tests.conftest.make_pkt.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from tests.conftest import make_pkt

try:
    from fastapi.testclient import TestClient

    from netcross_api.app import app
    from netcross_api.store import store

    client = TestClient(app)
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi non installé (extra [api])")


@pytest.fixture(autouse=True)
def reset_store():
    """Réinitialise le store entre les tests."""
    store._store.clear()
    yield
    store._store.clear()


def _fake_capture_file() -> bytes:
    """Crée un faux pcap (bytes quelconques, le parsing est mocké)."""
    return b"\xd4\xc3\xb2\xa1" + b"\x00" * 100


def _mock_parse_capture(label, path):
    """Mock de parse_capture qui retourne des paquets synthétiques.

    Duplication d'un paquet (même empreinte à 30 ms) : l'analyse produit au
    moins un constat, donc des preuves cliquables et des extraits pcap de
    preuve (issue #1083).
    """
    paquets = [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.03),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]
    return paquets


def _mock_build_findings(report):
    """Mock de build_findings : un Finding référençant la trame 1 du point A
    (mêmes classes que les vrais constats de netcross_report.synthesis)."""
    from netcross_core.expert_model import EvidenceLink, PacketEvidence
    from netcross_report.synthesis import Finding

    return [
        Finding(
            severity="P1",
            category="TCP",
            segment="point-A->192.168.1.2",
            message="retransmission en rafale",
            evidence=[EvidenceLink("point-A", "trame 1", packet=PacketEvidence("point-A", 1))],
        )
    ]


def _upload_analysis(**params) -> str:
    """Upload une analyse mockée et retourne son ID (un constat, issue #1083)."""
    with (
        patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture),
        patch("netcross_api.app.build_findings", side_effect=_mock_build_findings),
    ):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A", **params},
        )
    assert response.status_code == 201, response.text
    return response.json()["analysis_id"]


def _fake_extraire_preuves(findings, fichiers, dossier, contexte=3, redactor=None):
    """Faux extracteur : un extrait par constat, fichier bidon sur disque."""
    nom = "constat-001-point-a.pcapng"
    with open(os.path.join(dossier, nom), "wb") as sortie:
        sortie.write(b"\x0a\x0d\x0d\x0apreuve")
    return [{"ref": "point-A#1", "point": "point-A", "frame_number": 1, "fichier": nom}]


# --- Rapport HTML ----------------------------------------------------------


def test_html_report_export_success():
    """GET /analyses/{id}/report/html retourne le rapport HTML autonome (200, text/html)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/report/html")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "attachment" in response.headers.get("content-disposition", "")
    assert f"netcross-{analysis_id}.html" in response.headers.get("content-disposition", "")
    # Fichier unique, aucune ressource externe chargee (ni script, ni image,
    # ni style) : les seuls http:// possibles sont des namespaces XML
    # (ex. http://www.w3.org/2000/), jamais des attributs src/href
    assert "<!DOCTYPE html>" in response.text
    assert 'src="http' not in response.text
    assert 'href="http' not in response.text


def test_html_report_export_not_found():
    """GET /analyses/{id}/report/html avec un ID inexistant retourne 404."""
    response = client.get("/analyses/inexistant12345/report/html")
    assert response.status_code == 404


def test_html_report_export_pending():
    """GET /analyses/{id}/report/html sur une analyse pending retourne 409."""
    analysis_id = store.create_pending({"filename": "test.pcap"})
    response = client.get(f"/analyses/{analysis_id}/report/html")
    assert response.status_code == 409


# --- Extraits pcap de preuve ------------------------------------------------


def test_evidence_pcaps_success():
    """evidence_pcaps=true : l'archive zip des extraits est téléchargeable (200)."""
    analysis_id = _upload_analysis(evidence_pcaps="true")
    response = client.get(f"/analyses/{analysis_id}/evidence-pcaps")
    assert response.status_code == 200
    assert "application/zip" in response.headers.get("content-type", "")
    # Un zip commence par la signature PK\x03\x04
    assert response.content[:4] == b"PK\x03\x04"
    assert "attachment" in response.headers.get("content-disposition", "")
    # L'URL est annoncée dans le statut (résumé) de l'analyse
    statut = client.get(f"/analyses/{analysis_id}/status").json()
    assert statut.get("summary", {}).get("evidence_pcaps_url") == f"/analyses/{analysis_id}/evidence-pcaps"


def test_evidence_pcaps_not_requested():
    """Sans evidence_pcaps=true : la route retourne 404 (pas d'extraits)."""
    analysis_id = _upload_analysis()
    response = client.get(f"/analyses/{analysis_id}/evidence-pcaps")
    assert response.status_code == 404
    statut = client.get(f"/analyses/{analysis_id}/status").json()
    assert "evidence_pcaps_url" not in (statut.get("summary") or {})


def test_evidence_pcaps_extracteur_mocke():
    """L'extraction passe par extraire_preuves_pcaps et sert le fichier produit."""
    with (
        patch(
            "netcross_core.extract.evidence_pcaps.extraire_preuves_pcaps",
            side_effect=_fake_extraire_preuves,
        ) as moqueur,
        patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture),
        patch("netcross_api.app.build_findings", side_effect=_mock_build_findings),
    ):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A", "evidence_pcaps": "true"},
        )
    assert response.status_code == 201, response.text
    analysis_id = response.json()["analysis_id"]
    assert moqueur.called
    reponse_zip = client.get(f"/analyses/{analysis_id}/evidence-pcaps")
    assert reponse_zip.status_code == 200
    assert reponse_zip.content[:4] == b"PK\x03\x04"
    # L'extrait bidon est dans l'archive
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(reponse_zip.content)) as archive:
        assert "constat-001-point-a.pcapng" in archive.namelist()


def test_evidence_pcaps_not_found():
    """GET /analyses/{id}/evidence-pcaps avec un ID inexistant retourne 404."""
    response = client.get("/analyses/inexistant12345/evidence-pcaps")
    assert response.status_code == 404
