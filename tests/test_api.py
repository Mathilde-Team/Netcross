# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_api -- tests (issue #209).

Utilise FastAPI TestClient (httpx) pour tester les endpoints sans
démarrer un serveur. Les tests ne dépendent pas de tshark : on mocke
parse_capture pour injecter des paquets synthétiques.
"""

from __future__ import annotations

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
    """Mock de parse_capture qui retourne des paquets synthétiques."""
    return [
        make_pkt(src="192.168.1.1", dst="192.168.1.2", dport=80, ts=1000.0),
        make_pkt(src="192.168.1.2", dst="192.168.1.1", dport=50000, ts=1001.0),
    ]


# --- Health ----------------------------------------------------------------


def test_health_ok():
    """GET /health doit retourner 200 et status=ok."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


# --- Upload capture --------------------------------------------------------


def test_upload_capture_success():
    """POST /captures avec un pcap mocké doit retourner 201."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A"},
        )
    assert response.status_code == 201
    data = response.json()
    assert "analysis_id" in data
    assert data["status"] == "completed"
    assert data["packet_count"] == 2
    assert data["point_count"] >= 1


def test_upload_capture_no_filename():
    """POST /captures sans nom de fichier doit retourner une erreur (422 FastAPI)."""
    response = client.post(
        "/captures?wait=true",
        files={"file": ("", _fake_capture_file(), "application/octet-stream")},
        data={"label": "test"},
    )
    assert response.status_code in (400, 422)


def test_upload_capture_empty_file():
    """POST /captures avec un fichier vide doit retourner 400."""
    with patch("netcross_api.app.parse_capture", return_value=[]):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("empty.pcap", b"", "application/octet-stream")},
            data={"label": "test"},
        )
    assert response.status_code == 400


def test_upload_capture_parse_error():
    """POST /captures avec une erreur de parsing doit retourner 400."""
    with patch("netcross_api.app.parse_capture", side_effect=Exception("tshark not found")):
        response = client.post(
            "/captures?wait=true",
            files={"file": ("bad.pcap", b"garbage", "application/octet-stream")},
            data={"label": "test"},
        )
    assert response.status_code == 400
    assert "Erreur de parsing" in response.json()["detail"]


# --- Get analysis ----------------------------------------------------------


def test_get_analysis_success():
    """GET /analyses/{id} doit retourner le rapport JSON."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        upload = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A"},
        )
    analysis_id = upload.json()["analysis_id"]

    response = client.get(f"/analyses/{analysis_id}")
    assert response.status_code == 200
    data = response.json()
    # Le rapport JSON contient au moins des métadonnées
    assert isinstance(data, dict)


def test_get_analysis_not_found():
    """GET /analyses/{id} avec un ID inexistant doit retourner 404."""
    response = client.get("/analyses/inexistant12345")
    assert response.status_code == 404
    assert "introuvable" in response.json()["detail"]


# --- Security report -------------------------------------------------------


def test_get_security_report_success():
    """GET /analyses/{id}/security doit retourner les constats."""
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        upload = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A"},
        )
    analysis_id = upload.json()["analysis_id"]

    response = client.get(f"/analyses/{analysis_id}/security")
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"] == analysis_id
    assert isinstance(data["findings"], list)
    assert isinstance(data["service_fingerprints"], list)


def test_get_security_report_not_found():
    """GET /analyses/{id}/security avec un ID inexistant doit retourner 404."""
    response = client.get("/analyses/inexistant12345/security")
    assert response.status_code == 404


# --- List analyses ---------------------------------------------------------


def test_list_analyses():
    """GET /analyses doit lister les IDs d'analyses."""
    # Au début, liste vide
    response = client.get("/analyses")
    assert response.status_code == 200
    assert response.json()["analyses"] == []

    # Ajouter une analyse
    with patch("netcross_api.app.parse_capture", side_effect=_mock_parse_capture):
        upload = client.post(
            "/captures?wait=true",
            files={"file": ("test.pcap", _fake_capture_file(), "application/octet-stream")},
            data={"label": "point-A"},
        )
    analysis_id = upload.json()["analysis_id"]

    # La liste doit maintenant contenir l'ID
    response = client.get("/analyses")
    assert response.status_code == 200
    assert analysis_id in response.json()["analyses"]


# --- OpenAPI spec ----------------------------------------------------------


def test_openapi_json_available():
    """GET /openapi.json doit retourner la spec OpenAPI."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    assert spec["info"]["title"] == "Netcross API"
    assert "paths" in spec
    assert "/captures" in spec["paths"]
    assert "/analyses/{analysis_id}" in spec["paths"]
    assert "/health" in spec["paths"]


def test_swagger_ui_available():
    """GET /docs doit retourner la Swagger UI."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger" in response.text.lower()
