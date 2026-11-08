# SPDX-License-Identifier: GPL-3.0-or-later
"""Base CVE minimale embarquee (issue #353).

Sans --cve-db, un Apache 2.4.49 n'etait pas qualifie vulnerable. La base
`data/cve_seed.json` (extraite du NVD par scripts/build_cve_seed.py) sert
de filet de securite sans configuration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from netcross_core.security import correlate_banner
from netcross_core.security.cpe_match import PRODUCT_ALIASES, vendor_candidates
from netcross_core.security.cve_db import AffectedProduct, CveEntry, connect_cve_db, upsert_cve
from netcross_core.security.cve_seed import DEFAULT_SEED_PATH, SEED_FORMAT_VERSION, load_seed, open_seed_db

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_cve_seed  # noqa: E402
import import_nvd  # noqa: E402


@pytest.fixture(scope="module")
def seed_conn():
    conn, _ = open_seed_db()
    yield conn
    conn.close()


def _ids(conn, banner: str) -> set[str]:
    return {m.cve_id for m in correlate_banner(conn, banner)}


def test_fichier_embarque_valide_et_provenance_nvd():
    seed = load_seed()
    assert DEFAULT_SEED_PATH.name == "cve_seed.json"
    assert len(seed.entries) == len(build_cve_seed.SEED_CVE_IDS)
    assert {e.cve_id for e in seed.entries} == set(build_cve_seed.SEED_CVE_IDS)
    assert "NVD" in seed.source
    assert seed.generated


def test_chaque_cve_a_un_score_et_des_produits_catalogues():
    catalogued = {(v, p) for vendor, p in PRODUCT_ALIASES.values() for v in vendor_candidates(vendor, p)}
    for entry in load_seed().entries:
        assert entry.cvss_score is not None, entry.cve_id
        assert entry.cvss_severity, entry.cve_id
        assert entry.description, entry.cve_id
        assert entry.affected, entry.cve_id
        for product in entry.affected:
            assert (product.vendor, product.product) in catalogued, (entry.cve_id, product)


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("Apache/2.4.49", {"CVE-2021-41773", "CVE-2021-42013"}),
        ("Apache/2.4.50", {"CVE-2021-42013"}),
        ("OpenSSH_8.9p1", {"CVE-2024-6387"}),
        ("OpenSSL/1.0.1f", {"CVE-2014-0160"}),
        ("vsFTPd/2.3.4", {"CVE-2011-2523"}),
        # Vendeurs CPE renommes par le NVD (f5:nginx, vsftpd_project:vsftpd) :
        # avec l'ancien catalogue, ces bannieres ne trouvaient AUCUNE CVE.
        ("nginx/1.20.0", {"CVE-2021-23017"}),
        ("nginx/1.4.0", {"CVE-2013-2028"}),
    ],
)
def test_versions_vulnerables_qualifiees_sans_configuration(seed_conn, banner, expected):
    assert expected <= _ids(seed_conn, banner)


def test_apache_2_4_50_n_est_plus_touche_par_41773(seed_conn):
    assert "CVE-2021-41773" not in _ids(seed_conn, "Apache/2.4.50")


@pytest.mark.parametrize("banner", ["Apache/2.4.62", "nginx/1.27.3", "OpenSSH_9.9p1"])
def test_versions_recentes_sans_cve_de_la_selection(seed_conn, banner):
    assert _ids(seed_conn, banner) == set()


def test_format_inattendu_refuse(tmp_path):
    bad = tmp_path / "seed.json"
    bad.write_text(json.dumps({"version": SEED_FORMAT_VERSION + 1, "cves": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="format"):
        load_seed(bad)


# -- limitation de debit du NVD (HTTP 200, page vide) ----------------------------


def test_page_vide_de_limitation_detectee():
    assert import_nvd._is_throttled({"resultsPerPage": 0, "startIndex": 0, "totalResults": 1, "vulnerabilities": []})
    assert not import_nvd._is_throttled(
        {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    )
    assert not import_nvd._is_throttled({"startIndex": 0, "totalResults": 1, "vulnerabilities": [{"cve": {}}]})


def test_fetch_page_reessaie_puis_renvoie_la_page(monkeypatch):
    pages = iter(
        [
            {"startIndex": 0, "totalResults": 1, "vulnerabilities": []},
            {"startIndex": 0, "totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-41773"}}]},
        ]
    )
    monkeypatch.setattr(import_nvd, "_fetch_page_once", lambda params: next(pages))
    monkeypatch.setattr(import_nvd.time, "sleep", lambda s: None)
    assert import_nvd._fetch_page({"cveId": "CVE-2021-41773"})["vulnerabilities"]


def test_fetch_page_limitation_persistante_leve_au_lieu_de_tronquer(monkeypatch):
    monkeypatch.setattr(
        import_nvd, "_fetch_page_once", lambda params: {"startIndex": 0, "totalResults": 3, "vulnerabilities": []}
    )
    monkeypatch.setattr(import_nvd.time, "sleep", lambda s: None)
    with pytest.raises(RuntimeError, match="limite le debit"):
        import_nvd._fetch_page({"startIndex": 0})


def _db_with(tmp_path, *vendors, product):
    conn = connect_cve_db(tmp_path / "cve.db")
    upsert_cve(
        conn,
        CveEntry(
            cve_id="CVE-2099-0001",
            description="test",
            cvss_score=7.5,
            cvss_severity="HIGH",
            published=None,
            affected=[AffectedProduct(vendor=v, product=product, version_end_excluding="9.0") for v in vendors],
        ),
    )
    return conn


@pytest.mark.parametrize(
    ("vendor", "product", "banner"),
    [
        ("nginx", "nginx", "nginx/1.20.0"),
        ("f5", "nginx", "nginx/1.20.0"),
        ("beasts", "vsftpd", "vsFTPd/2.3.4"),
        ("vsftpd_project", "vsftpd", "vsFTPd/2.3.4"),
    ],
)
def test_vendeur_actuel_et_historique_reconnus(tmp_path, vendor, product, banner):
    """Une base --cve-db importee avant le renommage du vendeur par le NVD
    reste exploitable."""
    conn = _db_with(tmp_path, vendor, product=product)
    try:
        assert [m.cve_id for m in correlate_banner(conn, banner)] == ["CVE-2099-0001"]
    finally:
        conn.close()


def test_cve_listee_sous_deux_vendeurs_rapportee_une_fois(tmp_path):
    conn = _db_with(tmp_path, "nginx", "f5", product="nginx")
    try:
        assert [m.cve_id for m in correlate_banner(conn, "nginx/1.20.0")] == ["CVE-2099-0001"]
    finally:
        conn.close()
